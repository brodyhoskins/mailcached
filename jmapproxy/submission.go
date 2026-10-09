package jmapproxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/brodyhoskins/mailcached/internal/jmap"
	"github.com/brodyhoskins/mailcached/smtpproxy"
)

// Each account has one identity: its login. Sending goes through the
// SMTP side's Submit, so it passes the same Filter as mail from SMTP
// clients. The proxy keeps the submissions of this run in memory; once
// handed to the provider they are final.

func identityOf(c *client) jmap.Identity {
	h := sha256.Sum256([]byte(c.login))
	email := c.login
	if !strings.Contains(email, "@") {
		email = ""
	}
	return jmap.Identity{ID: jmap.ID("i" + hex.EncodeToString(h[:8])), Email: email,
		ReplyTo: []jmap.EmailAddress{}, Bcc: []jmap.EmailAddress{}}
}

// identityState never changes: the identity is the login.
const identityState = "1"

func identityGet(c *call) (any, error) {
	var args jmap.GetArgs
	if err := c.decode(&args); err != nil {
		return nil, err
	}
	id := identityOf(c.c)
	resp := jmap.GetResponse[any]{AccountID: c.c.id, State: identityState, List: []any{}, NotFound: []jmap.ID{}}
	if args.IDs == nil || slices.Contains(args.IDs, id.ID) {
		v, err := filterProps(id, args.Properties)
		if err != nil {
			return nil, err
		}
		resp.List = append(resp.List, v)
	}
	for _, x := range args.IDs {
		if x != id.ID {
			resp.NotFound = append(resp.NotFound, x)
		}
	}
	return resp, nil
}

func identityChanges(c *call) (any, error) {
	var args jmap.ChangesArgs
	if err := c.decode(&args); err != nil {
		return nil, err
	}
	if args.SinceState != identityState {
		return nil, &jmap.MethodError{Type: jmap.ErrCannotCalculateChanges}
	}
	return jmap.ChangesResponse{AccountID: c.c.id, OldState: identityState, NewState: identityState,
		Created: []jmap.ID{}, Updated: []jmap.ID{}, Destroyed: []jmap.ID{}}, nil
}

// submissions are an account's submissions of this run.
type submissions struct {
	mu    sync.Mutex
	list  []*jmap.EmailSubmission
	state int
	seq   int
}

func (s *Server) submissionsOf(login string) *submissions {
	s.subMu.Lock()
	defer s.subMu.Unlock()
	if s.subs == nil {
		s.subs = map[string]*submissions{}
	}
	if s.subs[login] == nil {
		s.subs[login] = &submissions{}
	}
	return s.subs[login]
}

func submissionGet(c *call) (any, error) {
	var args jmap.GetArgs
	if err := c.decode(&args); err != nil {
		return nil, err
	}
	subs := c.s.submissionsOf(c.c.login)
	subs.mu.Lock()
	defer subs.mu.Unlock()
	resp := jmap.GetResponse[any]{AccountID: c.c.id, State: jmap.State(strconv.Itoa(subs.state)), List: []any{}, NotFound: []jmap.ID{}}
	for _, sub := range subs.list {
		if args.IDs == nil || slices.Contains(args.IDs, sub.ID) {
			v, err := filterProps(sub, args.Properties)
			if err != nil {
				return nil, err
			}
			resp.List = append(resp.List, v)
		}
	}
	for _, id := range args.IDs {
		if !slices.ContainsFunc(subs.list, func(s *jmap.EmailSubmission) bool { return s.ID == id }) {
			resp.NotFound = append(resp.NotFound, id)
		}
	}
	return resp, nil
}

func submissionChanges(c *call) (any, error) {
	var args jmap.ChangesArgs
	if err := c.decode(&args); err != nil {
		return nil, err
	}
	subs := c.s.submissionsOf(c.c.login)
	subs.mu.Lock()
	defer subs.mu.Unlock()
	// Only "no changes" can be told apart: submissions are final at once.
	if string(args.SinceState) != strconv.Itoa(subs.state) {
		return nil, &jmap.MethodError{Type: jmap.ErrCannotCalculateChanges}
	}
	return jmap.ChangesResponse{AccountID: c.c.id, OldState: args.SinceState, NewState: args.SinceState,
		Created: []jmap.ID{}, Updated: []jmap.ID{}, Destroyed: []jmap.ID{}}, nil
}

func submissionQuery(c *call) (any, error) {
	var args jmap.QueryArgs
	if err := c.decode(&args); err != nil {
		return nil, err
	}
	subs := c.s.submissionsOf(c.c.login)
	subs.mu.Lock()
	ids := make([]jmap.ID, len(subs.list))
	for i, s := range subs.list {
		ids[i] = s.ID
	}
	state := strconv.Itoa(subs.state)
	subs.mu.Unlock()
	total := len(ids)
	ids, pos, err := window(&args, ids)
	if err != nil {
		return nil, err
	}
	resp := jmap.QueryResponse{AccountID: c.c.id, QueryState: jmap.State(state), Position: pos, IDs: ids}
	if args.CalculateTotal {
		resp.Total = &total
	}
	return resp, nil
}

var bccField = regexp.MustCompile(`(?mi)^Bcc:.*\r?\n(?:[ \t].*\r?\n)*`)

// withoutBcc removes the Bcc field from a message's header.
func withoutBcc(data []byte) []byte {
	end := bytes.Index(data, []byte("\r\n\r\n"))
	if end < 0 {
		return data
	}
	hdr := bccField.ReplaceAll(data[:end+2], nil)
	return append(hdr, data[end+2:]...)
}

func submissionSet(c *call) (any, error) {
	var args jmap.SetArgs[json.RawMessage]
	if err := c.decode(&args); err != nil {
		return nil, err
	}
	subs := c.s.submissionsOf(c.c.login)
	subs.mu.Lock()
	old := strconv.Itoa(subs.state)
	subs.mu.Unlock()
	if args.IfInState != "" && string(args.IfInState) != old {
		return nil, &jmap.MethodError{Type: jmap.ErrStateMismatch}
	}
	created := map[jmap.ID]any{}
	notCreated, notUpdated, notDestroyed := map[jmap.ID]jmap.SetError{}, map[jmap.ID]jmap.SetError{}, map[jmap.ID]jmap.SetError{}
	sentEmail := map[jmap.ID]jmap.ID{} // submission ID -> email ID

	for cid, raw := range args.Create {
		var in jmap.EmailSubmission
		if err := json.Unmarshal(raw, &in); err != nil {
			notCreated[cid] = jmap.SetError{Type: jmap.SetInvalidProperties, Description: err.Error()}
			continue
		}
		sub, serr := c.send(&in)
		if serr != nil {
			notCreated[cid] = *serr
			continue
		}
		subs.mu.Lock()
		subs.seq++
		subs.state++
		sub.ID = jmap.ID("s" + strconv.Itoa(subs.seq))
		subs.list = append(subs.list, sub)
		subs.mu.Unlock()
		c.created[cid] = sub.ID
		sentEmail[sub.ID] = sub.EmailID
		created[cid] = map[string]any{"id": sub.ID, "threadId": sub.ThreadID, "sendAt": sub.SendAt, "undoStatus": sub.UndoStatus}
	}
	for id := range args.Update {
		notUpdated[id] = jmap.SetError{Type: jmap.SetCannotUnsend, Description: "Sent already"}
	}
	var destroyed []jmap.ID
	for _, id := range args.Destroy {
		id = c.resolve(id)
		subs.mu.Lock()
		i := slices.IndexFunc(subs.list, func(s *jmap.EmailSubmission) bool { return s.ID == id })
		if i >= 0 {
			subs.list = slices.Delete(subs.list, i, i+1)
			subs.state++
		}
		subs.mu.Unlock()
		if i < 0 {
			notDestroyed[id] = jmap.SetError{Type: jmap.SetNotFound}
			continue
		}
		destroyed = append(destroyed, id)
	}

	subs.mu.Lock()
	resp := map[string]any{"accountId": c.c.id, "oldState": old, "newState": strconv.Itoa(subs.state)}
	subs.mu.Unlock()
	if len(created) > 0 {
		resp["created"] = created
	}
	if len(destroyed) > 0 {
		resp["destroyed"] = destroyed
	}
	if len(notCreated) > 0 {
		resp["notCreated"] = notCreated
	}
	if len(notUpdated) > 0 {
		resp["notUpdated"] = notUpdated
	}
	if len(notDestroyed) > 0 {
		resp["notDestroyed"] = notDestroyed
	}

	// The email changes asked for on success, as an implicit Email/set.
	if len(sentEmail) > 0 && (len(args.OnSuccessUpdateEmail) > 0 || len(args.OnSuccessDestroyEmail) > 0) {
		emailOf := func(ref jmap.ID) (jmap.ID, bool) {
			id := c.resolve(ref)
			e, ok := sentEmail[id]
			return e, ok
		}
		update := map[jmap.ID]jmap.PatchObject{}
		for ref, patch := range args.OnSuccessUpdateEmail {
			if e, ok := emailOf(ref); ok {
				update[e] = patch
			}
		}
		var destroy []jmap.ID
		for _, ref := range args.OnSuccessDestroyEmail {
			if e, ok := emailOf(ref); ok {
				destroy = append(destroy, e)
			}
		}
		setArgs, _ := json.Marshal(jmap.SetArgs[json.RawMessage]{AccountID: c.c.id, Update: update, Destroy: destroy})
		ec := &call{s: c.s, r: c.r, c: c.c, args: setArgs, created: c.created, id: c.id}
		res, err := emailSet(ec)
		inv, ierr := jmap.NewInvocation("Email/set", res, c.id)
		if err != nil || ierr != nil {
			inv, _ = jmap.NewInvocation("error", jmap.MethodError{Type: jmap.ErrServerFail}, c.id)
		}
		c.extra = append(c.extra, inv)
	}
	return resp, nil
}

// send hands one email to the provider.
func (c *call) send(in *jmap.EmailSubmission) (*jmap.EmailSubmission, *jmap.SetError) {
	if c.s.Submit == nil {
		return nil, &jmap.SetError{Type: jmap.SetForbiddenToSend, Description: "Sending is not set up on this server"}
	}
	if in.IdentityID != identityOf(c.c).ID {
		return nil, &jmap.SetError{Type: jmap.SetInvalidProperties, Properties: []string{"identityId"}}
	}
	email := c.resolve(in.EmailID)
	data, _, err := c.s.blob(c.c, emailBlob(string(email)))
	if err != nil {
		if errors.Is(err, errNoBlob) {
			return nil, &jmap.SetError{Type: jmap.SetInvalidProperties, Properties: []string{"emailId"}}
		}
		return nil, &jmap.SetError{Type: jmap.SetForbiddenToSend, Description: err.Error()}
	}
	env := in.Envelope
	if env == nil {
		env = &jmap.Envelope{}
		fields := splitHeader(data)
		last := func(name string) string {
			v := fieldsNamed(fields, name)
			if len(v) == 0 {
				return ""
			}
			return v[len(v)-1]
		}
		if l := asAddresses(last("Sender")); len(l) > 0 {
			env.MailFrom.Email = l[0].Email
		} else if l := asAddresses(last("From")); len(l) > 0 {
			env.MailFrom.Email = l[0].Email
		} else {
			env.MailFrom.Email = identityOf(c.c).Email
		}
		seen := map[string]bool{}
		for _, name := range []string{"To", "Cc", "Bcc"} {
			for _, v := range fieldsNamed(fields, name) {
				for _, a := range asAddresses(v) {
					if k := strings.ToLower(a.Email); a.Email != "" && !seen[k] {
						seen[k] = true
						env.RcptTo = append(env.RcptTo, jmap.Address{Email: a.Email})
					}
				}
			}
		}
	}
	if len(env.RcptTo) == 0 {
		return nil, &jmap.SetError{Type: jmap.SetNoRecipients}
	}
	to := make([]string, len(env.RcptTo))
	for i, r := range env.RcptTo {
		to[i] = r.Email
	}
	ctx, cancel := context.WithTimeout(c.r.Context(), 2*time.Minute)
	defer cancel()
	err = c.s.Submit(ctx, c.c.login, c.c.password, &smtpproxy.Envelope{From: env.MailFrom.Email, To: to, Data: withoutBcc(data)})
	if err != nil {
		var se *smtp.SMTPError
		desc := "Upstream submission failed"
		if errors.As(err, &se) {
			desc = se.Message
		}
		c.s.Log.Info("jmap: submission refused", "user", c.c.login, "err", err)
		return nil, &jmap.SetError{Type: jmap.SetForbiddenToSend, Description: desc}
	}
	now := time.Now().UTC()
	return &jmap.EmailSubmission{IdentityID: in.IdentityID, EmailID: email, ThreadID: jmap.ID(threadID(string(email))),
		Envelope: env, SendAt: &now, UndoStatus: "final"}, nil
}
