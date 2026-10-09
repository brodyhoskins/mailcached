package jmapproxy

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/internal/jmap"
)

// --- Email/set -------------------------------------------------------------

func emailSet(c *call) (any, error) {
	var args jmap.SetArgs[json.RawMessage]
	if err := c.decode(&args); err != nil {
		return nil, err
	}
	if len(args.Create)+len(args.Update)+len(args.Destroy) > maxObjectsInSet {
		return nil, &jmap.MethodError{Type: jmap.ErrRequestTooLarge}
	}
	a := c.c.acct
	a.Lock()
	old := a.State()
	a.Unlock()
	if args.IfInState != "" && string(args.IfInState) != old {
		return nil, &jmap.MethodError{Type: jmap.ErrStateMismatch}
	}
	resp := jmap.SetResponse[any]{AccountID: c.c.id, OldState: jmap.State(old)}
	created, updated := map[jmap.ID]any{}, map[jmap.ID]*any{}
	notCreated, notUpdated, notDestroyed := map[jmap.ID]jmap.SetError{}, map[jmap.ID]jmap.SetError{}, map[jmap.ID]jmap.SetError{}

	for cid, raw := range args.Create {
		e, serr := c.createEmail(raw)
		if serr != nil {
			notCreated[cid] = *serr
			continue
		}
		c.created[cid] = e["id"].(jmap.ID)
		created[cid] = e
	}
	for id, patch := range args.Update {
		id = c.resolve(id)
		if serr := c.updateEmail(string(id), patch); serr != nil {
			notUpdated[id] = *serr
			continue
		}
		updated[id] = nil
	}
	for _, id := range args.Destroy {
		id = c.resolve(id)
		if serr := c.destroyEmail(string(id)); serr != nil {
			notDestroyed[id] = *serr
			continue
		}
		resp.Destroyed = append(resp.Destroyed, id)
	}

	a.Lock()
	resp.NewState = jmap.State(a.State())
	a.Unlock()
	if len(created) > 0 {
		resp.Created = created
	}
	if len(updated) > 0 {
		resp.Updated = updated
	}
	if len(notCreated) > 0 {
		resp.NotCreated = notCreated
	}
	if len(notUpdated) > 0 {
		resp.NotUpdated = notUpdated
	}
	if len(notDestroyed) > 0 {
		resp.NotDestroyed = notDestroyed
	}
	return resp, nil
}

// updateEmail applies a patch of keywords and mailboxIds.
func (c *call) updateEmail(id string, patch jmap.PatchObject) *jmap.SetError {
	a := c.c.acct
	a.Lock()
	in := infoOf(a, id)
	a.Unlock()
	if in == nil {
		return &jmap.SetError{Type: jmap.SetNotFound}
	}
	keywords := maps(in.keywords)
	mailboxes := maps(in.mailboxes)
	kwChanged, mbChanged := false, false
	bad := func(prop string) *jmap.SetError {
		return &jmap.SetError{Type: jmap.SetInvalidPatch, Properties: []string{prop}}
	}
	for path, v := range patch {
		switch {
		case path == "keywords":
			var m map[string]bool
			if json.Unmarshal(v, &m) != nil {
				return bad(path)
			}
			keywords = map[string]bool{}
			for k, on := range m {
				if !on || !validKeyword(k) {
					return bad(path)
				}
				keywords[strings.ToLower(k)] = true
			}
			kwChanged = true
		case strings.HasPrefix(path, "keywords/"):
			k := strings.ToLower(unescapePointer(strings.TrimPrefix(path, "keywords/")))
			if !validKeyword(k) {
				return bad(path)
			}
			if string(v) == "null" || string(v) == "false" {
				delete(keywords, k)
			} else if string(v) == "true" {
				keywords[k] = true
			} else {
				return bad(path)
			}
			kwChanged = true
		case path == "mailboxIds":
			var m map[jmap.ID]bool
			if json.Unmarshal(v, &m) != nil {
				return bad(path)
			}
			mailboxes = map[jmap.ID]bool{}
			for mb, on := range m {
				if !on {
					return bad(path)
				}
				mailboxes[c.resolve(mb)] = true
			}
			mbChanged = true
		case strings.HasPrefix(path, "mailboxIds/"):
			mb := c.resolve(jmap.ID(unescapePointer(strings.TrimPrefix(path, "mailboxIds/"))))
			if string(v) == "null" || string(v) == "false" {
				delete(mailboxes, mb)
			} else if string(v) == "true" {
				mailboxes[mb] = true
			} else {
				return bad(path)
			}
			mbChanged = true
		default:
			return &jmap.SetError{Type: jmap.SetInvalidProperties, Properties: []string{path},
				Description: "Only keywords and mailboxIds can change"}
		}
	}
	if mbChanged {
		if len(mailboxes) == 0 {
			return &jmap.SetError{Type: jmap.SetInvalidProperties, Properties: []string{"mailboxIds"},
				Description: "An email must be in a mailbox"}
		}
		if serr := c.moveEmail(in, mailboxes); serr != nil {
			return serr
		}
	}
	if kwChanged {
		// The copies the moves made share the email ID.
		a.Lock()
		msgs := slices.Clone(a.Email(id))
		a.Unlock()
		var add, del []imap.Flag
		for k := range keywords {
			add = append(add, flagOf(k))
		}
		for k := range in.keywords {
			if !keywords[k] {
				del = append(del, flagOf(k))
			}
		}
		if len(add) > 0 {
			a.SetFlags(msgs, "", imap.StoreFlagsAdd, add, nil)
		}
		if len(del) > 0 {
			a.SetFlags(msgs, "", imap.StoreFlagsDel, del, nil)
		}
	}
	return nil
}

func maps[K comparable](m map[K]bool) map[K]bool {
	out := make(map[K]bool, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// unescapePointer undoes JSON Pointer escaping in a patch path.
func unescapePointer(s string) string { return strings.NewReplacer("~1", "/", "~0", "~").Replace(s) }

// moveEmail puts the email's copies in exactly the folders want: a folder
// it leaves and one it joins make a move, other joins are copies and
// other leaves expunges.
func (c *call) moveEmail(in *emailInfo, want map[jmap.ID]bool) *jmap.SetError {
	a := c.c.acct
	a.Lock()
	var join []string
	for id := range want {
		m := a.MailboxByID(string(id))
		if m == nil || !m.Selectable() {
			a.Unlock()
			return &jmap.SetError{Type: jmap.SetInvalidProperties, Properties: []string{"mailboxIds/" + string(id)}}
		}
		if !in.mailboxes[id] {
			join = append(join, m.Name())
		}
	}
	var leave []*engine.Mailbox
	for id := range in.mailboxes {
		if !want[id] {
			if m := a.MailboxByID(string(id)); m != nil {
				leave = append(leave, m)
			}
		}
	}
	a.Unlock()
	mine := map[*engine.Message]bool{}
	for _, m := range in.msgs {
		mine[m] = true
	}
	isMine := func(m *engine.Message) bool { return mine[m] }
	for len(leave) > 0 && len(join) > 0 {
		if _, _, err := a.Move(leave[0], isMine, join[0]); err != nil {
			serr := setError(err)
			return &serr
		}
		leave, join = leave[1:], join[1:]
	}
	for _, dest := range join {
		if _, _, err := a.Copy(in.msgs[:1], "", dest); err != nil {
			serr := setError(err)
			return &serr
		}
	}
	for _, m := range leave {
		a.Expunge(m, isMine)
	}
	return nil
}

// destroyEmail expunges every copy.
func (c *call) destroyEmail(id string) *jmap.SetError {
	a := c.c.acct
	a.Lock()
	in := infoOf(a, id)
	var boxes []*engine.Mailbox
	if in != nil {
		for mb := range in.mailboxes {
			if m := a.MailboxByID(string(mb)); m != nil {
				boxes = append(boxes, m)
			}
		}
	}
	a.Unlock()
	if in == nil {
		return &jmap.SetError{Type: jmap.SetNotFound}
	}
	mine := map[*engine.Message]bool{}
	for _, m := range in.msgs {
		mine[m] = true
	}
	for _, m := range boxes {
		a.Expunge(m, func(x *engine.Message) bool { return mine[x] })
	}
	return nil
}

// --- Storing new messages --------------------------------------------------

// store stores data in the folders mailboxes, with keywords, and returns
// the new email as Email/import describes it.
func (c *call) store(data []byte, mailboxes map[jmap.ID]bool, keywords map[string]bool, received *time.Time) (map[string]any, *jmap.SetError) {
	if int64(len(data)) > c.s.maxMessage() {
		return nil, &jmap.SetError{Type: jmap.SetTooLarge}
	}
	if len(mailboxes) == 0 {
		return nil, &jmap.SetError{Type: jmap.SetInvalidProperties, Properties: []string{"mailboxIds"}}
	}
	a := c.c.acct
	var names []string
	a.Lock()
	for id, on := range mailboxes {
		m := a.MailboxByID(string(c.resolve(id)))
		if !on || m == nil || !m.Selectable() {
			a.Unlock()
			return nil, &jmap.SetError{Type: jmap.SetInvalidProperties, Properties: []string{"mailboxIds/" + string(id)}}
		}
		names = append(names, m.Name())
	}
	a.Unlock()
	slices.Sort(names)
	opts := &imap.AppendOptions{}
	for k, on := range keywords {
		if !on || !validKeyword(k) {
			return nil, &jmap.SetError{Type: jmap.SetInvalidProperties, Properties: []string{"keywords"}}
		}
		opts.Flags = append(opts.Flags, flagOf(k))
	}
	if received != nil {
		opts.Time = *received
	}
	msg, err := a.Append(names[0], data, opts)
	if errors.Is(err, engine.ErrTransform) {
		return nil, &jmap.SetError{Type: jmap.SetForbidden, Description: "The message could not be stored"}
	}
	if err != nil {
		serr := setError(err)
		return nil, &serr
	}
	if msg == nil {
		return nil, &jmap.SetError{Type: jmap.SetForbidden,
			Description: "Stored, but the provider did not say where (no UIDPLUS); it shows up after the next sync"}
	}
	for _, dest := range names[1:] {
		if _, _, err := a.Copy([]*engine.Message{msg}, "", dest); err != nil {
			c.s.Log.Warn("jmap: could not copy a new message", "user", c.c.login, "mailbox", dest, "err", err)
		}
	}
	id := engine.EmailID(msg.Key())
	entries, _, _ := a.HeaderEntries([]*engine.Message{msg}, nil)
	size := int64(len(data))
	if e := entries[msg]; e != nil {
		size = e.Size
	}
	return map[string]any{"id": jmap.ID(id), "blobId": emailBlob(id), "threadId": threadID(id), "size": size}, nil
}

func emailImport(c *call) (any, error) {
	var args jmap.ImportArgs
	if err := c.decode(&args); err != nil {
		return nil, err
	}
	if len(args.Emails) > maxObjectsInSet {
		return nil, &jmap.MethodError{Type: jmap.ErrRequestTooLarge}
	}
	a := c.c.acct
	a.Lock()
	old := a.State()
	a.Unlock()
	if args.IfInState != "" && string(args.IfInState) != old {
		return nil, &jmap.MethodError{Type: jmap.ErrStateMismatch}
	}
	created := map[jmap.ID]any{}
	notCreated := map[jmap.ID]jmap.SetError{}
	for cid, e := range args.Emails {
		data, _, err := c.s.blob(c.c, string(c.resolve(e.BlobID)))
		if err != nil {
			notCreated[cid] = jmap.SetError{Type: jmap.SetBlobNotFound, Description: err.Error()}
			continue
		}
		out, serr := c.store(data, e.MailboxIDs, e.Keywords, e.ReceivedAt)
		if serr != nil {
			notCreated[cid] = *serr
			continue
		}
		c.created[cid] = out["id"].(jmap.ID)
		created[cid] = out
	}
	a.Lock()
	resp := map[string]any{"accountId": c.c.id, "oldState": old, "newState": a.State()}
	a.Unlock()
	if len(created) > 0 {
		resp["created"] = created
	}
	if len(notCreated) > 0 {
		resp["notCreated"] = notCreated
	}
	return resp, nil
}

// createEmail makes a message from a JMAP Email (a draft) and stores it.
func (c *call) createEmail(raw json.RawMessage) (map[string]any, *jmap.SetError) {
	var e struct {
		MailboxIDs map[jmap.ID]bool `json:"mailboxIds"`
		Keywords   map[string]bool  `json:"keywords"`
		ReceivedAt *time.Time       `json:"receivedAt"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, &jmap.SetError{Type: jmap.SetInvalidProperties, Description: err.Error()}
	}
	data, serr := compose(c, raw)
	if serr != nil {
		return nil, serr
	}
	return c.store(data, e.MailboxIDs, e.Keywords, e.ReceivedAt)
}
