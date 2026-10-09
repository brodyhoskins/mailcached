package jmapproxy

// PushSubscription (RFC 8620 section 7.2): the client registers a URL,
// usually a Web Push endpoint of its platform, and the server POSTs a
// StateChange there whenever the account changes, so a client that is
// not running hears of new mail.
//
//   - A new subscription gets a PushVerification with a random code at
//     once, and nothing else until the client sets that code on it.
//   - With keys, every message is encrypted for them (RFC 8291), and every
//     request is signed with the server's VAPID key (RFC 8292), which the
//     session advertises (RFC 9749). The key is kept in the Store's
//     folder, so subscriptions outlive a restart.
//   - A subscription belongs to the credentials that made it, and lasts
//     at most pushMaxAge (Basic auth does not expire). A 404 or 410 from
//     the push service ends it; a 429 slows its pushes down.
//   - Changes are gathered for pushGather, so a burst of them is one push.
//
// After a restart, nothing syncs until a client logs in (the password is
// kept in memory only), so nothing is pushed until then either.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/brodyhoskins/mailcached/internal/jmap"
	"github.com/brodyhoskins/mailcached/internal/webpush"
)

// capVAPID is RFC 9749's capability.
const capVAPID = "urn:ietf:params:jmap:webpush-vapid"

var (
	// pushMaxAge is the longest a subscription lasts before the client
	// renews it.
	pushMaxAge = 7 * 24 * time.Hour
	// pushGather is how long changes are gathered into one push.
	pushGather = time.Second
	// pushTTL is how long a push service keeps an undelivered push.
	pushTTL = 24 * time.Hour
)

// pushSub is a subscription, as saved.
type pushSub struct {
	ID             string    `json:"id"`
	Login          string    `json:"login"`
	Owner          string    `json:"owner"` // a hash of the credentials
	DeviceClientID string    `json:"deviceClientId"`
	URL            string    `json:"url"`
	P256DH         string    `json:"p256dh,omitempty"`
	Auth           string    `json:"auth,omitempty"`
	Code           string    `json:"code"`     // the verification code sent
	Verified       bool      `json:"verified"` // the client set it
	Expires        time.Time `json:"expires"`
	Types          []string  `json:"types"` // nil: every type

	// Not saved: the last state pushed, and when pushing may resume
	// after a 429.
	sent    string
	backoff time.Time
	delay   time.Duration
}

// pushes is the server's subscriptions.
type pushes struct {
	once  sync.Once
	err   error
	vapid *webpush.VAPID
	file  string // "" without a Store

	mu       sync.Mutex
	subs     map[string]*pushSub
	watching map[string]bool // logins with a running watch
}

// pushState loads the subscriptions and the VAPID key once, and starts the
// watches.
func (s *Server) pushState() (*pushes, error) {
	p := &s.push
	p.once.Do(func() {
		p.subs, p.watching = map[string]*pushSub{}, map[string]bool{}
		keyFile := ""
		if st := s.Engine.Store; st != nil && st.Dir != "" {
			dir := filepath.Join(st.Dir, "jmap")
			keyFile, p.file = filepath.Join(dir, "vapid.pem"), filepath.Join(dir, "push.json")
		}
		if p.vapid, p.err = webpush.LoadVAPID(keyFile); p.err != nil {
			return
		}
		p.vapid.Subject = s.PushSubject
		if p.file != "" {
			b, err := os.ReadFile(p.file)
			if err != nil && !os.IsNotExist(err) {
				p.err = err
				return
			}
			var list []*pushSub
			if len(b) > 0 {
				if err := json.Unmarshal(b, &list); err != nil {
					p.err = fmt.Errorf("%s: %w", p.file, err)
					return
				}
			}
			for _, sub := range list {
				if time.Now().Before(sub.Expires) {
					p.subs[sub.ID] = sub
				}
			}
		}
		p.mu.Lock()
		for _, sub := range p.subs {
			s.startPushWatch(sub.Login)
		}
		p.mu.Unlock()
	})
	return p, p.err
}

// save writes the subscriptions (p.mu held).
func (p *pushes) save() error {
	if p.file == "" {
		return nil
	}
	list := make([]*pushSub, 0, len(p.subs))
	for _, sub := range p.subs {
		list = append(list, sub)
	}
	slices.SortFunc(list, func(a, b *pushSub) int { return cmpString(a.ID, b.ID) })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p.file), 0o700); err != nil {
		return err
	}
	tmp := p.file + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p.file)
}

func cmpString(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// owner names a client's credentials.
func owner(c *client) string {
	h := sha256.Sum256([]byte(c.login + "\x00" + c.password))
	return hex.EncodeToString(h[:16])
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// pushView is a subscription as PushSubscription/get shows it: without
// url and keys.
type pushView struct {
	ID               string   `json:"id"`
	DeviceClientID   string   `json:"deviceClientId"`
	VerificationCode *string  `json:"verificationCode"`
	Expires          string   `json:"expires"`
	Types            []string `json:"types"`
}

func viewOf(sub *pushSub) pushView {
	v := pushView{ID: sub.ID, DeviceClientID: sub.DeviceClientID, Expires: sub.Expires.UTC().Format(time.RFC3339), Types: sub.Types}
	if sub.Verified {
		v.VerificationCode = &sub.Code
	}
	return v
}

func pushSubscriptionGet(c *call) (any, error) {
	var args struct {
		IDs        []string `json:"ids"`
		Properties []string `json:"properties"`
	}
	if err := c.decode(&args); err != nil {
		return nil, err
	}
	for _, p := range args.Properties {
		if p == "url" || p == "keys" {
			return nil, &jmap.MethodError{Type: jmap.ErrForbidden, Description: "url and keys are not shown"}
		}
	}
	p, err := c.s.pushState()
	if err != nil {
		return nil, err
	}
	me := owner(c.c)
	p.mu.Lock()
	defer p.mu.Unlock()
	list := []map[string]any{}
	notFound := []string{}
	add := func(sub *pushSub) {
		b, _ := json.Marshal(viewOf(sub))
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		if args.Properties != nil {
			for k := range m {
				if k != "id" && !slices.Contains(args.Properties, k) {
					delete(m, k)
				}
			}
		}
		list = append(list, m)
	}
	if args.IDs == nil {
		for _, sub := range p.subs {
			if sub.Owner == me {
				add(sub)
			}
		}
	} else {
		for _, id := range args.IDs {
			if sub := p.subs[id]; sub != nil && sub.Owner == me {
				add(sub)
			} else {
				notFound = append(notFound, id)
			}
		}
	}
	return map[string]any{"list": list, "notFound": notFound}, nil
}

func pushSubscriptionSet(c *call) (any, error) {
	var args struct {
		Create  map[string]json.RawMessage            `json:"create"`
		Update  map[string]map[string]json.RawMessage `json:"update"`
		Destroy []string                              `json:"destroy"`
	}
	if err := c.decode(&args); err != nil {
		return nil, err
	}
	p, err := c.s.pushState()
	if err != nil {
		return nil, err
	}
	me := owner(c.c)
	created, updated := map[string]any{}, map[string]any{}
	notCreated, notUpdated, notDestroyed := map[string]jmap.SetError{}, map[string]jmap.SetError{}, map[string]jmap.SetError{}
	destroyed := []string{}
	var verify []*pushSub

	p.mu.Lock()
	for cid, raw := range args.Create {
		sub, serr := newPushSub(raw)
		if serr != nil {
			notCreated[cid] = *serr
			continue
		}
		sub.ID, sub.Login, sub.Owner, sub.Code = "P"+randomHex(12), c.c.login, me, randomHex(16)
		p.subs[sub.ID] = sub
		c.created[jmap.ID(cid)] = jmap.ID(sub.ID)
		created[cid] = map[string]any{"id": sub.ID, "keys": nil, "expires": sub.Expires.UTC().Format(time.RFC3339)}
		verify = append(verify, sub)
	}
	for id, patch := range args.Update {
		sub := p.subs[string(c.resolve(jmap.ID(id)))]
		if sub == nil || sub.Owner != me {
			notUpdated[id] = jmap.SetError{Type: jmap.SetNotFound}
			continue
		}
		res, serr := sub.update(patch)
		if serr != nil {
			notUpdated[id] = *serr
			continue
		}
		updated[id] = res
	}
	for _, id := range args.Destroy {
		real := string(c.resolve(jmap.ID(id)))
		if sub := p.subs[real]; sub != nil && sub.Owner == me {
			delete(p.subs, real)
			destroyed = append(destroyed, id)
		} else {
			notDestroyed[id] = jmap.SetError{Type: jmap.SetNotFound}
		}
	}
	err = p.save()
	if len(created) > 0 || len(updated) > 0 {
		c.s.startPushWatch(c.c.login)
	}
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	for _, sub := range verify {
		go c.s.sendVerification(sub)
	}
	out := map[string]any{"created": created, "updated": updated, "destroyed": destroyed}
	if len(notCreated) > 0 {
		out["notCreated"] = notCreated
	}
	if len(notUpdated) > 0 {
		out["notUpdated"] = notUpdated
	}
	if len(notDestroyed) > 0 {
		out["notDestroyed"] = notDestroyed
	}
	return out, nil
}

func invalidProp(prop, desc string) *jmap.SetError {
	return &jmap.SetError{Type: jmap.SetInvalidProperties, Properties: []string{prop}, Description: desc}
}

// newPushSub reads a subscription to create.
func newPushSub(raw json.RawMessage) (*pushSub, *jmap.SetError) {
	var in struct {
		DeviceClientID string `json:"deviceClientId"`
		URL            string `json:"url"`
		Keys           *struct {
			P256DH string `json:"p256dh"`
			Auth   string `json:"auth"`
		} `json:"keys"`
		VerificationCode *string    `json:"verificationCode"`
		Expires          *time.Time `json:"expires"`
		Types            []string   `json:"types"`
		ID               *string    `json:"id"`
	}
	if err := json.Unmarshal(raw, &in); err != nil {
		return nil, &jmap.SetError{Type: jmap.SetInvalidProperties, Description: err.Error()}
	}
	switch {
	case in.ID != nil:
		return nil, invalidProp("id", "the server sets it")
	case in.DeviceClientID == "":
		return nil, invalidProp("deviceClientId", "required")
	case in.VerificationCode != nil:
		return nil, invalidProp("verificationCode", "must be null on create")
	}
	u, err := url.Parse(in.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, invalidProp("url", "an https URL is required")
	}
	sub := &pushSub{DeviceClientID: in.DeviceClientID, URL: in.URL}
	if in.Keys != nil {
		if _, err := webpush.ParseKeys(in.Keys.P256DH, in.Keys.Auth); err != nil {
			return nil, invalidProp("keys", err.Error())
		}
		sub.P256DH, sub.Auth = in.Keys.P256DH, in.Keys.Auth
	}
	if serr := sub.setTypes(in.Types); serr != nil {
		return nil, serr
	}
	sub.setExpires(in.Expires)
	return sub, nil
}

func (sub *pushSub) setTypes(types []string) *jmap.SetError {
	for _, t := range types {
		if !slices.Contains(pushTypes, t) && t != "PushSubscription" {
			return invalidProp("types", "unknown type "+t)
		}
	}
	sub.Types = types
	return nil
}

// setExpires sets the expiry, at most pushMaxAge from now.
func (sub *pushSub) setExpires(t *time.Time) {
	limit := time.Now().Add(pushMaxAge).Truncate(time.Second)
	if t == nil || t.After(limit) {
		sub.Expires = limit
		return
	}
	sub.Expires = *t
}

// update patches a subscription (p.mu held). It returns what the server
// changed of what the client asked.
func (sub *pushSub) update(patch map[string]json.RawMessage) (map[string]any, *jmap.SetError) {
	out := map[string]any{}
	for k, v := range patch {
		switch k {
		case "verificationCode":
			var code string
			if json.Unmarshal(v, &code) != nil || code != sub.Code {
				return nil, invalidProp(k, "wrong verification code")
			}
			sub.Verified = true
		case "expires":
			var t *time.Time
			if json.Unmarshal(v, &t) != nil {
				return nil, invalidProp(k, "not a date")
			}
			want := t
			sub.setExpires(t)
			if want == nil || !sub.Expires.Equal(*want) {
				out["expires"] = sub.Expires.UTC().Format(time.RFC3339)
			}
		case "types":
			var types []string
			if json.Unmarshal(v, &types) != nil {
				return nil, invalidProp(k, "not a list")
			}
			if serr := sub.setTypes(types); serr != nil {
				return nil, serr
			}
		default:
			return nil, invalidProp(k, "cannot be changed")
		}
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// --- Delivery ---------------------------------------------------------

func (s *Server) pushClient() *http.Client {
	if s.PushClient != nil {
		return s.PushClient
	}
	return &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// errGone means the push service says the subscription is gone.
var errGone = errors.New("the push subscription is gone")

// post sends one push to a subscription.
func (s *Server) post(sub *pushSub, v any) error {
	p := &s.push
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, sub.URL, nil)
	if err != nil {
		return err
	}
	if sub.P256DH != "" {
		keys, err := webpush.ParseKeys(sub.P256DH, sub.Auth)
		if err != nil {
			return err
		}
		if body, err = webpush.Encrypt(keys, body); err != nil {
			return err
		}
		req.Header.Set("Content-Encoding", "aes128gcm")
	}
	auth, err := p.vapid.Authorization(sub.URL)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("TTL", strconv.Itoa(int(pushTTL.Seconds())))
	req.Body = http.NoBody
	if len(body) > 0 {
		req.Body, req.ContentLength = readCloser(body), int64(len(body))
	}
	resp, err := s.pushClient().Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		return errGone
	case resp.StatusCode == http.StatusTooManyRequests:
		wait := time.Minute
		if n, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && n > 0 {
			wait = time.Duration(n) * time.Second
		}
		return &slowDown{wait}
	case resp.StatusCode >= 300:
		return fmt.Errorf("push service answered %s", resp.Status)
	}
	return nil
}

type slowDown struct{ wait time.Duration }

func (e *slowDown) Error() string { return "push service asked to slow down" }

func readCloser(b []byte) *bodyReader { return &bodyReader{bytes.NewReader(b)} }

type bodyReader struct{ *bytes.Reader }

func (bodyReader) Close() error { return nil }

func (s *Server) sendVerification(sub *pushSub) {
	err := s.post(sub, map[string]string{"@type": "PushVerification", "pushSubscriptionId": sub.ID, "verificationCode": sub.Code})
	if err != nil {
		// Not tried again (RFC 9749 section 6): the client makes a new
		// one.
		s.Log.Info("jmap: push verification failed", "user", sub.Login, "err", err)
	}
}

// startPushWatch starts pushing a login's changes, if it is not running
// (p.mu held).
func (s *Server) startPushWatch(login string) {
	p := &s.push
	if p.watching[login] {
		return
	}
	p.watching[login] = true
	go s.pushWatch(login)
}

// pushWatch pushes a login's changes until it has no subscription left.
func (s *Server) pushWatch(login string) {
	p := &s.push
	a := s.Engine.Account(login)
	id := accountID(login)
	a.Lock()
	wake := a.Changed()
	a.Unlock()
	for {
		// Expired subscriptions go, and the watch with the last one.
		p.mu.Lock()
		has := false
		for sid, sub := range p.subs {
			if sub.Login != login {
				continue
			}
			if time.Now().After(sub.Expires) {
				delete(p.subs, sid)
				continue
			}
			has = true
		}
		if !has {
			delete(p.watching, login)
			_ = p.save()
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()

		// A minute at most: a push held back by a 429 goes then.
		select {
		case <-wake:
			time.Sleep(pushGather)
		case <-time.After(time.Minute):
		}
		a.Lock()
		state := a.State()
		wake = a.Changed()
		a.Unlock()

		p.mu.Lock()
		var due []*pushSub
		for _, sub := range p.subs {
			if sub.Login == login && sub.Verified && sub.sent != state && time.Now().After(sub.backoff) && time.Now().Before(sub.Expires) {
				due = append(due, sub)
			}
		}
		p.mu.Unlock()
		for _, sub := range due {
			types := sub.Types
			if types == nil {
				types = pushTypes
			}
			changed := map[string]jmap.State{}
			for _, t := range types {
				if t != "PushSubscription" {
					changed[t] = jmap.State(state)
				}
			}
			err := s.post(sub, jmap.StateChange{Type: "StateChange", Changed: map[jmap.ID]map[string]jmap.State{id: changed}})
			p.mu.Lock()
			var sd *slowDown
			switch {
			case err == nil:
				sub.sent, sub.delay = state, 0
			case errors.Is(err, errGone):
				delete(p.subs, sub.ID)
				_ = p.save()
			case errors.As(err, &sd):
				sub.delay = max(sd.wait, 2*sub.delay)
				sub.delay = min(sub.delay, time.Hour)
				sub.backoff = time.Now().Add(sub.delay)
			default:
				s.Log.Info("jmap: push failed", "user", login, "err", err)
			}
			p.mu.Unlock()
		}
	}
}
