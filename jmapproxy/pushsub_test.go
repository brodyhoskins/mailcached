package jmapproxy

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/brodyhoskins/mailcached/internal/jmap"
	"github.com/brodyhoskins/mailcached/internal/webpush"
)

func init() { pushGather = 10 * time.Millisecond }

// pushService is a Web Push service that decrypts what it gets.
type pushService struct {
	t    *testing.T
	priv *ecdh.PrivateKey
	auth []byte
	srv  *httptest.Server

	mu     sync.Mutex
	status int
	got    chan map[string]any
	vapid  *webpush.VAPID
	bad    string // what was wrong with a request
}

func newPushService(t *testing.T) *pushService {
	ps := &pushService{t: t, auth: make([]byte, 16), got: make(chan map[string]any, 16), status: http.StatusCreated}
	var err error
	if ps.priv, err = ecdh.P256().GenerateKey(rand.Reader); err != nil {
		t.Fatal(err)
	}
	rand.Read(ps.auth)
	ps.srv = httptest.NewTLSServer(http.HandlerFunc(ps.serve))
	t.Cleanup(ps.srv.Close)
	return ps
}

func (ps *pushService) serve(w http.ResponseWriter, r *http.Request) {
	ps.mu.Lock()
	status, vapid := ps.status, ps.vapid
	ps.mu.Unlock()
	body, _ := io.ReadAll(r.Body)
	switch {
	case r.Header.Get("TTL") == "":
		ps.fail("no TTL")
	case r.Header.Get("Content-Encoding") != "aes128gcm":
		ps.fail("not encrypted")
	case vapid != nil && !vapid.Verify(r.Header.Get("Authorization")):
		ps.fail("bad VAPID signature: " + r.Header.Get("Authorization"))
	}
	pt, err := webpush.Decrypt(ps.priv, ps.auth, body)
	if err != nil {
		ps.fail("decrypt: " + err.Error())
	}
	var m map[string]any
	_ = json.Unmarshal(pt, &m)
	w.WriteHeader(status)
	if status < 300 {
		ps.got <- m
	}
}

func (ps *pushService) fail(why string) {
	ps.mu.Lock()
	ps.bad = why
	ps.mu.Unlock()
}

func (ps *pushService) next(t *testing.T) map[string]any {
	t.Helper()
	select {
	case m := <-ps.got:
		ps.mu.Lock()
		bad := ps.bad
		ps.mu.Unlock()
		if bad != "" {
			t.Fatal(bad)
		}
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("no push")
	}
	return nil
}

func (ps *pushService) none(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case m := <-ps.got:
		t.Fatalf("unexpected push %v", m)
	case <-time.After(d):
	}
}

func TestPushSubscription(t *testing.T) {
	ps := newPushService(t)
	e := newEnvConf(t, func(s *Server) { s.PushClient = ps.srv.Client() })
	s, err := e.c.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var vc struct {
		Key string `json:"applicationServerKey"`
	}
	if err := json.Unmarshal(s.Capabilities[capVAPID], &vc); err != nil || vc.Key == "" {
		t.Fatalf("no VAPID key: %s", s.Capabilities[capVAPID])
	}
	p, _ := e.srv.pushState()
	ps.mu.Lock()
	ps.vapid = p.vapid
	ps.mu.Unlock()
	b64 := base64.RawURLEncoding

	var set map[string]json.RawMessage
	e.call(t, "PushSubscription/set", map[string]any{"create": map[string]any{
		"k1": map[string]any{"deviceClientId": "dev1", "url": ps.srv.URL + "/push/1", "types": []string{"Email", "Mailbox"},
			"keys": map[string]string{"p256dh": b64.EncodeToString(ps.priv.PublicKey().Bytes()), "auth": b64.EncodeToString(ps.auth)}},
		"plain": map[string]any{"deviceClientId": "dev2", "url": "http://insecure.example/push"},
	}}, &set)
	var created map[string]struct {
		ID      string `json:"id"`
		Expires string `json:"expires"`
	}
	json.Unmarshal(set["created"], &created)
	id := created["k1"].ID
	if id == "" || !strings.Contains(string(set["notCreated"]), "plain") {
		t.Fatalf("set: %s", set)
	}
	if exp, _ := time.Parse(time.RFC3339, created["k1"].Expires); exp.After(time.Now().Add(pushMaxAge + time.Minute)) {
		t.Fatalf("expires %s", created["k1"].Expires)
	}

	v := ps.next(t)
	if v["@type"] != "PushVerification" || v["pushSubscriptionId"] != id {
		t.Fatalf("verification %v", v)
	}
	// Nothing until verified.
	appendMsg(t, e.upstream(t), "INBOX", plain("push-1@test", "Before", "Not pushed."))
	ps.none(t, 300*time.Millisecond)

	e.call(t, "PushSubscription/set", map[string]any{"update": map[string]any{id: map[string]any{"verificationCode": "wrong"}}}, &set)
	if !strings.Contains(string(set["notUpdated"]), jmap.SetInvalidProperties) {
		t.Fatalf("a wrong code: %s", set)
	}
	e.call(t, "PushSubscription/set", map[string]any{"update": map[string]any{id: map[string]any{"verificationCode": v["verificationCode"]}}}, &set)
	if !strings.Contains(string(set["updated"]), id) {
		t.Fatalf("verify: %s", set)
	}

	appendMsg(t, e.upstream(t), "INBOX", plain("push-2@test", "After", "Pushed."))
	sc := ps.next(t)
	if sc["@type"] != "StateChange" {
		t.Fatalf("state change %v", sc)
	}
	types := sc["changed"].(map[string]any)[string(e.acct)].(map[string]any)
	if types["Email"] == nil || types["Mailbox"] == nil || types["Thread"] != nil {
		t.Fatalf("types %v", types)
	}

	var got struct {
		List []map[string]any `json:"list"`
	}
	e.call(t, "PushSubscription/get", map[string]any{"ids": nil}, &got)
	if len(got.List) != 1 || got.List[0]["verificationCode"] != v["verificationCode"] || got.List[0]["url"] != nil {
		t.Fatalf("get: %v", got.List)
	}
	b := e.c.NewBatch()
	call := b.Add("PushSubscription/get", map[string]any{"properties": []string{"url"}})
	res, err := b.Do(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var me *jmap.MethodError
	if err := res.Get(call, "PushSubscription/get", &got); err == nil || !errors.As(err, &me) || me.Type != jmap.ErrForbidden {
		t.Fatalf("url asked for: %v", err)
	}

	// The push service says the subscription is gone.
	ps.mu.Lock()
	ps.status = http.StatusGone
	ps.mu.Unlock()
	appendMsg(t, e.upstream(t), "INBOX", plain("push-3@test", "Gone", "Ends it."))
	eventually(t, "the subscription to go", func() bool {
		e.call(t, "PushSubscription/get", map[string]any{"ids": nil}, &got)
		return len(got.List) == 0
	})
}
