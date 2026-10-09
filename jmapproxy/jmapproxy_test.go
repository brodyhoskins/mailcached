package jmapproxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"

	"github.com/brodyhoskins/mailcached/config"
	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/internal/enginetest"
	"github.com/brodyhoskins/mailcached/internal/jmap"
	"github.com/brodyhoskins/mailcached/internal/sealtest"
	"github.com/brodyhoskins/mailcached/smtpproxy"
)

var testLog = slog.New(slog.NewTextHandler(io.Discard, nil))

func init() {
	engine.SyncPoll = 50 * time.Millisecond
	engine.SyncListEvery = 50 * time.Millisecond
	engine.SelectFresh = 0
	engine.SelectWaits = true
}

// env is a provider, the engine and the JMAP server, and a client.
type env struct {
	provider string
	user     *imapmemserver.User
	eng      *engine.Engine
	srv      *Server
	http     *httptest.Server
	c        *jmap.Client
	acct     jmap.ID

	mu   sync.Mutex
	sent []*smtpproxy.Envelope
}

// newEnv makes the environment, with the sealer as the Transform unless
// another is given.
func newEnv(t *testing.T, transform ...engine.Transform) *env {
	t.Helper()
	return newEnvConf(t, nil, transform...)
}

// newEnvConf also lets configure change the server before it serves.
func newEnvConf(t *testing.T, configure func(*Server), transform ...engine.Transform) *env {
	t.Helper()
	var tr engine.Transform = sealtest.Sealer{}
	if len(transform) > 0 {
		tr = transform[0]
	}
	addr, user := enginetest.IMAP(t, testLog, nil)
	st, err := engine.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{provider: addr, user: user}
	e.eng = &engine.Engine{
		Store: st, Timeout: 5 * time.Second, Transform: tr, Log: testLog,
		Cache: &engine.Cache{Dir: t.TempDir(), MaxBytes: 1 << 20},
		Route: func(login string) (engine.Upstream, bool) {
			return engine.Upstream{Addr: addr, TLS: config.TLSNone, Timeout: 5 * time.Second}, login == enginetest.User
		},
	}
	t.Cleanup(e.eng.Close)
	e.srv = &Server{Engine: e.eng, Log: testLog, Submit: func(_ context.Context, login, password string, env *smtpproxy.Envelope) error {
		if login != enginetest.User || password != enginetest.Password {
			return errors.New("bad credentials")
		}
		e.mu.Lock()
		e.sent = append(e.sent, env)
		e.mu.Unlock()
		return nil
	}}
	if configure != nil {
		configure(e.srv)
	}
	e.http = httptest.NewServer(e.srv.Handler())
	t.Cleanup(e.http.Close)
	e.c = &jmap.Client{SessionURL: e.http.URL + "/.well-known/jmap", User: enginetest.User, Secret: enginetest.Password}
	s, err := e.c.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	e.acct = s.MailAccount()
	return e
}

// upstream logs in to the provider.
func (e *env) upstream(t *testing.T) *imapclient.Client {
	t.Helper()
	c, err := imapclient.DialInsecure(e.provider, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Login(enginetest.User, enginetest.Password).Wait(); err != nil {
		t.Fatal(err)
	}
	return c
}

func appendMsg(t *testing.T, c *imapclient.Client, box string, data []byte) {
	t.Helper()
	cmd := c.Append(box, int64(len(data)), nil)
	cmd.Write(data)
	cmd.Close()
	if _, err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

func plain(id, subject, body string) []byte {
	return []byte("Message-ID: <" + id + ">\r\nFrom: Bob <" + enginetest.Bob + ">\r\nTo: " + enginetest.User +
		"\r\nSubject: " + subject + "\r\nDate: Mon, 02 Mar 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n\r\n" + body + "\r\n")
}

func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for " + what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// call runs one method and decodes its response.
func (e *env) call(t *testing.T, name string, args any, out any) {
	t.Helper()
	b := e.c.NewBatch(jmap.CapMail, jmap.CapSubmission)
	id := b.Add(name, args)
	res, err := b.Do(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := res.Get(id, name, out); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}

func (e *env) mailboxes(t *testing.T) map[string]jmap.Mailbox {
	t.Helper()
	var got jmap.GetResponse[jmap.Mailbox]
	e.call(t, "Mailbox/get", jmap.GetArgs{AccountID: e.acct}, &got)
	out := map[string]jmap.Mailbox{}
	for _, m := range got.List {
		out[m.Name] = m
	}
	return out
}

// query returns the emails in a mailbox, newest first.
func (e *env) query(t *testing.T, mailbox jmap.ID) []jmap.ID {
	t.Helper()
	var q jmap.QueryResponse
	e.call(t, "Email/query", map[string]any{"accountId": e.acct, "filter": map[string]any{"inMailbox": mailbox},
		"sort": []any{map[string]any{"property": "receivedAt", "isAscending": false}}}, &q)
	return q.IDs
}

func TestSessionAndAuth(t *testing.T) {
	e := newEnv(t)
	s, _ := e.c.Session(context.Background())
	if s.Username != enginetest.User || s.Core().MaxCallsInRequest != maxCalls || s.UploadURL == "" {
		t.Fatalf("session %+v", s)
	}
	bad := &jmap.Client{SessionURL: e.http.URL + "/.well-known/jmap", User: enginetest.User, Secret: "wrong"}
	if _, err := bad.Session(context.Background()); !errors.Is(err, jmap.ErrUnauthorized) {
		t.Fatalf("wrong password: %v", err)
	}
	other := &jmap.Client{SessionURL: e.http.URL + "/.well-known/jmap", User: "eve@example.org", Secret: "x"}
	if _, err := other.Session(context.Background()); !errors.Is(err, jmap.ErrUnauthorized) {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestCompressedResponses(t *testing.T) {
	e := newEnv(t)
	for _, enc := range []string{"zstd", "gzip"} {
		req, _ := http.NewRequest(http.MethodGet, e.http.URL+"/jmap/session", nil)
		req.SetBasicAuth(enginetest.User, enginetest.Password)
		req.Header.Set("Accept-Encoding", enc)
		resp, err := (&http.Transport{DisableCompression: true}).RoundTrip(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if got := resp.Header.Get("Content-Encoding"); got != enc {
			t.Errorf("Accept-Encoding %s: Content-Encoding %q", enc, got)
		}
	}
}

// TestReadMail lists and reads mail, the sealed message as the Transform
// opens it.
func TestReadMail(t *testing.T) {
	e := newEnv(t)
	up := e.upstream(t)
	appendMsg(t, up, "INBOX", plain("plain-1@test", "Lunch", "Tacos?"))
	appendMsg(t, up, "INBOX", sealtest.Seal(plain("sealed-1@test", "Secret", "The number is 42.")))

	boxes := e.mailboxes(t)
	inbox, ok := boxes["INBOX"]
	if !ok || inbox.Role == nil || *inbox.Role != jmap.RoleInbox {
		t.Fatalf("mailboxes %+v", boxes)
	}
	eventually(t, "both messages", func() bool { return e.mailboxes(t)["INBOX"].TotalEmails == 2 })

	// Email/query and Email/get in one request, by back-reference.
	b := e.c.NewBatch(jmap.CapMail)
	q := b.Add("Email/query", map[string]any{"accountId": e.acct, "filter": map[string]any{"inMailbox": inbox.ID},
		"sort": []any{map[string]any{"property": "subject"}}})
	g := b.Add("Email/get", map[string]any{"accountId": e.acct, "#ids": b.Ref(q, "Email/query", "/ids"),
		"properties":          []string{"subject", "from", "preview", "textBody", "bodyValues", "keywords", "mailboxIds", "hasAttachment"},
		"fetchTextBodyValues": true})
	res, err := b.Do(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var got jmap.GetResponse[jmap.Email]
	if err := res.Get(g, "Email/get", &got); err != nil {
		t.Fatal(err)
	}
	if len(got.List) != 2 || *got.List[0].Subject != "Lunch" || *got.List[1].Subject != "Secret" {
		t.Fatalf("emails %+v", got.List)
	}
	secret := got.List[1]
	if len(secret.TextBody) != 1 || !strings.Contains(secret.BodyValues[*secret.TextBody[0].PartID].Value, "The number is 42.") {
		t.Fatalf("the sealed message was not opened: %+v", secret)
	}
	if !strings.Contains(secret.Preview, "The number is 42.") || secret.From[0].Email != enginetest.Bob {
		t.Fatalf("preview %q, from %+v", secret.Preview, secret.From)
	}
	if !secret.MailboxIDs[inbox.ID] || secret.HasAttachment {
		t.Fatalf("mailboxIds %v, hasAttachment %v", secret.MailboxIDs, secret.HasAttachment)
	}

	// The whole message as a blob, opened too.
	var blob jmap.GetResponse[jmap.Email]
	e.call(t, "Email/get", jmap.GetArgs{AccountID: e.acct, IDs: []jmap.ID{secret.ID}, Properties: []string{"blobId"}}, &blob)
	data, err := e.c.Download(context.Background(), e.acct, blob.List[0].BlobID)
	if err != nil || !strings.Contains(string(data), "X-Opened: yes") {
		t.Fatalf("download: %v\n%s", err, data)
	}
	part, err := e.c.Download(context.Background(), e.acct, jmap.ID(partBlob(secret.ID, *secret.TextBody[0].PartID)))
	if err != nil || strings.TrimSpace(string(part)) != "The number is 42." {
		t.Fatalf("part: %q, %v", part, err)
	}
}

// TestChangeMail changes keywords and folders through JMAP, and checks
// the provider and Email/changes.
func TestChangeMail(t *testing.T) {
	e := newEnv(t)
	up := e.upstream(t)
	appendMsg(t, up, "INBOX", plain("move-1@test", "Move me", "x"))
	if err := up.Create("Archive", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	var boxes map[string]jmap.Mailbox
	eventually(t, "the folders and the message", func() bool {
		boxes = e.mailboxes(t)
		return boxes["INBOX"].TotalEmails == 1 && boxes["Archive"].ID != ""
	})
	ids := e.query(t, boxes["INBOX"].ID)
	var before jmap.GetResponse[jmap.Email]
	e.call(t, "Email/get", jmap.GetArgs{AccountID: e.acct, IDs: ids, Properties: []string{"id"}}, &before)
	state := before.State

	var set jmap.SetResponse[jmap.Email]
	e.call(t, "Email/set", map[string]any{"accountId": e.acct, "update": map[string]any{string(ids[0]): map[string]any{
		"keywords/$seen":                            true,
		"keywords/$flagged":                         true,
		"mailboxIds/" + string(boxes["INBOX"].ID):   nil,
		"mailboxIds/" + string(boxes["Archive"].ID): true,
	}}}, &set)
	if _, ok := set.Updated[ids[0]]; !ok {
		t.Fatalf("not updated: %+v", set.NotUpdated)
	}
	// The email keeps its ID across the move.
	if got := e.query(t, boxes["Archive"].ID); !slices.Equal(got, ids) {
		t.Fatalf("Archive has %v, want %v", got, ids)
	}
	var ch jmap.ChangesResponse
	e.call(t, "Email/changes", jmap.ChangesArgs{AccountID: e.acct, SinceState: state}, &ch)
	if !slices.Equal(ch.Updated, ids) || len(ch.Created)+len(ch.Destroyed) != 0 {
		t.Fatalf("changes %+v", ch)
	}
	var mch jmap.ChangesResponse
	e.call(t, "Mailbox/changes", jmap.ChangesArgs{AccountID: e.acct, SinceState: state}, &mch)
	if len(mch.Updated) != 2 || mch.UpdatedProperties == nil {
		t.Fatalf("mailbox changes %+v", mch)
	}

	eventually(t, "the move and flags at the provider", func() bool {
		if _, err := up.Select("Archive", nil).Wait(); err != nil {
			return false
		}
		got, err := up.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
		return err == nil && len(got) == 1 && slices.Contains(got[0].Flags, imap.FlagSeen) &&
			slices.Contains(got[0].Flags, imap.FlagFlagged)
	})

	// Destroyed: gone at the provider.
	e.call(t, "Email/set", map[string]any{"accountId": e.acct, "destroy": ids}, &set)
	if !slices.Equal(set.Destroyed, ids) {
		t.Fatalf("destroy: %+v", set)
	}
	eventually(t, "the expunge at the provider", func() bool {
		sel, err := up.Select("Archive", nil).Wait()
		return err == nil && sel.NumMessages == 0
	})
}

// TestUpstreamChangesReachClients checks Email/changes and the event
// source after mail arrives at the provider.
func TestUpstreamChangesReachClients(t *testing.T) {
	e := newEnv(t)
	var got jmap.GetResponse[jmap.Email]
	e.call(t, "Email/get", jmap.GetArgs{AccountID: e.acct, IDs: []jmap.ID{}}, &got)
	state := got.State

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events := make(chan jmap.StateChange, 10)
	go e.c.Events(ctx, []string{"Email"}, 0, func(sc jmap.StateChange) { events <- sc })
	// The first event is the state on connect.
	select {
	case <-events:
	case <-time.After(5 * time.Second):
		t.Fatal("no first event")
	}

	appendMsg(t, e.upstream(t), "INBOX", plain("new-1@test", "New", "Hello."))
	select {
	case sc := <-events:
		if sc.Changed[e.acct]["Email"] == state {
			t.Fatalf("event with the old state: %+v", sc)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event after new mail")
	}
	var ch jmap.ChangesResponse
	e.call(t, "Email/changes", jmap.ChangesArgs{AccountID: e.acct, SinceState: state}, &ch)
	if len(ch.Created) != 1 {
		t.Fatalf("changes %+v", ch)
	}
}

// TestImportAndSend uploads and imports a message, writes a draft, and
// sends it.
func TestImportAndSend(t *testing.T) {
	e := newEnv(t)
	up := e.upstream(t)
	if err := up.Create("Drafts", &imap.CreateOptions{SpecialUse: []imap.MailboxAttr{imap.MailboxAttrDrafts}}).Wait(); err != nil {
		t.Fatal(err)
	}
	if err := up.Create("Sent", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	var boxes map[string]jmap.Mailbox
	eventually(t, "the folders", func() bool { boxes = e.mailboxes(t); return boxes["Drafts"].ID != "" && boxes["Sent"].ID != "" })

	// Import: the Transform seals what is stored.
	ctx := context.Background()
	upl, err := e.c.Upload(ctx, e.acct, "message/rfc822", plain("import-1@test", "Imported", "Kept."))
	if err != nil {
		t.Fatal(err)
	}
	var imp struct {
		Created    map[jmap.ID]jmap.Email    `json:"created"`
		NotCreated map[jmap.ID]jmap.SetError `json:"notCreated"`
	}
	e.call(t, "Email/import", map[string]any{"accountId": e.acct, "emails": map[string]any{
		"k1": map[string]any{"blobId": upl.BlobID, "mailboxIds": map[jmap.ID]bool{boxes["INBOX"].ID: true}, "keywords": map[string]bool{"$seen": true}},
	}}, &imp)
	if imp.Created["k1"].ID == "" {
		t.Fatalf("import: %+v", imp.NotCreated)
	}
	if _, err := up.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	raw, err := up.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{{}}}).Collect()
	if err != nil || len(raw) != 1 || !sealtest.IsSealed(raw[0].BodySection[0].Bytes) {
		t.Fatalf("the provider's copy is not sealed: %v", err)
	}

	// A draft, then sent, then moved to Sent without $draft.
	b := e.c.NewBatch(jmap.CapMail, jmap.CapSubmission)
	b.Add("Email/set", map[string]any{"accountId": e.acct, "create": map[string]any{"d1": map[string]any{
		"mailboxIds": map[jmap.ID]bool{boxes["Drafts"].ID: true},
		"keywords":   map[string]bool{"$draft": true, "$seen": true},
		"from":       []any{map[string]any{"name": "Alice", "email": enginetest.User}},
		"to":         []any{map[string]any{"email": enginetest.Bob}},
		"bcc":        []any{map[string]any{"email": "carol@example.net"}},
		"subject":    "Hello Bob",
		"textBody":   []any{map[string]any{"partId": "t", "type": "text/plain"}},
		"bodyValues": map[string]any{"t": map[string]any{"value": "Hi Bob,\nSee you.\n"}},
	}}})
	var ident jmap.GetResponse[jmap.Identity]
	e.call(t, "Identity/get", jmap.GetArgs{AccountID: e.acct}, &ident)
	sub := b.Add("EmailSubmission/set", map[string]any{"accountId": e.acct,
		"create": map[string]any{"s1": map[string]any{"identityId": ident.List[0].ID, "emailId": "#d1"}},
		"onSuccessUpdateEmail": map[string]any{"#s1": map[string]any{
			"keywords/$draft":                          nil,
			"mailboxIds/" + string(boxes["Drafts"].ID): nil,
			"mailboxIds/" + string(boxes["Sent"].ID):   true,
		}}})
	res, err := b.Do(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var subResp jmap.SetResponse[jmap.EmailSubmission]
	if err := res.Get(sub, "EmailSubmission/set", &subResp); err != nil || len(subResp.Created) != 1 {
		t.Fatalf("submission: %v %+v", err, subResp.NotCreated)
	}
	var implicit jmap.SetResponse[jmap.Email]
	if err := res.Get(sub, "Email/set", &implicit); err != nil || len(implicit.Updated) != 1 {
		t.Fatalf("onSuccessUpdateEmail: %v %+v", err, implicit)
	}
	e.mu.Lock()
	sent := e.sent
	e.mu.Unlock()
	if len(sent) != 1 || sent[0].From != enginetest.User || len(sent[0].To) != 2 {
		t.Fatalf("sent %+v", sent)
	}
	msg := string(sent[0].Data)
	if strings.Contains(msg, "carol@example.net") || !strings.Contains(msg, "Hi Bob,") || !strings.Contains(msg, "Subject: Hello Bob") {
		t.Fatalf("sent message:\n%s", msg)
	}
	if got := e.query(t, boxes["Sent"].ID); len(got) != 1 {
		t.Fatalf("Sent has %v", got)
	}
}

func TestMailboxSet(t *testing.T) {
	e := newEnv(t)
	var set jmap.SetResponse[jmap.Mailbox]
	e.call(t, "Mailbox/set", map[string]any{"accountId": e.acct, "create": map[string]any{
		"p": map[string]any{"name": "Projects"},
	}}, &set)
	parent := set.Created["p"].ID
	if parent == "" {
		t.Fatalf("create: %+v", set.NotCreated)
	}
	e.call(t, "Mailbox/set", map[string]any{"accountId": e.acct, "create": map[string]any{
		"c": map[string]any{"name": "Child", "parentId": parent},
	}}, &set)
	child := set.Created["c"].ID
	boxes := e.mailboxes(t)
	if boxes["Child"].ParentID == nil || *boxes["Child"].ParentID != parent {
		t.Fatalf("child %+v", boxes["Child"])
	}
	e.call(t, "Mailbox/set", map[string]any{"accountId": e.acct, "update": map[string]any{
		string(child): map[string]any{"name": "Renamed"},
	}}, &set)
	if boxes := e.mailboxes(t); boxes["Renamed"].ID != child {
		t.Fatalf("rename kept no ID: %+v", boxes)
	}
	e.call(t, "Mailbox/set", map[string]any{"accountId": e.acct, "destroy": []jmap.ID{parent}}, &set)
	if set.NotDestroyed[parent].Type != jmap.SetMailboxHasChild {
		t.Fatalf("destroy a parent: %+v", set.NotDestroyed)
	}
	e.call(t, "Mailbox/set", map[string]any{"accountId": e.acct, "destroy": []jmap.ID{child, parent}}, &set)
	if len(set.Destroyed) != 2 {
		t.Fatalf("destroy: %+v", set.NotDestroyed)
	}
}

func TestResultReferences(t *testing.T) {
	doc := map[string]any{"list": []any{
		map[string]any{"id": "a", "ids": []any{"x", "y"}},
		map[string]any{"id": "b", "ids": []any{"z"}},
	}}
	got, err := pointer(doc, "/list/*/ids")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(got)
	if string(b) != `["x","y","z"]` {
		t.Fatalf("got %s", b)
	}
	if got, _ := pointer(doc, "/list/1/id"); got != "b" {
		t.Fatalf("got %v", got)
	}
}
