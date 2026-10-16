package easproxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strconv"
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

// env is a provider, the engine and the ActiveSync server.
type env struct {
	provider string
	user     *imapmemserver.User
	eng      *engine.Engine
	srv      *Server
	http     *httptest.Server
	device   string

	mu   sync.Mutex
	sent []*smtpproxy.Envelope
}

func newEnv(t *testing.T) *env {
	t.Helper()
	addr, user := enginetest.IMAP(t, testLog, nil)
	st, err := engine.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := &env{provider: addr, user: user, device: "dev1"}
	e.eng = &engine.Engine{
		Store: st, Timeout: 5 * time.Second, Transform: sealtest.Sealer{}, Log: testLog,
		Cache: &engine.Cache{Dir: t.TempDir(), MaxBytes: 1 << 20},
		Route: func(login string) (engine.Upstream, bool) {
			return engine.Upstream{Addr: addr, TLS: config.TLSNone, Timeout: 5 * time.Second}, login == enginetest.User
		},
	}
	t.Cleanup(func() { e.eng.Close(); e.eng.Cache.Close() })
	e.srv = &Server{Engine: e.eng, Log: testLog, Submit: func(_ context.Context, login, password string, env *smtpproxy.Envelope) error {
		if login != enginetest.User || password != enginetest.Password {
			return errors.New("bad credentials")
		}
		e.mu.Lock()
		e.sent = append(e.sent, env)
		e.mu.Unlock()
		return nil
	}}
	e.http = httptest.NewServer(e.srv.Handler())
	t.Cleanup(e.http.Close)
	return e
}

// post sends a command and decodes the answer; nil for an empty one.
func (e *env) post(t *testing.T, cmd string, doc *node) *node {
	t.Helper()
	n, status := e.postStatus(t, cmd, doc)
	if status != http.StatusOK {
		t.Fatalf("%s: HTTP %d", cmd, status)
	}
	return n
}

func (e *env) postStatus(t *testing.T, cmd string, doc *node) (*node, int) {
	t.Helper()
	var body []byte
	if doc != nil {
		var err error
		if body, err = encode(doc); err != nil {
			t.Fatal(err)
		}
	}
	u := e.http.URL + "/Microsoft-Server-ActiveSync?Cmd=" + cmd + "&User=" + enginetest.User +
		"&DeviceId=" + e.device + "&DeviceType=iPhone"
	req, _ := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	req.SetBasicAuth(enginetest.User, enginetest.Password)
	req.Header.Set("Content-Type", "application/vnd.ms-sync.wbxml")
	req.Header.Set("MS-ASProtocolVersion", "14.1")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.StatusCode != http.StatusOK || len(b) == 0 {
		return nil, res.StatusCode
	}
	n, err := decode(b)
	if err != nil {
		t.Fatalf("%s: %v", cmd, err)
	}
	return n, res.StatusCode
}

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
	return []byte("Message-ID: <" + id + ">\r\nFrom: Bob <" + enginetest.Bob + ">\r\nTo: Alice <" + enginetest.User +
		">\r\nSubject: " + subject + "\r\nDate: Mon, 02 Mar 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\n" +
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

// folders runs a first FolderSync and returns the folder IDs by name, and
// the folder key.
func (e *env) folders(t *testing.T) (map[string]string, string) {
	t.Helper()
	got := e.post(t, "FolderSync", el("FolderHierarchy:FolderSync", tx("FolderHierarchy:SyncKey", "0")))
	if got.Value("Status") != "1" {
		t.Fatalf("FolderSync status %s", got.Value("Status"))
	}
	out := map[string]string{}
	for _, a := range got.Child("Changes").Children("Add") {
		out[a.Value("DisplayName")] = a.Value("ServerId")
	}
	return out, got.Value("SyncKey")
}

// syncOnce syncs a collection from key and returns the collection's
// answer.
func (e *env) syncOnce(t *testing.T, id, key string, extra ...*node) *node {
	t.Helper()
	kids := []*node{tx("AirSync:SyncKey", key), tx("AirSync:CollectionId", id)}
	if key != "0" {
		kids = append(kids, el("AirSync:GetChanges"))
	}
	kids = append(kids, el("AirSync:Options", tx("AirSync:FilterType", "0"), tx("AirSync:MIMESupport", "0"),
		el("AirSyncBase:BodyPreference", tx("AirSyncBase:Type", "1"), tx("AirSyncBase:TruncationSize", "200000"))))
	kids = append(kids, extra...)
	got := e.post(t, "Sync", el("AirSync:Sync", el("AirSync:Collections", el("AirSync:Collection", kids...))))
	if got == nil {
		return nil
	}
	return got.Child("Collections").Child("Collection")
}

func TestFolderSyncAndSync(t *testing.T) {
	e := newEnv(t)
	up := e.upstream(t)
	if err := up.Create("Sent", &imap.CreateOptions{SpecialUse: []imap.MailboxAttr{imap.MailboxAttrSent}}).Wait(); err != nil {
		t.Fatal(err)
	}
	appendMsg(t, up, "INBOX", plain("one@x", "Hello", "first body"))

	ids, _ := e.folders(t)
	inbox := ids["INBOX"]
	if inbox == "" {
		t.Fatalf("no INBOX in %v", ids)
	}
	c := e.syncOnce(t, inbox, "0")
	if c.Value("Status") != "1" || c.Value("SyncKey") != "1" {
		t.Fatalf("first sync: status %s key %s", c.Value("Status"), c.Value("SyncKey"))
	}
	c = e.syncOnce(t, inbox, "1")
	adds := c.Child("Commands").Children("Add")
	if len(adds) != 1 {
		t.Fatalf("adds: %d", len(adds))
	}
	ad := adds[0].Child("ApplicationData")
	if ad.Value("Email:Subject") != "Hello" || ad.Value("Email:Read") != "0" || ad.Value("Email:DisplayTo") != "Alice" {
		t.Fatalf("app data %+v", ad)
	}
	if body := ad.Child("AirSyncBase:Body").Value("Data"); !strings.Contains(body, "first body") {
		t.Fatalf("body %q", body)
	}
	key := c.Value("SyncKey")
	serverID := adds[0].Value("ServerId")

	// Nothing new: the same key.
	c = e.syncOnce(t, inbox, key)
	if c.Value("SyncKey") != key || c.Child("Commands") != nil {
		t.Fatalf("idle sync: key %s commands %v", c.Value("SyncKey"), c.Child("Commands"))
	}

	// The device marks it read: the provider hears of it.
	c = e.syncOnce(t, inbox, key, el("AirSync:Commands", el("AirSync:Change", tx("AirSync:ServerId", serverID),
		el("AirSync:ApplicationData", tx("Email:Read", "1")))))
	if c.Child("Commands") != nil {
		t.Fatalf("the device's own change came back: %+v", c.Child("Commands"))
	}
	key = c.Value("SyncKey")
	eventually(t, "\\Seen at the provider", func() bool {
		if _, err := up.Select("INBOX", nil).Wait(); err != nil {
			t.Fatal(err)
		}
		msgs, err := up.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
		return err == nil && len(msgs) == 1 && slices.Contains(msgs[0].Flags, imap.FlagSeen)
	})

	// A flag another client sets reaches the device as a Change.
	a := e.eng.Account(enginetest.User)
	a.Lock()
	m := a.Mailbox("INBOX")
	msgs := slices.Clone(m.Msgs())
	a.Unlock()
	a.SetFlags(msgs, "INBOX", imap.StoreFlagsAdd, []imap.Flag{imap.FlagFlagged}, nil)
	eventually(t, "a flag change", func() bool {
		c = e.syncOnce(t, inbox, key)
		key = c.Value("SyncKey")
		ch := c.Child("Commands").Child("Change")
		return ch != nil && ch.Child("ApplicationData").Child("Email:Flag").Value("FlagStatus") == "2"
	})

	// A message that arrives is pushed: Ping returns with the INBOX.
	done := make(chan *node, 1)
	go func() {
		done <- e.post(t, "Ping", el("Ping:Ping", tx("Ping:HeartbeatInterval", "120"),
			el("Ping:Folders", el("Ping:Folder", tx("Ping:Id", inbox), tx("Ping:Class", "Email")))))
	}()
	time.Sleep(200 * time.Millisecond)
	appendMsg(t, up, "INBOX", plain("two@x", "Second", "second body"))
	select {
	case p := <-done:
		if p.Value("Status") != "2" || p.Child("Folders").Value("Folder") != inbox {
			t.Fatalf("ping: status %s", p.Value("Status"))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ping did not return")
	}
	c = e.syncOnce(t, inbox, key)
	if adds := c.Child("Commands").Children("Add"); len(adds) != 1 ||
		adds[0].Child("ApplicationData").Value("Email:Subject") != "Second" {
		t.Fatalf("after ping: %+v", c.Child("Commands"))
	}
	key = c.Value("SyncKey")

	// The device deletes the first: it goes to the Trash if there is one,
	// expunged here.
	beforeDelete := key
	c = e.syncOnce(t, inbox, key, el("AirSync:Commands", el("AirSync:Delete", tx("AirSync:ServerId", serverID))))
	key = c.Value("SyncKey")
	eventually(t, "the expunge at the provider", func() bool {
		sd, err := up.Status("INBOX", &imap.StatusOptions{NumMessages: true}).Wait()
		return err == nil && *sd.NumMessages == 1
	})
	c = e.syncOnce(t, inbox, key)
	if c.Child("Commands") != nil {
		for _, k := range c.Child("Commands").All() {
			t.Logf("%s %s %+v", k.Name, k.Value("ServerId"), k.Child("ApplicationData"))
		}
		t.Fatalf("the device's own delete came back")
	}

	// A lost answer: the device asks again with the key before.
	again := e.syncOnce(t, inbox, beforeDelete)
	if again.Value("Status") != "1" {
		t.Fatalf("retry with the old key: status %s", again.Value("Status"))
	}
	if bad := e.syncOnce(t, inbox, "99"); bad.Value("Status") != "3" {
		t.Fatalf("unknown key: status %s", bad.Value("Status"))
	}
}

func TestMoveItemsAndFetch(t *testing.T) {
	e := newEnv(t)
	up := e.upstream(t)
	if err := up.Create("Archive", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	attached := "Message-ID: <att@x>\r\nFrom: " + enginetest.Bob + "\r\nTo: " + enginetest.User + "\r\nSubject: Files\r\n" +
		"MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n" +
		"<p>See <b>attached</b></p>\r\n--b\r\nContent-Type: application/pdf; name=\"r.pdf\"\r\nContent-Disposition: attachment; filename=\"r.pdf\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte("%PDF-1.4 fake")) + "\r\n--b--\r\n"
	appendMsg(t, up, "INBOX", []byte(attached))
	ids, _ := e.folders(t)
	inbox, archive := ids["INBOX"], ids["Archive"]
	e.syncOnce(t, inbox, "0")
	c := e.syncOnce(t, inbox, "1")
	add := c.Child("Commands").Child("Add")
	ad := add.Child("ApplicationData")
	if got := ad.Child("AirSyncBase:Body").Value("Data"); !strings.Contains(got, "See attached") {
		t.Fatalf("plain text from HTML: %q", got)
	}
	att := ad.Child("AirSyncBase:Attachments").Child("Attachment")
	if att.Value("DisplayName") != "r.pdf" {
		t.Fatalf("attachment %+v", att)
	}
	got := e.post(t, "ItemOperations", el("ItemOperations:ItemOperations", el("ItemOperations:Fetch",
		tx("ItemOperations:Store", "Mailbox"), tx("AirSyncBase:FileReference", att.Value("FileReference")))))
	f := got.Child("Response").Child("Fetch")
	data, _ := base64.StdEncoding.DecodeString(f.Child("Properties").Value("Data"))
	if f.Value("Status") != "1" || string(data) != "%PDF-1.4 fake" {
		t.Fatalf("attachment fetch: status %s data %q", f.Value("Status"), data)
	}

	e.syncOnce(t, archive, "0")
	akey := e.syncOnce(t, archive, "1").Value("SyncKey")
	mv := e.post(t, "MoveItems", el("Move:MoveItems", el("Move:Move", tx("Move:SrcMsgId", add.Value("ServerId")),
		tx("Move:SrcFldId", inbox), tx("Move:DstFldId", archive))))
	r := mv.Child("Response")
	if r.Value("Status") != "3" || !strings.HasPrefix(r.Value("DstMsgId"), archive+":") {
		t.Fatalf("move: %s %s", r.Value("Status"), r.Value("DstMsgId"))
	}
	// The device knows of the move: neither folder reports it.
	if c := e.syncOnce(t, archive, akey); c.Child("Commands") != nil {
		t.Fatalf("archive: %+v", c.Child("Commands"))
	}
	eventually(t, "the move at the provider", func() bool {
		sd, err := up.Status("Archive", &imap.StatusOptions{NumMessages: true}).Wait()
		return err == nil && *sd.NumMessages == 1
	})
}

func TestSendMail(t *testing.T) {
	e := newEnv(t)
	up := e.upstream(t)
	if err := up.Create("Sent", &imap.CreateOptions{SpecialUse: []imap.MailboxAttr{imap.MailboxAttrSent}}).Wait(); err != nil {
		t.Fatal(err)
	}
	appendMsg(t, up, "INBOX", plain("orig@x", "Question", "what?"))
	ids, _ := e.folders(t)
	inbox := ids["INBOX"]
	e.syncOnce(t, inbox, "0")
	add := e.syncOnce(t, inbox, "1").Child("Commands").Child("Add")

	reply := "From: " + enginetest.User + "\nTo: " + enginetest.Bob + "\nBcc: carol@example.net\nSubject: Re: Question\n\nAnswer.\n"
	got := e.post(t, "SmartReply", el("ComposeMail:SmartReply", tx("ComposeMail:ClientId", "c1"),
		el("ComposeMail:SaveInSentItems"), el("ComposeMail:Source", tx("ComposeMail:FolderId", inbox),
			tx("ComposeMail:ItemId", add.Value("ServerId"))), op("ComposeMail:Mime", []byte(reply))))
	if got != nil {
		t.Fatalf("SmartReply: status %s", got.Value("Status"))
	}
	e.mu.Lock()
	sent := e.sent
	e.mu.Unlock()
	if len(sent) != 1 || len(sent[0].To) != 2 || bytes.Contains(sent[0].Data, []byte("Bcc:")) ||
		!bytes.Contains(sent[0].Data, []byte("In-Reply-To: <orig@x>\r\n")) {
		t.Fatalf("sent %+v %q", sent, sent[0].Data)
	}
	eventually(t, "the Sent copy", func() bool {
		sd, err := up.Status("Sent", &imap.StatusOptions{NumMessages: true}).Wait()
		return err == nil && *sd.NumMessages == 1
	})
	eventually(t, "\\Answered at the provider", func() bool {
		if _, err := up.Select("INBOX", nil).Wait(); err != nil {
			t.Fatal(err)
		}
		msgs, err := up.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
		return err == nil && len(msgs) == 1 && slices.Contains(msgs[0].Flags, imap.FlagAnswered)
	})
}

func TestForwardAddsAttachments(t *testing.T) {
	orig := []byte("Subject: x\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n" +
		"Content-Type: text/plain\r\n\r\nhi\r\n--b\r\nContent-Type: image/png\r\nContent-Disposition: attachment; filename=\"ü.png\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte("PNG")) + "\r\n--b--\r\n")
	fwd := []byte("From: a@x\r\nTo: b@y\r\nSubject: Fwd: x\r\nContent-Type: text/plain\r\n\r\nsee below\r\n")
	out := withAttachments(fwd, orig)
	p := parse(out)
	if p.text != "see below\r\n" || len(p.attachments) != 1 || p.attachments[0].name != "ü.png" {
		t.Fatalf("%q -> %+v", out, p)
	}
	if b, _, _ := partData(out, p.attachments[0].path); string(b) != "PNG" {
		t.Fatalf("attachment %q", b)
	}
}

func TestAutodiscoverAndAuth(t *testing.T) {
	e := newEnv(t)
	body := `<?xml version="1.0"?><Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/mobilesync/requestschema/2006"><Request><EMailAddress>` +
		enginetest.User + `</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006</AcceptableResponseSchema></Request></Autodiscover>`
	req, _ := http.NewRequest(http.MethodPost, e.http.URL+"/Autodiscover/Autodiscover.xml", strings.NewReader(body))
	req.SetBasicAuth(enginetest.User, enginetest.Password)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !bytes.Contains(b, []byte("<Url>"+e.http.URL+"/Microsoft-Server-ActiveSync</Url>")) {
		t.Fatalf("%d %s", res.StatusCode, b)
	}

	req, _ = http.NewRequest(http.MethodOptions, e.http.URL+"/Microsoft-Server-ActiveSync", nil)
	req.SetBasicAuth(enginetest.User, "wrong")
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", res.StatusCode)
	}
}

func TestBase64Query(t *testing.T) {
	q := []byte{141, 0, 9, 4} // 14.1, Sync, locale
	q = append(q, 4)
	q = append(q, "dev9"...)
	q = append(q, 0) // no policy key
	q = append(q, 6)
	q = append(q, "iPhone"...)
	q = append(q, 7, 1, 1) // Options: SaveInSent
	r := httptest.NewRequest(http.MethodPost, "/Microsoft-Server-ActiveSync?"+base64.StdEncoding.EncodeToString(q), nil)
	req, err := parseQuery(r)
	if err != nil {
		t.Fatal(err)
	}
	if req.cmd != "Sync" || req.version != "14.1" || req.deviceID != "dev9" || req.deviceType != "iPhone" || req.params["SaveInSent"] != "T" {
		t.Fatalf("%+v", req)
	}
}

func TestProvision(t *testing.T) {
	e := newEnv(t)
	got := e.post(t, "Provision", el("Provision:Provision", el("Provision:Policies", el("Provision:Policy",
		tx("Provision:PolicyType", policyType)))))
	pol := got.Child("Policies").Child("Policy")
	key := pol.Value("PolicyKey")
	if got.Value("Status") != "1" || key == "" || pol.Child("Data").Child("EASProvisionDoc") == nil {
		t.Fatalf("first step: %+v", got)
	}
	if _, err := strconv.Atoi(key); err != nil {
		t.Fatalf("policy key %q", key)
	}
	got = e.post(t, "Provision", el("Provision:Provision", el("Provision:Policies", el("Provision:Policy",
		tx("Provision:PolicyType", policyType), tx("Provision:PolicyKey", key), tx("Provision:Status", "1")))))
	if pol := got.Child("Policies").Child("Policy"); pol.Value("Status") != "1" || pol.Child("Data") != nil {
		t.Fatalf("ack: %+v", got)
	}
}
