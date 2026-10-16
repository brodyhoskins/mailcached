package imapproxy

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"

	"github.com/brodyhoskins/mailcached/config"

	"github.com/brodyhoskins/mailcached/engine"
)

const password = "correct horse"

// debugLog is the test proxy's log; MAILCACHED_DEBUG=1 sends it to stderr.
var debugLog = testLog

func init() {
	// Fast enough for tests: the engine checks folders every 50ms and a
	// SELECT always rereads the provider.
	engine.SyncPoll = 50 * time.Millisecond
	engine.SelectFresh = 0
	engine.SelectWaits = true
}

// eventually retries f until it reports true or two seconds pass.
func eventually(t *testing.T, what string, f func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !f() {
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for " + what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// env is a provider (go-imap's in-memory server) with the proxy in front.
type env struct {
	provider string // provider address
	proxy    string // proxy address
	eng      *engine.Engine
	b        *Server
}

func newEnv(t *testing.T) *env { return newEnvWith(t, nil) }

// newEnvWith wraps the provider's listener with wrap, if not nil.
func newEnvWith(t *testing.T, wrap func(net.Listener) net.Listener) *env {
	return newEnvConf(t, wrap, nil)
}

// newEnvConf also lets configure change the engine and the proxy before
// it serves.
func newEnvConf(t *testing.T, wrap func(net.Listener) net.Listener, configure func(*engine.Engine, *Server)) *env {
	t.Helper()
	mem := imapmemserver.New()
	u := imapmemserver.NewUser(alice, password)
	if err := u.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}
	mem.AddUser(u)
	up := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		Caps:         imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapIMAP4rev2: {}},
		InsecureAuth: true,
		Logger:       slogLogger{testLog},
	})
	ul := listen(t)
	var served net.Listener = ul
	if wrap != nil {
		served = wrap(ul)
	}
	go up.Serve(served)
	t.Cleanup(func() { up.Close() })

	// The database too, as in production: its lock interacts with the
	// account's.
	st, err := engine.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	eng := &engine.Engine{
		Store: st,
		Route: func(login string) (engine.Upstream, bool) {
			if login != alice {
				return engine.Upstream{}, false
			}
			return engine.Upstream{Addr: ul.Addr().String(), TLS: config.TLSNone, Timeout: 5 * time.Second}, true
		},
		Timeout:   5 * time.Second,
		Transform: sealer{},
		Cache:     &engine.Cache{Dir: t.TempDir(), MaxBytes: 1 << 20},
		Log:       debugLog,
	}
	b := &Server{
		Engine:          eng,
		MaxMessageBytes: 1 << 20,
		Log:             debugLog,
		Trace:           debugLog != testLog,
	}
	if configure != nil {
		configure(eng, b)
	}
	bl := listen(t)
	go b.Serve(bl)
	t.Cleanup(func() { b.Close(); eng.Close(); eng.Cache.Close() })

	return &env{provider: ul.Addr().String(), proxy: bl.Addr().String(), eng: eng, b: b}
}

func listen(t *testing.T) net.Listener {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func login(t *testing.T, addr string, h *imapclient.UnilateralDataHandler) *imapclient.Client {
	t.Helper()
	c, err := imapclient.DialInsecure(addr, &imapclient.Options{UnilateralDataHandler: h})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Login(alice, password).Wait(); err != nil {
		t.Fatal(err)
	}
	return c
}

func appendMsg(t *testing.T, c *imapclient.Client, mailbox string, data []byte) imap.UID {
	t.Helper()
	cmd := c.Append(mailbox, int64(len(data)), nil)
	if _, err := cmd.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Close(); err != nil {
		t.Fatal(err)
	}
	res, err := cmd.Wait()
	if err != nil {
		t.Fatal(err)
	}
	return res.UID
}

func plain(from, subject, body string) []byte {
	return []byte("From: " + from + "\r\n" +
		"To: alice@corp.example\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" + body + "\r\n")
}

// sealed is a sealed message from bob.
func sealed(subject, body string) []byte { return seal(plain(bob, subject, body)) }

func TestFetchTransforms(t *testing.T) {
	e := newEnv(t)
	up := login(t, e.provider, nil)
	msg := sealed("Quarterly numbers", "The secret number is 42.")
	uid := appendMsg(t, up, "INBOX", msg)
	appendMsg(t, up, "INBOX", plain(bob, "Lunch", "Tacos?"))

	c := login(t, e.proxy, nil)
	sel, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	if sel.NumMessages != 2 {
		t.Fatalf("NumMessages = %d, want 2", sel.NumMessages)
	}

	full := &imap.FetchItemBodySection{Peek: true}
	text := &imap.FetchItemBodySection{Specifier: imap.PartSpecifierText, Peek: true}
	partial := &imap.FetchItemBodySection{Peek: true, Partial: &imap.SectionPartial{Offset: 0, Size: 22}}
	msgs, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{
		UID: true, RFC822Size: true, Envelope: true,
		BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
		BodySection:   []*imap.FetchItemBodySection{full, text, partial},
	}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 {
		t.Fatalf("got %d messages", len(msgs))
	}
	m := msgs[0]
	body := m.FindBodySection(full)
	for _, want := range []string{"X-Opened: yes", "The secret number is 42."} {
		if !bytes.Contains(body, []byte(want)) {
			t.Errorf("body lacks %q:\n%s", want, body)
		}
	}
	if m.RFC822Size != int64(len(body)) {
		t.Errorf("RFC822.SIZE = %d, body is %d bytes", m.RFC822Size, len(body))
	}
	if got := string(m.FindBodySection(text)); strings.TrimSpace(got) != "The secret number is 42." {
		t.Errorf("BODY[TEXT] = %q", got)
	}
	if got := m.FindBodySection(partial); !bytes.Equal(got, body[:22]) {
		t.Errorf("BODY[]<0.22> = %q, want %q", got, body[:22])
	}
	if m.Envelope == nil || m.Envelope.Subject != "Quarterly numbers" {
		t.Errorf("envelope = %+v", m.Envelope)
	}
	if sp, ok := m.BodyStructure.(*imap.BodyStructureSinglePart); !ok || sp.Type != "text" {
		t.Errorf("BODYSTRUCTURE = %#v, want the opened text/plain", m.BodyStructure)
	}

	// The provider still holds the sealed message.
	if _, err := up.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	raw, err := up.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{full}}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw[0].FindBodySection(full), []byte("secret number")) {
		t.Fatal("provider copy is open")
	}
}

func TestFetchMarksSeen(t *testing.T) {
	e := newEnv(t)
	up := login(t, e.provider, nil)
	uid := appendMsg(t, up, "INBOX", sealed("Hi", "Hello."))

	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	msgs, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{Flags: true, BodySection: []*imap.FetchItemBodySection{{}}}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if !engine.HasFlag(msgs[0].Flags, imap.FlagSeen) {
		t.Errorf("flags in FETCH = %v, want \\Seen", msgs[0].Flags)
	}
	// The change reaches the provider through the queue.
	eventually(t, "\\Seen at the provider", func() bool {
		if _, err := up.Select("INBOX", nil).Wait(); err != nil {
			return false
		}
		got, err := up.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{Flags: true}).Collect()
		return err == nil && len(got) == 1 && engine.HasFlag(got[0].Flags, imap.FlagSeen)
	})
}

func TestSearchTransformedText(t *testing.T) {
	e := newEnv(t)
	up := login(t, e.provider, nil)
	secret := appendMsg(t, up, "INBOX", sealed("Numbers", "The secret number is 42."))
	appendMsg(t, up, "INBOX", plain(bob, "Lunch", "Tacos?"))

	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	res, err := c.UIDSearch(&imap.SearchCriteria{Body: []string{"secret number"}}, nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	if uids := res.AllUIDs(); len(uids) != 1 || uids[0] != secret {
		t.Fatalf("UID SEARCH BODY = %v, want [%d]", uids, secret)
	}
	res, err = c.Search(&imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "lunch"}}}, nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	if seqs := res.AllSeqNums(); len(seqs) != 1 || seqs[0] != 2 {
		t.Fatalf("SEARCH HEADER Subject = %v, want [2]", seqs)
	}
}

func TestAppendTransforms(t *testing.T) {
	e := newEnv(t)
	c := login(t, e.proxy, nil)
	if err := c.Create("Sent", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	uid := appendMsg(t, c, "Sent", plain(alice, "To bob", "Draft of the secret plan."))

	up := login(t, e.provider, nil)
	if _, err := up.Select("Sent", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	full := &imap.FetchItemBodySection{Peek: true}
	raw, err := up.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{full}}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	stored := raw[0].FindBodySection(full)
	if !isSealed(stored) || bytes.Contains(stored, []byte("secret plan")) {
		t.Fatalf("provider stored:\n%s", stored)
	}

	if _, err := c.Select("Sent", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	got, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{full}}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(got[0].FindBodySection(full), []byte("Draft of the secret plan.")) {
		t.Fatalf("proxy returned:\n%s", got[0].FindBodySection(full))
	}
}

// TestUpstreamChanges checks that messages added and removed at the
// provider by another client reach a proxy client with consistent
// sequence numbers.
func TestUpstreamChanges(t *testing.T) {
	e := newEnv(t)
	other := login(t, e.provider, nil)
	first := appendMsg(t, other, "INBOX", plain(bob, "One", "1"))
	second := appendMsg(t, other, "INBOX", plain(bob, "Two", "2"))

	var expunged []uint32
	c := login(t, e.proxy, &imapclient.UnilateralDataHandler{Expunge: func(n uint32) { expunged = append(expunged, n) }})
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}

	third := appendMsg(t, other, "INBOX", plain(bob, "Three", "3"))
	eventually(t, "the new message", func() bool {
		return c.Noop().Wait() == nil && c.Mailbox().NumMessages == 3
	})

	if _, err := other.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if err := other.Store(imap.UIDSetNum(first), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Close(); err != nil {
		t.Fatal(err)
	}
	if err := other.Expunge().Close(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the EXPUNGE", func() bool {
		return c.Noop().Wait() == nil && len(expunged) > 0
	})
	if len(expunged) != 1 || expunged[0] != 1 {
		t.Fatalf("EXPUNGE responses = %v, want [1]", expunged)
	}
	msgs, err := c.Fetch(imap.SeqSetNum(1, 2), &imap.FetchOptions{UID: true}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[0].UID != second || msgs[1].UID != third {
		t.Fatalf("seq 1:2 = %+v, want UIDs %d, %d", msgs, second, third)
	}
}

func TestIdleSeesNewMail(t *testing.T) {
	e := newEnv(t)
	other := login(t, e.provider, nil)

	exists := make(chan uint32, 4)
	c := login(t, e.proxy, &imapclient.UnilateralDataHandler{Mailbox: func(d *imapclient.UnilateralDataMailbox) {
		if d.NumMessages != nil {
			exists <- *d.NumMessages
		}
	}})
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	idle, err := c.Idle()
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()

	appendMsg(t, other, "INBOX", sealed("Ping", "pong"))
	select {
	case n := <-exists:
		if n != 1 {
			t.Fatalf("EXISTS %d, want 1", n)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no EXISTS during IDLE")
	}
}

func TestStoreAndMove(t *testing.T) {
	e := newEnv(t)
	other := login(t, e.provider, nil)
	uid := appendMsg(t, other, "INBOX", plain(bob, "One", "1"))
	if err := other.Create("Archive", nil).Wait(); err != nil {
		t.Fatal(err)
	}

	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	res, err := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagFlagged}}, nil).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || !engine.HasFlag(res[0].Flags, imap.FlagFlagged) {
		t.Fatalf("STORE response = %+v", res)
	}
	if _, err := c.Move(imap.UIDSetNum(uid), "Archive").Wait(); err != nil {
		t.Fatal(err)
	}
	if err := c.Noop().Wait(); err != nil {
		t.Fatal(err)
	}
	if n := c.Mailbox().NumMessages; n != 0 {
		t.Fatalf("INBOX has %d messages after MOVE", n)
	}
	// The provider follows from the queue.
	eventually(t, "the move to reach the provider", func() bool {
		st, err := other.Status("Archive", &imap.StatusOptions{NumMessages: true}).Wait()
		return err == nil && *st.NumMessages == 1
	})
}

// Apple Mail moves with COPY, STORE \Deleted and UID EXPUNGE. The proxy
// applies the expunge without a resync, and only to the messages that had
// \Deleted.
func TestMoveByCopyAndExpunge(t *testing.T) {
	e := newEnv(t)
	other := login(t, e.provider, nil)
	var uids []imap.UID
	for _, s := range []string{"One", "Two", "Three"} {
		uids = append(uids, appendMsg(t, other, "INBOX", plain(bob, s, s)))
	}
	if err := other.Create("Archive", nil).Wait(); err != nil {
		t.Fatal(err)
	}

	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	moved := imap.UIDSetNum(uids[0], uids[1])
	if _, err := c.Copy(moved, "Archive").Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Store(moved, &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Collect(); err != nil {
		t.Fatal(err)
	}
	// Two in the set, one of them without \Deleted.
	all := imap.UIDSetNum(uids...)
	if _, err := c.Store(imap.UIDSetNum(uids[1]), &imap.StoreFlags{Op: imap.StoreFlagsDel, Silent: true, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Collect(); err != nil {
		t.Fatal(err)
	}
	expunged, err := c.UIDExpunge(all).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(expunged) != 1 {
		t.Fatalf("expunged %v, want one message", expunged)
	}
	a := e.eng.Account(alice)
	a.Lock()
	var left []imap.UID
	for _, m := range a.Mailbox("INBOX").Msgs() {
		left = append(left, m.UID())
	}
	a.Unlock()
	if !slices.Equal(left, uids[1:]) {
		t.Fatalf("INBOX has %v, want %v", left, uids[1:])
	}
	eventually(t, "the copies to show in Archive", func() bool {
		a.Lock()
		defer a.Unlock()
		arch := a.Mailbox("Archive")
		return arch != nil && len(arch.Msgs()) == 2
	})
}

func TestUnknownAccountRejected(t *testing.T) {
	e := newEnv(t)
	c, err := imapclient.DialInsecure(e.proxy, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Login("mallory@elsewhere.example", password).Wait(); err == nil {
		t.Fatal("login for an address with no account succeeded")
	}
}

func TestBadPassword(t *testing.T) {
	e := newEnv(t)
	c, err := imapclient.DialInsecure(e.proxy, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Login(alice, "wrong").Wait(); err == nil {
		t.Fatal("login with a wrong password succeeded")
	}
}

// TestAuthorizeRefusalText checks that a client sees the code and text of
// an Authorize hook's refusal, not a bare AUTHENTICATIONFAILED.
func TestAuthorizeRefusalText(t *testing.T) {
	refusal := &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeAuthorizationFailed, Text: "this provider does not report DMARC results"}
	e := newEnvConf(t, nil, func(eng *engine.Engine, _ *Server) {
		eng.Authorize = func(*engine.Account) error { return fmt.Errorf("%w: %w", engine.ErrLoginRejected, refusal) }
	})
	c, err := imapclient.DialInsecure(e.proxy, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	err = c.Login(alice, password).Wait()
	var ie *imap.Error
	if !errors.As(err, &ie) || ie.Code != refusal.Code || ie.Text != refusal.Text {
		t.Fatalf("login: %v", err)
	}
}

// TestFetchEmptyMultipart checks BODYSTRUCTURE of a forwarded message
// whose multipart body has no parts, which go-imap cannot write as is.
func TestFetchEmptyMultipart(t *testing.T) {
	e := newEnv(t)
	up := login(t, e.provider, nil)
	raw := "From: bob@other.example\r\nTo: alice@corp.example\r\nSubject: Fwd\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=outer\r\n\r\n" +
		"--outer\r\nContent-Type: text/plain\r\n\r\nSee below.\r\n" +
		"--outer\r\nContent-Type: message/rfc822\r\n\r\n" +
		"Subject: Empty\r\nContent-Type: multipart/alternative; boundary=inner\r\n\r\nno parts here\r\n" +
		"--outer--\r\n"
	uid := appendMsg(t, up, "INBOX", []byte(raw))

	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	// Read it whole first, so the structure comes from the proxy's copy,
	// not from the provider.
	full := &imap.FetchItemBodySection{Peek: true}
	if _, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{full}}).Collect(); err != nil {
		t.Fatal(err)
	}
	msgs, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{
		UID: true, BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
	}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	mp, ok := msgs[0].BodyStructure.(*imap.BodyStructureMultiPart)
	if !ok || len(mp.Children) != 2 {
		t.Fatalf("BODYSTRUCTURE = %#v", msgs[0].BodyStructure)
	}
	fwd, ok := mp.Children[1].(*imap.BodyStructureSinglePart)
	if !ok || fwd.MessageRFC822 == nil || fwd.MessageRFC822.BodyStructure.MediaType() != "text/plain" {
		t.Errorf("forwarded part = %#v", mp.Children[1])
	}
}

// TestFetchHeadersFromProvider checks that a message list of unchanged
// mail is filled from the provider without downloading the messages, that
// the sizes agree with the message read later, and that changed mail is
// still described by its transformed copy.
func TestFetchHeadersFromProvider(t *testing.T) {
	counter := &countingListener{needle: []byte("BODY.PEEK[HEADER]")}
	e := newEnvWith(t, func(l net.Listener) net.Listener { counter.Listener = l; return counter })
	up := login(t, e.provider, nil)
	plainUID := appendMsg(t, up, "INBOX", plain(bob, "Lunch", "Tacos?"))
	spoofed := appendMsg(t, up, "INBOX", append([]byte("X-Opened: yes\r\n"), plain(bob, "Fake", "Trust me.")...))
	encUID := appendMsg(t, up, "INBOX", sealed("Secret", "The secret number is 42."))

	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	a := e.eng.Account(alice)
	a.Lock()
	msgs := slices.Clone(a.Mailbox("INBOX").Msgs())
	a.Unlock()
	if !msgs[0].Direct() || msgs[1].Direct() || msgs[2].Direct() {
		t.Fatalf("direct = %v %v %v, want true false false", msgs[0].Direct(), msgs[1].Direct(), msgs[2].Direct())
	}

	header := &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader, Peek: true}
	list := &imap.FetchOptions{UID: true, RFC822Size: true, Envelope: true,
		BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
		BodySection:   []*imap.FetchItemBodySection{header}}
	got, err := c.Fetch(imap.UIDSetNum(plainUID, spoofed, encUID), list).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d messages", len(got))
	}
	if e.eng.Cache.Has(alice, msgs[0].Key()) {
		t.Error("the unchanged message was downloaded for its header")
	}
	if !e.eng.Cache.Has(alice, msgs[2].Key()) {
		t.Error("the sealed message was not transformed for its header")
	}
	byUID := map[imap.UID]*imapclient.FetchMessageBuffer{}
	for _, m := range got {
		byUID[m.UID] = m
	}
	p := byUID[plainUID]
	if p.Envelope == nil || p.Envelope.Subject != "Lunch" || !bytes.Contains(p.FindBodySection(header), []byte("Subject: Lunch")) {
		t.Errorf("unchanged message = %+v", p)
	}
	if bytes.Contains(byUID[spoofed].FindBodySection(header), []byte("X-Opened: yes\r\n")) {
		t.Error("an incoming X-Opened header reached the client")
	}
	if s := byUID[encUID].Envelope; s == nil || s.Subject != "Secret" || !bytes.Contains(byUID[encUID].FindBodySection(header), []byte("X-Opened: yes")) {
		t.Errorf("sealed message header = %s", byUID[encUID].FindBodySection(header))
	}

	// Listed again, the unchanged message is answered from its header
	// entry: the provider is not asked.
	asked := counter.n.Load()
	again, err := c.Fetch(imap.UIDSetNum(plainUID), list).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if n := counter.n.Load(); n != asked {
		t.Errorf("the provider was asked for headers %d more times", n-asked)
	}
	// So are some fields of the header, as Thunderbird and iOS ask.
	fields := &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader, HeaderFields: []string{"Subject", "From"}, Peek: true}
	some, err := c.Fetch(imap.UIDSetNum(plainUID), &imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{fields}}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if b := some[0].FindBodySection(fields); !bytes.Contains(b, []byte("Subject: Lunch")) || bytes.Contains(b, []byte("Message-Id")) || bytes.Contains(b, []byte("Message-ID")) {
		t.Errorf("HEADER.FIELDS = %q", b)
	}
	if e.eng.Cache.Has(alice, msgs[0].Key()) {
		t.Error("HEADER.FIELDS downloaded the message")
	}
	if !bytes.Equal(again[0].FindBodySection(header), p.FindBodySection(header)) || again[0].RFC822Size != p.RFC822Size ||
		again[0].BodyStructure.MediaType() != p.BodyStructure.MediaType() {
		t.Errorf("second listing differs: %+v, first %+v", again[0], p)
	}

	// Read whole, the unchanged message is cached and has the size the
	// list showed.
	full := &imap.FetchItemBodySection{Peek: true}
	body, err := c.Fetch(imap.UIDSetNum(plainUID), &imap.FetchOptions{UID: true, RFC822Size: true,
		BodySection: []*imap.FetchItemBodySection{full}}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if raw := body[0].FindBodySection(full); int64(len(raw)) != p.RFC822Size || body[0].RFC822Size != p.RFC822Size {
		t.Errorf("size %d, body %d bytes; the list said %d", body[0].RFC822Size, len(raw), p.RFC822Size)
	}
	if !e.eng.Cache.Has(alice, msgs[0].Key()) {
		t.Error("the unchanged message was not cached when read")
	}
}

// countingListener counts the reads from the proxy that contain needle.
type countingListener struct {
	net.Listener
	needle []byte
	n      atomic.Int32
}

func (l *countingListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &countingConn{Conn: c, l: l}, nil
}

type countingConn struct {
	net.Conn
	l *countingListener
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if bytes.Contains(p[:n], c.l.needle) {
		c.l.n.Add(1)
	}
	return n, err
}

// TestBackfill fills the message list after a login with no client asking:
// a header entry for the unchanged message, a transformed copy of the
// sealed one. A list then needs nothing from the provider.
func TestBackfill(t *testing.T) {
	counter := &countingListener{needle: []byte("FETCH")}
	e := newEnvConf(t, func(l net.Listener) net.Listener { counter.Listener = l; return counter },
		func(eng *engine.Engine, _ *Server) { eng.Backfill = true })
	up := login(t, e.provider, nil)
	plainUID := appendMsg(t, up, "INBOX", plain(bob, "Lunch", "Tacos?"))
	encUID := appendMsg(t, up, "INBOX", sealed("Secret", "The secret number is 42."))
	if err := up.Create("Archive", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	oldUID := appendMsg(t, up, "Archive", plain(bob, "Old", "From last year."))

	c := login(t, e.proxy, nil)
	a := e.eng.Account(alice)
	keys := func(name string) []string {
		a.Lock()
		defer a.Unlock()
		var out []string
		if m := a.Mailbox(name); m != nil {
			for _, msg := range m.Msgs() {
				out = append(out, msg.Key())
			}
		}
		return out
	}
	eventually(t, "backfill", func() bool {
		inbox, archive := keys("INBOX"), keys("Archive")
		if len(inbox) != 2 || len(archive) != 1 {
			return false
		}
		have, _ := e.eng.Store.HeaderKeys(alice)
		return have[inbox[0]] && have[archive[0]] && e.eng.Cache.Has(alice, inbox[1]) && !a.Backfilling()
	})
	if e.eng.Cache.Has(alice, keys("INBOX")[0]) {
		t.Error("the backfill downloaded the unchanged message")
	}

	header := &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader, Peek: true}
	list := &imap.FetchOptions{UID: true, RFC822Size: true, Envelope: true,
		BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
		BodySection:   []*imap.FetchItemBodySection{header}}
	asked := counter.n.Load()
	for name, uids := range map[string][]imap.UID{"INBOX": {plainUID, encUID}, "Archive": {oldUID}} {
		if _, err := c.Select(name, nil).Wait(); err != nil {
			t.Fatal(err)
		}
		got, err := c.Fetch(imap.UIDSetNum(uids...), list).Collect()
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(uids) {
			t.Fatalf("%s: got %d messages", name, len(got))
		}
	}
	if n := counter.n.Load(); n != asked {
		t.Errorf("listing asked the provider %d times", n-asked)
	}
}

// TestReadAhead reads a folder downward a message at a time, as Apple Mail
// does for its offline copy. After two steps the proxy reads ahead, so
// the next messages need nothing from the provider, and it reads ahead
// again halfway there, without going past what it needs.
func TestReadAhead(t *testing.T) {
	defer func(n int) { engine.ReadAheadCount = n }(engine.ReadAheadCount)
	engine.ReadAheadCount = 4
	counter := &countingListener{needle: []byte("BODY.PEEK[]")}
	e := newEnvWith(t, func(l net.Listener) net.Listener { counter.Listener = l; return counter })
	up := login(t, e.provider, nil)
	uids := make([]imap.UID, 12)
	for i := range uids {
		uids[i] = appendMsg(t, up, "INBOX", plain(bob, fmt.Sprint("Message ", i), "Body."))
	}
	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	a := e.eng.Account(alice)
	cached := func(i int) bool {
		a.Lock()
		key := a.Mailbox("INBOX").Msgs()[i].Key()
		a.Unlock()
		return e.eng.Cache.Has(alice, key)
	}
	full := &imap.FetchItemBodySection{Peek: true}
	read := func(i int) {
		t.Helper()
		got, err := c.Fetch(imap.UIDSetNum(uids[i]), &imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{full}}).Collect()
		if err != nil || len(got) != 1 || !bytes.Contains(got[0].FindBodySection(full), []byte("Body.")) {
			t.Fatalf("message %d = %v, %v", i, got, err)
		}
	}

	read(11)
	read(10)
	read(9) // the second step down: read-ahead of 8, 7, 6, 5
	eventually(t, "read-ahead", func() bool { return cached(5) && cached(8) })
	if cached(4) {
		t.Error("read ahead past readAheadCount")
	}
	asked := counter.n.Load()
	read(8)
	if n := counter.n.Load(); n != asked {
		t.Errorf("a message read ahead was fetched from the provider %d more times", n-asked)
	}
	read(7) // halfway: read-ahead of 4, 3, 2, 1
	eventually(t, "the next read-ahead", func() bool { return cached(1) && cached(4) })
	if cached(0) {
		t.Error("read ahead past readAheadCount, the second time")
	}
}

// TestFetchTrace logs, per FETCH, where the messages came from.
func TestFetchTrace(t *testing.T) {
	var buf syncBuffer
	e := newEnvConf(t, nil, func(_ *engine.Engine, b *Server) {
		b.Log = slog.New(slog.NewTextHandler(&buf, nil))
		b.Trace = true
	})
	up := login(t, e.provider, nil)
	uid := appendMsg(t, up, "INBOX", plain(bob, "Traced", "Body."))
	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	full := &imap.FetchItemBodySection{Peek: true}
	for range 2 {
		if _, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{full}}).Collect(); err != nil {
			t.Fatal(err)
		}
	}
	var lines []string
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.Contains(l, "imap trace: fetch") {
			lines = append(lines, l)
		}
	}
	if len(lines) != 2 || !strings.Contains(lines[0], "provider=1") || !strings.Contains(lines[1], "memory=1") || !strings.Contains(lines[1], "provider=0") {
		t.Errorf("fetch trace:\n%s", strings.Join(lines, "\n"))
	}
}

// syncBuffer is a bytes.Buffer safe for concurrent writes.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// Transforming a message saves its header entry, so a client's list of it
// never reads the whole message again.
func TestTransformSavesHeaderEntry(t *testing.T) {
	e := newEnv(t)
	up := login(t, e.provider, nil)
	appendMsg(t, up, "INBOX", sealed("Quarterly numbers", "The secret number is 42."))

	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	full := &imap.FetchItemBodySection{Peek: true}
	if _, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{full}}).Collect(); err != nil {
		t.Fatal(err)
	}
	a := e.eng.Account(alice)
	a.Lock()
	key := a.Mailbox("INBOX").Msgs()[0].Key()
	a.Unlock()
	h := e.eng.Store.Headers(alice, []string{key})[key]
	if h == nil {
		t.Fatal("no header entry after transforming")
	}
	if got := envelope(h.Header).Subject; got != "Quarterly numbers" {
		t.Fatalf("entry subject %q", got)
	}

	// Answered from the entry, with the cached copy gone.
	if err := e.eng.Cache.Delete(alice, key); err != nil {
		t.Fatal(err)
	}
	res, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Envelope: true, RFC822Size: true}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 1 || res[0].Envelope.Subject != "Quarterly numbers" || res[0].RFC822Size != h.Size {
		t.Fatalf("list entry %+v", res)
	}
	if e.eng.Cache.Has(alice, key) {
		t.Fatal("the list read the whole message")
	}
}

// A SELECT of a folder synced before answers from the proxy's state; what
// the check at the provider finds reaches the client as updates.
func TestSelectChecksInBackground(t *testing.T) {
	engine.SelectWaits = false
	t.Cleanup(func() { engine.SelectWaits = true })
	e := newEnv(t)
	up := login(t, e.provider, nil)
	appendMsg(t, up, "INBOX", plain(bob, "One", "1"))
	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if err := c.Unselect().Wait(); err != nil {
		t.Fatal(err)
	}
	appendMsg(t, up, "INBOX", plain(bob, "Two", "2"))
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the new message to reach the client", func() bool {
		return c.Noop().Wait() == nil && c.Mailbox().NumMessages == 2
	})
}
