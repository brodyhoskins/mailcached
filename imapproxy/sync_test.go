package imapproxy

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/brodyhoskins/mailcached/config"
	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/internal/enginetest"
)

// TestSyncPrefetchesNewMail checks that the background sync runs after a
// client leaves, downloads mail that arrives later so it opens without
// waiting, leaves older mail until a client asks for it, and marks
// nothing \Seen.
func TestSyncPrefetchesNewMail(t *testing.T) {
	e := newEnv(t)
	up := login(t, e.provider, nil)
	old := appendMsg(t, up, "INBOX", sealed("Before", "Already here."))
	sel, err := up.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatal(err)
	}

	c := login(t, e.proxy, nil)
	if err := c.Logout().Wait(); err != nil {
		t.Fatal(err)
	}
	waitSyncing(t, e.b, alice)
	uid := appendMsg(t, up, "INBOX", sealed("After", "Arrived while away."))
	time.Sleep(300 * time.Millisecond) // time for IDLE to report it

	a := e.eng.Account(alice)
	eventually(t, "the engine to see the new message", func() bool {
		a.Lock()
		defer a.Unlock()
		m := a.Mailbox("INBOX")
		return m != nil && len(m.Msgs()) == 2
	})
	a.Lock()
	msgs := slices.Clone(a.Mailbox("INBOX").Msgs())
	a.Unlock()
	eventually(t, "the new message to be downloaded", func() bool { return e.eng.Cache.Has(alice, msgs[1].Key()) })
	if e.eng.Cache.Has(alice, msgs[0].Key()) {
		t.Errorf("UID %d, there before the first sync, was downloaded with no client asking", msgs[0].UID())
	}
	_ = sel
	got, err := up.Fetch(imap.UIDSetNum(old, uid), &imap.FetchOptions{Flags: true}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range got {
		if engine.HasFlag(m.Flags, imap.FlagSeen) {
			t.Errorf("UID %d was marked \\Seen by the sync", m.UID)
		}
	}
}

func waitSyncing(t *testing.T, b *Server, login string) {
	t.Helper()
	a := b.Engine.Account(login)
	eventually(t, "the engine", func() bool {
		// And past its first sweep, so what arrives now is new mail.
		return a.Running() && a.Sweeps() > 0
	})
}

// TestSyncForgetsRejectedPassword checks that a password the provider
// rejects is dropped and the engine stops.
func TestSyncForgetsRejectedPassword(t *testing.T) {
	e := newEnv(t)
	u, _ := e.eng.Route(alice)
	a := e.eng.Account(alice)
	a.SetCredentials("wrong", u)
	eventually(t, "the engine to stop", func() bool {
		return !a.Running() && !a.HasPassword()
	})
}

// TestClientsShareState checks that a flag change by one client reaches
// another through the proxy's own copy.
func TestClientsShareState(t *testing.T) {
	e := newEnv(t)
	up := login(t, e.provider, nil)
	uid := appendMsg(t, up, "INBOX", plain(bob, "Shared", "x"))

	var got []imap.Flag
	var mu sync.Mutex
	watcher := login(t, e.proxy, &imapclient.UnilateralDataHandler{Fetch: func(m *imapclient.FetchMessageData) {
		if b, err := m.Collect(); err == nil && b.Flags != nil {
			mu.Lock()
			got = b.Flags
			mu.Unlock()
		}
	}})
	if _, err := watcher.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	idle, err := watcher.Idle()
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()

	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if err := c.Store(imap.UIDSetNum(uid), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagFlagged}}, nil).Close(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the other client to see \\Flagged", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return engine.HasFlag(got, imap.FlagFlagged)
	})
}

// TestStateSurvivesRestart checks that the folder list and messages are
// saved and loaded back, before any provider connection, in a database of
// the account's own; and that, when the account goes to another provider,
// what clients see is kept but not where the old provider had it.
func TestStateSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	st, err := engine.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnvConf(t, nil, func(eng *engine.Engine, _ *Server) { eng.Store = st })
	up := login(t, e.provider, nil)
	uid := appendMsg(t, up, "INBOX", plain(bob, "Saved", "x"))
	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	st.Close()
	if _, err := os.Stat(filepath.Join(dir, "accounts", alice, "state.sqlite3")); err != nil {
		t.Fatal(err)
	}

	restored := func(route func(string) (engine.Upstream, bool)) *engine.Mailbox {
		st, err := engine.OpenStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer st.Close()
		eng := &engine.Engine{Store: st, Route: route, Log: testLog}
		a := eng.Account(alice)
		a.Lock()
		defer a.Unlock()
		return a.Mailbox("INBOX")
	}
	m := restored(e.eng.Route)
	if m == nil || len(m.Msgs()) != 1 || m.Msgs()[0].UID() != uid || m.UIDValidity() == 0 {
		t.Fatalf("restored INBOX = %+v", m)
	}
	other := func(string) (engine.Upstream, bool) { return engine.Upstream{Addr: "imap.elsewhere.example:993"}, true }
	m = restored(other)
	if m == nil || len(m.Msgs()) != 1 || m.Msgs()[0].UID() != uid {
		t.Fatalf("state for another provider = %+v", m)
	}
	if box, pUID := m.Msgs()[0].AtProvider(); box != "" || pUID != 0 {
		t.Fatalf("the old provider's place survived: %s %d", box, pUID)
	}
}

// TestProviderSwitchKeepsUIDs checks that when an account moves to another
// provider with the same mail, clients keep their UIDs: the messages are
// matched by their cache keys, not numbered again.
func TestProviderSwitchKeepsUIDs(t *testing.T) {
	dir := t.TempDir()
	st, err := engine.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := newEnvConf(t, nil, func(eng *engine.Engine, _ *Server) { eng.Store = st })
	date := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	msgs := [][]byte{
		withID(plain(bob, "First", "One."), "<switch-1@test>"),
		withID(plain(bob, "Second", "Two."), "<switch-2@test>"),
	}
	put := func(c *imapclient.Client, data []byte) {
		t.Helper()
		cmd := c.Append("INBOX", int64(len(data)), &imap.AppendOptions{Time: date})
		cmd.Write(data)
		cmd.Close()
		if _, err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	up := login(t, e.provider, nil)
	for _, m := range msgs {
		put(up, m)
	}
	subjects := func(addr string) (uint32, map[imap.UID]string) {
		t.Helper()
		c := login(t, addr, nil)
		defer c.Close()
		sel, err := c.Select("INBOX", nil).Wait()
		if err != nil {
			t.Fatal(err)
		}
		got, err := c.Fetch(imap.SeqSetNum(1, 2, 3), &imap.FetchOptions{UID: true, Envelope: true}).Collect()
		if err != nil {
			t.Fatal(err)
		}
		out := map[imap.UID]string{}
		for _, m := range got {
			out[m.UID] = m.Envelope.Subject
		}
		return sel.UIDValidity, out
	}
	validity, before := subjects(e.proxy)
	e.b.Close()
	e.eng.Close()

	// The new provider has the same messages, in the other order, and one
	// more.
	addr, _ := enginetest.IMAP(t, testLog, nil)
	up2 := login(t, addr, nil)
	put(up2, msgs[1])
	put(up2, msgs[0])
	put(up2, withID(plain(bob, "Third", "Three."), "<switch-3@test>"))

	eng := &engine.Engine{Store: st, Log: testLog, Timeout: 5 * time.Second, Cache: &engine.Cache{MaxBytes: 1 << 20},
		Route: func(string) (engine.Upstream, bool) {
			return engine.Upstream{Addr: addr, TLS: config.TLSNone, Timeout: 5 * time.Second}, true
		}}
	t.Cleanup(eng.Close)
	b := &Server{Engine: eng, MaxMessageBytes: 1 << 20, Log: testLog}
	l := listen(t)
	go b.Serve(l)
	t.Cleanup(func() { b.Close() })

	validity2, after := subjects(l.Addr().String())
	if validity2 != validity {
		t.Fatalf("UIDVALIDITY %d, was %d", validity2, validity)
	}
	for uid, subject := range before {
		if after[uid] != subject {
			t.Errorf("UID %d is %q, was %q", uid, after[uid], subject)
		}
	}
	if len(after) != 3 || after[3] != "Third" {
		t.Errorf("after the switch: %v", after)
	}
}

// TestCacheFollowsMovedMessage checks that a message moved to another
// folder keeps its cached copy, and that a deleted one loses it after a
// full sweep.
func TestCacheFollowsMovedMessage(t *testing.T) {
	e := newEnv(t)
	up := login(t, e.provider, nil)
	uid := appendMsg(t, up, "INBOX", withID(sealed("Keep", "Moved, not lost."), "<move-1@test>"))
	if err := up.Create("Archive", nil).Wait(); err != nil {
		t.Fatal(err)
	}

	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	full := &imap.FetchItemBodySection{Peek: true}
	if _, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{full}}).Collect(); err != nil {
		t.Fatal(err)
	}
	a := e.eng.Account(alice)
	a.Lock()
	key := a.Mailbox("INBOX").Msgs()[0].Key()
	a.Unlock()
	if !e.eng.Cache.Has(alice, key) {
		t.Fatal("not cached after the client read it")
	}

	// Moved at the provider, not through the proxy.
	if _, err := up.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := up.Move(imap.UIDSetNum(uid), "Archive").Wait(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the move to reach the proxy", func() bool {
		a.Lock()
		defer a.Unlock()
		arch := a.Mailbox("Archive")
		return len(a.Mailbox("INBOX").Msgs()) == 0 && arch != nil && len(arch.Msgs()) == 1
	})
	a.Lock()
	moved := a.Mailbox("Archive").Msgs()[0].Key()
	a.Unlock()
	sweeps := a.Sweeps()
	if moved != key {
		t.Fatal("the moved message has a different cache key")
	}
	waitSweeps(t, a, sweeps+2)
	if !e.eng.Cache.Has(alice, key) {
		t.Fatal("the moved message lost its cached copy")
	}

	// Deleted for good: the copy goes after a full sweep.
	if _, err := up.Select("Archive", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if err := up.Store(imap.UIDSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Close(); err != nil {
		t.Fatal(err)
	}
	if err := up.Expunge().Close(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the deleted message's cached copy to go", func() bool { return !e.eng.Cache.Has(alice, key) })
}

func waitSweeps(t *testing.T, a *engine.Account, n int) {
	t.Helper()
	eventually(t, "sweeps", func() bool { return a.Sweeps() >= n })
}

// withID puts a Message-ID header in front of a message.
func withID(msg []byte, id string) []byte {
	return append([]byte("Message-ID: "+id+"\r\n"), msg...)
}

// gateListener holds every full-body FETCH after the first until open is
// closed, so a test can look at the proxy between batches.
type gateListener struct {
	net.Listener
	open    chan struct{}
	fetches atomic.Int32
}

func (l *gateListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &gateConn{Conn: c, l: l}, nil
}

type gateConn struct {
	net.Conn
	l *gateListener
}

func (c *gateConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if bytes.Contains(p[:n], []byte("BODY.PEEK[]")) && c.l.fetches.Add(1) > 1 {
		<-c.l.open
	}
	return n, err
}

// TestDownloadReleasesEachBatch checks that a bulk download releases each
// batch when it is cached, not when the whole download ends.
func TestDownloadReleasesEachBatch(t *testing.T) {
	gate := &gateListener{open: make(chan struct{})}
	e := newEnvWith(t, func(l net.Listener) net.Listener { gate.Listener = l; return gate })
	up := login(t, e.provider, nil)
	for i := range engine.FetchBatch + 5 {
		appendMsg(t, up, "INBOX", plain(bob, fmt.Sprint("Message ", i), "Hello."))
	}
	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}

	a := e.eng.Account(alice)
	a.Lock()
	msgs := slices.Clone(a.Mailbox("INBOX").Msgs())
	a.Unlock()
	errc := make(chan error, 1)
	go func() { errc <- a.Prefetch(msgs, false) }()

	first, last := msgs[0].Key(), msgs[len(msgs)-1].Key()
	inflight := func(key string) bool {
		return e.eng.Downloading(key)
	}
	eventually(t, "the first batch", func() bool { return e.eng.Cache.Has(alice, first) && !inflight(first) })
	if !inflight(last) {
		t.Error("the second batch is not claimed while it downloads")
	}
	close(gate.open)
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if !e.eng.Cache.Has(alice, last) || inflight(last) {
		t.Error("the second batch is not cached and released")
	}
}

// holdFirstListener holds the provider's first read containing
// "BODY.PEEK[]" until open closes, and passes the rest. n counts them.
type holdFirstListener struct {
	net.Listener
	open chan struct{}
	seen atomic.Bool
	n    atomic.Int32
}

func (l *holdFirstListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &holdFirstConn{Conn: c, l: l}, nil
}

type holdFirstConn struct {
	net.Conn
	l *holdFirstListener
}

func (c *holdFirstConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if !bytes.Contains(p[:n], []byte("BODY.PEEK[]")) {
		return n, err
	}
	c.l.n.Add(1)
	if c.l.seen.CompareAndSwap(false, true) {
		<-c.l.open
	}
	return n, err
}

// TestClientWaitsForBackgroundDownload checks that a client asking for a
// message a background download (read-ahead) is fetching waits for it,
// and the provider is asked for the message once.
func TestClientWaitsForBackgroundDownload(t *testing.T) {
	hold := &holdFirstListener{open: make(chan struct{})}
	e := newEnvWith(t, func(l net.Listener) net.Listener { hold.Listener = l; return hold })
	up := login(t, e.provider, nil)
	uid := appendMsg(t, up, "INBOX", plain(bob, "Wanted", "Now."))
	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	a := e.eng.Account(alice)
	a.Lock()
	m := a.Mailbox("INBOX").Msgs()[0]
	a.Unlock()

	errc := make(chan error, 1)
	go func() { errc <- a.Prefetch([]*engine.Message{m}, true) }()
	eventually(t, "the background download", func() bool { return hold.seen.Load() })

	full := &imap.FetchItemBodySection{Peek: true}
	got := make(chan error, 1)
	go func() {
		msgs, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{full}}).Collect()
		if err == nil && (len(msgs) != 1 || !bytes.Contains(msgs[0].FindBodySection(full), []byte("Now."))) {
			err = fmt.Errorf("got %v", msgs)
		}
		got <- err
	}()
	select {
	case err := <-got:
		close(hold.open)
		t.Fatalf("the client did not wait for the background download: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(hold.open)
	if err := <-got; err != nil {
		t.Fatal(err)
	}
	if err := <-errc; err != nil {
		t.Fatal(err)
	}
	if n := hold.n.Load(); n != 1 {
		t.Errorf("the provider was asked for the message %d times, want 1", n)
	}
}

// TestNewMailCachedBeforeShown checks that new mail from a fast provider
// is downloaded before clients are told of it (newmail.go): when EXISTS
// reaches a client, the message is cached.
func TestNewMailCachedBeforeShown(t *testing.T) {
	e := newEnv(t)
	up := login(t, e.provider, nil)
	a := e.eng.Account(alice)
	cached := make(chan bool, 1)
	c := login(t, e.proxy, &imapclient.UnilateralDataHandler{Mailbox: func(d *imapclient.UnilateralDataMailbox) {
		if d.NumMessages == nil || *d.NumMessages != 1 {
			return
		}
		a.Lock()
		msgs := slices.Clone(a.Mailbox("INBOX").Msgs())
		a.Unlock()
		select {
		case cached <- len(msgs) == 1 && e.eng.Cache.Has(alice, msgs[0].Key()):
		default:
		}
	}})
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	waitSyncing(t, e.b, alice)
	idle, err := c.Idle()
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	// A message with no Message-ID has its cache key only once shown:
	// it does not wait.
	appendMsg(t, up, "INBOX", append([]byte("Message-ID: <new@corp.example>\r\n"), plain(bob, "New", "Arrived now.")...))

	select {
	case ok := <-cached:
		if !ok {
			t.Error("clients were told of the new message before it was downloaded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for EXISTS")
	}
}
