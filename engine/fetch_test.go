package engine

import (
	"bytes"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/config"
	"github.com/brodyhoskins/mailcached/internal/enginetest"
)

// fetchLog records the provider's reads that fetch whole messages, and
// holds the first until open closes, if open is not nil.
type fetchLog struct {
	net.Listener
	open chan struct{}

	mu   sync.Mutex
	cmds []string
	held bool
}

func (l *fetchLog) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &fetchLogConn{Conn: c, l: l}, nil
}

func (l *fetchLog) commands() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.Clone(l.cmds)
}

type fetchLogConn struct {
	net.Conn
	l *fetchLog
}

func (c *fetchLogConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if bytes.Contains(p[:n], []byte("BODY.PEEK[]")) {
		c.l.mu.Lock()
		c.l.cmds = append(c.l.cmds, string(p[:n]))
		hold := c.l.open != nil && !c.l.held
		c.l.held = true
		c.l.mu.Unlock()
		if hold {
			<-c.l.open
		}
	}
	return n, err
}

// fetchEnv returns an account whose INBOX has n messages, synced, the
// messages in UID order, and the provider's fetch log. The messages are
// there before the login, so the sync does not download them as new mail.
func fetchEnv(t *testing.T, n int, open chan struct{}) (*Account, []*Message, *fetchLog) {
	t.Helper()
	log := &fetchLog{open: open}
	addr, _ := enginetest.IMAP(t, testLog, func(l net.Listener) net.Listener { log.Listener = l; return log })
	for i := range n {
		appendTo(t, addr, "INBOX", fmt.Appendf(nil, "Message-ID: <fetch-%d@test>\r\nSubject: Fetch\r\n\r\nBody.\r\n", i))
	}
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	b := &Engine{Store: st, Timeout: 5 * time.Second, Cache: &Cache{MaxBytes: 1 << 20}, Log: testLog,
		Route: func(string) (Upstream, bool) {
			return Upstream{Addr: addr, TLS: config.TLSNone, Timeout: 5 * time.Second, MaxConns: 6}, true
		}}
	t.Cleanup(b.Close)
	a := b.Account(enginetest.User)
	if err := a.Login(enginetest.Password); err != nil {
		t.Fatal(err)
	}
	if err := a.SyncNow("INBOX"); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	msgs := slices.Clone(a.boxes["INBOX"].msgs)
	a.mu.Unlock()
	if len(msgs) != n {
		t.Fatalf("%d messages, want %d", len(msgs), n)
	}
	if cmds := log.commands(); len(cmds) > 0 {
		t.Fatalf("the sync downloaded messages: %q", cmds)
	}
	return a, msgs, log
}

// uidsOf returns the UID set of a logged UID FETCH command.
func uidsOf(cmd string) string {
	f := strings.Fields(cmd)
	if i := slices.Index(f, "FETCH"); i >= 0 && i+1 < len(f) {
		return f[i+1]
	}
	return ""
}

// TestDownloadOrder fetches messages in the order asked, a batch at a
// time: read-ahead going down a folder gets the nearest first.
func TestDownloadOrder(t *testing.T) {
	a, msgs, log := fetchEnv(t, FetchBatch+5, nil)
	down := slices.Clone(msgs)
	slices.Reverse(down)
	if err := a.download(down, nil, true, nil); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, cmd := range log.commands() {
		got = append(got, uidsOf(cmd))
	}
	if want := []string{"6:30", "1:5"}; !slices.Equal(got, want) {
		t.Errorf("fetched %q, want %q", got, want)
	}
}

// TestBoxesInOrder orders folders by their first message.
func TestBoxesInOrder(t *testing.T) {
	m := make([]*Message, 4)
	for i := range m {
		m[i] = &Message{}
	}
	where := map[string]located{
		"INBOX": {1: {m[1]}, 2: {m[3]}},
		"Trash": {7: {m[0]}},
		"Sent":  {3: {m[2]}},
	}
	if got, want := boxesInOrder(where, m), []string{"Trash", "INBOX", "Sent"}; !slices.Equal(got, want) {
		t.Errorf("boxes %q, want %q", got, want)
	}
	if got, want := where["INBOX"].inOrder([]*Message{m[3], m[1]}), []imap.UID{2, 1}; !slices.Equal(got, want) {
		t.Errorf("UIDs %v, want %v", got, want)
	}
}

// TestClientTakesOver gives a client a message a background download has
// not started on: the client does not wait, and the message is fetched
// once.
func TestClientTakesOver(t *testing.T) {
	open := make(chan struct{})
	a, msgs, log := fetchEnv(t, FetchBatch+5, open)
	down := slices.Clone(msgs)
	slices.Reverse(down)
	bg := make(chan error, 1)
	go func() { bg <- a.download(down, nil, true, nil) }()
	eventually(t, "the first batch", func() bool { return len(log.commands()) == 1 })

	got := make(chan error, 1)
	go func() {
		_, err := a.Download(msgs[:1], nil) // UID 1, in the second batch
		got <- err
	}()
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		close(open)
		t.Fatal("the client waited for the background download")
	}
	close(open)
	if err := <-bg; err != nil {
		t.Fatal(err)
	}
	var sets []string
	for _, cmd := range log.commands() {
		sets = append(sets, uidsOf(cmd))
	}
	slices.Sort(sets)
	if want := []string{"1", "2:5", "6:30"}; !slices.Equal(sets, want) {
		t.Errorf("fetched %q, want %q", sets, want)
	}
}

// TestClientBatchInteractive serves a client's request for more than a
// few messages while bulk downloads hold their connections.
func TestClientBatchInteractive(t *testing.T) {
	a, msgs, _ := fetchEnv(t, 6, nil)
	var held []Conn
	for range bulkSlots(a) {
		pc, err := a.conn(PriorityBulk, "INBOX")
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, pc)
	}
	defer func() {
		for _, pc := range held {
			pc.Release(nil)
		}
	}()
	got := make(chan error, 1)
	go func() {
		out, err := a.Download(msgs, nil)
		if err == nil && len(out) != len(msgs) {
			t.Errorf("%d of %d messages", len(out), len(msgs))
		}
		got <- err
	}()
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a client's six messages waited behind bulk downloads")
	}
}
