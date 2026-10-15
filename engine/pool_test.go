package engine

import (
	"io"
	"log/slog"
	"math"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/config"
	"github.com/brodyhoskins/mailcached/internal/enginetest"
)

var testLog = slog.New(slog.NewTextHandler(io.Discard, nil))

// newTestEngine returns an engine for an in-memory provider, and the
// provider's account, logged in.
func newTestEngine(t *testing.T) (*Engine, *Account) {
	t.Helper()
	addr, _ := enginetest.IMAP(t, testLog, nil)
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	b := &Engine{
		Store: st,
		Route: func(login string) (Upstream, bool) {
			return Upstream{Addr: addr, TLS: config.TLSNone, Timeout: 5 * time.Second, MaxConns: 6}, login == enginetest.User
		},
		Timeout: 5 * time.Second,
		Cache:   &Cache{MaxBytes: 1 << 20},
		Log:     testLog,
	}
	t.Cleanup(b.Close)
	a := b.Account(enginetest.User)
	if err := a.Login(enginetest.Password); err != nil {
		t.Fatal(err)
	}
	return b, a
}

// TestInteractiveBeatsBulk checks that with every bulk connection busy, an
// interactive request still gets a connection at once, and a further bulk
// request waits.
func TestInteractiveBeatsBulk(t *testing.T) {
	_, a := newTestEngine(t)

	var held []conn
	for range bulkSlots(a) {
		pc, err := a.conn(bulk, "INBOX")
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, pc)
	}

	got := make(chan conn, 1)
	go func() {
		pc, err := a.conn(bulk, "INBOX")
		if err == nil {
			got <- pc
		}
	}()

	done := make(chan conn, 1)
	go func() {
		pc, err := a.conn(interactive, "INBOX")
		if err != nil {
			t.Error(err)
		}
		done <- pc
	}()
	select {
	case pc := <-done:
		pc.Release(nil)
	case <-time.After(2 * time.Second):
		t.Fatal("an interactive request waited behind bulk ones")
	}
	select {
	case <-got:
		t.Fatal("a bulk request took more than its share of connections")
	case <-time.After(100 * time.Millisecond):
	}
	held[0].Release(nil)
	select {
	case pc := <-got:
		pc.Release(nil)
	case <-time.After(2 * time.Second):
		t.Fatal("the waiting bulk request never got a connection")
	}
	for _, pc := range held[1:] {
		pc.Release(nil)
	}
}

// bulkSlots returns how many connections bulk requests may hold.
func bulkSlots(a *Account) int {
	a.credMu.Lock()
	p := a.prov.(*imapProvider)
	a.credMu.Unlock()
	p.poolMu.Lock()
	defer p.poolMu.Unlock()
	return p.bulkLimit()
}

// capListener closes the connections over max open at a time, as a
// provider with a connection limit does.
type capListener struct {
	net.Listener
	mu   sync.Mutex
	open int
	max  int
}

func (l *capListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		l.mu.Lock()
		full := l.open >= l.max
		if !full {
			l.open++
		}
		l.mu.Unlock()
		if full {
			c.Close()
			continue
		}
		return &capConn{Conn: c, l: l}, nil
	}
}

type capConn struct {
	net.Conn
	l    *capListener
	once sync.Once
}

func (c *capConn) Close() error {
	c.once.Do(func() {
		c.l.mu.Lock()
		c.l.open--
		c.l.mu.Unlock()
	})
	return c.Conn.Close()
}

// newTestProvider returns an IMAP provider for the test server, which
// wrap may change.
func newTestProvider(t *testing.T, wrap func(net.Listener) net.Listener) *imapProvider {
	t.Helper()
	addr, _ := enginetest.IMAP(t, testLog, wrap)
	u := Upstream{Addr: addr, TLS: config.TLSNone, Timeout: 5 * time.Second}
	p := newIMAPProvider(enginetest.User, u, &imap.IDData{}, nil, func() string { return enginetest.Password }, testLog)
	t.Cleanup(p.Close)
	return p
}

// TestPoolLowersAtProviderLimit checks that a provider that refuses a
// connection caps the pool at the connections open, and that the cap
// goes away later.
func TestPoolLowersAtProviderLimit(t *testing.T) {
	p := newTestProvider(t, func(l net.Listener) net.Listener { return &capListener{Listener: l, max: 2} })
	var held []conn
	for range 2 {
		pc, err := p.Conn(interactive, "")
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, pc)
	}
	// The third request is refused a connection, and waits for one of
	// the two.
	got := make(chan error, 1)
	go func() {
		pc, err := p.Conn(interactive, "")
		if err == nil {
			pc.Release(nil)
		}
		got <- err
	}()
	select {
	case err := <-got:
		t.Fatalf("a third request did not wait: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	p.poolMu.Lock()
	limit := p.srcs[0].limit
	p.poolMu.Unlock()
	if limit != 2 {
		t.Fatalf("limit %d after the refusal, want 2", limit)
	}
	held[0].Release(nil)
	select {
	case err := <-got:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the waiting request never got the released connection")
	}
	held[1].Release(nil)

	p.poolMu.Lock()
	p.srcs[0].limitAt = p.srcs[0].limitAt.Add(-connRetryAfter)
	limit = p.srcs[0].poolLimit()
	p.poolMu.Unlock()
	if limit != math.MaxInt {
		t.Fatalf("limit %d after connRetryAfter, want none", limit)
	}
}

// TestPoolClosesIdle checks that connections idle for connIdleClose are
// closed, except the last one used.
func TestPoolClosesIdle(t *testing.T) {
	old := connIdleClose
	connIdleClose = 50 * time.Millisecond
	t.Cleanup(func() { connIdleClose = old })
	p := newTestProvider(t, nil)
	var held []conn
	for range 3 {
		pc, err := p.Conn(interactive, "")
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, pc)
	}
	for _, pc := range held {
		pc.Release(nil)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		p.poolMu.Lock()
		open, idle := p.open, len(p.idle)
		p.poolMu.Unlock()
		if open == 1 && idle == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d open, %d idle; want 1 and 1", open, idle)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestPoolGivesToSmallerPool checks that when the server refuses an
// account a connection, a larger pool of another account on the server
// gives one up for it.
func TestPoolGivesToSmallerPool(t *testing.T) {
	addr, _ := enginetest.IMAP(t, testLog, func(l net.Listener) net.Listener { return &capListener{Listener: l, max: 4} })
	u := Upstream{Addr: addr, TLS: config.TLSNone, Timeout: 5 * time.Second}
	h := &imapHost{pools: map[*imapSource]bool{}}
	newPool := func() *imapProvider {
		p := newIMAPProvider(enginetest.User, u, &imap.IDData{}, nil, func() string { return enginetest.Password }, testLog)
		p.srcs[0].host = h
		h.add(p.srcs[0])
		t.Cleanup(p.Close)
		return p
	}
	big, small := newPool(), newPool()
	var held []conn
	for range 3 {
		pc, err := big.Conn(interactive, "")
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, pc)
	}
	for _, pc := range held {
		pc.Release(nil)
	}
	first, err := small.Conn(interactive, "")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release(nil)
	second, err := small.Conn(interactive, "")
	if err != nil {
		t.Fatalf("the small pool got no second connection: %v", err)
	}
	second.Release(nil)
	big.poolMu.Lock()
	open, limit := big.open, big.srcs[0].limit
	big.poolMu.Unlock()
	if open != 2 || limit != 2 {
		t.Fatalf("big pool has %d open, limit %d; want 2 and 2", open, limit)
	}
	small.poolMu.Lock()
	limit = small.srcs[0].limit
	small.poolMu.Unlock()
	if limit != math.MaxInt {
		t.Fatalf("small pool lowered its own limit to %d", limit)
	}
}

// TestPoolSpreadsOverSources checks that a provider that allows one
// connection from each address gets one from each source.
func TestPoolSpreadsOverSources(t *testing.T) {
	if l, err := net.Listen("tcp", "127.0.0.2:0"); err != nil {
		t.Skip("127.0.0.2 is not a local address here")
	} else {
		l.Close()
	}
	perIP := func(l net.Listener) net.Listener { return &perIPListener{Listener: l, open: map[string]int{}} }
	addr, _ := enginetest.IMAP(t, testLog, perIP)
	u := Upstream{Addr: addr, TLS: config.TLSNone, Timeout: 5 * time.Second, Sources: []string{"127.0.0.1", "127.0.0.2"}}
	p := newIMAPProvider(enginetest.User, u, &imap.IDData{}, nil, func() string { return enginetest.Password }, testLog)
	t.Cleanup(p.Close)
	var held []conn
	for range 2 {
		pc, err := p.Conn(interactive, "")
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
	p.poolMu.Lock()
	defer p.poolMu.Unlock()
	for _, s := range p.srcs {
		if s.open != 1 || s.limit != math.MaxInt {
			t.Errorf("source %s: %d open, limit %d; want 1 and none", s.addr, s.open, s.limit)
		}
	}
}

// perIPListener closes a second connection from one address.
type perIPListener struct {
	net.Listener
	mu   sync.Mutex
	open map[string]int
}

func (l *perIPListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip, _, _ := net.SplitHostPort(c.RemoteAddr().String())
		l.mu.Lock()
		full := l.open[ip] >= 1
		if !full {
			l.open[ip]++
		}
		l.mu.Unlock()
		if full {
			c.Close()
			continue
		}
		return c, nil
	}
}
