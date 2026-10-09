package engine

import (
	"io"
	"log/slog"
	"testing"
	"time"

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
			return Upstream{Addr: addr, TLS: config.TLSNone, Timeout: 5 * time.Second}, login == enginetest.User
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
	for i := 0; i < poolSize; i++ {
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
