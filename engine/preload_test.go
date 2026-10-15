package engine

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestPreload checks that Preload loads the accounts with saved state
// that a route covers, and only those.
func TestPreload(t *testing.T) {
	dir := t.TempDir()
	// A folder named by the hash of a login that is not safe as a name.
	const hashed = "0123456789abcdef0123456789abcdef"
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	for _, name := range []string{"alice@example.org", "gone@example.net", hashed} {
		if err := os.MkdirAll(filepath.Join(dir, "accounts", name), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	b := &Engine{Store: st, Log: testLog, Route: func(login string) (Upstream, bool) {
		return Upstream{Addr: "imap.example.org:993"}, login == "alice@example.org" || login == hashed
	}}
	b.Preload()
	deadline := time.Now().Add(5 * time.Second)
	for {
		b.syncMu.Lock()
		a := b.accounts["alice@example.org"]
		_, gone := b.accounts["gone@example.net"]
		_, hash := b.accounts[hashed]
		b.syncMu.Unlock()
		if gone {
			t.Fatal("Preload loaded an account no route covers")
		}
		if hash {
			t.Fatal("Preload loaded a hashed folder as a login")
		}
		if a != nil && a.isLoaded() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("Preload did not load the account")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestAccountOnce checks that concurrent first lookups of an account get
// the same one, loaded.
func TestAccountOnce(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	b := &Engine{Store: st, Log: testLog}
	var wg sync.WaitGroup
	got := make([]*Account, 8)
	for i := range got {
		wg.Go(func() { got[i] = b.account("bob@example.org") })
	}
	wg.Wait()
	for _, a := range got {
		if a != got[0] || !a.isLoaded() {
			t.Fatal("concurrent lookups got different or unloaded accounts")
		}
	}
}
