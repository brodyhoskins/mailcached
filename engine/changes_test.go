package engine

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/brodyhoskins/mailcached/config"
	"github.com/brodyhoskins/mailcached/internal/enginetest"
)

func changesOf(t *testing.T, a *Account, kind, since string) *Changes {
	t.Helper()
	a.Lock()
	defer a.Unlock()
	c, err := a.Changes(kind, since, 0)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func stateOf(a *Account) string {
	a.Lock()
	defer a.Unlock()
	return a.State()
}

func appendTo(t *testing.T, addr, box string, data []byte) {
	t.Helper()
	c, err := imapclient.DialInsecure(addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Login(enginetest.User, enginetest.Password).Wait(); err != nil {
		t.Fatal(err)
	}
	cmd := c.Append(box, int64(len(data)), &imap.AppendOptions{Time: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)})
	cmd.Write(data)
	cmd.Close()
	if _, err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestChangeLog(t *testing.T) {
	addr, _ := enginetest.IMAP(t, testLog, nil)
	dir := t.TempDir()
	open := func() (*Engine, *Account) {
		st, err := OpenStore(dir)
		if err != nil {
			t.Fatal(err)
		}
		b := &Engine{Store: st, Timeout: 5 * time.Second, Cache: &Cache{MaxBytes: 1 << 20}, Log: testLog,
			Route: func(string) (Upstream, bool) {
				return Upstream{Addr: addr, TLS: config.TLSNone, Timeout: 5 * time.Second}, true
			}}
		t.Cleanup(func() { b.Close(); st.Close() })
		a := b.Account(enginetest.User)
		if err := a.Login(enginetest.Password); err != nil {
			t.Fatal(err)
		}
		return b, a
	}
	_, a := open()
	if err := a.SyncNow("INBOX"); err != nil {
		t.Fatal(err)
	}
	start := stateOf(a)

	appendTo(t, addr, "INBOX", []byte("Message-ID: <log-1@test>\r\nSubject: One\r\n\r\nHello.\r\n"))
	if err := a.SyncNow("INBOX"); err != nil {
		t.Fatal(err)
	}
	c := changesOf(t, a, KindEmail, start)
	if len(c.Created) != 1 || len(c.Updated)+len(c.Destroyed) != 0 {
		t.Fatalf("after new mail: %+v", c)
	}
	email := c.Created[0]
	m := changesOf(t, a, KindMailbox, start)
	a.Lock()
	inbox := a.Mailbox("INBOX")
	msgs := slices.Clone(inbox.Msgs())
	a.Unlock()
	if len(m.Updated) != 1 || m.Updated[0] != inbox.ID() || !m.CountsOnly {
		t.Fatalf("mailbox changes after new mail: %+v", m)
	}

	// A flag change updates the email, and INBOX's counts (unread).
	s1 := stateOf(a)
	a.SetFlags(msgs, "INBOX", imap.StoreFlagsAdd, []imap.Flag{imap.FlagSeen}, nil)
	if c := changesOf(t, a, KindEmail, s1); !slices.Equal(c.Updated, []string{email}) {
		t.Fatalf("after \\Seen: %+v", c)
	}
	if m := changesOf(t, a, KindMailbox, s1); len(m.Updated) != 1 || !m.CountsOnly {
		t.Fatalf("mailbox changes after \\Seen: %+v", m)
	}

	// A new folder is created; a copy there is the same email, updated.
	s2 := stateOf(a)
	if err := a.CreateFolder("Archive", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Copy(msgs, "INBOX", "Archive"); err != nil {
		t.Fatal(err)
	}
	a.Lock()
	archive := a.Mailbox("Archive").ID()
	a.Unlock()
	if m := changesOf(t, a, KindMailbox, s2); !slices.Equal(m.Created, []string{archive}) {
		t.Fatalf("mailbox changes after create: %+v", m)
	}
	if c := changesOf(t, a, KindEmail, s2); !slices.Equal(c.Updated, []string{email}) || len(c.Created) != 0 {
		t.Fatalf("after copy: %+v", c)
	}

	// Gone from both folders: destroyed. From the first state, it was
	// never seen.
	s3 := stateOf(a)
	all := func(*Message) bool { return true }
	a.Expunge(inbox, all)
	a.Lock()
	arch := a.MailboxByID(archive)
	a.Unlock()
	a.Expunge(arch, all)
	if c := changesOf(t, a, KindEmail, s3); !slices.Equal(c.Destroyed, []string{email}) {
		t.Fatalf("after expunge: %+v", c)
	}
	if c := changesOf(t, a, KindEmail, start); len(c.Created)+len(c.Updated)+len(c.Destroyed) != 0 {
		t.Fatalf("created and destroyed since start: %+v", c)
	}

	// Paged: the oldest change first.
	a.Lock()
	p, err := a.Changes(KindMailbox, start, 1)
	a.Unlock()
	if err != nil || !p.HasMore || len(p.Updated)+len(p.Created) != 1 || p.Updated[0] != inbox.ID() {
		t.Fatalf("paged: %+v, %v", p, err)
	}

	a.Lock()
	_, err = a.Changes(KindEmail, "nope-1", 0)
	a.Unlock()
	if !errors.Is(err, ErrCannotCalculateChanges) {
		t.Fatalf("foreign state: %v", err)
	}

	// The log is saved: a restart answers from the same states.
	end := stateOf(a)
	_, a2 := open()
	if got := stateOf(a2); got != end {
		t.Fatalf("state after restart %s, was %s", got, end)
	}
	if c := changesOf(t, a2, KindEmail, s3); !slices.Equal(c.Destroyed, []string{email}) {
		t.Fatalf("after restart: %+v", c)
	}
}

// TestChangedWakes checks that Changed's channel closes on a change.
func TestChangedWakes(t *testing.T) {
	_, a := newTestEngine(t)
	a.Lock()
	ch := a.Changed()
	a.Unlock()
	go func() {
		_ = a.CreateFolder("Later", nil)
	}()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("no wake after a change")
	}
}
