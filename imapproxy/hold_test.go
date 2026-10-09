package imapproxy

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/brodyhoskins/mailcached/engine"
)

// holder is the sealer, but while locked it holds what it would open, and
// while shaky it opens only for now (ReadRetry).
type holder struct {
	sealer
	locked, shaky atomic.Bool
}

func (h *holder) Read(ctx context.Context, raw []byte) ([]byte, engine.ReadStatus) {
	if isSealed(raw) && h.locked.Load() {
		return raw, engine.ReadHold
	}
	out, st := h.sealer.Read(ctx, raw)
	if isSealed(raw) && h.shaky.Load() {
		return append([]byte("X-Shaky: yes\r\n"), out...), engine.ReadRetry
	}
	return out, st
}

func appendAt(t *testing.T, c *imapclient.Client, box string, data []byte, at time.Time) {
	t.Helper()
	cmd := c.Append(box, int64(len(data)), &imap.AppendOptions{Time: at})
	cmd.Write(data)
	cmd.Close()
	if _, err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

func numIn(t *testing.T, c *imapclient.Client, box string) uint32 {
	t.Helper()
	s, err := c.Status(box, &imap.StatusOptions{NumMessages: true}).Wait()
	if err != nil {
		t.Fatal(err)
	}
	return *s.NumMessages
}

// TestHold checks that new mail the Transform holds reaches no client
// until a later Read lets it, and then arrives as new mail.
func TestHold(t *testing.T) {
	h := &holder{}
	h.locked.Store(true)
	dir := t.TempDir()
	st, err := engine.OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	e := newEnvConf(t, nil, func(eng *engine.Engine, _ *Server) { eng.Transform, eng.Store = h, st })
	up := login(t, e.provider, nil)
	// From before the account's first sync: served even while locked.
	appendAt(t, up, "INBOX", sealed("Old", "From last year."), time.Now().Add(-time.Hour))

	c := login(t, e.proxy, nil)
	a := e.eng.Account(alice)
	waitSyncing(t, e.b, alice)
	if since := a.Since(); since.IsZero() {
		t.Fatal("no cutoff after the first sync")
	}
	if _, err := os.Stat(filepath.Join(dir, "accounts", alice, "since")); err != nil {
		t.Fatalf("the cutoff is not saved: %v", err)
	}
	if n := numIn(t, c, "INBOX"); n != 1 {
		t.Fatalf("INBOX has %d messages before new mail", n)
	}

	// New mail: the sealed one is held, the plain one is not.
	later := time.Now().Add(time.Minute)
	appendAt(t, up, "INBOX", sealed("Secret", "The number is 42."), later)
	appendAt(t, up, "INBOX", plain(bob, "Plain", "Hello."), later)
	eventually(t, "the sync to hold one", func() bool { return a.Held() == 1 && numIn(t, c, "INBOX") == 2 })
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if n := c.Mailbox().NumMessages; n != 2 {
		t.Fatalf("SELECT shows %d messages, want 2 (the held one hidden)", n)
	}

	// The key arrives: a recheck shows it as new mail, opened.
	h.locked.Store(false)
	e.eng.Recheck()
	eventually(t, "the held message", func() bool {
		if err := c.Noop().Wait(); err != nil {
			return false
		}
		return a.Held() == 0 && c.Mailbox().NumMessages == 3
	})
	full := &imap.FetchItemBodySection{Peek: true}
	msgs, err := c.Fetch(imap.SeqSetNum(3), &imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{full}}).Collect()
	if err != nil || len(msgs) != 1 || !bytes.Contains(msgs[0].FindBodySection(full), []byte("The number is 42.")) {
		t.Fatalf("the released message: %v %+v", err, msgs)
	}
}

// TestRecheckDropsRetry checks that Recheck makes a ReadRetry result go
// through Read again.
func TestRecheckDropsRetry(t *testing.T) {
	h := &holder{}
	h.shaky.Store(true)
	e := newEnvConf(t, nil, func(eng *engine.Engine, _ *Server) { eng.Transform = h })
	up := login(t, e.provider, nil)
	appendAt(t, up, "INBOX", sealed("Shaky", "Maybe."), time.Now().Add(-time.Hour))
	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	full := &imap.FetchItemBodySection{Peek: true}
	body := func() []byte {
		msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{full}}).Collect()
		if err != nil || len(msgs) != 1 {
			t.Fatalf("fetch: %v", err)
		}
		return msgs[0].FindBodySection(full)
	}
	if !bytes.Contains(body(), []byte("X-Shaky: yes")) {
		t.Fatal("not the retry result")
	}
	h.shaky.Store(false)
	if !bytes.Contains(body(), []byte("X-Shaky: yes")) {
		t.Fatal("a retry result was read again without a recheck")
	}
	e.eng.Recheck()
	if b := body(); bytes.Contains(b, []byte("X-Shaky: yes")) || !bytes.Contains(b, []byte("Maybe.")) {
		t.Fatalf("after Recheck:\n%s", b)
	}
}
