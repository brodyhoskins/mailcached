package imapproxy

import (
	"errors"
	"slices"
	"sync"
	"testing"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/engine"
)

// hookOps sets opHook for the test. It records each group's kinds, and
// holds every group back while blocked returns true.
func hookOps(t *testing.T, blocked func() bool) func() [][]string {
	var mu sync.Mutex
	var seen [][]string
	h := func(kinds []string) error {
		if blocked != nil && blocked() {
			return errors.New("held by the test")
		}
		mu.Lock()
		seen = append(seen, kinds)
		mu.Unlock()
		return nil
	}
	engine.SetOpHook(h)
	t.Cleanup(func() { engine.SetOpHook(nil) })
	return func() [][]string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

// numMessages asks the provider directly.
func numMessages(t *testing.T, e *env, mailbox string) uint32 {
	t.Helper()
	c := login(t, e.provider, nil)
	defer c.Logout()
	st, err := c.Status(mailbox, &imap.StatusOptions{NumMessages: true}).Wait()
	if err != nil {
		t.Fatal(err)
	}
	return *st.NumMessages
}

// Apple Mail's move (COPY, STORE \Deleted, UID EXPUNGE) reaches the
// provider as one MOVE, and the copies keep the UIDs the client was given.
func TestQueueMailMoveIsOneMove(t *testing.T) {
	seen := hookOps(t, nil)
	e := newEnv(t)
	up := login(t, e.provider, nil)
	for _, s := range []string{"One", "Two", "Three"} {
		appendMsg(t, up, "INBOX", plain(bob, s, s))
	}
	if err := up.Create("Archive", nil).Wait(); err != nil {
		t.Fatal(err)
	}

	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	set := imap.UIDSetNum(1, 2)
	data, err := c.Copy(set, "Archive").Wait()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Store(set, &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Collect(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.UIDExpunge(set).Collect(); err != nil {
		t.Fatal(err)
	}

	eventually(t, "the move to reach the provider", func() bool {
		return numMessages(t, e, "Archive") == 2 && numMessages(t, e, "INBOX") == 1
	})
	if got := seen(); len(got) != 1 || !slices.Equal(got[0], []string{"copy", "flags", "expunge"}) {
		t.Fatalf("ops ran as %v, want one group of copy, flags and expunge", got)
	}
	a := e.eng.Account(alice)
	eventually(t, "the copies to be bound", func() bool {
		q := a.Queued()
		a.Lock()
		defer a.Unlock()
		for _, m := range a.Mailbox("Archive").Msgs() {
			if box, uid := m.AtProvider(); uid == 0 || box != "Archive" {
				return false
			}
		}
		return q == 0
	})
	sel, err := c.Select("Archive", nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	if sel.UIDValidity != data.UIDValidity {
		t.Fatalf("UIDVALIDITY %d, COPYUID said %d", sel.UIDValidity, data.UIDValidity)
	}
	got, err := c.UIDSearch(&imap.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := data.DestUIDs.Nums(); !slices.Equal(got.AllUIDs(), want) {
		t.Fatalf("Archive has UIDs %v, COPYUID said %v", got.AllUIDs(), want)
	}
}

// A move the proxy accepted but could not make before a restart is made
// after it, and the client's UIDs stay valid.
func TestQueueSurvivesRestart(t *testing.T) {
	var mu sync.Mutex
	held := true
	hookOps(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return held
	})
	e := newEnv(t)
	up := login(t, e.provider, nil)
	appendMsg(t, up, "INBOX", plain(bob, "One", "1"))
	appendMsg(t, up, "INBOX", plain(bob, "Two", "2"))
	if err := up.Create("Archive", nil).Wait(); err != nil {
		t.Fatal(err)
	}

	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	data, err := c.Move(imap.UIDSetNum(1), "Archive").Wait()
	if err != nil {
		t.Fatal(err)
	}
	if n := numMessages(t, e, "INBOX"); n != 2 {
		t.Fatalf("the provider's INBOX has %d messages before the queue ran", n)
	}
	c.Close()
	e.b.Close()
	e.eng.Close()

	// Started again with the same database.
	eng2 := &engine.Engine{Store: e.eng.Store, Route: e.eng.Route, Timeout: e.eng.Timeout, Transform: e.eng.Transform,
		Cache: e.eng.Cache, Log: e.eng.Log}
	b2 := &Server{Engine: eng2, MaxMessageBytes: e.b.MaxMessageBytes, Log: e.b.Log}
	l := listen(t)
	go b2.Serve(l)
	t.Cleanup(func() { b2.Close(); eng2.Close() })
	mu.Lock()
	held = false
	mu.Unlock()

	c2 := login(t, l.Addr().String(), nil)
	eventually(t, "the move to reach the provider", func() bool {
		return numMessages(t, e, "Archive") == 1 && numMessages(t, e, "INBOX") == 1
	})
	sel, err := c2.Select("Archive", nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	if sel.UIDValidity != data.UIDValidity {
		t.Fatalf("UIDVALIDITY %d after the restart, MOVE said %d", sel.UIDValidity, data.UIDValidity)
	}
	got, err := c2.UIDSearch(&imap.SearchCriteria{}, nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	if want, _ := data.DestUIDs.(imap.UIDSet).Nums(); !slices.Equal(got.AllUIDs(), want) {
		t.Fatalf("Archive has UIDs %v, MOVE said %v", got.AllUIDs(), want)
	}
}

// A move the provider refuses is undone: the message shows up again where
// it is, with a new UID.
func TestQueueRefusedMoveUndone(t *testing.T) {
	var mu sync.Mutex
	held := true
	hookOps(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return held
	})
	e := newEnv(t)
	up := login(t, e.provider, nil)
	appendMsg(t, up, "INBOX", plain(bob, "One", "1"))
	if err := up.Create("Archive", nil).Wait(); err != nil {
		t.Fatal(err)
	}

	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Move(imap.UIDSetNum(1), "Archive").Wait(); err != nil {
		t.Fatal(err)
	}
	// Gone at the provider before the queue gets to it.
	if err := up.Delete("Archive").Wait(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	held = false
	mu.Unlock()

	a := e.eng.Account(alice)
	eventually(t, "the move to be undone", func() bool {
		q := a.Queued()
		a.Lock()
		defer a.Unlock()
		in := a.Mailbox("INBOX").Msgs()
		return q == 0 && len(in) == 1 && in[0].UID() == 2
	})
	if err := c.Noop().Wait(); err != nil {
		t.Fatal(err)
	}
	if n := c.Mailbox().NumMessages; n != 1 {
		t.Fatalf("the client sees %d messages in INBOX", n)
	}
}

// Flag changes in a row go to the provider as one STORE.
func TestQueueMergesFlagChanges(t *testing.T) {
	var mu sync.Mutex
	held := true
	seen := hookOps(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return held
	})
	e := newEnv(t)
	up := login(t, e.provider, nil)
	for _, s := range []string{"One", "Two", "Three"} {
		appendMsg(t, up, "INBOX", plain(bob, s, s))
	}

	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	for uid := imap.UID(1); uid <= 3; uid++ {
		if _, err := c.Store(imap.UIDSetNum(uid), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Flags: []imap.Flag{imap.FlagSeen}}, nil).Collect(); err != nil {
			t.Fatal(err)
		}
	}
	mu.Lock()
	held = false
	mu.Unlock()

	eventually(t, "the flags to reach the provider", func() bool {
		st, err := up.Status("INBOX", &imap.StatusOptions{NumUnseen: true}).Wait()
		return err == nil && *st.NumUnseen == 0
	})
	if got := seen(); len(got) != 1 || len(got[0]) != 3 {
		t.Fatalf("ops ran as %v, want one group of three", got)
	}
}

// The provider is the truth: a message another client moved elsewhere at
// the provider before the queue moved it ends up where that client put it.
func TestQueueOutsideMoveWins(t *testing.T) {
	var mu sync.Mutex
	held := true
	hookOps(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return held
	})
	e := newEnv(t)
	up := login(t, e.provider, nil)
	appendMsg(t, up, "INBOX", plain(bob, "One", "1"))
	for _, name := range []string{"Archive", "Elsewhere"} {
		if err := up.Create(name, nil).Wait(); err != nil {
			t.Fatal(err)
		}
	}

	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Move(imap.UIDSetNum(1), "Archive").Wait(); err != nil {
		t.Fatal(err)
	}
	// Another client, straight at the provider, first.
	if _, err := up.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := up.Move(imap.UIDSetNum(1), "Elsewhere").Wait(); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	held = false
	mu.Unlock()

	a := e.eng.Account(alice)
	eventually(t, "the proxy to follow the provider", func() bool {
		_ = a.SyncNow("Elsewhere")
		q := a.Queued()
		a.Lock()
		defer a.Unlock()
		return q == 0 && len(a.Mailbox("Archive").Msgs()) == 0 && len(a.Mailbox("Elsewhere").Msgs()) == 1
	})
	if n := numMessages(t, e, "Elsewhere"); n != 1 {
		t.Fatalf("the provider has %d messages in Elsewhere", n)
	}
	if n := numMessages(t, e, "Archive"); n != 0 {
		t.Fatalf("the provider has %d messages in Archive", n)
	}
}
