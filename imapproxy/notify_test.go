package imapproxy

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/config"
	"github.com/brodyhoskins/mailcached/engine"
)

// expect reads lines the proxy sends unasked until one matches re.
func (rc *rawClient) expect(re string) string {
	rc.t.Helper()
	r := regexp.MustCompile(re)
	_ = rc.c.SetReadDeadline(time.Now().Add(3 * time.Second))
	defer rc.c.SetReadDeadline(time.Now().Add(10 * time.Second))
	var seen []string
	for {
		line, err := rc.r.ReadString('\n')
		if err != nil {
			rc.t.Fatalf("no line matching %s; got %q: %v", re, seen, err)
		}
		line = strings.TrimRight(line, "\r\n")
		if r.MatchString(line) {
			return line
		}
		seen = append(seen, line)
	}
}

// quiet checks that the proxy sends nothing for a while.
func (rc *rawClient) quiet(d time.Duration) {
	rc.t.Helper()
	_ = rc.c.SetReadDeadline(time.Now().Add(d))
	defer rc.c.SetReadDeadline(time.Now().Add(10 * time.Second))
	if line, err := rc.r.ReadString('\n'); err == nil {
		rc.t.Fatalf("unexpected %q", line)
	}
}

func TestNotify(t *testing.T) {
	e := newEnv(t)
	up := login(t, e.provider, nil)
	appendMsg(t, up, "INBOX", plain(bob, "One", "1"))
	if err := up.Create("Archive", nil).Wait(); err != nil {
		t.Fatal(err)
	}

	rc := dialRaw(t, e.proxy)
	rc.ok(`LOGIN "` + alice + `" "` + password + `"`)
	if caps := rc.ok("CAPABILITY"); !strings.Contains(caps[0], " NOTIFY") {
		t.Fatalf("capabilities %q", caps)
	}
	other := login(t, e.proxy, nil)
	waitSyncing(t, e.b, alice)
	eventually(t, "INBOX synced", func() bool { return numIn(t, other, "INBOX") == 1 })

	// The STATUS indicator: one STATUS a watched folder.
	got := rc.ok("NOTIFY SET STATUS (selected (MessageNew (UID FLAGS) MessageExpunge)) " +
		"(personal (MessageNew MessageExpunge FlagChange MailboxName SubscriptionChange))")
	if len(got) != 2 || !strings.Contains(strings.Join(got, "\n"), `* STATUS "INBOX" (MESSAGES 1 UIDNEXT 2 UIDVALIDITY`) {
		t.Fatalf("NOTIFY SET STATUS: %q", got)
	}
	rc.ok("SELECT INBOX")

	// Another folder: a STATUS, with no command running.
	appendMsg(t, other, "Archive", plain(bob, "Two", "2"))
	rc.expect(`^\* STATUS "Archive" \(MESSAGES 1 UIDNEXT 2 UIDVALIDITY \d+ UNSEEN 1\)$`)

	// The selected folder: EXISTS and the FETCH asked for.
	appendMsg(t, other, "INBOX", plain(bob, "Three", "3"))
	rc.expect(`^\* 2 EXISTS$`)
	rc.expect(`^\* 2 FETCH \(.*UID 2`)

	// Flags elsewhere: UNSEEN.
	if _, err := other.Select("Archive", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if err := other.Store(imap.SeqSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagSeen}}, nil).Close(); err != nil {
		t.Fatal(err)
	}
	rc.expect(`^\* STATUS "Archive" \(UNSEEN 0\)$`)

	// The folder list.
	if err := other.Create("Projects", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	rc.expect(`^\* LIST \(.*\) "/" "Projects"$`)
	if err := other.Rename("Projects", "Plans", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	rc.expect(`^\* LIST \(.*\) "/" "Plans" \("OLDNAME" \("Projects"\)\)$`)
	if err := other.Subscribe("Plans").Wait(); err != nil {
		t.Fatal(err)
	}
	rc.expect(`^\* LIST \(.*\\Subscribed\) "/" "Plans"$`)
	if err := other.Delete("Plans").Wait(); err != nil {
		t.Fatal(err)
	}
	rc.expect(`^\* LIST \(\\NonExistent\) "/" "Plans"$`)

	// The proxy's own NOOPs leave no trace, and commands still work.
	if got := rc.ok("NOOP"); len(got) != 0 {
		t.Fatalf("NOOP: %q", got)
	}

	rc.ok("NOTIFY NONE")
	appendMsg(t, other, "Archive", plain(bob, "Four", "4"))
	rc.quiet(300 * time.Millisecond)
}

func TestNotifyErrors(t *testing.T) {
	e := newEnv(t)
	rc := dialRaw(t, e.proxy)
	if _, st := rc.do("NOTIFY NONE"); !strings.HasPrefix(st, "BAD") {
		t.Fatalf("before login: %s", st)
	}
	rc.ok(`LOGIN "` + alice + `" "` + password + `"`)
	for cmd, want := range map[string]string{
		"NOTIFY SET (personal (MessageNew))":                             "BAD",
		"NOTIFY SET (personal (FlagChange))":                             "BAD",
		"NOTIFY SET (selected (MailboxName))":                            "BAD",
		"NOTIFY SET (personal (MessageNew (UID) MessageExpunge))":        "BAD",
		"NOTIFY SET (selected NONE) (selected-delayed NONE)":             "BAD",
		"NOTIFY SET (personal (AnnotationChange))":                       "NO [BADEVENT (MessageNew MessageExpunge FlagChange MailboxName SubscriptionChange)]",
		"NOTIFY SET (subtree (Lists {4}\r\nWork) (MailboxName))":         "OK",
		"NOTIFY SET (mailboxes \"Archive\" (MessageNew MessageExpunge))": "OK",
	} {
		if _, st := rc.do(cmd); !strings.HasPrefix(st, want) {
			t.Errorf("%q: %s, want %s", cmd, st, want)
		}
	}
}

func TestUTF7(t *testing.T) {
	for dec, enc := range map[string]string{
		"INBOX": "INBOX", "Entwürfe": "Entw&APw-rfe", "A&B": "A&-B", "日本語": "&ZeVnLIqe-",
	} {
		if got := encodeUTF7(dec); got != enc {
			t.Errorf("encode %q: %q, want %q", dec, got, enc)
		}
		if got, err := decodeUTF7(enc); err != nil || got != dec {
			t.Errorf("decode %q: %q %v", enc, got, err)
		}
	}
}

// TestNotifyUpstream runs an engine against this proxy as its provider,
// which offers NOTIFY: a change in a folder other than INBOX reaches the
// second engine at once, not at its next check of every folder.
//
//	IMAP provider <- engine A <- this proxy <- engine B
func TestNotifyUpstream(t *testing.T) {
	poll := engine.SyncPoll
	engine.SyncPoll = time.Hour
	t.Cleanup(func() { engine.SyncPoll = poll })
	e := newEnv(t)
	up := login(t, e.provider, nil)
	if err := up.Create("Archive", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	other := login(t, e.proxy, nil)
	waitSyncing(t, e.b, alice)

	b := &engine.Engine{Timeout: 5 * time.Second, Log: e.b.Log, Cache: &engine.Cache{MaxBytes: 1 << 20},
		Route: func(login string) (engine.Upstream, bool) {
			return engine.Upstream{Addr: e.proxy, TLS: config.TLSNone, Timeout: 5 * time.Second}, login == alice
		}}
	t.Cleanup(b.Close)
	a := b.Account(alice)
	if err := a.Login(password); err != nil {
		t.Fatal(err)
	}
	eventually(t, "engine B", func() bool { return a.Running() && a.Sweeps() > 0 })
	count := func(name string) int {
		a.Lock()
		defer a.Unlock()
		if m := a.Mailbox(name); m != nil {
			return len(m.Msgs())
		}
		return -1
	}

	appendMsg(t, other, "Archive", plain(bob, "Elsewhere", "Not in INBOX."))
	eventually(t, "the message at engine B", func() bool { return count("Archive") == 1 })
	if err := other.Create("Projects", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the new folder at engine B", func() bool { return count("Projects") == 0 })

	// A flag elsewhere: NOTIFY's HIGHESTMODSEQ, then CONDSTORE's
	// CHANGEDSINCE, bring it.
	if _, err := other.Select("Archive", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if err := other.Store(imap.SeqSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagFlagged}}, nil).Close(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the flag at engine B", func() bool {
		a.Lock()
		defer a.Unlock()
		m := a.Mailbox("Archive")
		return m != nil && len(m.Msgs()) == 1 && engine.HasFlag(m.Msgs()[0].Flags(), imap.FlagFlagged)
	})
}
