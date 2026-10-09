package easproxy

import (
	"bytes"
	"context"
	"slices"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/internal/enginetest"
)

// The engine's ActiveSync provider, tested against this package's server:
// a second engine reaches the first's account over ActiveSync.

// easEngine makes an engine whose provider is the env's ActiveSync server.
func (e *env) easEngine(t *testing.T) *engine.Engine {
	t.Helper()
	st, err := engine.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	eng := &engine.Engine{
		Store: st, Timeout: 5 * time.Second, Log: testLog,
		Cache: &engine.Cache{Dir: t.TempDir(), MaxBytes: 1 << 20},
		Route: func(login string) (engine.Upstream, bool) {
			return engine.Upstream{ActiveSync: e.http.URL + "/Microsoft-Server-ActiveSync", Timeout: 5 * time.Second},
				login == enginetest.User
		},
	}
	t.Cleanup(eng.Close)
	return eng
}

// msgs returns a folder's messages in the engine, by subject.
func msgs(t *testing.T, a *engine.Account, name string) map[string]*engine.Message {
	t.Helper()
	m, err := a.MailboxFor(name)
	if err != nil {
		t.Fatal(err)
	}
	a.Lock()
	list := slices.Clone(m.Msgs())
	a.Unlock()
	data, err := a.Download(list, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]*engine.Message{}
	for msg, raw := range data {
		i := bytes.Index(raw, []byte("Subject: "))
		if i < 0 {
			continue
		}
		subj := raw[i+9:]
		subj = subj[:bytes.IndexByte(subj, '\r')]
		out[string(subj)] = msg
	}
	return out
}

func TestProvider(t *testing.T) {
	e := newEnv(t)
	up := e.upstream(t)
	for _, name := range []string{"Archive", "Sent"} {
		if err := up.Create(name, nil).Wait(); err != nil {
			t.Fatal(err)
		}
	}
	appendMsg(t, up, "INBOX", plain("one@x", "One", "first body"))
	appendMsg(t, up, "INBOX", plain("two@x", "Two", "second body"))

	eng := e.easEngine(t)
	a := eng.Account(enginetest.User)
	if err := a.Login("wrong"); err == nil {
		t.Fatal("a wrong password was accepted")
	}
	if err := a.Login(enginetest.Password); err != nil {
		t.Fatal(err)
	}
	a.Lock()
	var names []string
	for _, m := range a.Mailboxes() {
		names = append(names, m.Name())
	}
	a.Unlock()
	slices.Sort(names)
	if !slices.Equal(names, []string{"Archive", "INBOX", "Sent"}) {
		t.Fatalf("folders %v", names)
	}

	got := msgs(t, a, "INBOX")
	if len(got) != 2 || got["One"] == nil {
		t.Fatalf("INBOX: %v", got)
	}
	data, _ := a.Download([]*engine.Message{got["One"]}, nil)
	if !bytes.Contains(data[got["One"]], []byte("first body")) {
		t.Fatalf("message %q", data[got["One"]])
	}

	// A flag set through the provider reaches the IMAP side.
	a.SetFlags([]*engine.Message{got["One"]}, "INBOX", imap.StoreFlagsAdd, []imap.Flag{imap.FlagSeen, imap.FlagAnswered}, nil)
	eventually(t, `\Seen at the IMAP side`, func() bool {
		if _, err := up.Select("INBOX", nil).Wait(); err != nil {
			t.Fatal(err)
		}
		ms, err := up.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{Flags: true}).Collect()
		return err == nil && len(ms) == 1 && slices.Contains(ms[0].Flags, imap.FlagSeen)
	})

	// New mail is pushed: Ping wakes the engine.
	appendMsg(t, up, "INBOX", plain("three@x", "Three", "third body"))
	eventually(t, "the new message", func() bool {
		a.Lock()
		defer a.Unlock()
		return len(a.Mailbox("INBOX").Msgs()) == 3
	})
	a.Lock()
	for _, msg := range a.Mailbox("INBOX").Msgs() {
		if msg.UID() == got["One"].UID() && !slices.Contains(msg.Flags(), imap.FlagAnswered) {
			t.Errorf("\\Answered, kept by the provider, is lost: %v", msg.Flags())
		}
	}
	a.Unlock()

	// A move goes through MoveItems.
	m, _ := a.MailboxFor("INBOX")
	two := got["Two"].UID()
	if _, _, err := a.Move(m, func(msg *engine.Message) bool { return msg.UID() == two }, "Archive"); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the move at the IMAP side", func() bool {
		sd, err := up.Status("Archive", &imap.StatusOptions{NumMessages: true}).Wait()
		return err == nil && *sd.NumMessages == 1
	})

	// An expunge deletes.
	a.Expunge(m, func(msg *engine.Message) bool { return msg.UID() == got["One"].UID() })
	eventually(t, "the expunge at the IMAP side", func() bool {
		sd, err := up.Status("INBOX", &imap.StatusOptions{NumMessages: true}).Wait()
		return err == nil && *sd.NumMessages == 1
	})

	// Sending goes through SendMail, which keeps a Sent copy.
	msg := []byte("From: " + enginetest.User + "\r\nTo: " + enginetest.Bob + "\r\nSubject: Out\r\n\r\nhello\r\n")
	if err := a.Send(context.Background(), enginetest.User, []string{enginetest.Bob, "hidden@example.net"}, msg); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	sent := e.sent
	e.mu.Unlock()
	if len(sent) != 1 || !slices.Contains(sent[0].To, "hidden@example.net") || bytes.Contains(sent[0].Data, []byte("Bcc:")) {
		t.Fatalf("sent %+v", sent)
	}
	eventually(t, "the Sent copy", func() bool {
		sd, err := up.Status("Sent", &imap.StatusOptions{NumMessages: true}).Wait()
		return err == nil && *sd.NumMessages == 1
	})
	// A client's own Sent copy is the server's: kept nowhere else.
	if _, err := a.Append("Sent", msg, nil); err != nil {
		t.Fatalf("append to Sent: %v", err)
	}
	if _, err := a.Append("Archive", msg, nil); err == nil {
		t.Fatal("an append to another folder was accepted")
	}

	// Folders.
	if err := a.CreateFolder("Archive/2026", nil); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the new folder at the IMAP side", func() bool {
		_, err := up.Status("Archive/2026", &imap.StatusOptions{NumMessages: true}).Wait()
		return err == nil
	})
	if err := a.RenameFolder("Archive/2026", "Old", nil); err != nil {
		t.Fatal(err)
	}
	if err := a.DeleteFolder("Old"); err != nil {
		t.Fatal(err)
	}
	a.Lock()
	gone := a.Mailbox("Old") == nil && a.Mailbox("Archive/2026") == nil
	a.Unlock()
	if !gone {
		t.Fatal("the folder is still there")
	}
}

// TestProviderRestart checks that the provider's model survives a
// restart: the same UIDs, and no message fetched again.
func TestProviderRestart(t *testing.T) {
	e := newEnv(t)
	up := e.upstream(t)
	appendMsg(t, up, "INBOX", plain("one@x", "One", "first body"))
	st, err := engine.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	newEng := func() *engine.Engine {
		return &engine.Engine{
			Store: st, Timeout: 5 * time.Second, Log: testLog,
			Cache: &engine.Cache{Dir: t.TempDir(), MaxBytes: 1 << 20},
			Route: func(string) (engine.Upstream, bool) {
				return engine.Upstream{ActiveSync: e.http.URL + "/Microsoft-Server-ActiveSync", Timeout: 5 * time.Second}, true
			},
		}
	}
	eng := newEng()
	a := eng.Account(enginetest.User)
	if err := a.Login(enginetest.Password); err != nil {
		t.Fatal(err)
	}
	before := msgs(t, a, "INBOX")["One"].UID()
	eng.Close()

	appendMsg(t, up, "INBOX", plain("two@x", "Two", "second body"))
	eng = newEng()
	defer eng.Close()
	a = eng.Account(enginetest.User)
	if err := a.Login(enginetest.Password); err != nil {
		t.Fatal(err)
	}
	got := msgs(t, a, "INBOX")
	if len(got) != 2 || got["One"].UID() != before {
		t.Fatalf("after a restart: %v (One had UID %d)", got, before)
	}
}

// TestProviderPush checks that new mail arrives by Ping, with polling
// off.
func TestProviderPush(t *testing.T) {
	e := newEnv(t)
	up := e.upstream(t)
	appendMsg(t, up, "INBOX", plain("one@x", "One", "first body"))
	eng := e.easEngine(t)
	a := eng.Account(enginetest.User)
	if err := a.Login(enginetest.Password); err != nil {
		t.Fatal(err)
	}
	msgs(t, a, "INBOX")
	// Let the first sweep finish and the Ping start.
	time.Sleep(300 * time.Millisecond)
	poll, notified := engine.SyncPoll, engine.SyncPollNotified
	engine.SyncPoll, engine.SyncPollNotified = time.Hour, time.Hour
	t.Cleanup(func() { engine.SyncPoll, engine.SyncPollNotified = poll, notified })
	time.Sleep(300 * time.Millisecond)

	appendMsg(t, up, "INBOX", plain("two@x", "Two", "second body"))
	eventually(t, "the pushed message", func() bool {
		a.Lock()
		defer a.Unlock()
		return len(a.Mailbox("INBOX").Msgs()) == 2
	})
}
