package jmapproxy

import (
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"context"
	"errors"
	"fmt"
	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/imapproxy"
	"github.com/brodyhoskins/mailcached/internal/enginetest"
	"github.com/brodyhoskins/mailcached/internal/sealtest"
	"github.com/brodyhoskins/mailcached/smtpproxy"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// TestLoop runs the engine against a JMAP provider: this package's server
// in front of an IMAP provider. An IMAP client of the second engine reads
// and changes mail that lives at the IMAP provider:
//
//	IMAP provider <- engine A <- JMAP server <- JMAP provider <- engine B <- IMAP server <- client
func TestLoop(t *testing.T) {
	e := newEnv(t)
	up := e.upstream(t)
	if err := up.Create("Archive", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	appendMsg(t, up, "INBOX", plain("loop-1@test", "Plain", "Hello."))
	appendMsg(t, up, "INBOX", sealtest.Seal(plain("loop-2@test", "Sealed", "The number is 42.")))
	// Engine B sees engine A's copy: wait for A to have the mail.
	eventually(t, "the mail at engine A", func() bool { return e.mailboxes(t)["INBOX"].TotalEmails == 2 })

	st, err := engine.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	b := &engine.Engine{Store: st, Timeout: 5 * time.Second, Log: testLog, Cache: &engine.Cache{MaxBytes: 1 << 20},
		Route: func(login string) (engine.Upstream, bool) {
			return engine.Upstream{URL: e.http.URL + "/.well-known/jmap", Timeout: 5 * time.Second}, login == enginetest.User
		}}
	t.Cleanup(b.Close)
	srv := &imapproxy.Server{Engine: b, MaxMessageBytes: 1 << 20, Log: testLog}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })

	c, err := imapclient.DialInsecure(l.Addr().String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.Login(enginetest.User, "wrong").Wait(); err == nil {
		t.Fatal("a wrong password got in")
	}
	if err := c.Login(enginetest.User, enginetest.Password).Wait(); err != nil {
		t.Fatal(err)
	}
	sel, err := c.Select("INBOX", nil).Wait()
	if err != nil {
		t.Fatal(err)
	}
	if sel.NumMessages != 2 {
		t.Fatalf("INBOX has %d messages", sel.NumMessages)
	}
	full := &imap.FetchItemBodySection{Peek: true}
	msgs, err := c.Fetch(imap.SeqSetNum(1, 2), &imap.FetchOptions{UID: true, Envelope: true,
		BodySection: []*imap.FetchItemBodySection{full}}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	bySubject := map[string]*imapclient.FetchMessageBuffer{}
	for _, m := range msgs {
		bySubject[m.Envelope.Subject] = m
	}
	plainMsg, sealedMsg := bySubject["Plain"], bySubject["Sealed"]
	if plainMsg == nil || sealedMsg == nil || !strings.Contains(string(sealedMsg.FindBodySection(full)), "The number is 42.") {
		for _, m := range msgs {
			t.Logf("UID %d subject %q body:\n%s", m.UID, m.Envelope.Subject, m.FindBodySection(full))
		}
		t.Fatal("read through the loop")
	}
	// The provider numbers its messages by arrival; find Plain there.
	plainAt := func() uint32 {
		if _, err := up.Select("INBOX", nil).Wait(); err != nil {
			return 0
		}
		res, err := up.Search(&imap.SearchCriteria{Header: []imap.SearchCriteriaHeaderField{{Key: "Subject", Value: "Plain"}}}, nil).Wait()
		if err != nil || len(res.AllSeqNums()) == 0 {
			return 0
		}
		return res.AllSeqNums()[0]
	}

	// A flag, at the IMAP provider.
	if err := c.Store(imap.UIDSetNum(plainMsg.UID), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true,
		Flags: []imap.Flag{imap.FlagFlagged}}, nil).Close(); err != nil {
		t.Fatal(err)
	}
	upFlags := func(box string, seq uint32) []imap.Flag {
		if _, err := up.Select(box, nil).Wait(); err != nil {
			return nil
		}
		got, err := up.Fetch(imap.SeqSetNum(seq), &imap.FetchOptions{Flags: true}).Collect()
		if err != nil || len(got) == 0 {
			return nil
		}
		return got[0].Flags
	}
	eventually(t, "the flag at the IMAP provider", func() bool {
		n := plainAt()
		return n > 0 && slices.Contains(upFlags("INBOX", n), imap.FlagFlagged)
	})

	// A move, once the folder made at the IMAP provider reached engine B.
	eventually(t, "Archive through the loop", func() bool {
		l, err := c.List("", "*", nil).Collect()
		return err == nil && slices.ContainsFunc(l, func(d *imap.ListData) bool { return d.Mailbox == "Archive" })
	})
	if _, err := c.Move(imap.UIDSetNum(sealedMsg.UID), "Archive").Wait(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the move at the IMAP provider", func() bool {
		s, err := up.Status("Archive", &imap.StatusOptions{NumMessages: true}).Wait()
		return err == nil && *s.NumMessages == 1
	})

	// New mail at the IMAP provider reaches the client.
	appendMsg(t, up, "INBOX", plain("loop-3@test", "New", "Fresh."))
	eventually(t, "new mail through the loop", func() bool {
		if err := c.Noop().Wait(); err != nil {
			return false
		}
		return c.Mailbox().NumMessages == 2
	})

	// An append, stored at the IMAP provider (and sealed by engine A).
	data := plain("loop-4@test", "Appended", "Stored.")
	cmd := c.Append("INBOX", int64(len(data)), nil)
	cmd.Write(data)
	cmd.Close()
	if _, err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the append at the IMAP provider", func() bool {
		s, err := up.Status("INBOX", &imap.StatusOptions{NumMessages: true}).Wait()
		return err == nil && *s.NumMessages == 3
	})

	// An expunge.
	if err := c.Store(imap.SeqSetNum(1), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true,
		Flags: []imap.Flag{imap.FlagDeleted}}, nil).Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Expunge().Close(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the expunge at the IMAP provider", func() bool {
		s, err := up.Status("INBOX", &imap.StatusOptions{NumMessages: true}).Wait()
		return err == nil && *s.NumMessages == 2
	})
}

// sender is daemon's jmapSender, for the test.
type sender struct{ eng *engine.Engine }

func (s sender) Verify(login, password string) error {
	if err := s.eng.Account(login).Login(password); errors.Is(err, engine.ErrLoginRejected) {
		return fmt.Errorf("%w: %w", smtpproxy.ErrLoginRejected, err)
	} else {
		return err
	}
}

func (s sender) Send(ctx context.Context, login, _ string, env *smtpproxy.Envelope) error {
	return s.eng.Account(login).Send(ctx, env.From, env.To, env.Data)
}

// TestSendThroughJMAP sends from an SMTP client to a provider that only
// speaks JMAP: the message is stored, submitted, and its stored copy
// destroyed.
func TestSendThroughJMAP(t *testing.T) {
	e := newEnv(t)
	up := e.upstream(t)
	if err := up.Create("Drafts", &imap.CreateOptions{SpecialUse: []imap.MailboxAttr{imap.MailboxAttrDrafts}}).Wait(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "Drafts at the JMAP server", func() bool { return e.mailboxes(t)["Drafts"].ID != "" })

	b := &engine.Engine{Timeout: 5 * time.Second, Log: testLog, Cache: &engine.Cache{MaxBytes: 1 << 20},
		Route: func(login string) (engine.Upstream, bool) {
			return engine.Upstream{URL: e.http.URL + "/.well-known/jmap", Timeout: 5 * time.Second}, login == enginetest.User
		}}
	t.Cleanup(b.Close)
	srv := &smtpproxy.Server{Domain: "localhost", MaxMessageBytes: 1 << 20, Log: testLog,
		Route: func(login string) (smtpproxy.Upstream, bool) {
			return smtpproxy.Upstream{Provider: sender{b}, Timeout: 5 * time.Second}, login == enginetest.User
		}}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })

	c, err := smtp.Dial(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Auth(sasl.NewPlainClient("", enginetest.User, "wrong")); err == nil {
		t.Fatal("a wrong password got in")
	}
	if err := c.Auth(sasl.NewPlainClient("", enginetest.User, enginetest.Password)); err != nil {
		t.Fatal(err)
	}
	msg := "From: " + enginetest.User + "\r\nTo: " + enginetest.Bob + "\r\nSubject: Via JMAP\r\nMessage-ID: <smtp-jmap@test>\r\n\r\nHello.\r\n"
	if err := c.SendMail(enginetest.User, []string{enginetest.Bob, "carol@example.net"}, strings.NewReader(msg)); err != nil {
		t.Fatal(err)
	}
	e.mu.Lock()
	sent := e.sent
	e.mu.Unlock()
	if len(sent) != 1 || sent[0].From != enginetest.User || !slices.Equal(sent[0].To, []string{enginetest.Bob, "carol@example.net"}) ||
		!strings.Contains(string(sent[0].Data), "Subject: Via JMAP") {
		t.Fatalf("sent %+v", sent)
	}
	eventually(t, "the stored copy to go", func() bool {
		s, err := up.Status("Drafts", &imap.StatusOptions{NumMessages: true}).Wait()
		return err == nil && *s.NumMessages == 0
	})
}
