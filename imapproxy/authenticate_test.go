package imapproxy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/brodyhoskins/mailcached/engine"
)

const provider = "mx.provider.example"

// stamped is a message from from, with the provider's verdict on top and
// any forged fields below it.
func stamped(id, from, verdict string, forged ...string) []byte {
	var b bytes.Buffer
	if verdict != "" {
		fmt.Fprintf(&b, "Authentication-Results: %s; dmarc=%s header.from=x\r\n", provider, verdict)
	}
	for _, f := range forged {
		fmt.Fprintf(&b, "Authentication-Results: %s; dmarc=pass header.from=x\r\n", f)
	}
	b.Write(withID(plain(from, "Message "+id, "Body of "+id+"."), "<"+id+"@test>"))
	return b.Bytes()
}

// senders are the domains the tests' mail comes from.
var senders = []string{"a.example", "b.example", "c.example", "d.example", "e.example", "f.example"}

// dmarcRecords are the tests' DMARC records; other domains have none.
var dmarcRecords = map[string]string{"_dmarc.reject.example": "v=DMARC1; p=reject"}

func lookupTXT(_ context.Context, name string) ([]string, error) {
	if v, ok := dmarcRecords[name]; ok {
		return []string{v}, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
}

// authEnv is a proxy with sender authentication in mode. The provider has
// a Junk folder.
func authEnv(t *testing.T, mode engine.AuthMode) (e *env, up, c *imapclient.Client, a *engine.Account) {
	t.Helper()
	e = newEnvConf(t, nil, func(eng *engine.Engine, _ *Server) {
		eng.Authentication, eng.LookupTXT = mode, lookupTXT
	})
	up = login(t, e.provider, nil)
	if err := up.Create("Junk", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	return e, up, nil, nil
}

func subjects(t *testing.T, c *imapclient.Client, box string) []string {
	t.Helper()
	if _, err := c.Select(box, nil).Wait(); err != nil {
		t.Fatal(err)
	}
	hdr := &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader, HeaderFields: []string{"Subject"}, Peek: true}
	msgs, err := c.Fetch(imap.SeqSetNum(1, 0), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{hdr}}).Collect()
	if err != nil {
		return nil
	}
	var out []string
	for _, m := range msgs {
		out = append(out, string(bytes.TrimSpace(bytes.TrimPrefix(m.FindBodySection(hdr), []byte("Subject: ")))))
	}
	return out
}

// TestAuthenticationJunk checks that the stamp is learned from the mail in
// INBOX at the first sync, that new mail the provider says fails goes to
// Junk before any client sees it, that a forged pass below the provider's
// fail does not count, and that a message the user moves back stays.
func TestAuthenticationJunk(t *testing.T) {
	e, up, _, _ := authEnv(t, engine.AuthStandard)
	old := time.Now().Add(-time.Hour)
	for i := range 20 {
		appendAt(t, up, "INBOX", stamped(fmt.Sprintf("old%d", i), "x@"+senders[i%len(senders)], "pass"), old)
	}
	c := login(t, e.proxy, nil)
	a := e.eng.Account(alice)
	waitSyncing(t, e.b, alice)
	if n := numIn(t, c, "INBOX"); n != 20 {
		t.Fatalf("INBOX has %d messages", n)
	}
	eventually(t, "the stamp learned from INBOX", func() bool {
		e.eng.Recheck() // runs the upkeep that learns from INBOX
		st := a.AuthState()
		return len(st.Stamp) == 1 && st.Stamp[0] == provider
	})

	later := time.Now().Add(time.Minute)
	appendAt(t, up, "INBOX", stamped("spoof", "x@a.example", "fail", "mx.forged.example"), later)
	appendAt(t, up, "INBOX", stamped("real", "x@b.example", "pass"), later)
	appendAt(t, up, "INBOX", stamped("unstamped", "x@c.example", ""), later)
	// The domain says p=reject: deleted, not junked.
	appendAt(t, up, "INBOX", stamped("rejected", "x@reject.example", "fail"), later)
	// DMARC passes: a softfail does not count in standard mode.
	appendAt(t, up, "INBOX", stamped("softfail", "x@d.example", "pass header.from=x; spf=softfail smtp.mailfrom=x@d.example;"), later)

	eventually(t, "the spoofed message in Junk, the rejected one gone", func() bool {
		return numIn(t, up, "Junk") == 1 && numIn(t, up, "INBOX") == 23 && a.Held() == 0
	})
	eventually(t, "the others at the proxy", func() bool { return numIn(t, c, "INBOX") == 23 })
	if got := subjects(t, up, "Junk"); len(got) != 1 || got[0] != "Message spoof" {
		t.Fatalf("Junk: %v", got)
	}

	// The user moves it back: it stays.
	if _, err := up.Move(imap.SeqSetNum(1), "INBOX").Wait(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the rescued message", func() bool { return numIn(t, c, "INBOX") == 24 })
	if n := numIn(t, up, "Junk"); n != 0 {
		t.Fatalf("Junk has %d messages after the move back", n)
	}
}

// TestAuthenticationLearning checks an empty mailbox: new mail waits in
// Junk until the stamp is learned from it, and then comes back.
func TestAuthenticationLearning(t *testing.T) {
	e, up, _, _ := authEnv(t, engine.AuthStandard)
	c := login(t, e.proxy, nil)
	a := e.eng.Account(alice)
	waitSyncing(t, e.b, alice)

	later := time.Now().Add(time.Minute)
	for i := range 20 {
		appendAt(t, up, "INBOX", stamped(fmt.Sprintf("new%d", i), "x@"+senders[i%len(senders)], "pass"), later)
	}
	eventually(t, "the stamp learned from new mail", func() bool { return len(a.AuthState().Stamp) == 1 })
	eventually(t, "every message back in INBOX", func() bool {
		e.eng.Recheck()
		return numIn(t, up, "Junk") == 0 && numIn(t, c, "INBOX") == 20
	})
}

// deferrer is the sealer, but sends new mail with "Defer" in its subject
// to Junk to read again (ReadDefer), as the bridge does with crypto mail
// that has no verdict.
type deferrer struct{ sealer }

func (d deferrer) Read(ctx context.Context, raw []byte) ([]byte, engine.ReadStatus) {
	if r, ok := engine.AuthResultFrom(ctx); ok && r.New && bytes.Contains(raw, []byte("Message-ID: <defer@test>")) {
		return raw, engine.ReadDefer
	}
	return d.sealer.Read(ctx, raw)
}

// TestAuthenticationDeferStays checks that mail a Transform sends away to
// read again once the stamp is known, when the stamp is known already,
// stays in Junk: releasing it would bring it back every sweep.
func TestAuthenticationDeferStays(t *testing.T) {
	e := newEnvConf(t, nil, func(eng *engine.Engine, _ *Server) {
		eng.Transform = deferrer{}
		eng.Authentication = engine.AuthStandard
	})
	up := login(t, e.provider, nil)
	if err := up.Create("Junk", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	for i := range 20 {
		appendAt(t, up, "INBOX", stamped(fmt.Sprintf("old%d", i), "x@"+senders[i%len(senders)], "pass"), old)
	}
	login(t, e.proxy, nil)
	a := e.eng.Account(alice)
	waitSyncing(t, e.b, alice)
	eventually(t, "the stamp", func() bool { e.eng.Recheck(); return len(a.AuthState().Stamp) == 1 })

	// Sealed, as encrypted mail, and without the provider's verdict.
	appendAt(t, up, "INBOX", withID(sealed("Defer", "Secret."), "<defer@test>"), time.Now().Add(time.Minute))
	eventually(t, "the message in Junk", func() bool { return numIn(t, up, "Junk") == 1 })
	for range 10 {
		e.eng.Recheck()
		time.Sleep(50 * time.Millisecond)
		if n := numIn(t, up, "Junk"); n != 1 {
			t.Fatalf("Junk has %d messages: the deferred message was released", n)
		}
	}
}

// unknownDeferrer sends new mail with Message-ID <defer@test> to Junk
// to read again while it has no verdict, as the bridge does with crypto
// mail.
type unknownDeferrer struct{ sealer }

func (d unknownDeferrer) Read(ctx context.Context, raw []byte) ([]byte, engine.ReadStatus) {
	r, ok := engine.AuthResultFrom(ctx)
	if ok && r.New && r.Status == engine.AuthUnknown && bytes.Contains(raw, []byte("Message-ID: <defer@test>")) {
		return raw, engine.ReadDefer
	}
	return d.sealer.Read(ctx, raw)
}

// TestAuthenticationStampRenamed checks that mail deferred under a known
// stamp is released when the provider's new name is learned, though the
// old name stays trusted throughout.
func TestAuthenticationStampRenamed(t *testing.T) {
	const renamed = "mx2.provider.example"
	e := newEnvConf(t, nil, func(eng *engine.Engine, _ *Server) {
		eng.Transform = unknownDeferrer{}
		eng.Authentication, eng.LookupTXT = engine.AuthStandard, lookupTXT
	})
	up := login(t, e.provider, nil)
	if err := up.Create("Junk", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	c := login(t, e.proxy, nil)
	a := e.eng.Account(alice)
	waitSyncing(t, e.b, alice)

	// The old name, confirmed by three messages moved back.
	later := time.Now().Add(time.Minute)
	for i := range 3 {
		appendAt(t, up, "INBOX", stamped(fmt.Sprintf("new%d", i), "x@"+senders[i], "pass"), later)
	}
	eventually(t, "Junk at the proxy", func() bool { return numIn(t, c, "Junk") == 3 })
	if _, err := c.Select("Junk", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Move(imap.SeqSetNum(1, 2, 3), "INBOX").Wait(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the old name confirmed", func() bool {
		st := a.AuthState()
		return len(st.Stamp) == 1 && st.Stamp[0] == provider
	})

	// Stamped by the new name only: no verdict yet.
	defer1 := append([]byte("Authentication-Results: "+renamed+"; dmarc=pass header.from=x\r\n"),
		withID(sealed("Defer", "Secret."), "<defer@test>")...)
	appendAt(t, up, "INBOX", defer1, later.Add(time.Minute))
	eventually(t, "the message in Junk", func() bool { return numIn(t, up, "Junk") == 1 })

	at := later.Add(2 * time.Minute)
	for i := range 20 {
		msg := append([]byte("Authentication-Results: "+renamed+"; dmarc=pass header.from=x\r\n"),
			withID(plain("x@"+senders[i%len(senders)], fmt.Sprintf("Message renamed%d", i), "Body."), fmt.Sprintf("<renamed%d@test>", i))...)
		appendAt(t, up, "INBOX", msg, at.Add(time.Duration(i)*time.Second))
	}
	eventually(t, "the new name trusted with the old", func() bool {
		st := a.AuthState()
		return slices.Contains(st.Stamp, provider) && slices.Contains(st.Stamp, renamed)
	})
	eventually(t, "the deferred message back in INBOX", func() bool {
		e.eng.Recheck()
		return numIn(t, up, "Junk") == 0 && numIn(t, up, "INBOX") == 24
	})
}

// TestAuthenticationStrict checks strict mode: an SPF softfail is deleted
// even though DMARC passes, and a DMARC failure is junked even under p=none.
func TestAuthenticationStrict(t *testing.T) {
	e, up, _, _ := authEnv(t, engine.AuthStrict)
	old := time.Now().Add(-time.Hour)
	for i := range 20 {
		appendAt(t, up, "INBOX", stamped(fmt.Sprintf("old%d", i), "x@"+senders[i%len(senders)], "pass"), old)
	}
	c := login(t, e.proxy, nil)
	a := e.eng.Account(alice)
	waitSyncing(t, e.b, alice)
	eventually(t, "the stamp", func() bool { e.eng.Recheck(); return len(a.AuthState().Stamp) == 1 })

	later := time.Now().Add(time.Minute)
	appendAt(t, up, "INBOX", stamped("softfail", "x@d.example", "pass header.from=x; spf=softfail smtp.mailfrom=x@d.example;"), later)
	appendAt(t, up, "INBOX", stamped("fail", "x@e.example", "fail"), later)
	appendAt(t, up, "INBOX", stamped("good", "x@f.example", "pass"), later)
	eventually(t, "the softfail gone, the failure in Junk", func() bool {
		return numIn(t, up, "INBOX") == 21 && numIn(t, up, "Junk") == 1 && a.Held() == 0
	})
	eventually(t, "the good one at the proxy", func() bool { return numIn(t, c, "INBOX") == 21 })
	if got := subjects(t, up, "Junk"); len(got) != 1 || got[0] != "Message fail" {
		t.Fatalf("Junk: %v", got)
	}
}

// TestAuthenticationCopyBack checks that mail a client copies out of Junk
// through the proxy, and deletes there, is taken for moved back by the
// user: three such messages confirm the provider's stamp before learning
// finds it.
func TestAuthenticationCopyBack(t *testing.T) {
	e, up, _, _ := authEnv(t, engine.AuthStandard)
	c := login(t, e.proxy, nil)
	a := e.eng.Account(alice)
	waitSyncing(t, e.b, alice)

	later := time.Now().Add(time.Minute)
	for i := range 3 {
		appendAt(t, up, "INBOX", stamped(fmt.Sprintf("new%d", i), "x@"+senders[i], "pass"), later)
	}
	eventually(t, "new mail waiting in Junk", func() bool { return numIn(t, up, "Junk") == 3 })
	eventually(t, "Junk at the proxy", func() bool { return numIn(t, c, "Junk") == 3 })
	if len(a.AuthState().Stamp) != 0 {
		t.Fatal("stamp known before the copies back")
	}
	if _, err := c.Select("Junk", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	all := imap.SeqSetNum(1, 2, 3)
	if _, err := c.Copy(all, "INBOX").Wait(); err != nil {
		t.Fatal(err)
	}
	if err := c.Store(all, &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Expunge().Close(); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the stamp confirmed by the copies back", func() bool {
		st := a.AuthState()
		return len(st.Stamp) == 1 && st.Stamp[0] == provider
	})
}

// labeler is the sealer, but sends new mail with Message-ID <junk@test>
// to Junk (ReadJunk), as the bridge does with crypto mail that fails, and
// puts the verdict it reads with in an X-Verdict field, "rescued" after
// it if moved back by the user.
type labeler struct{ sealer }

func (l labeler) Read(ctx context.Context, raw []byte) ([]byte, engine.ReadStatus) {
	r, ok := engine.AuthResultFrom(ctx)
	if ok && r.New && bytes.Contains(raw, []byte("Message-ID: <junk@test>")) {
		return raw, engine.ReadJunk
	}
	out, st := l.sealer.Read(ctx, raw)
	if ok {
		v := string(r.Status)
		if r.Rescued {
			v += " rescued"
		}
		out = append([]byte("X-Verdict: "+v+"\r\n"), out...)
	}
	return out, st
}

// TestAuthenticationJunkVerdict checks that mail a Transform sends to
// Junk is read there with its verdict, for the Transform to show.
func TestAuthenticationJunkVerdict(t *testing.T) {
	_, c := junkedEnv(t)
	if got := verdictIn(t, c, "Junk"); got != "X-Verdict: pass" {
		t.Fatalf("read in Junk with %q", got)
	}
}

// TestAuthenticationRescueRereads checks that a message read in Junk and
// moved back by a client is read again as rescued, not shown with the
// result cached in Junk.
func TestAuthenticationRescueRereads(t *testing.T) {
	_, c := junkedEnv(t)
	if got := verdictIn(t, c, "Junk"); got != "X-Verdict: pass" {
		t.Fatalf("read in Junk with %q", got)
	}
	if _, err := c.Move(imap.SeqSetNum(1), "INBOX").Wait(); err != nil {
		t.Fatal(err)
	}
	// The rescue runs when the queued move reaches the provider.
	eventually(t, "the rescued verdict in INBOX", func() bool { return verdictIn(t, c, "INBOX") == "X-Verdict: pass rescued" })
}

// junkedEnv is a proxy with the labeler that sent one new message to Junk.
func junkedEnv(t *testing.T) (*env, *imapclient.Client) {
	t.Helper()
	e := newEnvConf(t, nil, func(eng *engine.Engine, _ *Server) {
		eng.Transform = labeler{}
		eng.Authentication = engine.AuthStandard
	})
	up := login(t, e.provider, nil)
	if err := up.Create("Junk", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	for i := range 20 {
		appendAt(t, up, "INBOX", stamped(fmt.Sprintf("old%d", i), "x@"+senders[i%len(senders)], "pass"), old)
	}
	c := login(t, e.proxy, nil)
	a := e.eng.Account(alice)
	waitSyncing(t, e.b, alice)
	eventually(t, "the stamp", func() bool { e.eng.Recheck(); return len(a.AuthState().Stamp) == 1 })

	msg := append([]byte("Authentication-Results: "+provider+"; dmarc=pass header.from=x\r\n"),
		withID(sealed("Junked", "Secret."), "<junk@test>")...)
	appendAt(t, up, "INBOX", msg, time.Now().Add(time.Minute))
	eventually(t, "the message in Junk at the proxy", func() bool { return numIn(t, c, "Junk") == 1 })
	return e, c
}

// verdictIn returns the X-Verdict field of the message "Junked" in box.
func verdictIn(t *testing.T, c *imapclient.Client, box string) string {
	t.Helper()
	if _, err := c.Select(box, nil).Wait(); err != nil {
		t.Fatal(err)
	}
	hdr := &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader, HeaderFields: []string{"Subject", "X-Verdict"}, Peek: true}
	var all imap.SeqSet
	all.AddRange(1, 0)
	msgs, err := c.Fetch(all, &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{hdr}}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range msgs {
		fields := strings.Split(string(m.FindBodySection(hdr)), "\r\n")
		if !slices.Contains(fields, "Subject: Junked") {
			continue
		}
		for _, f := range fields {
			if strings.HasPrefix(f, "X-Verdict:") {
				return f
			}
		}
	}
	t.Fatalf("no message Junked in %s", box)
	return ""
}
