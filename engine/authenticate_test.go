package engine

import (
	"context"
	"log/slog"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-msgauth/authres"
)

func TestAligned(t *testing.T) {
	for _, c := range []struct {
		d, from string
		want    bool
	}{
		{"example.com", "example.com", true},
		{"mail.example.com", "example.com", true},
		{"example.co.uk", "other.co.uk", false},
		{"", "example.com", false},
	} {
		if got := aligned(c.d, c.from); got != c.want {
			t.Errorf("aligned(%q, %q) = %v", c.d, c.from, got)
		}
	}
}

// TestVerdictICloud reads the fields iCloud adds, one per method under its
// own name, with a sender's forged field below them.
func TestVerdictICloud(t *testing.T) {
	b := &Engine{LookupTXT: func(_ context.Context, name string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}}
	ctx := context.Background()
	stamp := []string{"dmarc.icloud.com", "dkim-verifier.icloud.com"}
	hdr := func(dmarc string) []byte {
		return []byte("Authentication-Results: bimi.icloud.com; bimi=skipped reason=\"insufficient dmarc\"\r\n" +
			"Authentication-Results: dmarc.icloud.com; dmarc=" + dmarc + " header.from=sender.example\r\n" +
			"Authentication-Results: dkim-verifier.icloud.com; dkim=pass header.d=sender.example header.b=OFyhy6Wu\r\n" +
			"Authentication-Results: dmarc.icloud.com; dmarc=pass header.from=sender.example\r\n" +
			"From: UPS Delivery <info@sender.example>\r\n\r\n")
	}
	if r := b.verdict(ctx, stamp, hdr("pass")); r.Status != AuthPass || !r.DKIMAligned || r.DMARC != "pass" ||
		r.DKIM != "pass" || len(r.DKIMDomains) != 1 || r.DKIMDomains[0] != "sender.example" {
		t.Errorf("pass: %+v", r)
	}
	if r := b.verdict(ctx, stamp, hdr("fail")); r.Status != AuthFail {
		t.Errorf("fail under a forged pass: %+v", r)
	}
	if r := b.verdict(ctx, stamp, hdr("none")); r.Status != AuthNoPolicy {
		t.Errorf("none: %+v", r)
	}
	if r := b.verdict(ctx, []string{"mx.other.example"}, hdr("pass")); r.Status != AuthUnknown || r.Learning {
		t.Errorf("no stamp on it: %+v", r)
	}
	if r := b.verdict(ctx, nil, hdr("pass")); r.Status != AuthUnknown || !r.Learning {
		t.Errorf("learning: %+v", r)
	}
}

// TestLearned checks that a name is learned from a full window of mail
// from many senders, that a forger's name is not, and that a provider's
// new name replaces the old one.
func TestLearned(t *testing.T) {
	l := &authLearn{}
	t0 := time.Now()
	add := func(i int, domain string, names ...string) {
		hdr := ""
		for _, n := range names {
			hdr += "Authentication-Results: " + n + "; dmarc=pass header.from=" + domain + "\r\n"
		}
		hdr += "From: a@" + domain + "\r\nMessage-ID: <" + string(rune('a'+i%26)) + time.Duration(i).String() + "@x>\r\n\r\n"
		l.observe(identity([]byte(hdr)), t0.Add(time.Duration(i)*time.Minute), []byte(hdr))
	}
	domains := []string{"a.example", "b.example", "c.example", "d.example", "e.example", "f.example"}
	for i := range authWindow - 1 {
		add(i, domains[i%len(domains)], "mx.provider.example")
	}
	if got := l.learned(); got != nil {
		t.Fatalf("learned before a full window: %v", got)
	}
	add(authWindow, "evil.example", "mx.provider.example", "mx.forged.example")
	if got := l.learned(); len(got) != 1 || got[0] != "mx.provider.example" {
		t.Fatalf("learned %v", got)
	}
	// The provider changes its name.
	for i := range authWindow {
		add(100+i, domains[i%len(domains)], "mx2.provider.example")
		if i == 2 && len(l.learned()) != 0 {
			t.Fatalf("the old name is still learned after 3 messages without it: %v", l.learned())
		}
	}
	if got := l.learned(); len(got) != 1 || got[0] != "mx2.provider.example" {
		t.Fatalf("after the change: %v", got)
	}
	// A run of mail from one sender keeps the name.
	for i := range authWindow {
		add(200+i, "one.example", "mx2.provider.example")
	}
	if got := l.learned(); len(got) != 1 || got[0] != "mx2.provider.example" {
		t.Fatalf("after mail from one sender: %v", got)
	}
}

// TestLearnedSenders checks that a name on mail from fewer than
// authSenders domains is not learned, but is a candidate.
func TestLearnedSenders(t *testing.T) {
	l := &authLearn{}
	t0 := time.Now()
	for i := range authWindow {
		domain := []string{"a.example", "b.example"}[i%2]
		hdr := "Authentication-Results: mx.provider.example; dmarc=pass header.from=" + domain + "\r\n" +
			"From: a@" + domain + "\r\nMessage-ID: <" + time.Duration(i).String() + "@x>\r\n\r\n"
		l.observe(identity([]byte(hdr)), t0.Add(time.Duration(i)*time.Minute), []byte(hdr))
	}
	if got := l.learned(); got != nil {
		t.Fatalf("learned from 2 senders: %v", got)
	}
	a := &Account{b: &Engine{Log: slog.New(slog.DiscardHandler)}}
	a.learning()
	a.auth.Seen, a.auth.Examined = l.Seen, l.Examined
	if st := a.AuthState(); len(st.Stamp) != 0 || !slices.Equal(st.Candidates, []string{"mx.provider.example"}) {
		t.Fatalf("state: %+v", st)
	}
}

// kolabHeader is the top of a message Kolab Now delivered: DKIM in its
// Authentication-Results field, with comments, and SPF in Received-SPF,
// above the Received field where it took the message in. The sender's
// fields below it, a forged Received-SPF among them, do not count.
func kolabHeader(dkimDomain, spfFrom, from string) []byte {
	return []byte("Received: from lmtpproxyd ([10.17.8.19]) by imapb055.kolabnow.com (Cyrus) with LMTPSA;\r\n" +
		" Fri, 16 Oct 2026 01:53:01 +0200\r\n" +
		"X-Spam-Flag: NO\r\n" +
		"Authentication-Results: kolabnow.com (amavis); dkim=pass (1024-bit key)\r\n" +
		" header.d=" + dkimDomain + "\r\n" +
		"Received-SPF: " + spfResult(spfFrom) + " identity=mailfrom; client-ip=52.101.62.136; helo=mail.outlook.com; envelope-from=" + spfFrom + ";\r\n" +
		"Received: from DM5PR21CU001.outbound.protection.outlook.com ([52.101.62.136])\r\n" +
		" by kolabnow.com (Postfix) with ESMTPS id 7F29F62\r\n" +
		"Received-SPF: Pass identity=mailfrom; envelope-from=x@" + strings.SplitN(from, "@", 2)[1] + ";\r\n" +
		"Authentication-Results: kolabnow.com; dmarc=pass header.from=forged\r\n" +
		"From: Jeff Malet <" + from + ">\r\n\r\n")
}

func TestVerdictKolab(t *testing.T) {
	dns := map[string]string{
		"_dmarc.westernu.edu":   "v=DMARC1; p=quarantine",
		"_dmarc.strict.example": "v=DMARC1; p=reject; aspf=s",
	}
	b := &Engine{LookupTXT: func(_ context.Context, name string) ([]string, error) {
		if v, ok := dns[name]; ok {
			return []string{v}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}}
	ctx, stamp := context.Background(), []string{"kolabnow.com"}
	for _, c := range []struct {
		name                string
		dkim, spfFrom, from string
		want                AuthStatus
	}{
		{"pass by SPF", "westernu.onmicrosoft.com", "jmalet@westernu.edu", "jmalet@westernu.edu", AuthPass},
		{"no record, signed", "nopolicy.example", "x@nopolicy.example", "a@nopolicy.example", AuthNoPolicy},
		{"pass by DKIM", "westernu.edu", "bounce@mailer.example", "jmalet@westernu.edu", AuthPass},
		{"spoofed", "evil.example", "x@evil.example", "jmalet@westernu.edu", AuthFail},
		{"no record", "evil.example", "x@evil.example", "a@nopolicy.example", AuthNoPolicy},
		{"strict SPF, subdomain", "evil.example", "x@mail.strict.example", "a@strict.example", AuthFail},
		{"SPF fail, no record", "evil.example", "spf-fail@nopolicy.example", "a@nopolicy.example", AuthNoPolicy},
		{"SPF fail, DMARC passes by DKIM", "westernu.edu", "spf-fail@westernu.edu", "jmalet@westernu.edu", AuthPass},
	} {
		r := b.verdict(ctx, stamp, kolabHeader(c.dkim, c.spfFrom, c.from))
		if r.Status != c.want {
			t.Errorf("%s: %+v, want %s", c.name, r, c.want)
		}
		if c.name == "no record, signed" && (r.DMARC != "none" || !r.DKIMAligned || !r.SPFAligned || r.SPF != "pass" ||
			r.SPFDomain != "nopolicy.example") {
			t.Errorf("%s: details %+v", c.name, r)
		}
	}
	// Kolab Now is learned from its fields, which carry no DMARC result.
	if got := stampsOf(kolabHeader("a.example", "x@a.example", "x@a.example")); len(got) != 1 || got[0] != "kolabnow.com" {
		t.Errorf("stamps: %v", got)
	}
}

func TestStripComments(t *testing.T) {
	for in, want := range map[string]string{
		`kolabnow.com (amavis); dkim=pass (1024-bit key) header.d=x`: `kolabnow.com ; dkim=pass  header.d=x`,
		`a (b (nested) c) d`:  `a  d`,
		`x; reason="a (b) c"`: `x; reason="a (b) c"`,
		`x \(not a comment\)`: `x \(not a comment\)`,
	} {
		if got := stripComments(in); got != want {
			t.Errorf("stripComments(%q) = %q, want %q", in, got, want)
		}
	}
}

// spfResult is Fail for an envelope sender starting "spf-fail@", else Pass.
func spfResult(from string) string {
	if strings.HasPrefix(from, "spf-fail@") {
		return "Fail"
	}
	return "Pass"
}

// TestModeAction checks what each mode does with a verdict.
func TestModeAction(t *testing.T) {
	for _, c := range []struct {
		name             string
		r                AuthResult
		standard, strict AuthAction
	}{
		{"pass", AuthResult{Status: AuthPass, SPF: "pass"}, AuthNone, AuthNone},
		{"DMARC fail, p=reject", AuthResult{Status: AuthFail, DMARCPolicy: "reject"}, AuthDelete, AuthDelete},
		{"DMARC fail, p=quarantine", AuthResult{Status: AuthFail, DMARCPolicy: "quarantine"}, AuthJunk, AuthJunk},
		{"DMARC fail, p=none", AuthResult{Status: AuthFail, DMARCPolicy: "none"}, AuthNone, AuthJunk},
		{"DMARC fail, record unread", AuthResult{Status: AuthFail}, AuthJunk, AuthJunk},
		{"DMARC fail, p=none, SPF fail", AuthResult{Status: AuthFail, DMARCPolicy: "none", SPF: "fail"}, AuthDelete, AuthDelete},
		{"DMARC fail, p=quarantine, SPF fail", AuthResult{Status: AuthFail, DMARCPolicy: "quarantine", SPF: "fail"}, AuthDelete, AuthDelete},
		{"DMARC fail, p=none, SPF softfail", AuthResult{Status: AuthFail, DMARCPolicy: "none", SPF: "softfail"}, AuthJunk, AuthDelete},
		{"DMARC fail, p=reject, SPF softfail", AuthResult{Status: AuthFail, DMARCPolicy: "reject", SPF: "softfail"}, AuthDelete, AuthDelete},
		{"no record, SPF fail", AuthResult{Status: AuthNoPolicy, SPF: "fail"}, AuthDelete, AuthDelete},
		{"no record, SPF softfail", AuthResult{Status: AuthNoPolicy, SPF: "softfail"}, AuthJunk, AuthDelete},
		{"DMARC pass, SPF softfail", AuthResult{Status: AuthPass, SPF: "softfail"}, AuthNone, AuthDelete},
		{"DMARC pass, SPF fail", AuthResult{Status: AuthPass, SPF: "fail"}, AuthNone, AuthDelete},
		{"no record, SPF neutral", AuthResult{Status: AuthNoPolicy, SPF: "neutral"}, AuthNone, AuthNone},
		{"no verdict, SPF fail", AuthResult{Status: AuthUnknown, SPF: "fail"}, AuthNone, AuthDelete},
		{"no verdict, SPF softfail", AuthResult{Status: AuthUnknown, SPF: "softfail"}, AuthNone, AuthDelete},
		{"moved back", AuthResult{Status: AuthPass, Rescued: true, SPF: "fail"}, AuthNone, AuthNone},
	} {
		if got := AuthStandard.action(c.r); got != c.standard {
			t.Errorf("standard, %s: %q, want %q", c.name, got, c.standard)
		}
		if got := AuthStrict.action(c.r); got != c.strict {
			t.Errorf("strict, %s: %q, want %q", c.name, got, c.strict)
		}
	}
}

// TestDMARCPolicy checks the policy a failure is acted on by: the
// domain's own p=, or its organizational domain's sp= for a subdomain.
func TestDMARCPolicy(t *testing.T) {
	dns := map[string]string{
		"_dmarc.example.com":     "v=DMARC1; p=reject; sp=quarantine",
		"_dmarc.own.example.com": "v=DMARC1; p=none",
	}
	b := &Engine{LookupTXT: func(_ context.Context, name string) ([]string, error) {
		if v, ok := dns[name]; ok {
			return []string{v}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}}
	ctx := context.Background()
	for domain, want := range map[string]string{
		"example.com": "reject", "mail.example.com": "quarantine", "own.example.com": "none", "nowhere.example": "",
	} {
		if got := b.dmarcPolicy(ctx, domain); got != want {
			t.Errorf("%s: %q, want %q", domain, got, want)
		}
	}
}

// TestForgedBelowIngress checks that fields below the Received field where
// the provider took the message in count neither for the verdict nor for
// learning, even with the provider's name, when the provider's own field
// is missing.
func TestForgedBelowIngress(t *testing.T) {
	hdr := []byte("Received: from relay by imap.provider.example; Fri, 16 Oct 2026 01:53:01 +0200\r\n" +
		"Authentication-Results: other.provider.example; spf=none\r\n" +
		"Received: from sender.example by mx.provider.example; Fri, 16 Oct 2026 01:53:00 +0200\r\n" +
		"Authentication-Results: mx.provider.example; dmarc=pass header.from=bank.example\r\n" +
		"Authentication-Results: zz.forged.example; dmarc=pass header.from=bank.example\r\n" +
		"From: a@bank.example\r\n\r\n")
	if r := (&Engine{}).verdict(context.Background(), []string{"mx.provider.example"}, hdr); r.Status != AuthUnknown {
		t.Errorf("verdict from a forged field: %+v", r)
	}
	if got := stampsOf(hdr); len(got) != 1 || got[0] != "other.provider.example" {
		t.Errorf("stamps: %v", got)
	}
}

func TestSPFDomainNullSender(t *testing.T) {
	for from, want := range map[string]string{"<>": "helo.example", "": "helo.example", "<a@b.example>": "b.example"} {
		if got := spfDomain(from, "helo.example"); got != want {
			t.Errorf("spfDomain(%q) = %q, want %q", from, got, want)
		}
	}
	if result, from, helo, id := parseReceivedSPF(`pass identity=mailfrom; envelope-from="<>"; helo=Helo.Example;`); spfVoteOf(authres.ResultValue(result), from, helo, id).domain != "helo.example" {
		t.Errorf("Received-SPF null sender: from %q, helo %q", from, helo)
	}
	// A provider may split its methods across fields: each counts.
	stamp := []string{"mx.provider.example"}
	split := []byte("Authentication-Results: mx.provider.example; dmarc=pass header.from=bank.example\r\n" +
		"Authentication-Results: mx.provider.example; spf=fail smtp.mailfrom=x@bank.example\r\n" +
		"Received: from x by mx.provider.example\r\n" +
		"Authentication-Results: mx.provider.example; spf=pass smtp.mailfrom=x@bank.example\r\n\r\n")
	if c := providerResults(split, stamp); c.dmarc != authres.ResultPass || c.spf != authres.ResultFail {
		t.Errorf("DMARC, then SPF: %+v", c)
	}
	split = []byte("Authentication-Results: mx.provider.example; dkim=fail header.d=bank.example\r\n" +
		"Authentication-Results: mx.provider.example; dmarc=fail header.from=bank.example\r\n\r\n")
	if c := providerResults(split, stamp); c.dmarc != authres.ResultFail || c.dkim != authres.ResultFail {
		t.Errorf("DKIM, then DMARC: %+v", c)
	}
	// An escaped quote in a quoted value does not end it.
	if _, from, _, _ := parseReceivedSPF(`pass identity=mailfrom; envelope-from="\"a; envelope-from=x@bank.example; z\"@evil.example";`); !strings.HasSuffix(from, "@evil.example") {
		t.Errorf("escaped quote: envelope-from %q", from)
	}
	// A HELO pass does not stand for a MAIL FROM that failed.
	hdr := []byte("Authentication-Results: mx.provider.example; spf=pass smtp.helo=bank.example; spf=fail smtp.mailfrom=x@other.example\r\n" +
		"From: a@bank.example\r\n\r\n")
	if c := providerResults(hdr, []string{"mx.provider.example"}); c.spf != authres.ResultFail || c.spfPass != "" {
		t.Errorf("HELO pass over a MAIL FROM fail: %+v", c)
	}
	hdr = []byte("Authentication-Results: mx.provider.example; spf=pass smtp.helo=bank.example\r\nFrom: a@bank.example\r\n\r\n")
	if c := providerResults(hdr, []string{"mx.provider.example"}); c.spfPass != "" {
		t.Errorf("HELO pass without MAIL FROM: %+v", c)
	}
	hdr = []byte("Authentication-Results: z.example; dmarc=fail header.from=bank.example\r\n" +
		"Authentication-Results: a.example; dmarc=pass header.from=bank.example\r\n\r\n")
	if c := providerResults(hdr, []string{"a.example", "z.example"}); c.dmarc != authres.ResultFail {
		t.Errorf("topmost field: %+v", c)
	}
}

// TestRescueSameDelivery checks that only the delivery moved away is
// moved back: a message sent again with its Message-ID is not, nor is one
// that was deleted.
func TestRescueSameDelivery(t *testing.T) {
	a := &Account{b: &Engine{Log: slog.New(slog.DiscardHandler)}}
	hdr := func(rcv string) []byte {
		return []byte("Received: " + rcv + "\r\nMessage-ID: <m@x>\r\nFrom: a@x.example\r\n\r\n")
	}
	moved := hdr("from x by mx; 1 Jan 2026 00:00:00 +0000")
	l := a.learning()
	l.Moved[refOf(moved).key("INBOX")] = &authMoved{Action: AuthJunk, Folder: "Junk", Origin: "INBOX", Copy: copyOf(moved)}
	if a.rescue(hdr("from x by mx; 2 Jan 2026 00:00:00 +0000"), "INBOX") {
		t.Error("another delivery rescued")
	}
	if a.rescue(moved, "Work") {
		t.Error("a copy in another folder rescued")
	}
	if !a.rescue(moved, "INBOX") {
		t.Error("the delivery moved away not rescued")
	}
	if !a.rescue(moved, "INBOX") || !a.rescued(moved) {
		t.Error("the rescue not kept for a later read")
	}
	l.Moved[refOf(moved).key("INBOX")] = &authMoved{Action: AuthDelete, Origin: "INBOX", Copy: copyOf(moved)}
	if a.rescue(moved, "INBOX") {
		t.Error("a deleted message rescued")
	}
	// One whose move is not known to have happened is not rescued, and
	// is forgotten once seen where it came from.
	l.Moved[refOf(moved).key("INBOX")] = &authMoved{Action: AuthJunk, Folder: "Junk", Origin: "INBOX", Copy: copyOf(moved), Pending: true}
	if a.rescue(moved, "Work") || a.rescue(moved, "INBOX") || l.Moved[refOf(moved).key("INBOX")] != nil {
		t.Error("a pending move rescued or kept")
	}
	// Two deliveries with one Message-ID have a record each.
	other := hdr("from x by mx; 3 Jan 2026 00:00:00 +0000")
	l.Moved[refOf(moved).key("INBOX")] = &authMoved{Action: AuthJunk, Folder: "Junk", Origin: "INBOX", Copy: copyOf(moved)}
	l.Moved[refOf(other).key("INBOX")] = &authMoved{Action: AuthJunk, Folder: "Junk", Origin: "INBOX", Copy: copyOf(other)}
	if !a.rescue(moved, "INBOX") || !a.rescue(other, "INBOX") {
		t.Error("deliveries with one Message-ID not rescued each")
	}
	// Copies of one delivery from two folders have a record each.
	l.Moved = map[string]*authMoved{}
	l.Moved[refOf(moved).key("INBOX")] = &authMoved{Action: AuthJunk, Folder: "Junk", Origin: "INBOX", Copy: copyOf(moved)}
	l.Moved[refOf(moved).key("Work")] = &authMoved{Action: AuthJunk, Folder: "Junk", Origin: "Work", Copy: copyOf(moved)}
	if !a.rescue(moved, "Work") || l.Moved[refOf(moved).key("INBOX")].Rescued || !l.Moved[refOf(moved).key("Work")].Rescued {
		t.Error("copies from two folders not rescued each")
	}
	// A client's move through the proxy rescues from where it was moved,
	// to any folder.
	l.Moved[refOf(moved).key("INBOX")] = &authMoved{Action: AuthJunk, Folder: "Junk", Origin: "INBOX", Copy: copyOf(moved)}
	if a.rescueMove(moved, "Trash") || !a.rescueMove(moved, "Junk") || !a.rescued(moved) {
		t.Error("a move out of Junk to another folder not rescued")
	}
}

// TestTempErrorUnknown checks that a temporary DKIM or SPF error without
// a pass gives no verdict, rather than a DMARC failure.
func TestTempErrorUnknown(t *testing.T) {
	b := &Engine{LookupTXT: func(_ context.Context, name string) ([]string, error) {
		if name == "_dmarc.reject.example" {
			return []string{"v=DMARC1; p=reject"}, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}}
	for _, res := range []string{"dkim=temperror header.d=reject.example", "spf=temperror smtp.mailfrom=x@reject.example",
		"dkim=pass header.i=@reject.example", "dkim=fail header.d=reject.example",
		"dkim=fail header.d=reject.example; spf=pass"} {
		hdr := []byte("Authentication-Results: mx.provider.example; " + res + "\r\nFrom: a@reject.example\r\n\r\n")
		if r := b.verdict(context.Background(), []string{"mx.provider.example"}, hdr); r.Status != AuthUnknown {
			t.Errorf("%s: %+v", res, r)
		}
	}
}

func TestDomainOf(t *testing.T) {
	for addr, want := range map[string]string{`"local@part"@example.com`: "example.com", "a@b.example": "b.example", "none": ""} {
		if got := domainOf(addr); got != want {
			t.Errorf("domainOf(%q) = %q, want %q", addr, got, want)
		}
	}
}

// TestRenameAuth checks that renaming a folder moves the records of mail
// moved away from it, and from folders below it.
func TestRenameAuth(t *testing.T) {
	a := &Account{b: &Engine{Authentication: AuthStandard, Log: slog.New(slog.DiscardHandler)}, delim: '/'}
	l := a.learning()
	ref := authRef{"<m@x>", "c"}
	l.Moved[ref.key("Work")] = &authMoved{Folder: "Junk", Origin: "Work"}
	l.Moved[ref.key("Work/Sub")] = &authMoved{Folder: "Junk", Origin: "Work/Sub"}
	l.Moved[ref.key("Workshop")] = &authMoved{Folder: "Junk", Origin: "Workshop"}
	a.renameAuth("Work", "Jobs")
	for _, origin := range []string{"Jobs", "Jobs/Sub", "Workshop"} {
		if m := l.Moved[ref.key(origin)]; m == nil || m.Origin != origin {
			t.Errorf("%s: %+v", origin, m)
		}
	}
	if len(l.Moved) != 3 {
		t.Errorf("records: %d", len(l.Moved))
	}
}

func TestHeaderFieldsUnfold(t *testing.T) {
	got := headerFields([]byte("A: one\r\n two\r\n\tthree\r\nB: four\r\n\r\nbody: no\r\n"))
	if len(got) != 2 || got[0] != (headerField{"A", "one two three"}) || got[1] != (headerField{"B", "four"}) {
		t.Errorf("%+v", got)
	}
}
