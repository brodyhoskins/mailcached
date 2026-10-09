package imapproxy

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var modSeqRe = regexp.MustCompile(`MODSEQ \(([0-9]+)\)`)

func modSeqOf(t *testing.T, line string) uint64 {
	t.Helper()
	m := modSeqRe.FindStringSubmatch(line)
	if m == nil {
		t.Fatalf("no MODSEQ in %q", line)
	}
	n, _ := strconv.ParseUint(m[1], 10, 64)
	return n
}

func TestCondStore(t *testing.T) {
	e := newEnv(t)
	up := login(t, e.provider, nil)
	appendMsg(t, up, "INBOX", plain(bob, "One", "1"))
	appendMsg(t, up, "INBOX", plain(bob, "Two", "2"))

	rc := dialRaw(t, e.proxy)
	rc.ok(fmt.Sprintf("LOGIN %q %q", alice, password))
	waitSyncing(t, e.b, alice)
	if caps := rc.ok("CAPABILITY"); !strings.Contains(caps[0], " CONDSTORE") {
		t.Fatalf("capabilities %q", caps)
	}
	sel := rc.ok("SELECT INBOX (CONDSTORE)")
	hm := regexp.MustCompile(`\[HIGHESTMODSEQ ([0-9]+)\]`).FindStringSubmatch(strings.Join(sel, "\n"))
	if hm == nil {
		t.Fatalf("SELECT %q", sel)
	}
	highest, _ := strconv.ParseUint(hm[1], 10, 64)

	got := rc.ok("FETCH 1:* (FLAGS MODSEQ)")
	if len(got) != 2 {
		t.Fatalf("FETCH %q", got)
	}
	one := modSeqOf(t, got[0])
	if one > highest {
		t.Fatalf("MODSEQ %d above HIGHESTMODSEQ %d", one, highest)
	}

	// A change raises the message's MODSEQ, and its FETCH says so.
	st := rc.ok(`STORE 1 +FLAGS (\Flagged)`)
	after := modSeqOf(t, strings.Join(st, "\n"))
	if after <= highest {
		t.Fatalf("MODSEQ %d after a change, HIGHESTMODSEQ was %d", after, highest)
	}
	changed := rc.ok(fmt.Sprintf("FETCH 1:* (FLAGS) (CHANGEDSINCE %d)", highest))
	if len(changed) != 1 || !strings.HasPrefix(changed[0], "* 1 FETCH") {
		t.Fatalf("CHANGEDSINCE %q", changed)
	}
	if st := rc.ok("STATUS INBOX (HIGHESTMODSEQ)"); !strings.Contains(st[0], "HIGHESTMODSEQ "+strconv.FormatUint(after, 10)) {
		t.Fatalf("STATUS %q, want HIGHESTMODSEQ %d", st, after)
	}

	// UNCHANGEDSINCE: message 1 changed since, so only 2 is stored.
	_, status := rc.do(fmt.Sprintf(`STORE 1:2 (UNCHANGEDSINCE %d) +FLAGS (\Seen)`, highest))
	if !strings.HasPrefix(status, "OK [MODIFIED 1]") {
		t.Fatalf("STORE UNCHANGEDSINCE: %s", status)
	}
	flags := rc.ok("FETCH 1:2 (FLAGS)")
	if strings.Contains(flags[0], `\Seen`) || !strings.Contains(flags[1], `\Seen`) {
		t.Fatalf("flags %q", flags)
	}
	if _, status := rc.do(`STORE 1 (UNCHANGEDSINCE 0) +FLAGS (\Seen)`); !strings.HasPrefix(status, "OK [MODIFIED 1]") {
		t.Fatalf("all modified: %s", status)
	}

	res := rc.ok(fmt.Sprintf("SEARCH MODSEQ %d", after))
	if len(res) != 1 || !regexp.MustCompile(`^\* SEARCH 1 2 \(MODSEQ [0-9]+\)$`).MatchString(res[0]) {
		t.Fatalf("SEARCH MODSEQ %q", res)
	}
	if en := rc.ok("ENABLE CONDSTORE"); len(en) != 1 || !strings.Contains(en[0], "CONDSTORE") {
		t.Fatalf("ENABLE %q", en)
	}
}
