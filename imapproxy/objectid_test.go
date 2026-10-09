package imapproxy

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"
)

// rawClient speaks IMAP by hand, for what imapclient does not know.
type rawClient struct {
	t   *testing.T
	c   net.Conn
	r   *bufio.Reader
	tag int
}

func dialRaw(t *testing.T, addr string) *rawClient {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	rc := &rawClient{t: t, c: c, r: bufio.NewReader(c)}
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := rc.r.ReadString('\n'); err != nil {
		t.Fatal(err)
	}
	return rc
}

// do sends a command and returns its untagged responses and its status.
func (rc *rawClient) do(cmd string) ([]string, string) {
	rc.t.Helper()
	rc.tag++
	tag := fmt.Sprintf("t%d", rc.tag)
	fmt.Fprintf(rc.c, "%s %s\r\n", tag, cmd)
	var untagged []string
	for {
		line, err := rc.r.ReadString('\n')
		if err != nil {
			rc.t.Fatal(err)
		}
		line = strings.TrimRight(line, "\r\n")
		if strings.HasPrefix(line, tag+" ") {
			return untagged, strings.TrimPrefix(line, tag+" ")
		}
		untagged = append(untagged, line)
	}
}

func (rc *rawClient) ok(cmd string) []string {
	rc.t.Helper()
	untagged, status := rc.do(cmd)
	if !strings.HasPrefix(status, "OK") {
		rc.t.Fatalf("%s: %s", cmd, status)
	}
	return untagged
}

var (
	mailboxIDRe = regexp.MustCompile(`MAILBOXID \(([A-Za-z0-9_-]+)\)`)
	emailIDRe   = regexp.MustCompile(`EMAILID \(([A-Za-z0-9_-]+)\)`)
	threadIDRe  = regexp.MustCompile(`THREADID \(([A-Za-z0-9_-]+)\)`)
)

func find(t *testing.T, re *regexp.Regexp, lines ...string) string {
	t.Helper()
	for _, l := range lines {
		if m := re.FindStringSubmatch(l); m != nil {
			return m[1]
		}
	}
	t.Fatalf("no %s in %q", re, lines)
	return ""
}

func TestObjectID(t *testing.T) {
	e := newEnv(t)
	up := login(t, e.provider, nil)
	appendMsg(t, up, "INBOX", withID(plain(bob, "One", "1"), "<oid-1@test>"))
	appendMsg(t, up, "INBOX", withID(plain(bob, "Two", "2"), "<oid-2@test>"))
	if err := up.Create("Archive", nil).Wait(); err != nil {
		t.Fatal(err)
	}

	rc := dialRaw(t, e.proxy)
	rc.ok(fmt.Sprintf("LOGIN %q %q", alice, password))
	if caps := rc.ok("CAPABILITY"); !strings.Contains(caps[0], "OBJECTID") {
		t.Fatalf("capabilities %q", caps)
	}
	inbox := find(t, mailboxIDRe, rc.ok("SELECT INBOX")...)

	fetched := rc.ok("FETCH 1:* (FLAGS EMAILID THREADID)")
	if len(fetched) != 2 {
		t.Fatalf("FETCH %q", fetched)
	}
	first := find(t, emailIDRe, fetched[0])
	if second := find(t, emailIDRe, fetched[1]); second == first {
		t.Fatalf("two messages, one EMAILID: %q", fetched)
	}
	if th := find(t, threadIDRe, fetched[0]); th != "t"+first[1:] {
		t.Fatalf("THREADID %s for EMAILID %s", th, first)
	}
	uidOnly := rc.ok("UID FETCH 1:* EMAILID")
	if find(t, emailIDRe, uidOnly...) != first {
		t.Fatalf("UID FETCH %q", uidOnly)
	}

	if got := find(t, mailboxIDRe, rc.ok("STATUS INBOX (MESSAGES MAILBOXID)")...); got != inbox {
		t.Fatalf("STATUS MAILBOXID %s, SELECT said %s", got, inbox)
	}
	_, status := rc.do("CREATE Projects")
	created := find(t, mailboxIDRe, status)
	if created == inbox || !strings.HasPrefix(status, "OK") {
		t.Fatalf("CREATE: %s", status)
	}

	// A copy is the same email.
	rc.ok("COPY 1 Archive")
	if res := rc.ok("SEARCH EMAILID " + first); len(res) != 1 || res[0] != "* SEARCH 1" {
		t.Fatalf("SEARCH EMAILID %q", res)
	}
	arch := find(t, mailboxIDRe, rc.ok("SELECT Archive")...)
	if arch == inbox {
		t.Fatal("Archive and INBOX share a MAILBOXID")
	}
	if got := find(t, emailIDRe, rc.ok("FETCH 1 EMAILID")...); got != first {
		t.Fatalf("the copy's EMAILID %s, the original's %s", got, first)
	}
}

// TestObjectIDCommands checks the rewriting of commands.
func TestObjectIDCommands(t *testing.T) {
	o := &objectState{}
	for in, want := range map[string]string{
		"a FETCH 1:* (FLAGS EMAILID)\r\n":             "a FETCH 1:* (FLAGS UID)\r\n",
		"a UID FETCH 1 (EMAILID THREADID)\r\n":        "a UID FETCH 1 (UID UID)\r\n",
		"a STATUS INBOX (MAILBOXID)\r\n":              "a STATUS INBOX (MESSAGES)\r\n",
		"a FETCH 1 (BODY[HEADER])\r\n":                "a FETCH 1 (BODY[HEADER])\r\n",
		"a SEARCH SUBJECT \"EMAILID x\"\r\n":          "a SEARCH SUBJECT \"EMAILID x\"\r\n",
		"a STATUS \"EMAILID MAILBOXID\" (UNSEEN)\r\n": "a STATUS \"EMAILID MAILBOXID\" (UNSEEN)\r\n",
	} {
		if got := string(o.command([]byte(in))); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}
