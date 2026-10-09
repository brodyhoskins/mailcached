package jmapproxy

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/brodyhoskins/mailcached/imapproxy"
	"github.com/brodyhoskins/mailcached/internal/enginetest"
	"github.com/brodyhoskins/mailcached/internal/jmap"
)

// TestSameIDs checks that IMAP's OBJECTID and JMAP name a folder and a
// message the same way, on one engine.
func TestSameIDs(t *testing.T) {
	e := newEnv(t)
	appendMsg(t, e.upstream(t), "INBOX", plain("same-1@test", "Same", "x"))
	var inbox jmap.Mailbox
	eventually(t, "the message", func() bool { inbox = e.mailboxes(t)["INBOX"]; return inbox.TotalEmails == 1 })
	ids := e.query(t, inbox.ID)

	srv := &imapproxy.Server{Engine: e.eng, MaxMessageBytes: 1 << 20, Log: testLog}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(c)
	r.ReadString('\n')
	n := 0
	do := func(cmd string) string {
		n++
		fmt.Fprintf(c, "t%d %s\r\n", n, cmd)
		var all strings.Builder
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			all.WriteString(line)
			if strings.HasPrefix(line, fmt.Sprintf("t%d ", n)) {
				return all.String()
			}
		}
	}
	do(fmt.Sprintf("LOGIN %q %q", enginetest.User, enginetest.Password))
	sel := do("SELECT INBOX")
	fetch := do("FETCH 1 (EMAILID THREADID)")
	mbox := regexp.MustCompile(`MAILBOXID \((\S+)\)`).FindStringSubmatch(sel)
	email := regexp.MustCompile(`EMAILID \((\S+)\)`).FindStringSubmatch(fetch)
	thread := regexp.MustCompile(`THREADID \((\S+)\)`).FindStringSubmatch(fetch)
	if mbox == nil || jmap.ID(mbox[1]) != inbox.ID {
		t.Fatalf("MAILBOXID %v, JMAP %s", mbox, inbox.ID)
	}
	if email == nil || jmap.ID(email[1]) != ids[0] {
		t.Fatalf("EMAILID %v, JMAP %s", email, ids[0])
	}
	var got jmap.GetResponse[jmap.Email]
	e.call(t, "Email/get", jmap.GetArgs{AccountID: e.acct, IDs: ids, Properties: []string{"threadId"}}, &got)
	if thread == nil || jmap.ID(thread[1]) != got.List[0].ThreadID {
		t.Fatalf("THREADID %v, JMAP %s", thread, got.List[0].ThreadID)
	}
}
