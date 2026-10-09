package imapproxy

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// TestCloseSaysBye checks that a client, idling, gets a BYE when the
// proxy shuts down, not only a dropped connection.
func TestCloseSaysBye(t *testing.T) {
	e := newEnv(t)
	c, err := net.Dial("tcp", e.proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := bufio.NewReader(c)
	readUntil := func(prefix string) {
		t.Helper()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				t.Fatalf("waiting for %q: %v", prefix, err)
			}
			if strings.HasPrefix(line, prefix) {
				return
			}
		}
	}
	readUntil("* OK")
	fmt.Fprintf(c, "a LOGIN %s \"%s\"\r\n", alice, password)
	readUntil("a OK")
	fmt.Fprintf(c, "b SELECT INBOX\r\nc IDLE\r\n")
	readUntil("+ ")

	if err := e.b.Close(); err != nil {
		t.Fatal(err)
	}
	readUntil("* BYE")
}
