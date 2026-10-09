package smtpproxy

import (
	"bufio"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// TestCloseDrains checks that Close waits for clients only up to
// drainTimeout, then closes the ones left.
func TestCloseDrains(t *testing.T) {
	old := drainTimeout
	drainTimeout = 200 * time.Millisecond
	t.Cleanup(func() { drainTimeout = old })

	b := &Server{
		Route:  func(string) (Upstream, bool) { return Upstream{}, false },
		Domain: "proxy.test",
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go b.Serve(l)
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := bufio.NewReader(c)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Close took %v", d)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := r.ReadString('\n'); err == nil {
		t.Fatal("the idle client is still connected")
	} else if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("the idle client is still connected")
	}
}
