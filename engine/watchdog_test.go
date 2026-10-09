package engine

import (
	"net"
	"testing"
	"time"
)

// TestWatchdog closes a connection whose write gets no answer, and leaves
// alone one that is answered, or silent with nothing asked.
func TestWatchdog(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	w := newWatchdog(client, 100*time.Millisecond)
	defer w.Close()
	go func() {
		buf := make([]byte, 64)
		n, _ := server.Read(buf)
		server.Write(buf[:n]) // the first command is answered
		server.Read(buf)      // the second is not
	}()

	if _, err := w.Write([]byte("a NOOP\r\n")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	if _, err := w.Read(buf); err != nil {
		t.Fatal(err)
	}
	// Silence with nothing asked: the connection stays.
	time.Sleep(250 * time.Millisecond)
	if _, err := w.Write([]byte("b NOOP\r\n")); err != nil {
		t.Fatalf("closed while idle: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := w.Read(buf)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("read after no answer: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the watchdog did not close the connection")
	}
}
