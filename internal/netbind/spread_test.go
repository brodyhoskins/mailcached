package netbind

import (
	"context"
	"net"
	"testing"
	"time"
)

// TestSpread checks that dials take turns over the sources, and that a
// source that fails is passed over.
func TestSpread(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	from := make(chan string, 8)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			from <- host
			c.Close()
		}
	}()
	// 192.0.2.1 is no address of this host: binding to it fails.
	s := NewSpread([]string{"127.0.0.1", "192.0.2.1"}, time.Second, nil)
	for range 4 {
		c, err := s.DialContext(context.Background(), "tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		if got := <-from; got != "127.0.0.1" {
			t.Fatalf("connection from %s, want 127.0.0.1", got)
		}
	}
}

// TestSpreadRotates checks that dials alternate over two sources that
// both work.
func TestSpreadRotates(t *testing.T) {
	if l, err := net.Listen("tcp", "127.0.0.2:0"); err != nil {
		t.Skip("127.0.0.2 is not a local address here")
	} else {
		l.Close()
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	from := make(chan string, 8)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
			from <- host
			c.Close()
		}
	}()
	s := NewSpread([]string{"127.0.0.1", "127.0.0.2"}, time.Second, nil)
	var last string
	for i := range 4 {
		c, err := s.DialContext(context.Background(), "tcp", l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		got := <-from
		if i > 0 && got == last {
			t.Fatalf("dial %d from %s again, want the other source", i, got)
		}
		last = got
	}
}
