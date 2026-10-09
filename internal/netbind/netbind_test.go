package netbind

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// loopback returns the loopback interface's name.
func loopback(t *testing.T) string {
	t.Helper()
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagLoopback != 0 && ifc.Flags&net.FlagUp != 0 {
			return ifc.Name
		}
	}
	t.Skip("no loopback interface")
	return ""
}

// roundTrip dials addr with d and checks that a byte comes back.
func roundTrip(t *testing.T, l net.Listener, d *net.Dialer, addr string) {
	t.Helper()
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		_, _ = io.Copy(c, c)
		c.Close()
	}()
	c, err := d.DialContext(context.Background(), "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(c, b); err != nil {
		t.Fatal(err)
	}
}

func TestInterface(t *testing.T) {
	lo := loopback(t)
	l, err := Listen(context.Background(), lo+":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	roundTrip(t, l, Dialer(lo, 5*time.Second, nil), net.JoinHostPort("127.0.0.1", port))
}

func TestSourceAddress(t *testing.T) {
	l, err := Listen(context.Background(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	roundTrip(t, l, Dialer("127.0.0.1", 5*time.Second, nil), l.Addr().String())
}

func TestMissingInterface(t *testing.T) {
	_, err := Dialer("nosuchif0", time.Second, nil).Dial("tcp", "127.0.0.1:9")
	if err == nil {
		t.Fatal("a dial through a missing interface worked")
	}
}

func TestMultiClose(t *testing.T) {
	var ls []net.Listener
	for range 2 {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ls = append(ls, l)
	}
	m := Multi(ls)
	done := make(chan error)
	go func() { _, err := m.Accept(); done <- err }()
	m.Close()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Accept after Close returned no error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
}
