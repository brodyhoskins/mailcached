// Package netbind ties sockets to a network interface or a local
// address: listeners that accept on chosen interfaces only, and outgoing
// connections that leave through a chosen interface.
//
// An interface is bound to as a device where the system can (Linux:
// SO_BINDTODEVICE, macOS: IP_BOUND_IF), so routing cannot send the
// packets elsewhere, and a connection accepted on it answers through it.
// Elsewhere, the interface's addresses stand for it.
package netbind

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Interface returns the interface named name, nil if name is an IP
// address, a host name or empty.
func Interface(name string) *net.Interface {
	if name == "" {
		return nil
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return nil
	}
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil
	}
	return ifc
}

// Listen listens for TCP on addr, host:port, where host is an IP address,
// a host name, an interface name, or empty for every address. Clients
// that have Multipath TCP or TCP Fast Open get them where the system does
// (Linux).
func Listen(ctx context.Context, addr string) (net.Listener, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	ifc := Interface(host)
	if ifc == nil {
		lc := listenConfig(nil)
		return lc.Listen(ctx, "tcp", addr)
	}
	if bindsDevice {
		// One socket for each family, both tied to the interface.
		var ls []net.Listener
		var errs []error
		for _, nw := range []string{"tcp4", "tcp6"} {
			lc := listenConfig(func(network string, fd int) error { return bindDevice(fd, network, ifc) })
			l, err := lc.Listen(ctx, nw, net.JoinHostPort("", port))
			if err != nil {
				errs = append(errs, err)
				continue
			}
			ls = append(ls, l)
		}
		if len(ls) == 0 {
			return nil, fmt.Errorf("listen on %s: %w", host, errors.Join(errs...))
		}
		return Multi(ls), nil
	}
	ips, err := addrs(ifc)
	if err != nil {
		return nil, err
	}
	var ls []net.Listener
	for _, ip := range ips {
		lc := listenConfig(nil)
		l, err := lc.Listen(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if err != nil {
			for _, l := range ls {
				l.Close()
			}
			return nil, fmt.Errorf("listen on %s: %w", host, err)
		}
		ls = append(ls, l)
	}
	return Multi(ls), nil
}

// listenConfig returns the configuration for a listener: Multipath TCP,
// TCP Fast Open, and bind, if not nil, on the socket.
func listenConfig(bind func(network string, fd int) error) net.ListenConfig {
	lc := net.ListenConfig{Control: func(network, _ string, c syscall.RawConn) error {
		return onFD(c, func(fd int) error {
			fastOpen(fd)
			if bind != nil {
				return bind(network, fd)
			}
			return nil
		})
	}}
	lc.SetMultipathTCP(true)
	return lc
}

// addrs returns an interface's addresses, without link-local ones.
func addrs(ifc *net.Interface) ([]netip.Addr, error) {
	as, err := ifc.Addrs()
	if err != nil {
		return nil, fmt.Errorf("interface %s: %w", ifc.Name, err)
	}
	var out []netip.Addr
	for _, a := range as {
		p, err := netip.ParsePrefix(a.String())
		if err != nil || p.Addr().IsLinkLocalUnicast() {
			continue
		}
		out = append(out, p.Addr().Unmap())
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("interface %s has no address", ifc.Name)
	}
	return out, nil
}

// Dialer returns a dialer whose connections leave from source: an
// interface name, an IP address, or empty for wherever routing says.
// control, if not nil, also runs on each socket. The interface is looked
// up at each dial, so it may come up after the dialer is made.
func Dialer(source string, timeout time.Duration, control func(network, address string, c syscall.RawConn) error) *net.Dialer {
	d := &net.Dialer{Timeout: timeout, Control: control}
	if source == "" {
		// Multipath TCP where the system and the server have it (Linux),
		// TCP otherwise. A connection tied to a source keeps to one path.
		d.SetMultipathTCP(true)
		return d
	}
	if ip, err := netip.ParseAddr(source); err == nil {
		d.LocalAddr = &net.TCPAddr{IP: ip.AsSlice()}
		return d
	}
	d.Control = func(network, address string, c syscall.RawConn) error {
		if control != nil {
			if err := control(network, address, c); err != nil {
				return err
			}
		}
		ifc, err := net.InterfaceByName(source)
		if err != nil {
			return fmt.Errorf("source %s: %w", source, err)
		}
		if bindsDevice {
			return onFD(c, func(fd int) error { return bindDevice(fd, network, ifc) })
		}
		// Bind to the interface's address of the connection's family.
		ips, err := addrs(ifc)
		if err != nil {
			return err
		}
		for _, ip := range ips {
			if ip.Is4() == (network == "tcp4") {
				return onFD(c, func(fd int) error { return unix.Bind(fd, sockaddr(ip)) })
			}
		}
		return fmt.Errorf("interface %s has no address for %s", source, network)
	}
	return d
}

func sockaddr(ip netip.Addr) unix.Sockaddr {
	if ip.Is4() {
		return &unix.SockaddrInet4{Addr: ip.As4()}
	}
	return &unix.SockaddrInet6{Addr: ip.As16()}
}

// onFD runs f on the socket's descriptor.
func onFD(c syscall.RawConn, f func(fd int) error) error {
	var ferr error
	if err := c.Control(func(fd uintptr) { ferr = f(int(fd)) }); err != nil {
		return err
	}
	return ferr
}

// Multi accepts on several listeners as one. Its Addr is the first's.
func Multi(ls []net.Listener) net.Listener {
	if len(ls) == 1 {
		return ls[0]
	}
	m := &multi{ls: ls, conns: make(chan accepted), done: make(chan struct{})}
	for _, l := range ls {
		go m.accept(l)
	}
	return m
}

type accepted struct {
	c   net.Conn
	err error
}

type multi struct {
	ls    []net.Listener
	conns chan accepted
	done  chan struct{}
	once  sync.Once
}

func (m *multi) accept(l net.Listener) {
	for {
		c, err := l.Accept()
		select {
		case m.conns <- accepted{c, err}:
		case <-m.done:
			if c != nil {
				c.Close()
			}
			return
		}
		if err != nil {
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				return
			}
		}
	}
}

func (m *multi) Accept() (net.Conn, error) {
	select {
	case a := <-m.conns:
		return a.c, a.err
	case <-m.done:
		return nil, net.ErrClosed
	}
}

func (m *multi) Close() error {
	var errs []error
	m.once.Do(func() {
		close(m.done)
		for _, l := range m.ls {
			errs = append(errs, l.Close())
		}
	})
	return errors.Join(errs...)
}

func (m *multi) Addr() net.Addr { return m.ls[0].Addr() }
