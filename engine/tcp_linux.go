package engine

import (
	"errors"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// dialControl caps how long TCP retransmits unacknowledged data before it
// fails the connection (TCP_USER_TIMEOUT), instead of the 15 minutes of
// tcp_retries2. An MPTCP socket on a kernel that does not take the option
// goes without it: the watchdog still closes a dead connection.
//
// With fastOpen, the first data goes in the SYN (TCP Fast Open) to a
// server that gave the system a cookie before: a round trip saved. Only
// for a protocol where the client speaks first (TLS, HTTP): the SYN waits
// for the first write. A socket that cannot goes without.
func dialControl(timeout time.Duration, fastOpen bool) func(network, address string, c syscall.RawConn) error {
	ms := int(timeout / time.Millisecond)
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if fastOpen {
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_FASTOPEN_CONNECT, 1)
			}
			serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_USER_TIMEOUT, ms)
		})
		if err != nil {
			return err
		}
		if errors.Is(serr, unix.EOPNOTSUPP) || errors.Is(serr, unix.ENOPROTOOPT) {
			return nil
		}
		return serr
	}
}
