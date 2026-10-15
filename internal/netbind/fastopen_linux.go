package netbind

import (
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// fastOpen lets clients send their first data in the SYN (TCP Fast Open,
// RFC 7413), which saves a round trip on each connection after the first.
// The queue of such connections not yet accepted is as long as the
// accept backlog. The system must allow it (FastOpenHint); a socket that
// cannot take it, as an MPTCP socket on an older kernel, goes without.
func fastOpen(fd int) {
	_ = unix.SetsockoptInt(fd, unix.IPPROTO_TCP, unix.TCP_FASTOPEN, backlog())
}

// FastOpenHint returns what the system needs for clients' TCP Fast Open,
// "" for nothing.
func FastOpenHint() string {
	if sysctl("/proc/sys/net/ipv4/tcp_fastopen")&2 == 0 {
		return "set net.ipv4.tcp_fastopen=3 for TCP Fast Open from clients"
	}
	return ""
}

func backlog() int {
	if n := sysctl("/proc/sys/net/core/somaxconn"); n > 0 {
		return n
	}
	return unix.SOMAXCONN
}

func sysctl(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}
