package netbind

import (
	"net"

	"golang.org/x/sys/unix"
)

const bindsDevice = true

// bindDevice ties the socket to the interface, by its index.
func bindDevice(fd int, network string, ifc *net.Interface) error {
	if network == "tcp4" {
		return unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_BOUND_IF, ifc.Index)
	}
	return unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, ifc.Index)
}
