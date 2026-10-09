package netbind

import (
	"net"

	"golang.org/x/sys/unix"
)

const bindsDevice = true

// bindDevice ties the socket to the interface. Since Linux 5.7 this needs
// no privilege on a socket not yet bound.
func bindDevice(fd int, _ string, ifc *net.Interface) error {
	return unix.BindToDevice(fd, ifc.Name)
}
