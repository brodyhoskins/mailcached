//go:build !linux && !darwin

package netbind

import "net"

// bindsDevice is false: the system cannot tie a socket to an interface,
// so the interface's addresses stand for it.
const bindsDevice = false

func bindDevice(int, string, *net.Interface) error { return nil }
