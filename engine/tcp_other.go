//go:build !linux

package engine

import (
	"syscall"
	"time"
)

// dialControl does nothing here: TCP_USER_TIMEOUT is Linux's. The
// watchdog closes a dead connection anyway.
func dialControl(time.Duration) func(network, address string, c syscall.RawConn) error { return nil }
