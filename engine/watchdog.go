package engine

import (
	"net"
	"sync"
	"time"
)

// A provider connection can die without a word: the provider's host goes
// away, or a NAT forgets the connection. Writes then wait in the socket
// until TCP gives up, which takes about 15 minutes on Linux, and the
// command waits with them. watchdog closes such a connection.
//
// It does not know IMAP: it only knows that every command gets an answer.
// When the proxy writes and nothing at all comes back within timeout of
// its last write, it closes the connection, and the command fails, so the
// engine reconnects.
// Any byte read counts as an answer. A provider that answers slowly but
// steadily is left alone, and so is an IDLE that waits in silence after
// the provider's "+ idling": nothing was written since it.
type watchdog struct {
	net.Conn
	timeout time.Duration

	mu      sync.Mutex
	waiting bool // the last write has had no answer yet
	timer   *time.Timer
	fired   bool
}

func newWatchdog(c net.Conn, timeout time.Duration) *watchdog {
	w := &watchdog{Conn: c, timeout: timeout}
	w.timer = time.AfterFunc(time.Hour, w.expire)
	w.timer.Stop()
	return w
}

func (w *watchdog) Write(b []byte) (int, error) {
	n, err := w.Conn.Write(b)
	if n > 0 {
		w.mu.Lock()
		// Each write that goes through starts the time again: a long
		// upload (APPEND) gets its answer only at the end, and a write
		// goes through only while the provider takes the data.
		if !w.fired {
			w.waiting = true
			w.timer.Reset(w.timeout)
		}
		w.mu.Unlock()
	}
	return n, err
}

func (w *watchdog) Read(b []byte) (int, error) {
	n, err := w.Conn.Read(b)
	if n > 0 {
		w.mu.Lock()
		if w.waiting {
			w.waiting = false
			w.timer.Stop()
		}
		w.mu.Unlock()
	}
	return n, err
}

func (w *watchdog) expire() {
	w.mu.Lock()
	if !w.waiting {
		w.mu.Unlock()
		return
	}
	w.fired = true
	w.mu.Unlock()
	w.Conn.Close()
}

func (w *watchdog) Close() error {
	w.timer.Stop()
	return w.Conn.Close()
}
