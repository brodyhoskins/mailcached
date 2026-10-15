// Package gate holds requests back: to a limit of requests at a time
// that may change, and after a server asks the client to wait.
package gate

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Gate counts the requests running. The zero Gate is ready.
type Gate struct {
	mu   sync.Mutex
	busy int
	wake chan struct{} // closed when a request ends; nil if none waits
}

// Enter waits until fewer than limit requests run, or ctx ends. A limit
// under 1 is 1. Call Leave when the request ends.
func (g *Gate) Enter(ctx context.Context, limit int) error {
	return g.EnterFunc(ctx, func() int { return limit })
}

// EnterFunc is Enter with a limit that may change while it waits: it is
// read again after each Leave and Wake, outside the gate's lock, so limit
// may take locks of its own.
func (g *Gate) EnterFunc(ctx context.Context, limit func() int) error {
	for {
		// The wake channel is taken before the limit is read: a Wake in
		// between closes it, and the loop reads the limit again.
		g.mu.Lock()
		if g.wake == nil {
			g.wake = make(chan struct{})
		}
		w := g.wake
		g.mu.Unlock()
		n := max(limit(), 1)
		// A request cancelled already does not enter, even with room.
		if err := ctx.Err(); err != nil {
			return err
		}
		g.mu.Lock()
		if g.busy < n {
			g.busy++
			g.mu.Unlock()
			return nil
		}
		g.mu.Unlock()
		select {
		case <-w:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// Busy returns the requests running.
func (g *Gate) Busy() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.busy
}

// Wake has the requests waiting read their limit again, after it rose.
func (g *Gate) Wake() {
	g.mu.Lock()
	if g.wake != nil {
		close(g.wake)
		g.wake = nil
	}
	g.mu.Unlock()
}

// Leave ends a request Enter let through.
func (g *Gate) Leave() {
	g.mu.Lock()
	g.busy--
	g.mu.Unlock()
	g.Wake()
}

// After a 503 or 429 without Retry-After, Backoff waits backoffMin, twice
// as long after each one in a row, up to backoffMax. A Retry-After has no
// such limit.
var (
	backoffMin = 30 * time.Second
	backoffMax = 10 * time.Minute
)

// ErrBusy means the server asked the client to wait longer than the
// request can.
var ErrBusy = errors.New("the server asked to wait")

// Backoff holds requests back after a server answers 503 or 429. The
// zero Backoff is ready.
type Backoff struct {
	mu    sync.Mutex
	until time.Time // no request before
	n     int       // 503s and 429s in a row
}

// Note records a response's status, and its Retry-After header.
func (b *Backoff) Note(status int, retryAfter string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch {
	case status == http.StatusServiceUnavailable || status == http.StatusTooManyRequests:
		b.n++
		d := min(backoffMin<<min(b.n-1, 10), backoffMax)
		if s, err := strconv.Atoi(retryAfter); err == nil && s >= 0 {
			d = time.Duration(s) * time.Second
		} else if t, err := http.ParseTime(retryAfter); err == nil {
			d = time.Until(t)
		}
		// A pause asked for already is never cut short.
		if until := time.Now().Add(max(d, time.Second)); until.After(b.until) {
			b.until = until
		}
	case status >= 200 && status <= 299, status == http.StatusSwitchingProtocols:
		b.n = 0
	}
}

// Wait waits until requests may go out again, or returns ErrBusy at once
// if ctx would end first. A pause made longer while it waits holds it
// longer.
func (b *Backoff) Wait(ctx context.Context) error {
	for {
		b.mu.Lock()
		until := b.until
		b.mu.Unlock()
		d := time.Until(until)
		if d <= 0 {
			return nil
		}
		if dl, ok := ctx.Deadline(); ok && until.After(dl) {
			return fmt.Errorf("%w: %s more", ErrBusy, d.Round(time.Second))
		}
		t := time.NewTimer(d)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return ctx.Err()
		}
	}
}
