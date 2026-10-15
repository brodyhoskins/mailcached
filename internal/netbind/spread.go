package netbind

import (
	"context"
	"math/rand/v2"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

// Spread dials from several sources in turn, so connections to a server
// share them: a server that caps the connections from one address allows
// more over several. A dial that fails is tried from the next source.
type Spread struct {
	dialers []*net.Dialer
	timeout time.Duration
	next    atomic.Uint32
}

// NewSpread returns a Spread over sources (interface names or local IP
// addresses; none for wherever routing says), starting at a random one.
// control is as for Dialer.
func NewSpread(sources []string, timeout time.Duration, control func(network, address string, c syscall.RawConn) error) *Spread {
	if len(sources) == 0 {
		sources = []string{""}
	}
	s := &Spread{timeout: timeout}
	for _, src := range sources {
		s.dialers = append(s.dialers, Dialer(src, timeout, control))
	}
	s.next.Store(rand.Uint32N(uint32(len(s.dialers))))
	return s
}

// DialContext dials address from the next source.
func (s *Spread) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	start := s.next.Add(1)
	n := uint32(len(s.dialers))
	if n > 1 && s.timeout > 0 {
		// The timeout is for all the sources together, shared below; an
		// earlier deadline of the caller's stands.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	var err error
	for i := range n {
		// Each source left gets its share of the time left: one that
		// drops packets leaves time for the others.
		dctx := ctx
		if dl, ok := ctx.Deadline(); ok && n-i > 1 {
			var cancel context.CancelFunc
			dctx, cancel = context.WithTimeout(ctx, time.Until(dl)/time.Duration(n-i))
			defer cancel()
		}
		var c net.Conn
		if c, err = s.dialers[(start+i)%n].DialContext(dctx, network, address); err == nil {
			return c, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, err
}
