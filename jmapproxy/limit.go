package jmapproxy

import (
	"context"
	"math"
	"math/bits"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/brodyhoskins/mailcached/internal/gate"
	procload "github.com/brodyhoskins/mailcached/internal/load"
)

// The requests a client may make at once follow the account's provider,
// which takes fewer when it pushes back, and the process, which takes
// fewer under CPU or memory pressure. The session advertises the lower
// of the two (maxConcurrentRequests, maxConcurrentUpload), rounded down
// to a power of two so that it changes seldom. It is part of the
// session's state: when it changes, clients read the session again.

// gates holds a gate for each account's provider, by login.
type gates struct {
	mu sync.Mutex
	m  map[string]*gate.Gate
}

func (g *gates) get(login string) *gate.Gate {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.m == nil {
		g.m = map[string]*gate.Gate{}
	}
	if g.m[login] == nil {
		g.m[login] = &gate.Gate{}
	}
	return g.m[login]
}

// capacity returns the requests c's provider takes at once, MaxInt for
// no known limit.
func capacity(c *client) int {
	if n := c.acct.Capacity(); n > 0 {
		return n
	}
	return math.MaxInt
}

// limit returns the requests at once to advertise to c: 4 at least, as
// RFC 8620 asks. The gates hold back what the provider or the process
// cannot take.
func limit(c *client) int {
	return max(4, floor2(min(capacity(c), procload.Default.Limit())))
}

// floor2 rounds n down to a power of two, 1 at least.
func floor2(n int) int {
	return 1 << (bits.Len(uint(max(n, 1))) - 1)
}

// enter waits until c's provider and the process have room for one more
// request, or ctx ends. Call leave when the request ends.
func (s *Server) enter(ctx context.Context, c *client) (leave func(), err error) {
	g := s.gates.get(c.login)
	if err := g.EnterFunc(ctx, func() int { return capacity(c) }); err != nil {
		return nil, err
	}
	if err := procload.Default.Enter(ctx); err != nil {
		g.Leave()
		return nil, err
	}
	// The limit advertised is rounded down: requests that fill the
	// rounded process limit may never reach the limit itself, but want
	// more. A client held back by its provider says nothing of the
	// process.
	if procload.Default.Busy() >= floor2(procload.Default.Limit()) {
		procload.Default.Demand()
	}
	return func() {
		procload.Default.Leave()
		g.Leave()
	}, nil
}

// transferTimeout bounds reading a request and writing its answer while
// it holds room: a client that stalls cannot keep it.
var transferTimeout = 5 * time.Minute

// afterKey holds, in a request's context, what auth runs once the
// compressed response is written out.
type afterKey struct{}

// hold is enter for an HTTP request, whose transfer is then bounded by
// transferTimeout. leave clears the deadlines: the server keeps them for
// the connection's next request otherwise, which may be a push stream.
// Under auth, the room and deadlines last until the response is written
// out, compression included, and leave does nothing.
func (s *Server) hold(w http.ResponseWriter, r *http.Request, c *client) (leave func(), err error) {
	enterLeave, err := s.enter(r.Context(), c)
	if err != nil {
		return nil, err
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(transferTimeout))
	_ = rc.SetWriteDeadline(time.Now().Add(transferTimeout))
	leave = func() {
		_ = rc.SetReadDeadline(time.Time{})
		_ = rc.SetWriteDeadline(time.Time{})
		enterLeave()
	}
	if after, ok := r.Context().Value(afterKey{}).(*[]func()); ok {
		*after = append(*after, leave)
		return func() {}, nil
	}
	return leave, nil
}

// sessionState is the session's state: the log's epoch, which changes
// only with the server's version, and the limit advertised.
func sessionState(accountState string, limit int) string {
	epoch, _, _ := strings.Cut(accountState, "-")
	return epoch + "-" + strconv.Itoa(limit)
}
