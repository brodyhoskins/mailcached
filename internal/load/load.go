// Package load keeps the process within the CPU and memory it has. It
// sets the Go memory limit from the container's or the machine's memory,
// watches for pressure on either, and holds a limit on the client
// requests served at once. The limit grows while requests reach it and
// nothing is under pressure, and falls by a quarter each second something
// is. Until the first pressure it doubles, as TCP's slow start does; after
// it, it grows by a little, until forgetAfter passes without pressure.
package load

import (
	"context"
	"fmt"
	"log/slog"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/brodyhoskins/mailcached/internal/gate"
)

var (
	tick        = time.Second
	forgetAfter = 10 * time.Minute
)

// maxLimit keeps the limit from overflowing; no process runs as many
// requests at once.
const maxLimit = 1 << 20

// Limiter holds a limit on requests at a time that follows the pressure
// on the process. The zero Limiter is not ready: use New.
type Limiter struct {
	gate gate.Gate

	mu        sync.Mutex
	limit     int
	probing   bool      // no pressure since forgetAfter: the limit doubles
	pressedAt time.Time // when pressure was last seen
	pressure  Pressure  // at the last tick
	peak      int       // most requests at once since the last tick
	waited    bool      // a request waited since the last tick
	// What the log said last, when, and why the limit changed since.
	shown    int
	loggedAt time.Time
	why      []string
}

// New returns a Limiter that starts at two requests for each CPU.
func New() *Limiter {
	n := 2 * runtime.GOMAXPROCS(0)
	return &Limiter{limit: n, shown: n, probing: true}
}

// Default is the process's Limiter, which Start runs.
var Default = New()

// Start sets the Go memory limit and has Default follow the pressure on
// the process until ctx ends.
func Start(ctx context.Context, log *slog.Logger) {
	if n := setMemoryLimit(); n > 0 {
		log.Info("memory limit", "bytes", n)
	}
	s := newSampler()
	if runtime.GOOS == "linux" && s.psi[0] == "" {
		log.Info("load: the kernel reports no pressure stall information", "hint", "add psi=1 to the kernel command line")
	}
	log.Info("load: limit", "limit", Default.Limit())
	go Default.Run(ctx, s, log)
}

// Limit returns the requests the process takes at once now.
func (l *Limiter) Limit() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.limit
}

// Pressed reports whether the process was under pressure at the last
// tick: no time to grow anything.
func (l *Limiter) Pressed() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.pressure.Any()
}

// Enter waits until the limit has room for one more request, or ctx
// ends. Call Leave when the request ends.
func (l *Limiter) Enter(ctx context.Context) error {
	if l.gate.Busy() >= l.Limit() {
		l.mu.Lock()
		l.waited = true
		l.mu.Unlock()
	}
	if err := l.gate.EnterFunc(ctx, l.Limit); err != nil {
		return err
	}
	n := l.gate.Busy()
	l.mu.Lock()
	l.peak = max(l.peak, n)
	l.mu.Unlock()
	return nil
}

// Demand records that a client used all the room it was told of, which
// may be less than the limit: the limit may grow.
func (l *Limiter) Demand() {
	l.mu.Lock()
	l.waited = true
	l.mu.Unlock()
}

// Busy returns the requests running.
func (l *Limiter) Busy() int { return l.gate.Busy() }

// Leave ends a request Enter let through.
func (l *Limiter) Leave() { l.gate.Leave() }

// Run samples the pressure each tick and moves the limit, until ctx
// ends.
func (l *Limiter) Run(ctx context.Context, s sampler, log *slog.Logger) {
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			l.step(now, s.sample(), log)
		}
	}
}

// logEvery is the most often the log reports the limit.
var logEvery = 5 * time.Second

// because records why the limit changed (l.mu held).
func (l *Limiter) because(why string) {
	if !slices.Contains(l.why, why) {
		l.why = append(l.why, why)
	}
}

// step moves the limit for the pressure p found at now.
func (l *Limiter) step(now time.Time, p Pressure, log *slog.Logger) {
	busy := l.gate.Busy() // before l.mu: the gate's lock is never taken under it
	l.mu.Lock()
	was, old := l.pressure, l.limit
	l.pressure = p
	demand := l.waited || l.peak >= l.limit
	l.waited, l.peak = false, busy
	switch {
	case p.Any():
		l.limit = max(1, l.limit*3/4)
		l.probing = false
		l.pressedAt = now
	case demand:
		if !l.probing && now.Sub(l.pressedAt) >= forgetAfter {
			l.probing = true
		}
		if l.probing {
			l.limit *= 2
		} else {
			l.limit += 1 + l.limit/16
		}
		l.limit = min(l.limit, maxLimit)
	}
	limit := l.limit
	switch {
	case limit < old:
		l.because("pressure from " + p.String())
	case limit > old && l.probing:
		l.because("demand, probing")
	case limit > old:
		l.because("demand")
	}
	// At most every logEvery: the limit moves each tick under load.
	var shown int
	var why []string
	switch {
	case limit == l.shown:
		l.why = nil // back where the log left it
	case now.Sub(l.loggedAt) >= logEvery:
		shown, why = l.shown, l.why
		l.shown, l.loggedAt, l.why = limit, now, nil
	}
	l.mu.Unlock()
	if why != nil {
		log.Info("load: limit", "limit", fmt.Sprintf("%d -> %d", shown, limit), "why", strings.Join(why, ", "))
	}
	if limit > old {
		l.gate.Wake()
	}
	switch {
	case p.Any() && !was.Any():
		log.Warn("load: under pressure", "pressure", p.String(), "limit", limit)
	case !p.Any() && was.Any():
		log.Info("load: pressure gone", "limit", limit)
	}
}
