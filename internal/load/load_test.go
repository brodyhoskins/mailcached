package load

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime/metrics"
	"testing"
	"time"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// The limit doubles under demand until the first pressure, falls by a
// quarter under it, then grows by a little until forgetAfter passes.
func TestLimiterSteps(t *testing.T) {
	l := &Limiter{limit: 4, probing: true}
	now := time.Now()
	ctx := context.Background()
	fill := func() {
		for range l.Limit() {
			if err := l.Enter(ctx); err != nil {
				t.Fatal(err)
			}
		}
	}
	drain := func() {
		for l.gate.Busy() > 0 {
			l.Leave()
		}
	}

	// No demand: the limit stays.
	l.step(now, Pressure{}, quiet)
	if got := l.Limit(); got != 4 {
		t.Fatalf("limit %d without demand, want 4", got)
	}
	fill()
	l.step(now, Pressure{}, quiet)
	if got := l.Limit(); got != 8 {
		t.Fatalf("limit %d after demand while probing, want 8", got)
	}
	l.step(now, Pressure{Memory: "test"}, quiet)
	if got := l.Limit(); got != 6 {
		t.Fatalf("limit %d under pressure, want 6", got)
	}
	if !l.Pressed() {
		t.Fatal("not pressed under pressure")
	}
	drain()
	fill()
	l.step(now.Add(time.Second), Pressure{}, quiet)
	if got := l.Limit(); got != 7 {
		t.Fatalf("limit %d after demand past pressure, want 7", got)
	}
	drain()
	fill()
	l.step(now.Add(forgetAfter), Pressure{}, quiet)
	if got := l.Limit(); got != 14 {
		t.Fatalf("limit %d after forgetAfter, want 14", got)
	}
	drain()
	for range 10 {
		l.step(now, Pressure{CPU: "test"}, quiet)
	}
	if got := l.Limit(); got != 1 {
		t.Fatalf("limit %d after long pressure, want 1", got)
	}
}

// A request waiting at the limit enters when the limit rises.
func TestLimiterWakes(t *testing.T) {
	l := &Limiter{limit: 1, probing: true}
	ctx := context.Background()
	if err := l.Enter(ctx); err != nil {
		t.Fatal(err)
	}
	in := make(chan error, 1)
	go func() { in <- l.Enter(ctx) }()
	time.Sleep(50 * time.Millisecond)
	l.step(time.Now(), Pressure{}, quiet)
	select {
	case err := <-in:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a waiting request did not enter when the limit rose")
	}
}

func TestP99(t *testing.T) {
	buckets := []float64{0, 0.001, 0.01, 0.1, 1}
	old := &metrics.Float64Histogram{Counts: []uint64{0, 0, 0, 0}, Buckets: buckets}
	h := &metrics.Float64Histogram{Counts: []uint64{90, 9, 1, 0}, Buckets: buckets}
	if got := p99(old, h); got != time.Millisecond {
		t.Fatalf("p99 %s, want 1ms", got)
	}
	h.Counts = []uint64{50, 0, 0, 50}
	if got := p99(old, h); got != 100*time.Millisecond {
		t.Fatalf("p99 %s, want 100ms", got)
	}
	h.Counts = []uint64{1, 0, 0, 1}
	if got := p99(old, h); got != 0 {
		t.Fatalf("p99 %s from 2 samples, want 0", got)
	}
}

func TestFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	psi := write("cpu.pressure", "some avg10=1.00 avg60=0.50 avg300=0.10 total=123456\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n")
	if got := psiTotal(psi); got != 123456 {
		t.Fatalf("psi total %v, want 123456", got)
	}
	stat := write("memory.stat", "anon 100\nfile 200\ninactive_file 150\n")
	if got := statInt(stat, "inactive_file"); got != 150 {
		t.Fatalf("inactive_file %d, want 150", got)
	}
	if got := readInt(write("memory.max", "max\n")); got != 0 {
		t.Fatalf("memory.max of max read as %d, want 0", got)
	}
}
