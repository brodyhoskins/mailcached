package gate

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"
)

func TestGate(t *testing.T) {
	var g Gate
	ctx := context.Background()
	for range 2 {
		if err := g.Enter(ctx, 2); err != nil {
			t.Fatal(err)
		}
	}
	short, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := g.Enter(short, 2); err == nil {
		t.Fatal("a third request entered a gate of two")
	}
	in := make(chan error, 1)
	go func() { in <- g.Enter(ctx, 2) }()
	g.Leave()
	select {
	case err := <-in:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("a waiting request did not enter after one left")
	}
	// A lower limit holds new requests while more run.
	short, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()
	if err := g.Enter(short, 1); err == nil {
		t.Fatal("a request entered over a lowered limit")
	}
}

// A request cancelled already does not enter, even with room.
func TestGateCancelled(t *testing.T) {
	var g Gate
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := g.Enter(ctx, 2); err == nil {
		t.Fatal("a cancelled request entered")
	}
	if n := g.Busy(); n != 0 {
		t.Fatalf("%d busy after a cancelled request, want 0", n)
	}
}

func TestBackoff(t *testing.T) {
	var b Backoff
	ctx := context.Background()
	if err := b.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	b.Note(http.StatusServiceUnavailable, "1")
	short, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
	defer cancel()
	if err := b.Wait(short); !errors.Is(err, ErrBusy) {
		t.Fatalf("got %v during Retry-After, want ErrBusy", err)
	}
	start := time.Now()
	if err := b.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d < 500*time.Millisecond {
		t.Fatalf("waited %s, want about 1s", d)
	}
	// Without Retry-After, the pause doubles with each one in a row, and
	// a success starts it over.
	b.Note(http.StatusTooManyRequests, "")
	b.Note(http.StatusTooManyRequests, "")
	if d := time.Until(b.until); d < 50*time.Second {
		t.Fatalf("second pause %s, want 60s", d)
	}
	b.Note(http.StatusOK, "")
	b.until = time.Time{} // the pause has passed
	b.Note(http.StatusTooManyRequests, "")
	if d := time.Until(b.until); d > 31*time.Second {
		t.Fatalf("pause %s after a success, want 30s", d)
	}
	// A shorter pause asked for later does not cut it short.
	b.Note(http.StatusServiceUnavailable, "1")
	if d := time.Until(b.until); d < 29*time.Second {
		t.Fatalf("pause cut to %s by a shorter Retry-After", d)
	}
}

// A Retry-After longer than backoffMax holds requests for all of it.
func TestBackoffLongRetryAfter(t *testing.T) {
	var b Backoff
	b.Note(http.StatusTooManyRequests, "3600")
	if d := time.Until(b.until); d < 59*time.Minute {
		t.Fatalf("paused %s, want an hour", d.Round(time.Second))
	}
}

// A pause made longer while a request waits holds that request too.
func TestBackoffExtended(t *testing.T) {
	var b Backoff
	b.Note(http.StatusServiceUnavailable, "1")
	done := make(chan time.Time, 1)
	go func() {
		_ = b.Wait(context.Background())
		done <- time.Now()
	}()
	time.Sleep(100 * time.Millisecond)
	start := time.Now()
	b.Note(http.StatusServiceUnavailable, "2")
	if at := <-done; at.Sub(start) < 1500*time.Millisecond {
		t.Fatalf("resumed %s after the pause grew to 2s", at.Sub(start).Round(time.Millisecond))
	}
}
