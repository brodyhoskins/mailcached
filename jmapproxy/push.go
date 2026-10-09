package jmapproxy

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/brodyhoskins/mailcached/internal/jmap"
)

// pushTypes are the types a StateChange names.
var pushTypes = []string{"Email", "Mailbox", "Thread", "EmailDelivery", "Identity", "EmailSubmission"}

// serveEvents is the event source (RFC 8620 section 7.3): a StateChange
// whenever the account changes, and pings if asked.
func (s *Server) serveEvents(w http.ResponseWriter, r *http.Request) {
	c := clientOf(r)
	q := r.URL.Query()
	types := pushTypes
	if t := q.Get("types"); t != "" && t != "*" {
		types = slices.DeleteFunc(strings.Split(t, ","), func(x string) bool { return !slices.Contains(pushTypes, x) })
	}
	closeAfter := q.Get("closeafter") == "state"
	ping, _ := strconv.Atoi(q.Get("ping"))
	if ping > 0 {
		ping = max(ping, 5)
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.WriteHeader(http.StatusOK)

	send := func(state string) bool {
		changed := map[string]jmap.State{}
		for _, t := range types {
			changed[t] = jmap.State(state)
		}
		b, _ := json.Marshal(jmap.StateChange{Type: "StateChange", Changed: map[jmap.ID]map[string]jmap.State{c.id: changed}})
		if _, err := fmt.Fprintf(w, "event: state\ndata: %s\n\n", b); err != nil {
			return false
		}
		flusher.Flush()
		return true
	}
	a := c.acct
	a.Lock()
	state, wake := a.State(), a.Changed()
	a.Unlock()
	if !send(state) {
		return
	}
	var tick <-chan time.Time
	if ping > 0 {
		t := time.NewTicker(time.Duration(ping) * time.Second)
		defer t.Stop()
		tick = t.C
	}
	quit := s.quitting()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-quit:
			return
		case <-tick:
			if _, err := fmt.Fprintf(w, "event: ping\ndata: {\"interval\":%d}\n\n", ping); err != nil {
				return
			}
			flusher.Flush()
		case <-wake:
			// Changes often come in bursts: one event for the burst.
			time.Sleep(50 * time.Millisecond)
			a.Lock()
			now := a.State()
			wake = a.Changed()
			a.Unlock()
			if now == state {
				continue
			}
			state = now
			if !send(state) || closeAfter {
				return
			}
		}
	}
}
