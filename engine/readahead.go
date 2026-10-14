package engine

import (
	"cmp"
	"errors"
	"slices"

	"github.com/emersion/go-imap/v2"
)

// Read-ahead serves a client that downloads a folder message by message,
// as Apple Mail does for its offline copy: one small request at a time,
// each waiting for the last. Each such request would wait for a round trip
// to the provider. When a client reads whole messages in one direction
// through a folder (lower UIDs each time, or higher), the proxy downloads
// the next readAheadCount messages that way in one bulk download, ahead of
// the client, and again when the client gets halfway there. It downloads
// only what the client is reading in order, not the whole folder, and as
// bulk work, so other requests go first.

var (
	// ReadAheadCount is how many messages one read-ahead downloads.
	ReadAheadCount = 100
	// readAheadAfter is how many requests in one direction start it.
	readAheadAfter = 2
)

// readAhead is a folder's reading pattern.
type readAhead struct {
	lo, hi  imap.UID // the last request's UIDs
	dir     int      // -1 lower UIDs each time, +1 higher, 0 unknown
	streak  int      // requests in a row in dir
	edge    imap.UID // the farthest UID read ahead, 0 for none
	running bool
}

// noteRead records a client's request for whole messages (or parts of
// them) in folder name, and starts a read-ahead when the client reads in
// one direction.
func (a *Account) noteRead(name string, uids []imap.UID) {
	if len(uids) == 0 || ReadAheadCount <= 0 {
		return
	}
	lo, hi := slices.Min(uids), slices.Max(uids)
	a.raMu.Lock()
	if a.ra == nil {
		a.ra = map[string]*readAhead{}
	}
	r := a.ra[name]
	if r == nil {
		r = &readAhead{}
		a.ra[name] = r
	}
	dir := 0
	switch {
	case r.hi == 0:
	case hi < r.lo:
		dir = -1
	case lo > r.hi:
		dir = 1
	}
	switch {
	case dir == 0:
		// The same messages again (structure, then body): no change.
	case dir == r.dir:
		r.streak++
	default:
		r.dir, r.streak, r.edge = dir, 1, 0
	}
	r.lo, r.hi = lo, hi
	if r.streak < readAheadAfter || r.running {
		a.raMu.Unlock()
		return
	}
	cursor, edge, dir := lo, r.edge, r.dir
	if dir > 0 {
		cursor = hi
	}
	a.raMu.Unlock()

	// The next messages past the cursor, or past what was read ahead
	// already once the client is halfway there.
	a.mu.Lock()
	var next []*Message
	if m := a.boxes[name]; m != nil {
		i, _ := slices.BinarySearchFunc(m.msgs, cursor, func(x *Message, u imap.UID) int { return cmp.Compare(x.uid, u) })
		if dir < 0 {
			from := i // messages below cursor are m.msgs[:i]
			if edge != 0 && edge < cursor {
				e, _ := slices.BinarySearchFunc(m.msgs, edge, func(x *Message, u imap.UID) int { return cmp.Compare(x.uid, u) })
				if i-e > ReadAheadCount/2 {
					from = -1 // far enough ahead still
				} else {
					from = e
				}
			}
			if from > 0 {
				next = slices.Clone(m.msgs[max(0, from-ReadAheadCount):from])
			}
		} else {
			from := i
			if i < len(m.msgs) && m.msgs[i].uid == cursor {
				from = i + 1
			}
			if edge != 0 && edge > cursor {
				e, _ := slices.BinarySearchFunc(m.msgs, edge, func(x *Message, u imap.UID) int { return cmp.Compare(x.uid, u) })
				if e-i > ReadAheadCount/2 {
					from = -1
				} else {
					from = e + 1
				}
			}
			if from >= 0 && from < len(m.msgs) {
				next = slices.Clone(m.msgs[from:min(len(m.msgs), from+ReadAheadCount)])
			}
		}
	}
	a.mu.Unlock()
	if len(next) == 0 {
		return
	}

	a.raMu.Lock()
	if r.running {
		a.raMu.Unlock()
		return
	}
	r.running = true
	if dir < 0 {
		r.edge = next[0].uid
		// Nearest to the client first: download keeps the order.
		slices.Reverse(next)
	} else {
		r.edge = next[len(next)-1].uid
	}
	a.raMu.Unlock()
	go func() {
		defer func() {
			a.raMu.Lock()
			r.running = false
			a.raMu.Unlock()
		}()
		// download skips what is cached already.
		if err := a.download(next, nil, true, nil); err != nil && !errors.Is(err, ErrNoCredentials) {
			a.b.Log.Info("imap: read-ahead stopped", "user", a.login, "mailbox", name, "err", err)
		}
	}()
}
