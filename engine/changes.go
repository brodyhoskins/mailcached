package engine

import (
	"cmp"
	"crypto/rand"
	"database/sql"
	"encoding/base32"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// The change log lets clients that keep their own copy of an account
// (JMAP) ask what changed since a state, and wake when something does.
// Every change to what such a client sees bumps the account's modseq and
// stamps the object: an email (all the messages that share a cache key:
// the same message in several folders), or a folder. A folder whose
// message counts alone changed is stamped apart, so clients can update
// the counts without reading the folder again.
//
// A state is the log's epoch and a modseq, "epoch-modseq". The epoch is
// new whenever the log starts empty (a new database, or none), so a state
// from before can never be taken for a later one.

// The kinds of object the log stamps.
const (
	KindEmail   = "Email"
	KindMailbox = "Mailbox"
)

// stamp is one object's place in the log: when it was created, last
// changed (counts apart, for folders), and destroyed (0: it exists).
type stamp struct {
	created, changed, counts, destroyed int64
}

// changeLog is an account's log (a.mu held).
type changeLog struct {
	epoch  string
	modseq int64
	// since is the oldest modseq the log can answer from: entries of
	// objects destroyed before it were dropped.
	since   int64
	entries map[string]map[string]*stamp // kind -> id -> stamp
	// touched holds the objects changed since the last settle, and
	// whether only their counts changed.
	touched map[[2]string]bool
	dirty   map[[2]string]bool // kind, id: to save
	// exists reports whether an object exists now.
	exists func(kind, id string) bool
	// wake is closed and replaced on every change.
	wake chan struct{}
}

func newChangeLog() *changeLog {
	return &changeLog{epoch: newEpoch(), entries: map[string]map[string]*stamp{KindEmail: {}, KindMailbox: {}},
		touched: map[[2]string]bool{}, dirty: map[[2]string]bool{}, wake: make(chan struct{})}
}

func newEpoch() string {
	var b [5]byte
	_, _ = rand.Read(b[:])
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b[:]))
}

// state returns the state string for modseq.
func (l *changeLog) state(modseq int64) string { return l.epoch + "-" + strconv.FormatInt(modseq, 10) }

// touch notes a change to an object; counts says only its counts changed.
// settle stamps it.
func (l *changeLog) touch(kind, id string, counts bool) {
	k := [2]string{kind, id}
	if only, ok := l.touched[k]; ok {
		counts = counts && only
	}
	l.touched[k] = counts
}

// settle stamps what was touched, all with one new modseq: an object that
// exists now and did not is created, one that existed and does not is
// destroyed, and one that exists still is changed. One a client could
// not tell from before (gone and back, or never there) is left alone.
func (l *changeLog) settle() {
	if len(l.touched) == 0 {
		return
	}
	n := l.modseq + 1
	stamped := false
	for k, counts := range l.touched {
		kind, id := k[0], k[1]
		s := l.entries[kind][id]
		existed := s != nil && s.destroyed == 0
		exists := l.exists(kind, id)
		switch {
		case exists && !existed:
			if s == nil {
				s = &stamp{}
				l.entries[kind][id] = s
			}
			s.created, s.changed, s.counts, s.destroyed = n, n, 0, 0
		case exists && counts:
			s.counts = n
		case exists:
			s.changed = n
		case existed:
			s.destroyed = n
		default:
			continue
		}
		l.dirty[k] = true
		stamped = true
	}
	clear(l.touched)
	if stamped {
		l.modseq = n
		close(l.wake)
		l.wake = make(chan struct{})
	}
}

// ErrCannotCalculateChanges means the log cannot answer from a state: it
// is from another epoch, or older than the log keeps.
var ErrCannotCalculateChanges = errors.New("cannot calculate changes")

// Changes is what changed since a state.
type Changes struct {
	Created, Updated, Destroyed []string
	// CountsOnly says every update changed folder counts alone.
	CountsOnly bool
	// NewState is the state the changes lead to; with HasMore, a state
	// before the current one, to ask from next.
	NewState string
	HasMore  bool
}

// parseState returns a state's modseq, or ErrCannotCalculateChanges.
func (l *changeLog) parseState(state string) (int64, error) {
	epoch, n, ok := strings.Cut(state, "-")
	if !ok || epoch != l.epoch {
		return 0, ErrCannotCalculateChanges
	}
	modseq, err := strconv.ParseInt(n, 10, 64)
	if err != nil || modseq < l.since || modseq > l.modseq {
		return 0, ErrCannotCalculateChanges
	}
	return modseq, nil
}

// changes lists the objects of kind changed since state, at most max (0
// for no limit).
func (l *changeLog) changes(kind, state string, max int) (*Changes, error) {
	since, err := l.parseState(state)
	if err != nil {
		return nil, err
	}
	type item struct {
		id string
		at int64
		s  *stamp
	}
	var items []item
	for id, s := range l.entries[kind] {
		at := max64(s.changed, s.counts, s.destroyed)
		if at <= since {
			continue
		}
		if s.destroyed > since && s.created > since {
			continue // created and destroyed since: never seen
		}
		items = append(items, item{id, at, s})
	}
	out := &Changes{NewState: l.state(l.modseq), CountsOnly: true}
	if max > 0 && len(items) > max {
		// The oldest changes first, up to a modseq every one of them is
		// at or below, so the next call starts after them.
		slices.SortFunc(items, func(x, y item) int { return cmp.Compare(x.at, y.at) })
		cut := items[max-1].at
		n := 0
		for n < len(items) && items[n].at <= cut {
			n++
		}
		if n > max {
			// Too many at one modseq to split: go back to the modseq
			// before.
			n = 0
			for n < len(items) && items[n].at < cut {
				n++
			}
			if n == 0 {
				return nil, fmt.Errorf("%w: more than %d changes in one step", ErrCannotCalculateChanges, max)
			}
			cut = items[n-1].at
		}
		items = items[:n]
		out.NewState, out.HasMore = l.state(cut), true
	}
	for _, it := range items {
		switch {
		case it.s.destroyed > since:
			out.Destroyed = append(out.Destroyed, it.id)
		case it.s.created > since:
			out.Created = append(out.Created, it.id)
		default:
			out.Updated = append(out.Updated, it.id)
			if it.s.changed > since {
				out.CountsOnly = false
			}
		}
	}
	if len(out.Updated) == 0 {
		out.CountsOnly = false
	}
	return out, nil
}

func max64(v ...int64) int64 {
	m := v[0]
	for _, x := range v[1:] {
		m = max(m, x)
	}
	return m
}

// loadLog reads an account's log. A database without one gets a new
// epoch.
func loadLog(db *sql.DB) (*changeLog, error) {
	l := newChangeLog()
	meta := map[string]string{}
	rows, err := db.Query(`SELECT name, value FROM meta WHERE name LIKE 'log_%'`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			rows.Close()
			return nil, err
		}
		meta[k] = v
	}
	rows.Close()
	if meta["log_epoch"] == "" {
		_, err := db.Exec(`INSERT INTO meta (name, value) VALUES ('log_epoch', ?), ('log_since', '0'), ('log_modseq', '0')
			ON CONFLICT (name) DO UPDATE SET value = excluded.value`, l.epoch)
		return l, err
	}
	l.epoch = meta["log_epoch"]
	l.since, _ = strconv.ParseInt(meta["log_since"], 10, 64)
	l.modseq, _ = strconv.ParseInt(meta["log_modseq"], 10, 64)
	rows, err = db.Query(`SELECT kind, id, created, changed, counts, destroyed FROM changes`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, id string
		s := &stamp{}
		if err := rows.Scan(&kind, &id, &s.created, &s.changed, &s.counts, &s.destroyed); err != nil {
			return nil, err
		}
		if l.entries[kind] != nil {
			l.entries[kind][id] = s
			l.modseq = max(l.modseq, max64(s.created, s.changed, s.counts, s.destroyed))
		}
	}
	return l, rows.Err()
}

// saveLog settles the log and writes its changed entries in the batch.
func (t *storeTx) saveLog() {
	l := t.log
	if l == nil {
		return
	}
	l.settle()
	if len(l.dirty) == 0 {
		return
	}
	for k := range l.dirty {
		s := l.entries[k[0]][k[1]]
		if s == nil {
			t.exec(`DELETE FROM changes WHERE kind = ? AND id = ?`, k[0], k[1])
			continue
		}
		t.exec(`INSERT INTO changes (kind, id, created, changed, counts, destroyed) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (kind, id) DO UPDATE SET created = excluded.created, changed = excluded.changed,
			counts = excluded.counts, destroyed = excluded.destroyed`, k[0], k[1], s.created, s.changed, s.counts, s.destroyed)
	}
	t.exec(`INSERT INTO meta (name, value) VALUES ('log_modseq', ?), ('log_since', ?)
		ON CONFLICT (name) DO UPDATE SET value = excluded.value`, strconv.FormatInt(l.modseq, 10), strconv.FormatInt(l.since, 10))
	clear(l.dirty)
}
