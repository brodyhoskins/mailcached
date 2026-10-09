package engine

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/emersion/go-imap/v2"
)

// Held messages. After an account's first sync, a new message the
// Transform changes (Changes reports true) reaches clients only after a
// Read: the sync binds it at the provider but shows it in no folder, and
// reads it in the background. ReadFinal and ReadRetry show it, as new
// mail; ReadHold keeps it hidden from IMAP and JMAP alike: no UID, no
// count, no EXISTS, no JMAP Email. A held message is read again after
// every sweep, and on Recheck, until its Read gives another result.
//
// "New" is: arrived at the provider (its INTERNALDATE) at or after the
// account's cutoff, Since, which is set when the account's first sync
// starts. It is kept in a file of its own beside the account's database,
// so it outlives a database deleted by hand.

// sinceFile is the cutoff's file in the account's folder.
const sinceFile = "since"

// Since returns the account's cutoff: messages that arrived at or after
// it are new. Zero before the account's first sync.
func (a *Account) Since() time.Time {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.since
}

// loadSince reads the saved cutoff (a.mu held).
func (a *Account) loadSince() {
	s := a.b.Store
	if s == nil {
		return
	}
	b, err := os.ReadFile(filepath.Join(accountDir(s.Dir, a.login), sinceFile))
	if err != nil {
		return
	}
	if t, err := time.Parse(time.RFC3339Nano, string(b)); err == nil {
		a.since = t
	}
}

// startSince sets the cutoff when the account's first sync starts.
func (a *Account) startSince() {
	a.mu.Lock()
	if !a.since.IsZero() {
		a.mu.Unlock()
		return
	}
	// INTERNALDATE has whole seconds: mail stamped with the second the
	// first sync starts in counts as there before it.
	a.since = time.Now().UTC()
	t := a.since
	a.mu.Unlock()
	s := a.b.Store
	if s == nil {
		return
	}
	dir := accountDir(s.Dir, a.login)
	err := os.MkdirAll(dir, 0o700)
	if err == nil {
		tmp := filepath.Join(dir, sinceFile+".tmp")
		if err = os.WriteFile(tmp, []byte(t.Format(time.RFC3339Nano)), 0o600); err == nil {
			err = os.Rename(tmp, filepath.Join(dir, sinceFile))
		}
	}
	if err != nil {
		a.b.Log.Warn("could not save the account's cutoff", "user", a.login, "err", err)
	}
}

// mustCheck reports whether a message the sync finds must be read before
// clients see it (a.mu held).
func (a *Account) mustCheck(msg *Message) bool {
	return a.b.Transform != nil && !msg.direct && !a.since.IsZero() && !msg.date.Before(a.since)
}

// holdKey is where a held message's provider copy is kept in memory, so
// a retry does not download it again.
func holdKey(key string) string { return hashKey("held", key) }

// checkHeld reads held messages, and shows those whose Read no longer
// holds them. Messages being checked already are skipped.
func (a *Account) checkHeld(msgs []*Message) {
	a.mu.Lock()
	if a.holdBusy == nil {
		a.holdBusy = map[string]bool{}
	}
	keys := map[string][]*Message{}
	for _, msg := range msgs {
		if msg.held && msg.pUID != 0 && (keys[msg.key] != nil || !a.holdBusy[msg.key]) {
			a.holdBusy[msg.key] = true
			keys[msg.key] = append(keys[msg.key], msg)
		}
	}
	a.mu.Unlock()
	if len(keys) == 0 {
		return
	}
	defer func() {
		a.mu.Lock()
		for key := range keys {
			delete(a.holdBusy, key)
		}
		a.mu.Unlock()
	}()

	// One Read a key: copies of a message are held or shown together.
	results := map[string]ReadStatus{}
	read := func(key string, raw []byte) {
		if _, done := results[key]; done {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), a.b.Timeout)
		out, st := a.b.Transform.Read(ctx, raw)
		cancel()
		results[key] = st
		switch st {
		case ReadFinal:
			if err := a.b.Cache.Put(a.login, key, out, true); err != nil {
				a.b.Log.Warn("cache write failed", "err", err)
			}
			if err := a.b.Store.putHeaders(a.login, map[string]*HeaderEntry{key: EntryOf(out)}); err != nil {
				a.b.Log.Warn("could not save header entries", "user", a.login, "err", err)
			}
		case ReadRetry:
			_ = a.b.Cache.Put(a.login, key, out, false)
		default:
			_ = a.b.Cache.Put(a.login, holdKey(key), raw, false)
		}
	}
	var fetch []*Message
	for key, l := range keys {
		if raw := a.b.Cache.Get(a.login, holdKey(key)); raw != nil {
			read(key, raw)
		} else {
			fetch = append(fetch, l[0])
		}
	}
	for box, at := range a.locate(fetch) {
		for chunk := range slices.Chunk(at.uids(), FetchBatch) {
			c, err := a.conn(interactive, box)
			if err != nil {
				if !errors.Is(err, ErrNoCredentials) {
					a.b.Log.Warn("could not read held messages", "user", a.login, "err", err)
				}
				return
			}
			err = c.FetchFull(box, chunk, func(uid imap.UID, raw []byte) {
				for _, msg := range at[uid] {
					read(msg.key, raw)
				}
			})
			c.Release(err)
			if err != nil {
				a.b.Log.Warn("could not read held messages", "user", a.login, "mailbox", box, "err", err)
				return
			}
		}
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	tx := a.begin()
	var shown []*Message
	for key, st := range results {
		if st == ReadHold {
			continue
		}
		for _, msg := range keys[key] {
			// Moved or gone at the provider meanwhile: the sync has it.
			m := a.boxes[msg.pBox]
			if !msg.held || msg.pUID == 0 || m == nil {
				continue
			}
			msg.held = false
			a.show(m, msg, tx)
			shown = append(shown, msg)
		}
		_ = a.b.Cache.Delete(a.login, holdKey(key))
	}
	if len(shown) > 0 {
		a.backfillStale.Store(true)
	}
	if err := tx.commit(); err != nil {
		a.b.Log.Warn("could not save mailbox state", "user", a.login, "err", err)
	}
}

// retryHeld reads every held message of the account again, in the
// background, and logs those still held. One retry runs at a time.
func (a *Account) retryHeld(logHeld bool) {
	a.mu.Lock()
	var held []*Message
	count := map[string]int{}
	for _, msg := range a.byID {
		if msg.held {
			held = append(held, msg)
			count[msg.pBox]++
		}
	}
	a.mu.Unlock()
	if logHeld {
		for box, n := range count {
			a.b.Log.Info("messages held from clients", "user", a.login, "mailbox", box, "count", n)
		}
	}
	if len(held) == 0 {
		return
	}
	// A retry asked for while one runs runs after it.
	a.retryAgain.Store(true)
	if !a.retrying.CompareAndSwap(false, true) {
		return
	}
	go func() {
		for a.retryAgain.Swap(false) {
			a.checkHeld(a.heldMessages())
		}
		a.retrying.Store(false)
		// One asked for in between.
		if a.retryAgain.Load() {
			a.retryHeld(false)
		}
	}()
}

func (a *Account) heldMessages() []*Message {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []*Message
	for _, msg := range a.byID {
		if msg.held {
			out = append(out, msg)
		}
	}
	return out
}

// Recheck drops the ReadRetry results from the memory cache, so they go
// through Read again, and reads every held message again, in the
// background. It is safe to call from any goroutine at any time.
func (b *Engine) Recheck() {
	if b.Cache != nil {
		b.Cache.DropNonFinal()
	}
	b.syncMu.Lock()
	accounts := make([]*Account, 0, len(b.accounts))
	for _, a := range b.accounts {
		accounts = append(accounts, a)
	}
	b.syncMu.Unlock()
	for _, a := range accounts {
		a.retryHeld(false)
	}
}

// Held returns how many messages of the account are held, for tests.
func (a *Account) Held() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, msg := range a.byID {
		if msg.held {
			n++
		}
	}
	return n
}
