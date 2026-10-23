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
	if a.since.IsZero() || msg.date.Before(a.since) {
		return false
	}
	return a.b.Transform != nil && !msg.direct || a.authChecks(msg.pBox) || a.authCopies(msg.pBox)
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
	// A copy in a checked folder decides, then one in authCopies, else the first.
	type heldKey struct {
		check, copies, direct, inbox bool
		box                          string
		date                         time.Time
		roles                        []AuthAction // actions that target its own folder
	}
	if a.b.Authentication != "" {
		a.seedLearning()
	}
	a.mu.Lock()
	info := map[string]heldKey{}
	for key, l := range keys {
		msg := l[0]
		if i := slices.IndexFunc(l, func(m *Message) bool { return a.authChecks(m.pBox) }); i >= 0 {
			msg = l[i]
		} else if i := slices.IndexFunc(l, func(m *Message) bool { return a.authCopies(m.pBox) }); i >= 0 {
			msg = l[i]
		}
		var roles []AuthAction
		for _, act := range []AuthAction{AuthTrash, AuthJunk} {
			if a.hasRole(msg.pBox, act.attr()) {
				roles = append(roles, act)
			}
		}
		info[key] = heldKey{check: a.authChecks(msg.pBox), copies: a.authCopies(msg.pBox), direct: msg.direct,
			inbox: msg.pBox == "INBOX", box: msg.pBox, date: msg.date, roles: roles}
	}
	a.mu.Unlock()

	start := time.Now()
	results := map[string]ReadStatus{}
	entries := map[string]*HeaderEntry{} // direct messages, headers only
	whole := map[string]bool{}           // direct messages fetched whole
	away := map[string]moveAway{}
	idents := map[string]authRef{}
	read := func(key string, raw []byte) {
		if _, done := results[key]; done {
			return
		}
		in := info[key]
		ctx, cancel := context.WithTimeout(context.Background(), a.b.Timeout)
		defer cancel()
		var r AuthResult
		mine := AuthNone
		hold := false // All Mail/Flagged copy not yet allowed
		if in.copies {
			// All Mail/Flagged only: held until allowed, never moved.
			hdr := headerOf(raw)
			if a.rescued(hdr) {
				r = rescuedResult
			} else {
				r = a.b.verdict(ctx, a.stamp(), hdr)
				hold = r.Learning || a.b.Authentication.action(r) != AuthNone
			}
			r.New = true
			ctx = WithAuthResult(ctx, r)
		}
		if in.check {
			hdr := headerOf(raw)
			idents[key] = refOf(hdr)
			if in.inbox {
				a.learn(in.date, hdr)
			}
			if a.rescue(hdr, in.box) || a.rescued(hdr) {
				r = rescuedResult
			} else {
				r = a.b.verdict(ctx, a.stamp(), hdr)
			}
			r.New = true
			ctx = WithAuthResult(ctx, r)
			mine = a.b.Authentication.action(r)
		}
		if !in.check && !in.copies && !in.direct {
			// Junk, Trash and the like: the verdict is for the
			// Transform to show, not to act on (New is false).
			ctx = a.withVerdict(ctx, raw)
		}
		out, st := raw, ReadFinal
		if !in.direct {
			out, st = a.b.Transform.Read(ctx, raw)
		}
		how, moved := st.moveAway()
		if in.copies && moved {
			st, moved = ReadHold, false
		}
		if mine.severity() > how.act.severity() {
			how, moved, st = moveAway{act: mine}, true, mine.status()
			a.b.Log.Info("sender authentication failed", "user", a.login, "from", r.From, "reason", r.Reason,
				"dmarc", r.DMARC, "policy", r.DMARCPolicy, "spf", r.SPF, "action", mine)
		}
		if moved {
			how.learning = r.Learning
			if slices.Contains(in.roles, how.act) {
				st = ReadRetry // in that folder already
			} else {
				away[key] = how
			}
		} else if in.check && r.Learning {
			// Wait in Junk until the stamp is known.
			st, away[key] = ReadDefer, moveAway{act: AuthJunk, deferred: true, learning: true}
		} else if hold && (st == ReadFinal || st == ReadRetry) {
			st = ReadHold
		}
		if how, ok := away[key]; ok && in.check && how.deferred && idents[key].id == "" {
			// No identity: a release could not find it.
			delete(away, key)
			st = ReadHold
		}
		results[key] = st
		if in.direct && !whole[key] {
			if e := entries[key]; e != nil && st == ReadFinal {
				if err := a.b.Store.putHeaders(a.login, map[string]*HeaderEntry{key: e}); err != nil {
					a.b.Log.Warn("could not save header entries", "user", a.login, "err", err)
				}
			}
			return
		}
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
	var fetch, fetchHeaders []*Message
	for key, l := range keys {
		if info[key].direct {
			fetchHeaders = append(fetchHeaders, l[0])
		} else if raw := a.b.Cache.Get(a.login, holdKey(key)); raw != nil {
			read(key, raw)
		} else {
			fetch = append(fetch, l[0])
		}
	}
	for box, at := range a.locate(fetchHeaders) {
		for chunk := range slices.Chunk(at.uids(), FetchBatch) {
			c, err := a.conn(PriorityInteractive, box)
			if err != nil {
				if !errors.Is(err, ErrNoCredentials) {
					a.b.Log.Warn("could not read held messages", "user", a.login, "err", err)
				}
				return
			}
			if !cheapHeaders(c) {
				// No header-only fetch: read whole and cache.
				err = c.FetchFull(box, chunk, func(uid imap.UID, raw []byte) {
					for _, msg := range at[uid] {
						whole[msg.key] = true
						read(msg.key, raw)
					}
				})
				c.Release(err)
				if err != nil {
					a.b.Log.Warn("could not read held messages", "user", a.login, "mailbox", box, "err", err)
					return
				}
				continue
			}
			got, err := c.FetchHeaders(box, chunk)
			c.Release(err)
			if err != nil {
				a.b.Log.Warn("could not read held messages", "user", a.login, "mailbox", box, "err", err)
				return
			}
			for uid, e := range got {
				for _, msg := range at[uid] {
					entries[msg.key] = e
					read(msg.key, e.Header)
				}
			}
		}
	}
	for box, at := range a.locate(fetch) {
		for chunk := range slices.Chunk(at.uids(), FetchBatch) {
			c, err := a.conn(PriorityInteractive, box)
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

	groups := map[moveAway][]*Message{}
	for key, how := range away {
		if how.deferred {
			// A stamp learned later in this batch must release it.
			how.verdictAt = start
		}
		groups[how] = append(groups[how], keys[key]...)
	}
	for how, msgs := range groups {
		a.discard(how, msgs, idents)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	tx := a.begin()
	var shown, ahead []*Message
	for key, st := range results {
		if _, gone := away[key]; gone || st == ReadHold {
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
			// Prefetch unless large (piece.go).
			if e := entries[key]; e != nil && e.Size <= PieceWhole {
				ahead = append(ahead, msg)
			}
		}
		_ = a.b.Cache.Delete(a.login, holdKey(key))
	}
	if len(shown) > 0 {
		a.backfillStale.Store(true)
	}
	if len(ahead) > 0 {
		go a.prefetch(ahead)
	}
	if err := tx.commit(); err != nil {
		a.b.Log.Warn("could not save mailbox state", "user", a.login, "err", err)
	}
}

// retryHeld reads every held message of the account again, in the
// background, and logs those still held. One retry runs at a time.
func (a *Account) retryHeld(logHeld bool) {
	if a.tending.CompareAndSwap(false, true) {
		go func() {
			defer a.tending.Store(false)
			if a.b.Authentication != "" {
				a.seedLearning()
				a.releaseDeferred()
			}
		}()
	}
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
		if a.isLoaded() {
			accounts = append(accounts, a)
		}
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
