package engine

import (
	"time"

	"github.com/emersion/go-imap/v2"
)

// The methods in this file let tests watch the engine.

// Queued returns how many changes wait for the provider.
func (a *Account) Queued() int { return a.queued() }

// Sweeps returns how many full syncs of every folder completed.
func (a *Account) Sweeps() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sweeps
}

// Running reports whether the account's engine runs.
func (a *Account) Running() bool {
	a.credMu.Lock()
	defer a.credMu.Unlock()
	return a.running
}

// HasPassword reports whether the account has a password the provider
// accepted.
func (a *Account) HasPassword() bool {
	a.credMu.Lock()
	defer a.credMu.Unlock()
	return a.password != ""
}

// SetCredentials records credentials as if the provider accepted them,
// and starts the engine.
func (a *Account) SetCredentials(password string, u Upstream) { a.setCredentials(password, u) }

// Backfilling reports whether a backfill runs.
func (a *Account) Backfilling() bool { return a.backfillRunning.Load() }

// Prefetch downloads msgs into the cache, as the engine does ahead of
// clients; background as read-ahead and the backfill do.
func (a *Account) Prefetch(msgs []*Message, background bool) error {
	return a.download(msgs, nil, background, nil)
}

// Downloading reports whether the message with cache key key is being
// downloaded.
func (b *Engine) Downloading(key string) bool {
	b.flightMu.Lock()
	defer b.flightMu.Unlock()
	return b.inflight[key] != nil
}

// SetOpHook makes h run before each group of queued changes goes to the
// provider, with their kinds ("flags", "copy", "move", "expunge"). An
// error from h counts as the provider's. nil removes the hook.
func SetOpHook(h func(kinds []string) error) {
	if h == nil {
		opHook.Store(nil)
		return
	}
	opHook.Store(&h)
}

// AtProvider returns where the provider has the message: a folder and its
// UID there, or "" and 0 (lock held).
func (msg *Message) AtProvider() (string, imap.UID) { return msg.pBox, msg.pUID }

// HeaderKeys returns the cache keys with a header entry.
func (s *Store) HeaderKeys(account string) (map[string]bool, error) { return s.headerKeys(account) }

// ReadKeys returns the cache keys of the messages a client read whole.
func (s *Store) ReadKeys(account string) (map[string]bool, error) {
	return s.readsSince(account, time.Time{})
}
