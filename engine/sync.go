package engine

import (
	"context"
	"errors"
	"time"

	"github.com/emersion/go-imap/v2"
)

// The engine keeps an account's mailbox state current, whether or not a
// client is connected. It holds one provider connection: it reads the
// folder list and every folder at start, then waits for the provider to
// report a change (IMAP IDLE on INBOX, and NOTIFY for the other folders
// when the provider has it; JMAP push), and checks every folder every
// SyncPoll (one STATUS each on IMAP, when nothing changed), or every
// SyncPollNotified when the provider reports every change itself. It
// never downloads message bodies; the backfill (backfill.go) and prefetch
// do that over the pool. It also runs the queue of client changes
// (queue.go).
//
// It needs the password from the last successful client login, kept in
// memory only. When the provider rejects it, the engine drops it and stops
// until a client logs in again. After a restart nothing syncs until a
// client logs in.

var (
	// SyncPoll is how often the other folders are checked, and INBOX on
	// providers without IDLE.
	SyncPoll = time.Minute
	// SyncPollNotified replaces SyncPoll for a provider that reports
	// every change itself (watchConn.Notifies).
	SyncPollNotified = 15 * time.Minute
	// SyncListEvery is how often the folder list is read again.
	SyncListEvery = 10 * time.Minute
	// syncRetryMax caps the pause between failed connections.
	syncRetryMax = 5 * time.Minute
)

var (
	ErrLoginRejected      = errors.New("login rejected")
	errCredentialsChanged = errors.New("credentials changed")
)

func (a *Account) run(ctx context.Context) {
	defer func() {
		a.credMu.Lock()
		a.running = false
		close(a.stopped)
		a.credMu.Unlock()
	}()
	log := a.b.Log.With("user", a.login)
	log.Info("sync: started")
	retry := time.Second
	for {
		err := a.session(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case errors.Is(err, ErrLoginRejected), errors.Is(err, ErrNoCredentials):
			log.Warn("sync: the provider rejected the password; stopped until a client logs in", "err", err)
			a.forgetCredentials()
			return
		case errors.Is(err, errCredentialsChanged):
			retry = time.Second
			continue
		}
		log.Warn("sync: connection lost, retrying", "err", err, "in", retry)
		select {
		case <-ctx.Done():
			return
		case <-a.changed:
			retry = time.Second
		case <-time.After(retry):
			retry = min(retry*2, syncRetryMax)
		}
	}
}

// session runs one provider connection until it fails.
func (a *Account) session(ctx context.Context) error {
	a.credMu.Lock()
	prov := a.prov
	a.credMu.Unlock()
	if prov == nil {
		return ErrNoCredentials
	}
	up, err := prov.Watch(a.signal)
	if err != nil {
		return err
	}
	defer up.Release(nil)
	// The backfill and the queue end with the connection; the next one
	// starts them again.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		up.Release(nil)
	}()
	// Mail from now on is new (hold.go).
	a.startSince()

	// Changes clients made while the provider was out of reach, or before
	// a restart. After a switch to another provider they wait for the
	// first sweep, which finds where the new one has the messages.
	if !a.rebinding.Load() {
		a.startQueue(ctx)
	}

	if err := a.refreshList(up); err != nil {
		return err
	}
	if err := a.sweep(up); err != nil {
		return err
	}
	if a.rebinding.CompareAndSwap(true, false) {
		a.startQueue(ctx)
	}
	a.mu.Lock()
	n := len(a.boxes)
	a.mu.Unlock()
	a.b.Log.Info("sync: up to date", append([]any{"user", a.login, "folders", n}, up.Describe()...)...)
	a.backfillStale.Store(true)
	a.startBackfill(ctx)

	// A provider that reports every change in every folder (IMAP NOTIFY
	// with CONDSTORE, JMAP push) needs the full check only as a safety
	// net.
	poll := SyncPoll
	if up.Notifies() {
		poll = SyncPollNotified
	}
	nextSweep := time.Now().Add(poll)
	for {
		if time.Now().After(nextSweep) {
			if time.Since(a.listedAt) > SyncListEvery {
				if err := a.refreshList(up); err != nil {
					return err
				}
			}
			if err := a.sweep(up); err != nil {
				return err
			}
			nextSweep = time.Now().Add(poll)
			a.startBackfill(ctx)
		}
		w, err := up.Wait(ctx, time.Until(nextSweep), a.changed, a.notify)
		if err != nil {
			return err
		}
		if w.list {
			if err := a.refreshList(up); err != nil {
				return err
			}
		}
		if w.all {
			nextSweep = time.Now()
			continue
		}
		for _, name := range w.names {
			if err := a.resync(up, name); err != nil {
				var ie *imap.Error
				if errors.As(err, &ie) {
					// A folder deleted meanwhile, for example.
					continue
				}
				return err
			}
		}
		if len(w.names) > 0 {
			a.startBackfill(ctx)
		}
	}
}

// sweep resyncs every selectable folder.
func (a *Account) sweep(up conn) error {
	a.mu.Lock()
	var names []string
	for name, m := range a.boxes {
		if m.selectable {
			names = append(names, name)
		}
	}
	a.mu.Unlock()
	for _, name := range names {
		if err := a.resync(up, name); err != nil {
			var ie *imap.Error
			if errors.As(err, &ie) {
				// A folder deleted since the list was read, for example.
				a.b.Log.Info("sync: folder skipped", "user", a.login, "mailbox", name, "err", err)
				continue
			}
			return err
		}
	}
	a.mu.Lock()
	a.sweeps++
	a.purgeOrphans()
	a.mu.Unlock()
	a.retryHeld(true)
	return nil
}

func (a *Account) signal() {
	select {
	case a.notify <- struct{}{}:
	default:
	}
}
