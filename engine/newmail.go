package engine

import (
	"cmp"
	"errors"
	"slices"
	"time"
)

// New mail waits a little for its download. When a resync finds new
// messages, it downloads them before it tells clients, so a client that
// opens a message on its EXISTS finds it cached. It waits at most
// NewMailWait: past that, clients are told anyway and the download goes on
// in the background, as prefetch. Only messages prefetch would download
// wait: not held messages (hold.go), and not large ones the proxy passes
// through unchanged (piece.go). Nor does one with no Message-ID, whose
// cache key comes from the ID the resync gives it.

// NewMailWait is the longest a resync waits for new mail's download
// before it tells clients. 0 does not wait.
var NewMailWait = 8 * time.Second

// awaitNewMail downloads the new messages among fresh, in folder name,
// and returns when they are cached or NewMailWait passes. It runs before
// the resync applies fresh, without a.mu.
func (a *Account) awaitNewMail(name string, fresh []freshMessage, reset bool) {
	if NewMailWait <= 0 || len(fresh) == 0 || a.b.Cache == nil {
		return
	}
	var msgs []*Message
	a.mu.Lock()
	m := a.boxes[name]
	// The folder's first sync finds no new mail (resyncLocked's known).
	if m == nil || reset || m.pUIDNext == 0 {
		a.mu.Unlock()
		return
	}
	for _, f := range fresh {
		if m.atP[f.uid] != nil {
			continue
		}
		key := a.keyFor(f)
		if key == "" {
			continue
		}
		// Not bound or shown: only download reads it.
		msg := &Message{date: f.date, key: key, direct: a.b.direct(f.header), pBox: name, pUID: f.uid}
		if a.mustCheck(msg) || msg.direct && f.size > PieceWhole {
			continue
		}
		msgs = append(msgs, msg)
	}
	a.mu.Unlock()
	if len(msgs) == 0 {
		return
	}
	// The ones prefetch downloads: the newest.
	slices.SortFunc(msgs, func(x, y *Message) int { return cmp.Compare(x.pUID, y.pUID) })
	if len(msgs) > prefetchMax {
		msgs = msgs[len(msgs)-prefetchMax:]
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := a.download(msgs, nil, false, nil); err != nil && !errors.Is(err, ErrNoCredentials) {
			a.b.Log.Warn("imap: could not download new mail", "user", a.login, "mailbox", name, "err", err)
		}
	}()
	t := time.NewTimer(NewMailWait)
	defer t.Stop()
	select {
	case <-done:
	case <-t.C:
	}
}
