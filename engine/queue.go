package engine

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync/atomic"
	"time"
	"uuid"

	"github.com/emersion/go-imap/v2"
)

// The queue takes the changes clients make to messages to the provider.
// A client's flag change, copy, move or expunge is made in the proxy's
// copy at once and saved together with an op, in one transaction. The
// queue then makes the ops at the provider one at a time, oldest first,
// over the pool. It runs with the sync engine, so it needs the password
// from a client login; after a restart it carries on where it stopped
// once a client logs in.
//
// An op names messages by their IDs and looks up where the provider has
// them when it runs, so it follows the ops before it: a flag change on a
// moved message goes to the folder the move took it to.
//
// Every op is safe to make again after a shutdown in the middle: flag
// changes, moves and expunges of messages the provider no longer has where
// the op says do nothing, and the copies an interrupted copy made are
// found, by their cache keys, before it copies again.
//
// When the provider refuses an op (a NO, for example for a folder deleted
// meanwhile, or over quota), the proxy's copy goes back to what the
// provider has: a message the provider did not move or expunge shows up
// again where it is, with a new UID, and a copy it did not make goes.

// The kinds of op.
const (
	opFlags   = "flags"   // STORE flags on ids
	opCopy    = "copy"    // ids are new copies in dest of their origins
	opMove    = "move"    // ids were moved to dest
	opExpunge = "expunge" // ids were expunged
)

// op is a change for the provider.
type op struct {
	seq     int64
	kind    string
	ids     []uuid.UUID
	dest    string            // copy, move
	flagOp  imap.StoreFlagsOp // flags
	flags   []imap.Flag       // flags
	at      time.Time         // when queued
	started bool              // sent to the provider at least once (copy)
	// alone is set after a group with this op as its head failed, so it
	// runs by itself.
	alone bool
}

// coalesceWait is how long a copy waits for the flag change and expunge
// that make it a move: Apple Mail moves with COPY, STORE \Deleted and UID
// EXPUNGE, which the provider then makes as one MOVE.
var coalesceWait = 2 * time.Second

// enqueue adds o to the queue, in tx (a.mu held). Call wakeQueue after
// the commit.
func (a *Account) enqueue(o *op, tx *storeTx) {
	a.opSeq++
	o.seq, o.at = a.opSeq, time.Now()
	for _, id := range o.ids {
		if msg := a.byID[id]; msg != nil {
			msg.pending++
		}
	}
	a.ops = append(a.ops, o)
	tx.putOp(o)
}

func (a *Account) wakeQueue() {
	select {
	case a.opWake <- struct{}{}:
	default:
	}
}

// startQueue runs the queue until ctx ends, unless it runs already.
func (a *Account) startQueue(ctx context.Context) {
	if !a.queueRunning.CompareAndSwap(false, true) {
		return
	}
	go func() {
		defer a.queueRunning.Store(false)
		a.runQueue(ctx)
	}()
}

// queued returns how many ops wait.
func (a *Account) queued() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.ops)
}

// flushQueue waits until the queue is empty, for changes that must not
// overtake it (to folders). It gives up after d.
func (a *Account) flushQueue(d time.Duration) error {
	deadline := time.Now().Add(d)
	for a.queued() > 0 {
		if time.Now().After(deadline) {
			return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeInUse,
				Text: "Earlier changes are still on their way to the server, try again"}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

func (a *Account) runQueue(ctx context.Context) {
	log := a.b.Log.With("user", a.login)
	retry := time.Second
	for {
		a.mu.Lock()
		head := slices.Clone(a.ops[:min(3, len(a.ops))])
		a.mu.Unlock()
		if len(head) == 0 {
			select {
			case <-ctx.Done():
				return
			case <-a.opWake:
			}
			continue
		}
		o := head[0]
		group := []*op{o}
		if o.kind != opCopy {
			group = a.mergeable()
		}
		if o.kind == opCopy && !o.started && !o.alone {
			if len(head) < 3 {
				if wait := coalesceWait - time.Since(o.at); wait > 0 {
					select {
					case <-ctx.Done():
						return
					case <-a.opWake:
					case <-time.After(wait):
					}
					continue
				}
			} else if a.coalescible(head) {
				group = head
			}
		}
		err := a.runOps(group)
		var ie *imap.Error
		switch {
		case err == nil:
			retry = time.Second
		case ctx.Err() != nil, errors.Is(err, ErrNoCredentials):
			return
		case errors.As(err, &ie) && len(group) > 1:
			// Alone, so a refusal undoes no more than it must.
			o.alone = true
		case errors.As(err, &ie):
			log.Warn("queue: the server refused a change; undone", "op", o.kind, "messages", len(o.ids), "err", err)
			a.mu.Lock()
			tx := a.begin()
			a.finishOps(group, true, tx)
			if err := tx.commit(); err != nil {
				log.Warn("imap: could not save mailbox state", "err", err)
			}
			a.mu.Unlock()
		default:
			log.Warn("queue: change not made yet, retrying", "op", o.kind, "err", err, "in", retry)
			select {
			case <-ctx.Done():
				return
			case <-time.After(retry):
			}
			retry = min(retry*2, syncRetryMax)
		}
	}
}

// mergeMax bounds the messages of merged ops, which go to the provider
// as one command.
const mergeMax = 1000

// mergeable returns the head of the queue and the ops right after it that
// can go to the provider with it as one command: of the same kind, the
// same flag change, or moves to the same folder.
func (a *Account) mergeable() []*op {
	a.mu.Lock()
	defer a.mu.Unlock()
	o := a.ops[0]
	group, n := []*op{o}, len(o.ids)
	if o.alone {
		return group
	}
	for _, x := range a.ops[1:] {
		if x.kind != o.kind || x.dest != o.dest || x.flagOp != o.flagOp || !sameFlags(x.flags, o.flags) ||
			n+len(x.ids) > mergeMax {
			break
		}
		group = append(group, x)
		n += len(x.ids)
	}
	return group
}

// merged is one op with the messages of group, which are all alike.
func merged(group []*op) *op {
	o := *group[0]
	o.ids = nil
	for _, x := range group {
		o.ids = append(o.ids, x.ids...)
	}
	return &o
}

// coalescible reports whether head is a copy, a flag change that adds
// \Deleted to exactly the copied messages, and their expunge: a move.
func (a *Account) coalescible(head []*op) bool {
	c, f, e := head[0], head[1], head[2]
	if f.kind != opFlags || f.flagOp != imap.StoreFlagsAdd || len(f.flags) != 1 ||
		!strings.EqualFold(string(f.flags[0]), string(imap.FlagDeleted)) || e.kind != opExpunge {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	origins := make([]uuid.UUID, 0, len(c.ids))
	for _, id := range c.ids {
		msg := a.byID[id]
		if msg == nil || msg.origin == uuid.Nil() {
			return false
		}
		origins = append(origins, msg.origin)
	}
	return sameIDs(origins, f.ids) && sameIDs(origins, e.ids)
}

func sameIDs(x, y []uuid.UUID) bool {
	if len(x) != len(y) {
		return false
	}
	x, y = slices.Clone(x), slices.Clone(y)
	slices.SortFunc(x, uuid.UUID.Compare)
	slices.SortFunc(y, uuid.UUID.Compare)
	return slices.Equal(x, y)
}

// opHook, for tests, runs before each group of ops with their kinds; an
// error from it counts as the provider's.
var opHook atomic.Pointer[func(kinds []string) error]

// runOps makes one op, merged ops, or a coalesced copy, flag change and
// expunge, at the provider, and finishes them.
func (a *Account) runOps(group []*op) error {
	if h := opHook.Load(); h != nil {
		kinds := make([]string, len(group))
		for i, o := range group {
			kinds[i] = o.kind
		}
		if err := (*h)(kinds); err != nil {
			return err
		}
	}
	o := group[0]
	switch {
	case o.kind == opCopy && len(group) > 1:
		return a.runCopy(o, group)
	case o.kind == opCopy:
		return a.runCopy(o, nil)
	case o.kind == opFlags:
		return a.runFlags(merged(group), group)
	case o.kind == opMove:
		return a.runMove(merged(group), group)
	case o.kind == opExpunge:
		return a.runExpunge(merged(group), group)
	}
	// An op this version does not know: dropped.
	a.mu.Lock()
	defer a.mu.Unlock()
	tx := a.begin()
	a.finishOps(group, false, tx)
	return tx.commit()
}

// finishOps removes ops from the queue, and settles the messages no other
// op waits for (a.mu held). failed says the provider refused them.
func (a *Account) finishOps(ops []*op, failed bool, tx *storeTx) {
	for _, o := range ops {
		a.ops = slices.DeleteFunc(a.ops, func(x *op) bool { return x.seq == o.seq })
		tx.deleteOp(o)
		for _, id := range o.ids {
			if msg := a.byID[id]; msg != nil {
				if msg.pending--; msg.pending == 0 {
					a.settle(msg, failed, tx)
				}
			}
		}
	}
}

// settle makes what clients see of msg agree with the provider, once no
// op waits for it (a.mu held).
func (a *Account) settle(msg *Message, failed bool, tx *storeTx) {
	switch {
	case msg.box == "" && (!failed || msg.pUID == 0):
		// Expunged, and the provider followed, or has nothing to show.
		a.forget(msg, tx)
	case msg.box == "":
		// An expunge the provider refused: back where it is.
		if m := a.boxes[msg.pBox]; m != nil {
			a.show(m, msg, tx)
		} else {
			a.forget(msg, tx)
		}
	case msg.pUID == 0:
		// A copy, or a move, the provider has not made where the proxy
		// can see: the next resync of the folder finds it by its key, or
		// removes it.
		if m := a.boxes[msg.box]; m != nil {
			m.stale = true
		}
	case failed && msg.pBox != msg.box:
		// A move the provider refused: back where it is.
		if m := a.boxes[msg.box]; m != nil {
			a.hide(m, func(x *Message) bool { return x == msg })
		}
		if m := a.boxes[msg.pBox]; m != nil {
			a.show(m, msg, tx)
		} else {
			a.forget(msg, tx)
		}
	case failed:
		// A flag change the provider refused: its flags on the next resync.
		if m := a.boxes[msg.pBox]; m != nil {
			m.refetchFlags = true
		}
	}
}

// placed groups the messages of ids by the folder the provider has them
// in (a.mu held). Messages it has nowhere are left out, and so are those
// skip reports true for.
func (a *Account) placed(ids []uuid.UUID, skip func(*Message) bool) map[string][]*Message {
	out := map[string][]*Message{}
	for _, id := range ids {
		msg := a.byID[id]
		if msg == nil || msg.pUID == 0 || (skip != nil && skip(msg)) {
			continue
		}
		out[msg.pBox] = append(out[msg.pBox], msg)
	}
	return out
}

func pUIDs(msgs []*Message) []imap.UID {
	out := make([]imap.UID, len(msgs))
	for i, msg := range msgs {
		out[i] = msg.pUID
	}
	return out
}

// runFlags makes o, which merges group.
func (a *Account) runFlags(o *op, group []*op) error {
	a.mu.Lock()
	byBox := a.placed(o.ids, nil)
	a.mu.Unlock()
	type result struct {
		box string
		res map[imap.UID][]imap.Flag
	}
	var results []result
	for box, msgs := range byBox {
		c, err := a.conn(interactive, box)
		if err != nil {
			return err
		}
		res, err := c.Store(box, pUIDs(msgs), o.flagOp, o.flags)
		c.Release(err)
		if err != nil {
			return err
		}
		results = append(results, result{box, res})
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	tx := a.begin()
	a.finishOps(group, false, tx)
	// The provider's flags, for messages no later change waits on.
	for _, r := range results {
		m := a.boxes[r.box]
		if m == nil {
			continue
		}
		for uid, flags := range r.res {
			if msg := m.atP[uid]; msg != nil && msg.pending == 0 {
				a.setFlags(msg, flags, nil, tx)
			}
		}
	}
	return tx.commit()
}

// copyMap maps source UIDs to destination UIDs from COPYUID data.
func copyMap(data *imap.CopyData) map[imap.UID]imap.UID {
	if data == nil {
		return nil
	}
	src, dst := uidList(data.SourceUIDs), uidList(data.DestUIDs)
	if len(src) != len(dst) {
		return nil
	}
	out := make(map[imap.UID]imap.UID, len(src))
	for i := range src {
		out[src[i]] = dst[i]
	}
	return out
}

// uidList lists the UIDs of a set without "*", in its order.
func uidList(set imap.UIDSet) []imap.UID {
	var out []imap.UID
	for _, r := range set {
		if r.Start == 0 || r.Stop == 0 {
			return nil
		}
		if r.Start <= r.Stop {
			for u := r.Start; u <= r.Stop; u++ {
				out = append(out, u)
			}
		} else {
			for u := r.Start; u >= r.Stop; u-- {
				out = append(out, u)
			}
		}
	}
	return out
}

// settleFolder resyncs dest with its lock held, which binds what the
// provider made without saying where, and removes what it did not make.
func (a *Account) settleFolder(dest string) {
	c, err := a.conn(interactive, "")
	if err != nil {
		return
	}
	err = a.resyncLocked(c, dest, true)
	c.Release(err)
	if err != nil && !errors.Is(err, ErrNoCredentials) {
		a.b.Log.Warn("imap: could not resync after a change", "user", a.login, "mailbox", dest, "err", err)
	}
}

// runMove makes o, which merges group.
func (a *Account) runMove(o *op, group []*op) error {
	dest := CanonicalName(o.dest)
	skip := func(msg *Message) bool { return msg.pBox == dest }
	a.mu.Lock()
	names := []string{dest}
	for box := range a.placed(o.ids, skip) {
		names = append(names, box)
	}
	a.mu.Unlock()
	defer a.lockFolders(names...)()

	// Again, now that nothing else moves them.
	a.mu.Lock()
	byBox := a.placed(o.ids, skip)
	a.mu.Unlock()
	for box, msgs := range byBox {
		if !slices.Contains(names, box) {
			continue // the next run takes it
		}
		c, err := a.conn(interactive, box)
		if err != nil {
			return err
		}
		to, err := c.Move(box, pUIDs(msgs), dest)
		c.Release(err)
		if err != nil {
			return err
		}
		a.mu.Lock()
		tx := a.begin()
		for _, msg := range msgs {
			if u, ok := to[msg.pUID]; ok {
				a.bind(msg, dest, u, tx)
			} else {
				a.lose(msg, tx)
			}
		}
		err = tx.commit()
		a.mu.Unlock()
		if err != nil {
			a.b.Log.Warn("imap: could not save mailbox state", "user", a.login, "err", err)
		}
	}
	a.mu.Lock()
	tx := a.begin()
	a.finishOps(group, false, tx)
	err := tx.commit()
	a.mu.Unlock()
	a.settleFolder(dest)
	return err
}

// runCopy makes a copy op. With more ops (the flag change and expunge of
// the origins, see coalescible) it moves the origins instead.
func (a *Account) runCopy(o *op, group []*op) error {
	dest := CanonicalName(o.dest)
	move := len(group) > 1
	// The copies to make, by the folder the provider has their origins in.
	plan := func() map[string][][2]*Message {
		out := map[string][][2]*Message{}
		for _, id := range o.ids {
			c := a.byID[id]
			if c == nil || c.pUID != 0 || (c.box == "" && !move) {
				continue // made already, or expunged before it was
			}
			src := a.byID[c.origin]
			if src == nil || src.pUID == 0 {
				continue // lost; the copy goes when it settles
			}
			out[src.pBox] = append(out[src.pBox], [2]*Message{c, src})
		}
		return out
	}
	a.mu.Lock()
	names := []string{dest}
	for box := range plan() {
		names = append(names, box)
	}
	a.mu.Unlock()
	defer a.lockFolders(names...)()

	if o.started && !move {
		// Interrupted: the copies the provider made already are found by
		// their keys first, so they are not made twice.
		c, err := a.conn(interactive, "")
		if err != nil {
			return err
		}
		err = a.resyncLocked(c, dest, true)
		c.Release(err)
		if err != nil {
			return err
		}
	}
	a.mu.Lock()
	byBox := plan()
	if !o.started {
		o.started = true
		tx := a.begin()
		tx.putOp(o)
		if err := tx.commit(); err != nil {
			a.mu.Unlock()
			return err
		}
	}
	a.mu.Unlock()

	for box, pairs := range byBox {
		if !slices.Contains(names, box) {
			continue // the next run takes it
		}
		srcs := make([]*Message, len(pairs))
		for i, p := range pairs {
			srcs[i] = p[1]
		}
		c, err := a.conn(interactive, box)
		if err != nil {
			return err
		}
		var to map[imap.UID]imap.UID
		if move {
			to, err = c.Move(box, pUIDs(srcs), dest)
		} else {
			to, err = c.Copy(box, pUIDs(srcs), dest)
		}
		c.Release(err)
		if err != nil {
			return err
		}
		a.mu.Lock()
		tx := a.begin()
		for _, p := range pairs {
			c, src := p[0], p[1]
			u, ok := to[src.pUID]
			if move {
				a.lose(src, tx)
			}
			if ok {
				a.bind(c, dest, u, tx)
			}
		}
		err = tx.commit()
		a.mu.Unlock()
		if err != nil {
			a.b.Log.Warn("imap: could not save mailbox state", "user", a.login, "err", err)
		}
	}
	ops := group
	if !move {
		ops = []*op{o}
	}
	a.mu.Lock()
	tx := a.begin()
	a.finishOps(ops, false, tx)
	err := tx.commit()
	a.mu.Unlock()
	a.settleFolder(dest)
	return err
}

// runExpunge makes o, which merges group.
func (a *Account) runExpunge(o *op, group []*op) error {
	a.mu.Lock()
	var names []string
	for box := range a.placed(o.ids, nil) {
		names = append(names, box)
	}
	a.mu.Unlock()
	defer a.lockFolders(names...)()

	a.mu.Lock()
	byBox := a.placed(o.ids, nil)
	a.mu.Unlock()
	for box, msgs := range byBox {
		if !slices.Contains(names, box) {
			continue // the next run takes it
		}
		c, err := a.conn(interactive, box)
		if err != nil {
			return err
		}
		err = c.Expunge(box, pUIDs(msgs))
		c.Release(err)
		if err != nil {
			return err
		}
		a.mu.Lock()
		tx := a.begin()
		for _, msg := range msgs {
			a.lose(msg, tx)
		}
		err = tx.commit()
		a.mu.Unlock()
		if err != nil {
			a.b.Log.Warn("imap: could not save mailbox state", "user", a.login, "err", err)
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	tx := a.begin()
	a.finishOps(group, false, tx)
	return tx.commit()
}
