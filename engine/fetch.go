package engine

import (
	"bytes"
	"context"
	"errors"
	"slices"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

// FetchBatch is how many messages one upstream FETCH of full bodies asks for.
const FetchBatch = 25

// interactiveFetch is the most messages a request for pieces may have
// and still go ahead of bulk downloads.
const interactiveFetch = 3

// fetchHeaders asks the provider for the header entries of msgs, and
// saves them. A message the provider no longer has is missing.
func (a *Account) fetchHeaders(msgs []*Message, p priority) (map[*Message]*HeaderEntry, error) {
	out := map[*Message]*HeaderEntry{}
	for box, at := range a.locate(msgs) {
		for chunk := range slices.Chunk(at.uids(), FetchBatch) {
			c, err := a.conn(p, box)
			if err != nil {
				return nil, err
			}
			got, err := c.FetchHeaders(box, chunk)
			c.Release(err)
			if err != nil {
				return nil, err
			}
			save := map[string]*HeaderEntry{}
			for uid, h := range got {
				for _, msg := range at[uid] {
					out[msg] = h
					save[msg.key] = h
				}
			}
			if err := a.b.Store.putHeaders(a.login, save); err != nil {
				a.b.Log.Warn("imap: could not save header entries", "user", a.login, "err", err)
			}
		}
	}
	return out, nil
}

// located is messages by the provider's UID in one folder. Two messages
// share a UID when one is a queued copy of the other.
type located map[imap.UID][]*Message

func (l located) uids() []imap.UID {
	out := make([]imap.UID, 0, len(l))
	for u := range l {
		out = append(out, u)
	}
	slices.Sort(out)
	return out
}

// inOrder returns the UIDs of l in the order of their first message in
// msgs.
func (l located) inOrder(msgs []*Message) []imap.UID {
	uidOf := make(map[*Message]imap.UID, len(l))
	for u, ms := range l {
		for _, msg := range ms {
			uidOf[msg] = u
		}
	}
	out := make([]imap.UID, 0, len(l))
	seen := make(map[imap.UID]bool, len(l))
	for _, msg := range msgs {
		if u, ok := uidOf[msg]; ok && !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out
}

// locate groups msgs by where the provider has them, or for a queued copy
// the message it copies. Messages the provider has nowhere are left out.
func (a *Account) locate(msgs []*Message) map[string]located {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := map[string]located{}
	for _, msg := range msgs {
		if box, uid := a.readFrom(msg); uid != 0 {
			if out[box] == nil {
				out[box] = located{}
			}
			out[box][uid] = append(out[box][uid], msg)
		}
	}
	return out
}

// boxesInOrder returns the folders of where in the order of their first
// message in msgs.
func boxesInOrder(where map[string]located, msgs []*Message) []string {
	boxOf := map[*Message]string{}
	for box, at := range where {
		for _, ms := range at {
			for _, msg := range ms {
				boxOf[msg] = box
			}
		}
	}
	var out []string
	seen := map[string]bool{}
	for _, msg := range msgs {
		if box, ok := boxOf[msg]; ok && !seen[box] {
			seen[box] = true
			out = append(out, box)
		}
	}
	return out
}

// readFrom returns where the provider has msg's contents (a.mu held).
func (a *Account) readFrom(msg *Message) (string, imap.UID) {
	for range 8 { // a copy of a copy, and so on
		if msg.pUID != 0 {
			return msg.pBox, msg.pUID
		}
		if msg = a.byID[msg.origin]; msg == nil {
			break
		}
	}
	return "", 0
}

// BodyStructure describes raw.
func BodyStructure(raw []byte) imap.BodyStructure {
	return repairStructure(imapserver.ExtractBodyStructure(bytes.NewReader(raw)))
}

// repairStructure makes a body structure safe for go-imap to write. A
// multipart with no parts is described as an empty text/plain part, as
// Dovecot does. Missing extension data, which a provider may leave out,
// is filled in empty.
func repairStructure(bs imap.BodyStructure) imap.BodyStructure {
	switch bs := bs.(type) {
	case *imap.BodyStructureMultiPart:
		if bs.Extended == nil {
			bs.Extended = &imap.BodyStructureMultiPartExt{}
		}
		if len(bs.Children) == 0 {
			return &imap.BodyStructureSinglePart{
				Type: "text", Subtype: "plain",
				Params:   map[string]string{"charset": "us-ascii"},
				Encoding: "7bit",
				Text:     &imap.BodyStructureText{},
				Extended: &imap.BodyStructureSinglePartExt{},
			}
		}
		for i, c := range bs.Children {
			bs.Children[i] = repairStructure(c)
		}
	case *imap.BodyStructureSinglePart:
		if bs.Extended == nil {
			bs.Extended = &imap.BodyStructureSinglePartExt{}
		}
		if bs.MessageRFC822 != nil {
			if bs.MessageRFC822.Envelope == nil {
				bs.MessageRFC822.Envelope = &imap.Envelope{}
			}
			if bs.MessageRFC822.BodyStructure == nil {
				bs.MessageRFC822.BodyStructure = &imap.BodyStructureSinglePart{Type: "text", Subtype: "plain"}
			}
			bs.MessageRFC822.BodyStructure = repairStructure(bs.MessageRFC822.BodyStructure)
		}
	}
	return bs
}

// FetchStats says where a FETCH got its messages, for the fetch trace.
type FetchStats struct {
	Memory, Disk int // from the cache
	Provider     int // fetched by this request
	Waited       int // fetched by another request, waited for
	Headers      int // answered from header entries
	Pieces       int // answered from pieces (piece.go)
}

// download gets msgs from the cache, or fetches, transforms and caches them.
// Results go to out, if not nil. A message another request is downloading
// is waited for, not fetched twice, except one a background download has
// not started on, which a client takes over (claim). Only the immutable
// fields of the messages (key, direct) are read without the lock. A
// background download is bulk however few messages it has. st, if not
// nil, counts where the messages came from.
func (a *Account) download(msgs []*Message, out map[*Message][]byte, background bool, st *FetchStats) error {
	if st == nil {
		st = &FetchStats{}
	}
	b := a.b
	cl := &claimer{background: background}
	var mine []*Message
	claimed := map[string]bool{}
	waits := map[*Message]chan struct{}{}
	for _, msg := range msgs {
		key := msg.key
		if out == nil && b.Cache.Has(a.login, key) {
			continue
		}
		if out != nil {
			if data, from := b.Cache.get(a.login, key); data != nil {
				out[msg] = data
				if from == fromMemory {
					st.Memory++
				} else {
					st.Disk++
				}
				continue
			}
		}
		if claimed[key] {
			mine = append(mine, msg)
			continue
		}
		if ch, ok := b.claim(key, cl); ok {
			claimed[key] = true
			mine = append(mine, msg)
		} else {
			waits[msg] = ch
		}
	}
	st.Provider += len(mine)
	st.Waited += len(waits)
	err := a.fetchFrom(mine, out, cl, background)
	// What a failed download left claimed is released before waiting on
	// others, so two requests never wait on each other.
	for key := range claimed {
		b.unclaim(key, cl)
	}
	if err != nil {
		return err
	}
	// Messages another request was downloading. If that download failed,
	// or kept nothing (a message too large to hold in memory), fetch here.
	var again []*Message
	for msg, ch := range waits {
		<-ch
		if out == nil {
			continue
		}
		if data := b.Cache.Get(a.login, msg.key); data != nil {
			out[msg] = data
		} else {
			again = append(again, msg)
		}
	}
	st.Provider += len(again)
	st.Waited -= len(again)
	return a.fetchFrom(again, out, nil, background)
}

// fetchFrom downloads msgs over the pool, from wherever the provider has
// them, in their order: folder by folder in the order of their first
// message, and the first batch has the first messages. A client's first
// batch is interactive; the rest, and all of a background download, are
// bulk, which gives its connection back between batches so interactive
// requests go first. With cl, it leaves out what a client took over
// (startBatch), and releases each batch's claims once it is cached. A
// message the queue moved at the provider meanwhile is fetched again from
// its new place.
func (a *Account) fetchFrom(msgs []*Message, out map[*Message][]byte, cl *claimer, background bool) error {
	first := !background
	for try := 0; try < 2 && len(msgs) > 0; try++ {
		type place struct {
			box string
			uid imap.UID
		}
		was := map[*Message]place{}
		a.mu.Lock()
		for _, msg := range msgs {
			box, uid := a.readFrom(msg)
			was[msg] = place{box, uid}
		}
		a.mu.Unlock()
		got := map[*Message]bool{}
		where := a.locate(msgs)
		for _, box := range boxesInOrder(where, msgs) {
			at := where[box]
			for chunk := range slices.Chunk(at.inOrder(msgs), FetchBatch) {
				p := bulk
				if first {
					p, first = interactive, false
				}
				c, err := a.conn(p, box)
				if err != nil {
					return err
				}
				chunk = a.b.startBatch(cl, chunk, at)
				if len(chunk) == 0 {
					c.Release(nil)
					continue
				}
				batch, err := a.b.fetchFull(c, box, a.login, slices.Sorted(slices.Values(chunk)), at, out, a.withVerdict)
				c.Release(err)
				if err != nil {
					return err
				}
				for _, msg := range batch {
					got[msg] = true
				}
				if cl != nil {
					for _, u := range chunk {
						for _, msg := range at[u] {
							a.b.unclaim(msg.key, cl)
						}
					}
				}
			}
		}
		// Not found where they were: moved meanwhile?
		var moved []*Message
		a.mu.Lock()
		for _, msg := range msgs {
			if box, uid := a.readFrom(msg); !got[msg] && uid != 0 && (place{box, uid}) != was[msg] {
				moved = append(moved, msg)
			}
		}
		a.mu.Unlock()
		msgs = moved
	}
	return nil
}

// claimer is one download's hold on the messages it fetches.
type claimer struct {
	background bool // read-ahead, backfill
}

// claim marks key as being downloaded by cl. ok is false if another
// download is fetching it: ch closes when that ends. A client's download takes over a message that a
// background one (read-ahead, backfill) holds but has not started to
// fetch, so the client does not wait behind the batches before it.
func (b *Engine) claim(key string, cl *claimer) (ch chan struct{}, ok bool) {
	b.flightMu.Lock()
	defer b.flightMu.Unlock()
	if f := b.inflight[key]; f != nil {
		if f.owner.background && !cl.background && !f.started {
			f.owner = cl
			return nil, true
		}
		return f.done, false
	}
	if b.inflight == nil {
		b.inflight = map[string]*flight{}
	}
	b.inflight[key] = &flight{done: make(chan struct{}), owner: cl}
	return nil, true
}

// unclaim ends cl's download of key, unless another download took it over.
func (b *Engine) unclaim(key string, cl *claimer) {
	b.flightMu.Lock()
	defer b.flightMu.Unlock()
	if f := b.inflight[key]; f != nil && f.owner == cl {
		close(f.done)
		delete(b.inflight, key)
	}
}

// startBatch marks the messages of chunk that cl claims as started, so no
// client takes them over. For a background download, it returns the UIDs
// whose messages cl still claims: a client took over the others. Otherwise
// it returns chunk.
func (b *Engine) startBatch(cl *claimer, chunk []imap.UID, at located) []imap.UID {
	if cl == nil || !cl.background {
		return chunk
	}
	b.flightMu.Lock()
	defer b.flightMu.Unlock()
	var out []imap.UID
	for _, u := range chunk {
		mine := false
		for _, msg := range at[u] {
			if f := b.inflight[msg.key]; f != nil && f.owner == cl {
				f.started = true
				mine = true
			}
		}
		if mine {
			out = append(out, u)
		}
	}
	return out
}

// flight is a download in progress.
type flight struct {
	done    chan struct{} // closed when it ends
	owner   *claimer
	started bool // its batch is being fetched
}

// prefetchMax is the most new messages one resync downloads ahead of
// clients.
const prefetchMax = 10

// prefetch downloads and transforms new mail in the background after
// clients were told about it, so it opens without waiting. Only the
// newest prefetchMax messages are fetched; the rest wait for a client.
func (a *Account) prefetch(msgs []*Message) {
	if len(msgs) > prefetchMax {
		msgs = msgs[len(msgs)-prefetchMax:]
	}
	if err := a.download(msgs, nil, false, nil); err != nil && !errors.Is(err, ErrNoCredentials) {
		a.b.Log.Warn("imap: could not download new mail", "user", a.login, "err", err)
	}
}

// fetchFull fetches uids from folder box over c, runs them through the
// Transform and caches them under the keys of their messages in at. A direct message
// is cached exactly as the provider has it, so the cache and the provider
// agree on every byte. Results also go to out, if not nil. It returns the
// messages it got. withAuth, if set, adds the verdict to Read's context.
func (b *Engine) fetchFull(c conn, box, account string, uids []imap.UID, at located, out map[*Message][]byte,
	withAuth func(context.Context, []byte) context.Context) ([]*Message, error) {
	var got []*Message
	// The header entries of transformed messages, so client lists need not
	// read them whole.
	entries := map[string]*HeaderEntry{}
	defer func() {
		if err := b.Store.putHeaders(account, entries); err != nil {
			b.Log.Warn("imap: could not save header entries", "user", account, "err", err)
		}
	}()
	err := c.FetchFull(box, uids, func(uid imap.UID, raw []byte) {
		msgs := at[uid]
		if len(msgs) == 0 {
			return
		}
		data, final := raw, true
		if !msgs[0].direct {
			ctx, cancel := context.WithTimeout(context.Background(), b.Timeout)
			if withAuth != nil {
				ctx = withAuth(ctx, raw)
			}
			var st ReadStatus
			data, st = b.Transform.Read(ctx, raw)
			cancel()
			// A message clients see already: ReadHold is ReadRetry.
			if final = st == ReadFinal; final {
				entries[msgs[0].key] = EntryOf(data)
			}
		}
		for _, m := range msgs {
			if err := b.Cache.Put(account, m.key, data, final); err != nil {
				b.Log.Warn("imap: cache write failed", "err", err)
			}
			if out != nil {
				out[m] = data
			}
			got = append(got, m)
		}
	})
	return got, err
}
