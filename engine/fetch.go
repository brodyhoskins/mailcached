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

// interactiveFetch is the most messages a download may have and still go
// ahead of bulk downloads.
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
// is waited for, not fetched twice. Only the immutable fields of the
// messages (key, direct) are read without the lock. A background download
// is bulk however few messages it has. st, if not nil, counts where the
// messages came from.
func (a *Account) download(msgs []*Message, out map[*Message][]byte, background bool, st *FetchStats) error {
	if st == nil {
		st = &FetchStats{}
	}
	b := a.b
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
		ch, ok, bg := b.claim(key, background)
		switch {
		case ok:
			claimed[key] = true
			mine = append(mine, msg)
		case bg && !background:
			// A client does not wait for a background download (read-ahead,
			// backfill), which may be busy with a large batch: it fetches
			// the message itself.
			mine = append(mine, msg)
		default:
			waits[msg] = ch
		}
	}
	// Each batch's claims are released as soon as it is cached, so a
	// client waiting for one message does not wait for a whole bulk
	// download.
	done := func(msgs []*Message) {
		for _, msg := range msgs {
			if claimed[msg.key] {
				delete(claimed, msg.key)
				b.unclaim(msg.key)
			}
		}
	}
	st.Provider += len(mine)
	st.Waited += len(waits)
	err := a.fetchFrom(mine, out, done, background)
	// What a failed download left claimed is released before waiting on
	// others, so two requests never wait on each other.
	done(mine)
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
// them. A few messages (what a client opens, or new mail) are interactive;
// more are a bulk download, which gives its connection back between
// batches so interactive requests go first. done, if not nil, is called
// with each batch once it is cached. A message the queue moved at the
// provider meanwhile is fetched again from its new place.
func (a *Account) fetchFrom(msgs []*Message, out map[*Message][]byte, done func([]*Message), background bool) error {
	p := bulk
	if len(msgs) <= interactiveFetch && !background {
		p = interactive
	}
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
		for box, at := range a.locate(msgs) {
			for chunk := range slices.Chunk(at.uids(), FetchBatch) {
				c, err := a.conn(p, box)
				if err != nil {
					return err
				}
				batch, err := a.b.fetchFull(c, box, a.login, chunk, at, out)
				c.Release(err)
				if err != nil {
					return err
				}
				for _, msg := range batch {
					got[msg] = true
				}
				if done != nil {
					var all []*Message
					for _, u := range chunk {
						all = append(all, at[u]...)
					}
					done(all)
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

// claim marks key as being downloaded. ok is false if another request is
// downloading it already: ch closes when that download ends, and bg says
// whether it is a background download.
func (b *Engine) claim(key string, background bool) (ch chan struct{}, ok, bg bool) {
	b.flightMu.Lock()
	defer b.flightMu.Unlock()
	if f := b.inflight[key]; f != nil {
		return f.done, false, f.background
	}
	if b.inflight == nil {
		b.inflight = map[string]*flight{}
	}
	b.inflight[key] = &flight{done: make(chan struct{}), background: background}
	return nil, true, false
}

func (b *Engine) unclaim(key string) {
	b.flightMu.Lock()
	defer b.flightMu.Unlock()
	close(b.inflight[key].done)
	delete(b.inflight, key)
}

// flight is a download in progress.
type flight struct {
	done       chan struct{} // closed when it ends
	background bool
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
// messages it got.
func (b *Engine) fetchFull(c conn, box, account string, uids []imap.UID, at located, out map[*Message][]byte) ([]*Message, error) {
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
