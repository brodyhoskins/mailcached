package imapproxy

import (
	"bufio"
	"bytes"
	"cmp"
	"io"
	"maps"
	"slices"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-message/textproto"

	"github.com/brodyhoskins/mailcached/engine"
)

func needsContent(o *imap.FetchOptions) bool {
	return o.Envelope || o.BodyStructure != nil || o.RFC822Size ||
		len(o.BodySection) > 0 || len(o.BinarySection) > 0 || len(o.BinarySectionSize) > 0
}

// headerOnly reports whether o asks for nothing beyond the top-level
// header, size, envelope and structure: what a client fills its message
// list with. HEADER.FIELDS and HEADER.FIELDS.NOT are HEADER with a field
// list.
func headerOnly(o *imap.FetchOptions) bool {
	if len(o.BinarySection) > 0 || len(o.BinarySectionSize) > 0 {
		return false
	}
	for _, bs := range o.BodySection {
		if len(bs.Part) > 0 || (bs.Specifier != imap.PartSpecifierHeader && bs.Specifier != imap.PartSpecifierMIME) {
			return false
		}
	}
	return true
}

// Fetch answers from the copy clients see (transformed, if the Transform
// changes the message): sizes, structure, envelope and
// body sections all describe what the client will actually read.
//
// A request for the header, size or structure alone (a client filling its
// message list) of a message the proxy does not change (message.direct)
// is answered from its header entry, without downloading the message: the
// entry is asked of the provider once, and kept in the Store. A request
// for parts of such a message (BODY[1.2], BODY[]<0.65536>) downloads just
// those parts (engine.Pieces), unless the message is small.
//
// What is at hand (header entries, cached messages) is answered first.
// The rest is downloaded in batches, unseen messages first and then the
// newest, and each batch is answered as it arrives, so a client that asks
// for many messages starts getting them at once. FETCH responses may come
// in any order.
func (s *Session) Fetch(w *imapserver.FetchWriter, numSet imap.NumSet, options *imap.FetchOptions) error {
	defer busy()()
	if s.mbox == nil {
		return errNotSelected
	}
	targets := s.targets(numSet)
	if len(targets) == 0 {
		return nil
	}
	var sent int        // message bytes written, for the trace
	var gotAt time.Time // when the first messages were ready to send
	if s.b.Trace && needsContent(options) {
		// One line per FETCH: where its messages came from, and whether
		// the time went to getting them or to sending them.
		st := &engine.FetchStats{}
		s.stats = st
		start := time.Now()
		defer func() {
			s.stats = nil
			if gotAt.IsZero() {
				gotAt = time.Now()
			}
			s.b.Log.Info("imap trace: fetch", "remote", s.conn.NetConn().RemoteAddr(), "messages", len(targets),
				"memory", st.Memory, "disk", st.Disk, "provider", st.Provider, "waited", st.Waited, "headers", st.Headers,
				"pieces", st.Pieces, "message_bytes", sent, "first_ms", gotAt.Sub(start).Milliseconds(), "ms", time.Since(start).Milliseconds())
		}()
	}
	if !needsContent(options) {
		gotAt = time.Now()
		if err := s.markSeen(targets, options); err != nil {
			return err
		}
		return s.writeAll(w, targets, options, nil, nil, nil, &sent)
	}

	secs, pieceable := sectionsOf(options)
	var headers map[*engine.Message]*engine.HeaderEntry
	whole := messagesOf(targets) // need the whole message
	if pieceable {
		var err error
		if headers, whole, err = s.acct.HeaderEntries(whole, s.stats); err != nil {
			return passError(err)
		}
	} else {
		s.noteRead(targets)
	}
	// What needs a download: whole messages not in the cache, and the
	// pieces of large direct messages.
	needWhole := map[*engine.Message]bool{}
	for _, msg := range whole {
		needWhole[msg] = true
	}
	piece := map[*engine.Message]bool{}
	if len(secs) > 0 {
		for msg, h := range headers {
			switch {
			case !msg.Direct() || h.Size <= engine.PieceWhole || s.b.Engine.Cache.Has(s.acct.User(), msg.Key()):
				delete(headers, msg)
				needWhole[msg] = true
			default:
				piece[msg] = true
			}
		}
	}
	if err := s.markSeen(targets, options); err != nil {
		return err
	}

	// First what is at hand.
	var now, later []target
	cached := map[*engine.Message][]byte{}
	for _, t := range targets {
		switch {
		case piece[t.msg]:
			later = append(later, t)
		case needWhole[t.msg]:
			if raw := s.b.Engine.Cache.Get(s.acct.User(), t.msg.Key()); raw != nil {
				cached[t.msg] = raw
				if s.stats != nil {
					s.stats.Memory++
				}
				now = append(now, t)
			} else {
				later = append(later, t)
			}
		default:
			now = append(now, t) // a header entry answers it
		}
	}
	gotAt = time.Now()
	if s.stats != nil {
		s.stats.Headers = len(now) - len(cached)
	}
	if err := s.writeAll(w, now, options, headers, cached, nil, &sent); err != nil {
		return err
	}
	s.acct.RecordReads(slices.Collect(maps.Keys(cached)))
	if len(later) == 0 {
		return nil
	}

	// Then the rest: unseen first, then the newest.
	s.acct.Lock()
	unseen := map[*engine.Message]bool{}
	for _, t := range later {
		unseen[t.msg] = !engine.HasFlag(t.msg.Flags(), imap.FlagSeen)
	}
	s.acct.Unlock()
	slices.SortStableFunc(later, func(a, b target) int {
		if unseen[a.msg] != unseen[b.msg] {
			if unseen[a.msg] {
				return -1
			}
			return 1
		}
		return cmp.Compare(b.seq, a.seq)
	})
	encodings := func(msg *engine.Message, sec engine.Section) string {
		h := headers[msg]
		if h == nil {
			return ""
		}
		enc, _ := engine.PartEncoding(h.Structure, sec.Part)
		return enc
	}
	for batch := range slices.Chunk(later, engine.FetchBatch) {
		var pmsgs, wmsgs []*engine.Message
		for _, t := range batch {
			if piece[t.msg] {
				pmsgs = append(pmsgs, t.msg)
			} else {
				wmsgs = append(wmsgs, t.msg)
			}
		}
		var pieces map[*engine.Message]map[string][]byte
		if len(pmsgs) > 0 {
			var err error
			if pieces, err = s.acct.Pieces(pmsgs, secs, encodings, s.stats); err != nil {
				return passError(err)
			}
			// Those the provider could not give in pieces are read whole.
			for _, msg := range pmsgs {
				if pieces[msg] == nil {
					delete(headers, msg)
					wmsgs = append(wmsgs, msg)
				}
			}
		}
		var contents map[*engine.Message][]byte
		if len(wmsgs) > 0 {
			var err error
			if contents, err = s.contents(wmsgs); err != nil {
				return err
			}
		}
		slices.SortFunc(batch, func(a, b target) int { return cmp.Compare(a.seq, b.seq) })
		if err := s.writeAll(w, batch, options, headers, contents, pieces, &sent); err != nil {
			return err
		}
	}
	return nil
}

// writeAll writes the responses for targets: from a header entry, from
// pieces, or from the whole message. A message with none of them, when
// contents were needed, was expunged meanwhile; its EXPUNGE follows.
func (s *Session) writeAll(w *imapserver.FetchWriter, targets []target, options *imap.FetchOptions,
	headers map[*engine.Message]*engine.HeaderEntry, contents map[*engine.Message][]byte,
	pieces map[*engine.Message]map[string][]byte, sent *int) error {
	content := needsContent(options)
	for _, t := range targets {
		s.acct.Lock()
		c := s.view.EncodeSeqNum(t.seq)
		uid, flags := t.msg.UID(), slices.Clone(t.msg.Flags())
		s.acct.Unlock()
		if c == 0 {
			continue
		}
		h := headers[t.msg]
		var err error
		switch {
		case !content:
			err = writeMessage(w.CreateMessage(c), uid, t.msg, flags, nil, options)
		case pieces[t.msg] != nil && h != nil:
			for _, b := range pieces[t.msg] {
				*sent += len(b)
			}
			err = writePieces(w.CreateMessage(c), uid, t.msg, flags, h, pieces[t.msg], options)
		case contents[t.msg] != nil:
			*sent += len(contents[t.msg])
			err = writeMessage(w.CreateMessage(c), uid, t.msg, flags, contents[t.msg], options)
		case h != nil:
			*sent += len(h.Header)
			err = writeFromHeader(w.CreateMessage(c), uid, t.msg, flags, h, options)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// sectionsOf returns the pieces a request asks for, beyond what a header
// entry answers (the top-level header, size, envelope, structure). ok is
// false when it asks for a whole message (BODY[], RFC822, BINARY[]).
func sectionsOf(o *imap.FetchOptions) (secs []engine.Section, ok bool) {
	add := func(s engine.Section) {
		if !slices.ContainsFunc(secs, func(x engine.Section) bool { return x.String() == s.String() }) {
			secs = append(secs, s)
		}
	}
	for _, bs := range o.BodySection {
		if len(bs.Part) == 0 {
			switch bs.Specifier {
			case imap.PartSpecifierHeader:
				continue // the header entry has it
			case imap.PartSpecifierNone:
				if bs.Partial == nil {
					return nil, false
				}
			}
		}
		s := engine.Section{Part: bs.Part, Specifier: bs.Specifier, Partial: bs.Partial}
		if len(bs.HeaderFieldsNot) > 0 {
			s.Fields, s.NotFields = bs.HeaderFieldsNot, true
		} else {
			s.Fields = bs.HeaderFields
		}
		add(s)
	}
	for _, bs := range o.BinarySection {
		if len(bs.Part) == 0 {
			return nil, false
		}
		add(engine.Section{Binary: true, Part: bs.Part, Partial: bs.Partial})
	}
	for _, bss := range o.BinarySectionSize {
		if len(bss.Part) == 0 {
			return nil, false
		}
		add(engine.Section{Binary: true, Part: bss.Part})
	}
	return secs, true
}

// writePieces answers from a header entry and the pieces asked for.
func writePieces(w *imapserver.FetchResponseWriter, uid imap.UID, m *engine.Message, flags []imap.Flag, h *engine.HeaderEntry,
	pieces map[string][]byte, o *imap.FetchOptions) error {
	w.WriteUID(uid)
	if o.Flags {
		w.WriteFlags(flags)
	}
	if o.InternalDate {
		w.WriteInternalDate(m.Date())
	}
	if o.RFC822Size {
		w.WriteRFC822Size(h.Size)
	}
	if o.Envelope {
		w.WriteEnvelope(envelope(h.Header))
	}
	if o.BodyStructure != nil {
		w.WriteBodyStructure(h.Structure)
	}
	for _, bs := range o.BodySection {
		var buf []byte
		if len(bs.Part) == 0 && bs.Specifier == imap.PartSpecifierHeader {
			buf = imapserver.ExtractBodySection(bytes.NewReader(h.Header), bs)
		} else {
			s := engine.Section{Part: bs.Part, Specifier: bs.Specifier, Partial: bs.Partial}
			if len(bs.HeaderFieldsNot) > 0 {
				s.Fields, s.NotFields = bs.HeaderFieldsNot, true
			} else {
				s.Fields = bs.HeaderFields
			}
			buf = pieces[s.String()]
		}
		if err := writeLiteral(w.WriteBodySection(bs, int64(len(buf))), buf); err != nil {
			return err
		}
	}
	for _, bs := range o.BinarySection {
		buf := pieces[engine.Section{Binary: true, Part: bs.Part, Partial: bs.Partial}.String()]
		if err := writeLiteral(w.WriteBinarySection(bs, int64(len(buf))), buf); err != nil {
			return err
		}
	}
	for _, bss := range o.BinarySectionSize {
		w.WriteBinarySectionSize(bss, uint32(len(pieces[engine.Section{Binary: true, Part: bss.Part}.String()])))
	}
	return w.Close()
}

// noteRead tells read-ahead about a request for message contents.
func (s *Session) noteRead(targets []target) {
	uids := make([]imap.UID, len(targets))
	s.acct.Lock()
	for i, t := range targets {
		uids[i] = t.msg.UID()
	}
	name := s.mbox.Name()
	s.acct.Unlock()
	s.acct.NoteRead(name, uids)
}

// writeFromHeader answers a header-only request from a header entry. UID,
// flags and date come from the proxy's state.
func writeFromHeader(w *imapserver.FetchResponseWriter, uid imap.UID, m *engine.Message, flags []imap.Flag, h *engine.HeaderEntry, o *imap.FetchOptions) error {
	w.WriteUID(uid)
	if o.Flags {
		w.WriteFlags(flags)
	}
	if o.InternalDate {
		w.WriteInternalDate(m.Date())
	}
	if o.RFC822Size {
		w.WriteRFC822Size(h.Size)
	}
	if o.Envelope {
		w.WriteEnvelope(envelope(h.Header))
	}
	if o.BodyStructure != nil {
		w.WriteBodyStructure(h.Structure)
	}
	for _, bs := range o.BodySection {
		buf := imapserver.ExtractBodySection(bytes.NewReader(h.Header), bs)
		if err := writeLiteral(w.WriteBodySection(bs, int64(len(buf))), buf); err != nil {
			return err
		}
	}
	return w.Close()
}

func writeMessage(w *imapserver.FetchResponseWriter, uid imap.UID, m *engine.Message, flags []imap.Flag, raw []byte, o *imap.FetchOptions) error {
	w.WriteUID(uid)
	if o.Flags {
		w.WriteFlags(flags)
	}
	if o.InternalDate {
		w.WriteInternalDate(m.Date())
	}
	if o.RFC822Size {
		w.WriteRFC822Size(int64(len(raw)))
	}
	if o.Envelope {
		w.WriteEnvelope(envelope(raw))
	}
	if o.BodyStructure != nil {
		w.WriteBodyStructure(engine.BodyStructure(raw))
	}
	for _, bs := range o.BodySection {
		buf := imapserver.ExtractBodySection(bytes.NewReader(raw), bs)
		if err := writeLiteral(w.WriteBodySection(bs, int64(len(buf))), buf); err != nil {
			return err
		}
	}
	for _, bs := range o.BinarySection {
		buf := imapserver.ExtractBinarySection(bytes.NewReader(raw), bs)
		if err := writeLiteral(w.WriteBinarySection(bs, int64(len(buf))), buf); err != nil {
			return err
		}
	}
	for _, bss := range o.BinarySectionSize {
		w.WriteBinarySectionSize(bss, imapserver.ExtractBinarySectionSize(bytes.NewReader(raw), bss))
	}
	return w.Close()
}

func writeLiteral(wc io.WriteCloser, b []byte) error {
	_, err := wc.Write(b)
	if cerr := wc.Close(); err == nil {
		err = cerr
	}
	return err
}

func envelope(raw []byte) *imap.Envelope {
	h, err := textproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		return &imap.Envelope{}
	}
	return imapserver.ExtractEnvelope(h)
}

// markSeen sets \Seen when the client reads a body without PEEK.
func (s *Session) markSeen(targets []target, o *imap.FetchOptions) error {
	if s.readOnly {
		return nil
	}
	seen := slices.ContainsFunc(o.BodySection, func(bs *imap.FetchItemBodySection) bool { return !bs.Peek }) ||
		slices.ContainsFunc(o.BinarySection, func(bs *imap.FetchItemBinarySection) bool { return !bs.Peek })
	if !seen {
		return nil
	}
	var unseen []target
	s.acct.Lock()
	for _, t := range targets {
		if !engine.HasFlag(t.msg.Flags(), imap.FlagSeen) {
			unseen = append(unseen, t)
		}
	}
	s.acct.Unlock()
	if len(unseen) == 0 {
		return nil
	}
	// An implicit flag change is reported to this client too (source nil).
	s.changeFlags(unseen, imap.StoreFlagsAdd, []imap.Flag{imap.FlagSeen}, nil)
	return nil
}

// contents returns the messages clients see, from the cache or by fetching
// and transforming them. A message the provider no longer has is missing
// from the result.
func (s *Session) contents(msgs []*engine.Message) (map[*engine.Message][]byte, error) {
	out, err := s.acct.Download(msgs, s.stats)
	return out, passError(err)
}
