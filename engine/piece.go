package engine

// Pieces: the parts of a message a client asks for, without the rest. A
// message the proxy does not change (direct) has the same bytes at the
// provider as at the client, so a body section the client asks for
// (BODY[1.2], BODY[]<0.65536>) is asked of the provider as it is, and
// cached by itself. A phone that opens a message reads its text and leaves
// its attachments, and only the text is downloaded.
//
// A message the Transform changes is read whole, as the Transform needs
// all of it; so is a small message (PieceWhole or less), which costs as
// little whole as in pieces, and opens at once from then on. A piece is
// dropped from the cache when its whole message is cached.
//
// BINARY[part] (the decoded part) is asked of a provider with BINARY as it
// is. From one without, the proxy asks for BODY[part] and decodes it,
// with the part's Content-Transfer-Encoding from the header entry.
//
// Only IMAP providers give pieces: JMAP has no byte ranges, and its part
// downloads are decoded, so their bytes are not the message's. With a
// JMAP provider, messages are read whole.

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime/quotedprintable"
	"slices"
	"strings"

	"github.com/emersion/go-imap/v2"
)

// PieceWhole is the size up to which a message is read whole when a
// client asks for a piece of it.
var PieceWhole int64 = 32 << 10

// Section is a piece of a message: a body section, or with Binary the
// decoded content of a part.
type Section struct {
	Binary    bool
	Part      []int
	Specifier imap.PartSpecifier
	Fields    []string // HEADER.FIELDS, or with NotFields HEADER.FIELDS.NOT
	NotFields bool
	Partial   *imap.SectionPartial
	// Encoding is the part's Content-Transfer-Encoding, for a Binary
	// section from a provider without BINARY.
	Encoding string
}

// String names the section as IMAP does, with its partial range.
func (s Section) String() string {
	var b strings.Builder
	if s.Binary {
		b.WriteString("BINARY[")
	} else {
		b.WriteString("BODY[")
	}
	for i, p := range s.Part {
		if i > 0 {
			b.WriteByte('.')
		}
		fmt.Fprint(&b, p)
	}
	if s.Specifier != imap.PartSpecifierNone {
		if len(s.Part) > 0 {
			b.WriteByte('.')
		}
		b.WriteString(string(s.Specifier))
		if len(s.Fields) > 0 {
			if s.NotFields {
				b.WriteString(".NOT")
			}
			b.WriteString(" (" + strings.ToUpper(strings.Join(s.Fields, " ")) + ")")
		}
	}
	b.WriteByte(']')
	if s.Partial != nil {
		fmt.Fprintf(&b, "<%d.%d>", s.Partial.Offset, s.Partial.Size)
	}
	return b.String()
}

// whole is the section without its partial range.
func (s Section) whole() Section {
	s.Partial = nil
	return s
}

// pieceKey is where the cache keeps a piece of the message with key.
func pieceKey(key string, s Section) string { return hashKey("piece", key, s.String()) }

// errNoPieces means the provider cannot give pieces: read the message
// whole.
var errNoPieces = errors.New("the provider gives whole messages only")

var errNoSearch = errors.New("the provider does not search")

// Pieces gets sections of direct messages: from the cache, or from the
// provider, which is asked for just them, and they are cached. A message
// the provider cannot give pieces of (a JMAP provider, a queued copy) is
// left out of the result: the caller reads it whole. Sections are the
// same for every message, except their Encoding, which encodings gives
// by message (for Binary sections; "" when unknown).
func (a *Account) Pieces(msgs []*Message, secs []Section, encodings func(*Message, Section) string, st *FetchStats) (map[*Message]map[string][]byte, error) {
	if st == nil {
		st = &FetchStats{}
	}
	out := map[*Message]map[string][]byte{}
	var missing []*Message
	for _, msg := range msgs {
		got := map[string][]byte{}
		all := true
		for _, s := range secs {
			if data := a.b.Cache.Get(a.login, pieceKey(msg.key, s)); data != nil {
				got[s.String()] = data
			} else {
				all = false
			}
		}
		if all {
			out[msg] = got
			st.Pieces++
			continue
		}
		missing = append(missing, msg)
	}
	if len(missing) == 0 {
		return out, nil
	}
	p := bulk
	if len(missing) <= interactiveFetch {
		p = interactive
	}
	st.Provider += len(missing)
	for box, at := range a.locate(missing) {
		for chunk := range slices.Chunk(at.uids(), FetchBatch) {
			c, err := a.conn(p, box)
			if err != nil {
				return nil, err
			}
			// The Encoding of a Binary section is per message: ask for each
			// message's own when they differ.
			groups := map[string][]imap.UID{}
			perGroup := map[string][]Section{}
			for _, u := range chunk {
				ss := make([]Section, len(secs))
				var sig strings.Builder
				for i, s := range secs {
					if s.Binary && encodings != nil {
						s.Encoding = encodings(at[u][0], s)
					}
					ss[i] = s
					sig.WriteString(s.Encoding + "\x00")
				}
				groups[sig.String()] = append(groups[sig.String()], u)
				perGroup[sig.String()] = ss
			}
			for sig, uids := range groups {
				ss := perGroup[sig]
				err = c.FetchSections(box, uids, ss, func(uid imap.UID, i int, data []byte) {
					for _, msg := range at[uid] {
						if out[msg] == nil {
							out[msg] = map[string][]byte{}
						}
						out[msg][secs[i].String()] = data
						if err := a.b.Cache.putPiece(a.login, msg.key, pieceKey(msg.key, secs[i]), data); err != nil {
							a.b.Log.Warn("cache write failed", "err", err)
						}
					}
				})
				if err != nil {
					break
				}
			}
			c.Release(err)
			if errors.Is(err, errNoPieces) {
				for _, u := range chunk {
					for _, msg := range at[u] {
						delete(out, msg)
					}
				}
				continue
			}
			if err != nil {
				return nil, err
			}
		}
	}
	// A message with a section missing (gone at the provider, or not
	// given) is read whole.
	for msg, got := range out {
		for _, s := range secs {
			if _, ok := got[s.String()]; !ok {
				delete(out, msg)
				break
			}
		}
	}
	return out, nil
}

// DecodePart decodes a part's body with its Content-Transfer-Encoding.
func DecodePart(body []byte, encoding string) ([]byte, error) { return decodePart(body, encoding) }

// decodePart decodes a part's body with its Content-Transfer-Encoding.
func decodePart(body []byte, encoding string) ([]byte, error) {
	var r io.Reader
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		// Line breaks and stray characters are skipped, as readers do.
		clean := bytes.Map(func(r rune) rune {
			switch {
			case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '+', r == '/':
				return r
			}
			return -1
		}, body)
		if len(clean)%4 == 1 {
			clean = clean[:len(clean)-1]
		}
		r = base64.NewDecoder(base64.RawStdEncoding, bytes.NewReader(clean))
	case "quoted-printable":
		r = quotedprintable.NewReader(bytes.NewReader(body))
	case "", "7bit", "8bit", "binary":
		return body, nil
	default:
		return nil, fmt.Errorf("unknown transfer encoding %q", encoding)
	}
	return io.ReadAll(r)
}

// applyPartial cuts the partial range out of data.
func applyPartial(data []byte, p *imap.SectionPartial) []byte {
	if p == nil {
		return data
	}
	if p.Offset >= int64(len(data)) {
		return []byte{}
	}
	end := int64(len(data))
	if p.Size >= 0 && p.Offset+p.Size < end {
		end = p.Offset + p.Size
	}
	return data[p.Offset:end]
}

// PartEncoding returns the Content-Transfer-Encoding of a part in a body
// structure, and whether the part is there.
func PartEncoding(bs imap.BodyStructure, part []int) (string, bool) {
	for _, n := range part {
		switch b := bs.(type) {
		case *imap.BodyStructureMultiPart:
			if n < 1 || n > len(b.Children) {
				return "", false
			}
			bs = b.Children[n-1]
		case *imap.BodyStructureSinglePart:
			if b.MessageRFC822 != nil {
				// Inside an attached message.
				bs = b.MessageRFC822.BodyStructure
				if mp, ok := bs.(*imap.BodyStructureMultiPart); ok {
					if n < 1 || n > len(mp.Children) {
						return "", false
					}
					bs = mp.Children[n-1]
					continue
				}
				if n != 1 {
					return "", false
				}
				continue
			}
			if n != 1 {
				return "", false
			}
		default:
			return "", false
		}
	}
	if sp, ok := bs.(*imap.BodyStructureSinglePart); ok {
		return sp.Encoding, true
	}
	return "", false
}

// ErrNoSearch means the provider cannot search: read the messages.
var ErrNoSearch = errNoSearch

// SearchAtProvider asks the provider which of msgs match c, for messages
// the proxy does not change: the provider has the same text. It returns
// ErrNoSearch if the provider cannot search; then the caller reads the
// messages.
func (a *Account) SearchAtProvider(msgs []*Message, c *imap.SearchCriteria) (map[*Message]bool, error) {
	out := map[*Message]bool{}
	for box, at := range a.locate(msgs) {
		cn, err := a.conn(interactive, box)
		if err != nil {
			return nil, err
		}
		uids, err := cn.Search(box, c)
		cn.Release(err)
		if err != nil {
			return nil, err
		}
		for _, u := range uids {
			for _, msg := range at[u] {
				out[msg] = true
			}
		}
	}
	return out, nil
}
