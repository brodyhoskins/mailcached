package engine

import (
	"bytes"
	"encoding/json"
	"errors"

	"github.com/emersion/go-imap/v2"
)

// HeaderEntry is what clients fill a message list with, kept in the Store
// so a client's list is answered without reading whole messages: the
// header, the size and the structure (which the header does not give). For
// a message the proxy does not change (message.direct) the provider is
// asked for these alone. For any other, they come from the changed
// message, when it is transformed or read from the disk cache.
type HeaderEntry struct {
	Header    []byte
	Size      int64
	Structure imap.BodyStructure
	// Preview is the start of the message's text, for JMAP; nil if
	// unknown (an entry the provider gave without the body).
	Preview *string
}

// EntryOf makes the header entry of a whole message.
func EntryOf(raw []byte) *HeaderEntry {
	hdr := raw
	// The header ends with the first empty line.
	for i := 0; i < len(raw); {
		j := bytes.IndexByte(raw[i:], '\n')
		if j < 0 {
			break
		}
		line := raw[i : i+j+1]
		i += j + 1
		if len(line) == 1 || (len(line) == 2 && line[0] == '\r') {
			hdr = raw[:i]
			break
		}
	}
	p := Preview(raw)
	return &HeaderEntry{Header: bytes.Clone(hdr), Size: int64(len(raw)), Structure: BodyStructure(raw), Preview: &p}
}

// jsonPart is a body structure part as saved in the Store.
type jsonPart struct {
	Multi bool `json:"m,omitempty"`
	// Multipart.
	Children []*jsonPart `json:"c,omitempty"`
	// Single part.
	Type        string            `json:"t,omitempty"`
	Subtype     string            `json:"s,omitempty"`
	Params      map[string]string `json:"p,omitempty"`
	ID          string            `json:"id,omitempty"`
	Description string            `json:"d,omitempty"`
	Encoding    string            `json:"e,omitempty"`
	Size        uint32            `json:"z,omitempty"`
	Text        bool              `json:"x,omitempty"`
	NumLines    int64             `json:"n,omitempty"`
	Envelope    *imap.Envelope    `json:"env,omitempty"` // message/rfc822
	Message     *jsonPart         `json:"msg,omitempty"` // message/rfc822
	// Extension data.
	Disposition *imap.BodyStructureDisposition `json:"dsp,omitempty"`
	Language    []string                       `json:"lang,omitempty"`
	Location    string                         `json:"loc,omitempty"`
}

func encodeStructure(bs imap.BodyStructure) (string, error) {
	p := toJSONPart(bs)
	if p == nil {
		return "", errors.New("no body structure")
	}
	b, err := json.Marshal(p)
	return string(b), err
}

func decodeStructure(s string) (imap.BodyStructure, error) {
	var p jsonPart
	if err := json.Unmarshal([]byte(s), &p); err != nil {
		return nil, err
	}
	return repairStructure(fromJSONPart(&p)), nil
}

func toJSONPart(bs imap.BodyStructure) *jsonPart {
	switch bs := bs.(type) {
	case *imap.BodyStructureMultiPart:
		p := &jsonPart{Multi: true, Subtype: bs.Subtype}
		for _, c := range bs.Children {
			if cp := toJSONPart(c); cp != nil {
				p.Children = append(p.Children, cp)
			}
		}
		if e := bs.Extended; e != nil {
			p.Params, p.Disposition, p.Language, p.Location = e.Params, e.Disposition, e.Language, e.Location
		}
		return p
	case *imap.BodyStructureSinglePart:
		p := &jsonPart{Type: bs.Type, Subtype: bs.Subtype, Params: bs.Params, ID: bs.ID,
			Description: bs.Description, Encoding: bs.Encoding, Size: bs.Size}
		if bs.Text != nil {
			p.Text, p.NumLines = true, bs.Text.NumLines
		}
		if m := bs.MessageRFC822; m != nil {
			p.Envelope, p.Message, p.NumLines = m.Envelope, toJSONPart(m.BodyStructure), m.NumLines
		}
		if e := bs.Extended; e != nil {
			p.Disposition, p.Language, p.Location = e.Disposition, e.Language, e.Location
		}
		return p
	}
	return nil
}

func fromJSONPart(p *jsonPart) imap.BodyStructure {
	if p.Multi {
		bs := &imap.BodyStructureMultiPart{Subtype: p.Subtype, Extended: &imap.BodyStructureMultiPartExt{
			Params: p.Params, Disposition: p.Disposition, Language: p.Language, Location: p.Location}}
		for _, c := range p.Children {
			bs.Children = append(bs.Children, fromJSONPart(c))
		}
		return bs
	}
	bs := &imap.BodyStructureSinglePart{Type: p.Type, Subtype: p.Subtype, Params: p.Params, ID: p.ID,
		Description: p.Description, Encoding: p.Encoding, Size: p.Size,
		Extended: &imap.BodyStructureSinglePartExt{Disposition: p.Disposition, Language: p.Language, Location: p.Location}}
	if p.Text {
		bs.Text = &imap.BodyStructureText{NumLines: p.NumLines}
	}
	if p.Message != nil || p.Envelope != nil {
		m := &imap.BodyStructureMessageRFC822{Envelope: p.Envelope, NumLines: p.NumLines}
		if p.Message != nil {
			m.BodyStructure = fromJSONPart(p.Message)
		}
		bs.MessageRFC822 = m
	}
	return bs
}
