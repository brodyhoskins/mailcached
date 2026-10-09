package jmapproxy

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"mime"
	"net/mail"
	"strings"
	"time"

	gomessage "github.com/emersion/go-message"

	"github.com/brodyhoskins/mailcached/internal/jmap"
)

// bodyIn is a body part of an Email a client creates.
type bodyIn struct {
	PartID      *string            `json:"partId"`
	BlobID      *string            `json:"blobId"`
	Type        string             `json:"type"`
	Charset     *string            `json:"charset"`
	Disposition *string            `json:"disposition"`
	Name        *string            `json:"name"`
	CID         *string            `json:"cid"`
	Language    []string           `json:"language"`
	Location    *string            `json:"location"`
	Headers     []jmap.EmailHeader `json:"headers"`
	SubParts    []bodyIn           `json:"subParts"`
}

// emailIn is an Email a client creates.
type emailIn struct {
	From          []jmap.EmailAddress            `json:"from"`
	Sender        []jmap.EmailAddress            `json:"sender"`
	To            []jmap.EmailAddress            `json:"to"`
	Cc            []jmap.EmailAddress            `json:"cc"`
	Bcc           []jmap.EmailAddress            `json:"bcc"`
	ReplyTo       []jmap.EmailAddress            `json:"replyTo"`
	Subject       *string                        `json:"subject"`
	SentAt        *time.Time                     `json:"sentAt"`
	MessageID     []string                       `json:"messageId"`
	InReplyTo     []string                       `json:"inReplyTo"`
	References    []string                       `json:"references"`
	BodyStructure *bodyIn                        `json:"bodyStructure"`
	TextBody      []bodyIn                       `json:"textBody"`
	HTMLBody      []bodyIn                       `json:"htmlBody"`
	Attachments   []bodyIn                       `json:"attachments"`
	BodyValues    map[string]jmap.EmailBodyValue `json:"bodyValues"`
}

// compose writes the message an Email describes.
func compose(c *call, raw json.RawMessage) ([]byte, *jmap.SetError) {
	var e emailIn
	if err := json.Unmarshal(raw, &e); err != nil {
		return nil, &jmap.SetError{Type: jmap.SetInvalidProperties, Description: err.Error()}
	}
	var all map[string]json.RawMessage
	_ = json.Unmarshal(raw, &all)
	bad := func(prop, desc string) *jmap.SetError {
		return &jmap.SetError{Type: jmap.SetInvalidProperties, Properties: []string{prop}, Description: desc}
	}
	for k := range all {
		switch k {
		case "id", "blobId", "threadId", "size", "hasAttachment", "preview":
			return nil, bad(k, "set by the server")
		case "headers":
			return nil, bad(k, "use header:Name properties")
		}
	}

	// The body: bodyStructure, or textBody, htmlBody and attachments.
	var root *bodyIn
	switch {
	case e.BodyStructure != nil:
		if len(e.TextBody)+len(e.HTMLBody)+len(e.Attachments) > 0 {
			return nil, bad("bodyStructure", "with textBody, htmlBody or attachments")
		}
		root = e.BodyStructure
	default:
		if len(e.TextBody) > 1 || len(e.HTMLBody) > 1 {
			return nil, bad("textBody", "at most one text and one HTML part")
		}
		var alt []bodyIn
		for _, p := range e.TextBody {
			if p.Type == "" {
				p.Type = "text/plain"
			}
			alt = append(alt, p)
		}
		for _, p := range e.HTMLBody {
			if p.Type == "" {
				p.Type = "text/html"
			}
			alt = append(alt, p)
		}
		var body *bodyIn
		switch len(alt) {
		case 0:
			empty := ""
			body = &bodyIn{PartID: &empty, Type: "text/plain"}
			if e.BodyValues == nil {
				e.BodyValues = map[string]jmap.EmailBodyValue{}
			}
			e.BodyValues[""] = jmap.EmailBodyValue{}
		case 1:
			body = &alt[0]
		default:
			body = &bodyIn{Type: "multipart/alternative", SubParts: alt}
		}
		root = body
		if len(e.Attachments) > 0 {
			root = &bodyIn{Type: "multipart/mixed", SubParts: append([]bodyIn{*body}, e.Attachments...)}
		}
	}

	var h gomessage.Header
	addrs := func(name string, l []jmap.EmailAddress) {
		if len(l) == 0 {
			return
		}
		out := make([]string, len(l))
		for i, a := range l {
			ma := mail.Address{Address: a.Email}
			if a.Name != nil {
				ma.Name = *a.Name
			}
			out[i] = ma.String()
		}
		h.Set(name, strings.Join(out, ", "))
	}
	ids := func(name string, l []string) {
		if len(l) == 0 {
			return
		}
		out := make([]string, len(l))
		for i, id := range l {
			out[i] = "<" + id + ">"
		}
		h.Set(name, strings.Join(out, " "))
	}
	date := time.Now()
	if e.SentAt != nil {
		date = *e.SentAt
	}
	h.Set("Date", date.Format(time.RFC1123Z))
	addrs("From", e.From)
	addrs("Sender", e.Sender)
	addrs("To", e.To)
	addrs("Cc", e.Cc)
	addrs("Bcc", e.Bcc)
	addrs("Reply-To", e.ReplyTo)
	if e.Subject != nil {
		h.Set("Subject", mime.QEncoding.Encode("utf-8", *e.Subject))
	}
	if len(e.MessageID) == 0 {
		e.MessageID = []string{newMessageID(e.From)}
	}
	ids("Message-ID", e.MessageID)
	ids("In-Reply-To", e.InReplyTo)
	ids("References", e.References)
	for k, v := range all {
		if !strings.HasPrefix(k, "header:") {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(k, "header:"), ":")
		var s string
		if json.Unmarshal(v, &s) != nil || len(parts) > 2 || strings.EqualFold(parts[0], "Content-Type") ||
			strings.EqualFold(parts[0], "Content-Transfer-Encoding") {
			return nil, bad(k, "")
		}
		switch {
		case len(parts) == 1 || parts[1] == "asRaw":
			h.Set(parts[0], strings.TrimLeft(s, " "))
		case parts[1] == "asText":
			h.Set(parts[0], mime.QEncoding.Encode("utf-8", s))
		default:
			return nil, bad(k, "only asRaw and asText")
		}
	}
	h.Set("MIME-Version", "1.0")

	var buf bytes.Buffer
	if serr := writeBody(c, &e, root, h, func(h gomessage.Header) (*gomessage.Writer, error) {
		return gomessage.CreateWriter(&buf, h)
	}); serr != nil {
		return nil, serr
	}
	return buf.Bytes(), nil
}

// writeBody writes part p with header h, which create starts.
func writeBody(c *call, e *emailIn, p *bodyIn, h gomessage.Header, create func(gomessage.Header) (*gomessage.Writer, error)) *jmap.SetError {
	bad := func(desc string) *jmap.SetError {
		return &jmap.SetError{Type: jmap.SetInvalidProperties, Properties: []string{"bodyStructure"}, Description: desc}
	}
	typ := strings.ToLower(p.Type)
	if typ == "" {
		typ = "text/plain"
	}
	for _, x := range p.Headers {
		h.Add(x.Name, strings.TrimLeft(x.Value, " "))
	}
	if strings.HasPrefix(typ, "multipart/") {
		h.SetContentType(typ, nil)
		w, err := create(h)
		if err != nil {
			return bad(err.Error())
		}
		for i := range p.SubParts {
			if serr := writeBody(c, e, &p.SubParts[i], gomessage.Header{}, w.CreatePart); serr != nil {
				return serr
			}
		}
		if err := w.Close(); err != nil {
			return bad(err.Error())
		}
		return nil
	}
	var data []byte
	params := map[string]string{}
	switch {
	case p.PartID != nil && p.BlobID == nil:
		v, ok := e.BodyValues[*p.PartID]
		if !ok {
			return bad("no bodyValues for part " + *p.PartID)
		}
		if v.IsTruncated || v.IsEncodingProblem {
			return bad("a truncated body value")
		}
		data = []byte(v.Value)
		params["charset"] = "utf-8"
	case p.BlobID != nil && p.PartID == nil:
		var err error
		var blobType string
		data, blobType, err = c.s.blob(c.c, string(c.resolve(jmap.ID(*p.BlobID))))
		if err != nil {
			return &jmap.SetError{Type: jmap.SetBlobNotFound, Description: err.Error()}
		}
		if p.Type == "" && blobType != "" {
			typ = blobType
		}
		if p.Charset != nil {
			params["charset"] = *p.Charset
		}
	default:
		return bad("a part needs a partId or a blobId")
	}
	if p.Name != nil {
		params["name"] = *p.Name
	}
	h.SetContentType(typ, params)
	if p.Disposition != nil || p.Name != nil {
		disp := "attachment"
		if p.Disposition != nil {
			disp = *p.Disposition
		}
		dparams := map[string]string{}
		if p.Name != nil {
			dparams["filename"] = *p.Name
		}
		h.SetContentDisposition(disp, dparams)
	}
	if p.CID != nil {
		h.Set("Content-Id", "<"+*p.CID+">")
	}
	if len(p.Language) > 0 {
		h.Set("Content-Language", strings.Join(p.Language, ", "))
	}
	if p.Location != nil {
		h.Set("Content-Location", *p.Location)
	}
	if strings.HasPrefix(typ, "text/") && p.PartID != nil {
		h.Set("Content-Transfer-Encoding", "quoted-printable")
	} else {
		h.Set("Content-Transfer-Encoding", "base64")
	}
	w, err := create(h)
	if err != nil {
		return bad(err.Error())
	}
	if _, err := w.Write(data); err != nil {
		return bad(err.Error())
	}
	if err := w.Close(); err != nil {
		return bad(err.Error())
	}
	return nil
}

// newMessageID makes a Message-ID in the sender's domain.
func newMessageID(from []jmap.EmailAddress) string {
	host := "mailcached.invalid"
	if len(from) > 0 {
		if _, d, ok := strings.Cut(from[0].Email, "@"); ok && d != "" {
			host = d
		}
	}
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:]) + "@" + host
}
