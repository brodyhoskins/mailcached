package jmapproxy

import (
	"bufio"
	"bytes"
	"io"
	"mime"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/emersion/go-imap/v2"
	gomessage "github.com/emersion/go-message"

	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/internal/jmap"
)

// --- Header fields ---------------------------------------------------------

// field is one header field as it is in the message.
type field struct {
	name string
	raw  string // the value: everything after the colon, folding kept
}

// splitHeader splits a header block into its fields.
func splitHeader(hdr []byte) []field {
	var out []field
	r := bufio.NewReader(bytes.NewReader(hdr))
	for {
		line, err := r.ReadString('\n')
		if len(line) > 0 {
			trimmed := strings.TrimRight(line, "\r\n")
			switch {
			case trimmed == "":
				return out
			case (line[0] == ' ' || line[0] == '\t') && len(out) > 0:
				out[len(out)-1].raw += "\r\n" + trimmed
			default:
				name, value, ok := strings.Cut(trimmed, ":")
				if ok && name != "" && !strings.ContainsAny(name, " \t") {
					out = append(out, field{name: name, raw: value})
				}
			}
		}
		if err != nil {
			return out
		}
	}
}

// fieldsNamed returns the values of the fields named name, in order.
func fieldsNamed(fields []field, name string) []string {
	var out []string
	for _, f := range fields {
		if strings.EqualFold(f.name, name) {
			out = append(out, f.raw)
		}
	}
	return out
}

func unfold(raw string) string {
	return strings.NewReplacer("\r\n", "", "\n", "").Replace(raw)
}

// asText is the value unfolded, decoded and trimmed.
func asText(raw string) string {
	s := strings.TrimSpace(engine.DecodeHeader(unfold(raw)))
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "�")
	}
	return s
}

var addrParser = &mail.AddressParser{WordDecoder: &mime.WordDecoder{CharsetReader: gomessage.CharsetReader}}

// asAddresses parses an address list; a group contributes its members.
func asAddresses(raw string) []jmap.EmailAddress {
	v := strings.TrimSpace(unfold(raw))
	if v == "" {
		return []jmap.EmailAddress{}
	}
	list, err := addrParser.ParseList(v)
	if err != nil {
		// A lenient fallback: each comma-separated item, as it is.
		list = nil
		for _, item := range strings.Split(v, ",") {
			if a, err := addrParser.Parse(item); err == nil {
				list = append(list, a)
			}
		}
	}
	out := make([]jmap.EmailAddress, 0, len(list))
	for _, a := range list {
		e := jmap.EmailAddress{Email: a.Address}
		if a.Name != "" {
			name := a.Name
			e.Name = &name
		}
		out = append(out, e)
	}
	return out
}

// asMessageIDs parses a list of <msg-id>s, without the brackets.
func asMessageIDs(raw string) []string {
	var out []string
	v := unfold(raw)
	for {
		i := strings.IndexByte(v, '<')
		if i < 0 {
			break
		}
		j := strings.IndexByte(v[i:], '>')
		if j < 0 {
			break
		}
		if id := strings.TrimSpace(v[i+1 : i+j]); id != "" {
			out = append(out, id)
		}
		v = v[i+j+1:]
	}
	if len(out) == 0 {
		if s := strings.TrimSpace(v); s != "" && !strings.ContainsAny(s, " \t") {
			out = append(out, s)
		}
	}
	return out
}

// asDate parses a date, nil if it does not parse.
func asDate(raw string) *time.Time {
	t, err := mail.ParseDate(strings.TrimSpace(unfold(raw)))
	if err != nil {
		return nil
	}
	return &t
}

// asURLs parses a list of <URL>s.
func asURLs(raw string) []string { return asMessageIDs(raw) }

// headerProperty computes a "header:Name[:asForm][:all]" property. ok is
// false for a malformed one.
func headerProperty(fields []field, prop string) (val any, ok bool) {
	parts := strings.Split(strings.TrimPrefix(prop, "header:"), ":")
	name, form, all := parts[0], "asRaw", false
	for _, p := range parts[1:] {
		switch {
		case p == "all":
			all = true
		case strings.HasPrefix(p, "as"):
			form = p
		default:
			return nil, false
		}
	}
	conv := map[string]func(string) any{
		"asRaw":              func(r string) any { return r },
		"asText":             func(r string) any { return asText(r) },
		"asAddresses":        func(r string) any { return asAddresses(r) },
		"asGroupedAddresses": func(r string) any { return []any{map[string]any{"name": nil, "addresses": asAddresses(r)}} },
		"asMessageIds":       func(r string) any { return asMessageIDs(r) },
		"asDate":             func(r string) any { return asDate(r) },
		"asURLs":             func(r string) any { return asURLs(r) },
	}[form]
	if conv == nil || name == "" {
		return nil, false
	}
	values := fieldsNamed(fields, name)
	if all {
		out := make([]any, len(values))
		for i, v := range values {
			out[i] = conv(v)
		}
		return out, true
	}
	if len(values) == 0 {
		return nil, true
	}
	return conv(values[len(values)-1]), true
}

// --- Body parts ------------------------------------------------------------

// part is a MIME part as JMAP describes it. partID is the IMAP section
// ("1", "1.2"), "" for a multipart.
type part struct {
	partID      string
	typ         string // lower case, type/subtype
	charset     string
	disposition string
	name        string
	cid         string
	language    []string
	location    string
	size        int64
	headers     []field // only for parts from a whole message
	body        []byte  // text parts from a whole message, decoded
	sub         []*part
}

const maxTextPart = 1 << 20 // the most of a text part kept for bodyValues

// partsOfRaw parses a whole message into parts, with headers and the
// decoded text of text parts.
func partsOfRaw(raw []byte) *part {
	e, _ := gomessage.Read(bytes.NewReader(raw))
	if e == nil {
		return &part{partID: "1", typ: "text/plain", size: int64(len(raw))}
	}
	hdr, _, _ := bytes.Cut(raw, []byte("\r\n\r\n"))
	// A copy: raw is shared, and append would write into it.
	return entityPart(e, splitHeader(append(hdr[:len(hdr):len(hdr)], "\r\n"...)), "")
}

func entityPart(e *gomessage.Entity, fields []field, prefix string) *part {
	p := &part{headers: fields}
	t, params, err := e.Header.ContentType()
	if err != nil || t == "" {
		t, params = "text/plain", map[string]string{}
	}
	p.typ = strings.ToLower(t)
	p.charset = params["charset"]
	if disp, dparams, err := e.Header.ContentDisposition(); err == nil {
		p.disposition = strings.ToLower(disp)
		p.name = dparams["filename"]
	}
	if p.name == "" {
		p.name = params["name"]
	}
	p.name = engine.DecodeHeader(p.name)
	p.cid = strings.Trim(strings.TrimSpace(e.Header.Get("Content-Id")), "<>")
	if l := e.Header.Get("Content-Language"); l != "" {
		for _, x := range strings.Split(l, ",") {
			p.language = append(p.language, strings.TrimSpace(x))
		}
	}
	p.location = strings.TrimSpace(e.Header.Get("Content-Location"))
	if mr := e.MultipartReader(); mr != nil {
		for i := 1; ; i++ {
			c, err := mr.NextPart()
			if err != nil {
				break
			}
			id := prefix + strconv.Itoa(i)
			var cf []field
			for f := c.Header.Fields(); f.Next(); {
				raw, _ := f.Raw()
				name, value, _ := strings.Cut(strings.TrimRight(string(raw), "\r\n"), ":")
				cf = append(cf, field{name: name, raw: value})
			}
			sp := entityPart(c, cf, id+".")
			if sp.partID == "" && !strings.HasPrefix(sp.typ, "multipart/") {
				sp.partID = id
			}
			p.sub = append(p.sub, sp)
		}
		return p
	}
	if prefix == "" {
		p.partID = "1"
	} else {
		p.partID = strings.TrimSuffix(prefix, ".")
	}
	if strings.HasPrefix(p.typ, "text/") {
		b, _ := io.ReadAll(io.LimitReader(e.Body, maxTextPart+1))
		p.body = b
		n, _ := io.Copy(io.Discard, e.Body)
		p.size = int64(len(b)) + n
	} else {
		p.size, _ = io.Copy(io.Discard, e.Body)
	}
	return p
}

// partsOfStructure describes the parts from an IMAP body structure, as a
// header entry keeps it: no headers and no bodies.
func partsOfStructure(bs imap.BodyStructure) *part {
	return structPart(bs, "")
}

func structPart(bs imap.BodyStructure, id string) *part {
	switch s := bs.(type) {
	case *imap.BodyStructureMultiPart:
		p := &part{typ: "multipart/" + strings.ToLower(s.Subtype)}
		for i, c := range s.Children {
			cid := strconv.Itoa(i + 1)
			if id != "" {
				cid = id + "." + cid
			}
			p.sub = append(p.sub, structPart(c, cid))
		}
		if s.Extended != nil && s.Extended.Disposition != nil {
			p.disposition = strings.ToLower(s.Extended.Disposition.Value)
		}
		return p
	case *imap.BodyStructureSinglePart:
		if id == "" {
			id = "1"
		}
		p := &part{partID: id, typ: strings.ToLower(s.Type + "/" + s.Subtype), charset: s.Params["charset"],
			name: s.Params["name"], cid: strings.Trim(s.ID, "<>"), size: int64(s.Size)}
		if strings.EqualFold(s.Encoding, "base64") {
			p.size = p.size * 3 / 4
		}
		if s.Extended != nil {
			if s.Extended.Disposition != nil {
				p.disposition = strings.ToLower(s.Extended.Disposition.Value)
				if f := s.Extended.Disposition.Params["filename"]; f != "" {
					p.name = f
				}
			}
			p.language, p.location = s.Extended.Language, s.Extended.Location
		}
		p.name = engine.DecodeHeader(p.name)
		return p
	}
	return &part{partID: "1", typ: "text/plain"}
}

func isInlineMedia(t string) bool {
	return strings.HasPrefix(t, "image/") || strings.HasPrefix(t, "audio/") || strings.HasPrefix(t, "video/")
}

// bodies sorts the leaf parts into textBody, htmlBody and attachments, as
// RFC 8621 section 4.1.4 says.
func bodies(root *part) (text, html, attachments []*part) {
	t, h := []*part{}, []*part{}
	tp, hp := &t, &h
	parseStructure([]*part{root}, "mixed", false, &hp, &tp, &attachments)
	if tp != nil {
		text = *tp
	}
	if hp != nil {
		html = *hp
	}
	return text, html, attachments
}

// parseStructure is RFC 8621's algorithm. A nil *[]*part is its "null".
func parseStructure(parts []*part, multipartType string, inAlternative bool, html, text **[]*part, attachments *[]*part) {
	textLength, htmlLength := -1, -1
	if *text != nil {
		textLength = len(**text)
	}
	if *html != nil {
		htmlLength = len(**html)
	}
	for i, p := range parts {
		isMultipart := strings.HasPrefix(p.typ, "multipart/")
		isInline := p.disposition != "attachment" &&
			(p.typ == "text/plain" || p.typ == "text/html" || isInlineMedia(p.typ)) &&
			(i == 0 || (multipartType != "related" && (isInlineMedia(p.typ) || p.name == "")))
		switch {
		case isMultipart:
			sub := strings.TrimPrefix(p.typ, "multipart/")
			parseStructure(p.sub, sub, inAlternative || sub == "alternative", html, text, attachments)
		case isInline:
			if multipartType == "alternative" {
				switch p.typ {
				case "text/plain":
					if *text != nil {
						**text = append(**text, p)
					}
				case "text/html":
					if *html != nil {
						**html = append(**html, p)
					}
				default:
					*attachments = append(*attachments, p)
				}
				continue
			} else if inAlternative {
				if p.typ == "text/plain" {
					*html = nil
				}
				if p.typ == "text/html" {
					*text = nil
				}
			}
			if *text != nil {
				**text = append(**text, p)
			}
			if *html != nil {
				**html = append(**html, p)
			}
			if (*text == nil || *html == nil) && isInlineMedia(p.typ) {
				*attachments = append(*attachments, p)
			}
		default:
			*attachments = append(*attachments, p)
		}
	}
	if multipartType == "alternative" && *text != nil && *html != nil {
		if textLength == len(**text) && htmlLength != len(**html) {
			for i := htmlLength; i < len(**html); i++ {
				**text = append(**text, (**html)[i])
			}
		}
		if htmlLength == len(**html) && textLength != len(**text) {
			for i := textLength; i < len(**text); i++ {
				**html = append(**html, (**text)[i])
			}
		}
	}
}

// find returns the part with partID id.
func (p *part) find(id string) *part {
	if p.partID == id {
		return p
	}
	for _, s := range p.sub {
		if f := s.find(id); f != nil {
			return f
		}
	}
	return nil
}

// bodyPart describes p with the body properties props.
func bodyPart(p *part, email jmap.ID, props []string) map[string]any {
	out := map[string]any{}
	str := func(s string) any {
		if s == "" {
			return nil
		}
		return s
	}
	for _, prop := range props {
		switch prop {
		case "partId":
			out[prop] = str(p.partID)
		case "blobId":
			if p.partID == "" {
				out[prop] = nil
			} else {
				out[prop] = partBlob(email, p.partID)
			}
		case "size":
			out[prop] = p.size
		case "headers":
			hs := make([]jmap.EmailHeader, len(p.headers))
			for i, f := range p.headers {
				hs[i] = jmap.EmailHeader{Name: f.name, Value: f.raw}
			}
			out[prop] = hs
		case "name":
			out[prop] = str(p.name)
		case "type":
			out[prop] = p.typ
		case "charset":
			cs := p.charset
			if cs == "" && strings.HasPrefix(p.typ, "text/") {
				cs = "us-ascii"
			}
			out[prop] = str(cs)
		case "disposition":
			out[prop] = str(p.disposition)
		case "cid":
			out[prop] = str(p.cid)
		case "language":
			if len(p.language) == 0 {
				out[prop] = nil
			} else {
				out[prop] = p.language
			}
		case "location":
			out[prop] = str(p.location)
		case "subParts":
			if strings.HasPrefix(p.typ, "multipart/") {
				subs := make([]any, len(p.sub))
				for i, s := range p.sub {
					subs[i] = bodyPart(s, email, props)
				}
				out[prop] = subs
			}
		default:
			if strings.HasPrefix(prop, "header:") {
				if v, ok := headerProperty(p.headers, prop); ok {
					out[prop] = v
				}
			}
		}
	}
	if slices.Contains(props, "subParts") && !strings.HasPrefix(p.typ, "multipart/") {
		out["subParts"] = nil
	}
	return out
}

// bodyValue is the text of a text part for bodyValues, cut at max bytes
// (0 for no limit).
func bodyValue(p *part, max int) jmap.EmailBodyValue {
	v := jmap.EmailBodyValue{Value: string(p.body), IsTruncated: int64(len(p.body)) < p.size}
	if !utf8.ValidString(v.Value) {
		v.Value, v.IsEncodingProblem = strings.ToValidUTF8(v.Value, "�"), true
	}
	if p.typ == "text/plain" || p.typ == "text/html" {
		v.Value = strings.ReplaceAll(v.Value, "\r\n", "\n")
	}
	if max > 0 && len(v.Value) > max {
		cut := max
		for cut > 0 && !utf8.RuneStart(v.Value[cut]) {
			cut--
		}
		v.Value, v.IsTruncated = v.Value[:cut], true
	}
	return v
}
