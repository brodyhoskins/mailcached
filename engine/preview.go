package engine

import (
	"bytes"
	"io"
	"mime"
	"strings"
	"unicode"
	"unicode/utf8"

	gomessage "github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset" // decode legacy charsets
	"golang.org/x/net/html"
)

// PreviewLen is how long a preview may be, in characters (RFC 8621
// section 4.1.4: up to 256).
const PreviewLen = 256

// Preview returns the start of a message's text, whitespace collapsed:
// the first text/plain part that is not an attachment, or else the first
// text/html part without its markup.
func Preview(raw []byte) string {
	e, err := gomessage.Read(bytes.NewReader(raw))
	if e == nil {
		return ""
	}
	_ = err // a message with an unknown charset still has a preview
	var htmlText string
	text, found := previewOf(e, &htmlText)
	if !found {
		text = htmlText
	}
	return clip(text)
}

// previewOf walks e for the first plain text part. The first HTML part's
// text goes to htmlText, if none was found before.
func previewOf(e *gomessage.Entity, htmlText *string) (string, bool) {
	if mr := e.MultipartReader(); mr != nil {
		for {
			p, err := mr.NextPart()
			if err != nil {
				return "", false
			}
			if t, ok := previewOf(p, htmlText); ok {
				return t, true
			}
		}
	}
	if disp, _, _ := e.Header.ContentDisposition(); disp == "attachment" {
		return "", false
	}
	t, _, err := e.Header.ContentType()
	if err != nil || t == "" {
		t = "text/plain"
	}
	switch t {
	case "text/plain":
		b, _ := io.ReadAll(io.LimitReader(e.Body, 16<<10))
		return string(b), true
	case "text/html":
		if *htmlText == "" {
			*htmlText = htmlToText(io.LimitReader(e.Body, 64<<10))
		}
	}
	return "", false
}

// htmlToText returns the text of an HTML document, without scripts and
// styles.
func htmlToText(r io.Reader) string {
	z := html.NewTokenizer(r)
	var b strings.Builder
	skip := 0
	for b.Len() < 4*PreviewLen {
		switch z.Next() {
		case html.ErrorToken:
			return b.String()
		case html.StartTagToken:
			name, _ := z.TagName()
			switch string(name) {
			case "script", "style", "head", "title":
				skip++
			case "br", "p", "div", "li", "tr", "td":
				b.WriteByte(' ')
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			switch string(name) {
			case "script", "style", "head", "title":
				skip = max(skip-1, 0)
			}
		case html.TextToken:
			if skip == 0 {
				b.Write(z.Text())
			}
		}
	}
	return b.String()
}

// clip collapses whitespace and cuts s to PreviewLen characters.
func clip(s string) string {
	var b strings.Builder
	n := 0
	space := false
	for _, r := range s {
		if r == utf8.RuneError {
			continue
		}
		if unicode.IsSpace(r) {
			space = b.Len() > 0
			continue
		}
		if !unicode.IsPrint(r) {
			continue
		}
		if space {
			if n+1 >= PreviewLen {
				break
			}
			b.WriteByte(' ')
			n++
			space = false
		}
		b.WriteRune(r)
		if n++; n >= PreviewLen {
			break
		}
	}
	return b.String()
}

// DecodeHeader decodes RFC 2047 encoded words in a header value.
func DecodeHeader(v string) string {
	d, err := (&mime.WordDecoder{CharsetReader: gomessage.CharsetReader}).DecodeHeader(v)
	if err != nil {
		return v
	}
	return d
}
