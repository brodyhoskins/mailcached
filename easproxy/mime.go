package easproxy

// What a device gets of a message: its body as plain text, HTML or the
// whole MIME message, and its attachments, which a device fetches one by
// one by their FileReference.

import (
	"bytes"
	"io"
	"mime"
	"strconv"
	"strings"
	"unicode/utf8"

	gomessage "github.com/emersion/go-message"
	_ "github.com/emersion/go-message/charset" // decode legacy charsets
	"golang.org/x/net/html"

	"github.com/brodyhoskins/mailcached/engine"
)

// attachment is an attachment of a message.
type attachment struct {
	path        string // the part's number, as IMAP numbers parts: "2", "1.3"
	name        string
	contentType string
	contentID   string
	size        int
	inline      bool
}

// parsed is a message taken apart.
type parsed struct {
	header      gomessage.Header
	text, html  string
	hasText     bool
	hasHTML     bool
	attachments []attachment
}

// parse takes a message apart. A message that cannot be parsed has an
// empty body.
func parse(raw []byte) *parsed {
	p := &parsed{}
	e, _ := gomessage.Read(bytes.NewReader(raw))
	if e == nil {
		return p
	}
	p.header = e.Header
	p.walk(e, "", false)
	return p
}

// walk visits a part and the parts under it. alt is set inside a
// multipart/alternative, whose parts are the body, never attachments.
func (p *parsed) walk(e *gomessage.Entity, path string, alt bool) {
	if mr := e.MultipartReader(); mr != nil {
		t, _, _ := e.Header.ContentType()
		inAlt := alt || t == "multipart/alternative"
		for i := 1; ; i++ {
			part, err := mr.NextPart()
			if err != nil {
				return
			}
			p.walk(part, joinPath(path, i), inAlt)
		}
	}
	if path == "" {
		path = "1"
	}
	t, params, err := e.Header.ContentType()
	if err != nil || t == "" {
		t = "text/plain"
	}
	disp, dparams, _ := e.Header.ContentDisposition()
	name := dparams["filename"]
	if name == "" {
		name = params["name"]
	}
	name = engine.DecodeHeader(name)
	cid := strings.Trim(e.Header.Get("Content-Id"), "<> ")
	body, _ := io.ReadAll(e.Body)
	isBody := disp != "attachment" && name == "" && (t == "text/plain" || t == "text/html")
	switch {
	case isBody && t == "text/plain" && !p.hasText:
		p.text, p.hasText = string(body), true
		return
	case isBody && t == "text/html" && !p.hasHTML:
		p.html, p.hasHTML = string(body), true
		return
	case isBody && alt:
		return
	}
	if name == "" {
		ext := ".bin"
		if exts, _ := mime.ExtensionsByType(t); len(exts) > 0 {
			ext = exts[0]
		}
		if t == "message/rfc822" {
			ext = ".eml"
		}
		name = "attachment-" + strings.ReplaceAll(path, ".", "-") + ext
	}
	p.attachments = append(p.attachments, attachment{path: path, name: name, contentType: t, contentID: cid,
		size: len(body), inline: disp == "inline" || (disp == "" && cid != "")})
}

func joinPath(path string, i int) string {
	if path == "" {
		return strconv.Itoa(i)
	}
	return path + "." + strconv.Itoa(i)
}

// partData returns a part's decoded content and type, by its number.
func partData(raw []byte, want string) ([]byte, string, bool) {
	e, _ := gomessage.Read(bytes.NewReader(raw))
	if e == nil {
		return nil, "", false
	}
	var find func(e *gomessage.Entity, path string) ([]byte, string, bool)
	find = func(e *gomessage.Entity, path string) ([]byte, string, bool) {
		if mr := e.MultipartReader(); mr != nil {
			for i := 1; ; i++ {
				part, err := mr.NextPart()
				if err != nil {
					return nil, "", false
				}
				p := joinPath(path, i)
				if p == want || strings.HasPrefix(want, p+".") {
					return find(part, p)
				}
			}
		}
		if path == "" {
			path = "1"
		}
		if path != want {
			return nil, "", false
		}
		t, _, _ := e.Header.ContentType()
		if t == "" {
			t = "text/plain"
		}
		b, err := io.ReadAll(e.Body)
		if err != nil {
			return nil, "", false
		}
		return b, t, true
	}
	return find(e, "")
}

// truncate cuts s to at most n bytes (0 for no limit), at a character
// boundary, and says whether it cut.
func truncate(s string, n int64) (string, bool) {
	if n <= 0 || int64(len(s)) <= n {
		return s, false
	}
	i := int(n)
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i], true
}

// plainOf returns the text of a message, from its HTML if it has no plain
// text.
func (p *parsed) plainOf() string {
	if p.hasText {
		return p.text
	}
	if p.hasHTML {
		return htmlText(p.html)
	}
	return ""
}

// htmlOf returns the HTML of a message, made from its plain text if it has
// none.
func (p *parsed) htmlOf() string {
	if p.hasHTML {
		return p.html
	}
	var b strings.Builder
	b.WriteString("<html><body><pre style=\"white-space: pre-wrap; font-family: inherit\">")
	b.WriteString(htmlEscape(p.text))
	b.WriteString("</pre></body></html>")
	return b.String()
}

var htmlEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")

func htmlEscape(s string) string { return htmlEscaper.Replace(s) }

// htmlText returns the text of an HTML document, without scripts and
// styles, a line break for each block.
func htmlText(doc string) string {
	z := html.NewTokenizer(strings.NewReader(doc))
	var b strings.Builder
	skip := 0
	for {
		switch z.Next() {
		case html.ErrorToken:
			return strings.TrimSpace(b.String())
		case html.StartTagToken, html.SelfClosingTagToken:
			name, _ := z.TagName()
			switch string(name) {
			case "script", "style", "head", "title":
				skip++
			case "br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote":
				b.WriteByte('\n')
			case "td", "th":
				b.WriteByte(' ')
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			switch string(name) {
			case "script", "style", "head", "title":
				skip = max(skip-1, 0)
			case "p", "div", "tr", "h1", "h2", "h3", "h4", "h5", "h6", "blockquote":
				b.WriteByte('\n')
			}
		case html.TextToken:
			if skip == 0 {
				t := string(z.Text())
				if len(t) > 0 && strings.IndexByte(" \t\r\n", t[0]) >= 0 {
					b.WriteByte(' ')
				}
				b.WriteString(strings.Join(strings.Fields(t), " "))
				if len(t) > 0 && strings.IndexByte(" \t\r\n", t[len(t)-1]) >= 0 {
					b.WriteByte(' ')
				}
			}
		}
	}
}
