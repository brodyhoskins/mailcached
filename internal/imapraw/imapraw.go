// Package imapraw speaks just enough IMAP by hand to log in.
package imapraw

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/emersion/go-imap/v2"
)

// Conn is a minimal IMAP client: enough to log in and turn on compression
// before go-imap takes over, and for tests that speak IMAP by hand.
type Conn struct {
	Conn net.Conn
	BR   *bufio.Reader
	tag  int
	Caps []string // last capabilities seen, nil if unknown
}

// New starts a client on conn.
func New(conn net.Conn) *Conn { return &Conn{Conn: conn, BR: bufio.NewReader(conn)} }

var literalSuffixRe = regexp.MustCompile(`\{([0-9]+)\+?\}\r\n$`)

// ReadResponse reads one response, including any literals it contains.
func (h *Conn) ReadResponse() (string, error) {
	var b strings.Builder
	for {
		line, err := h.BR.ReadString('\n')
		if err != nil {
			return "", err
		}
		b.WriteString(line)
		m := literalSuffixRe.FindStringSubmatch(line)
		if m == nil {
			return strings.TrimRight(b.String(), "\r\n"), nil
		}
		n, _ := strconv.Atoi(m[1])
		if _, err := io.CopyN(&b, h.BR, int64(n)); err != nil {
			return "", err
		}
	}
}

// noteCaps records capabilities from a CAPABILITY response or response code.
func (h *Conn) noteCaps(line string) {
	if rest, ok := strings.CutPrefix(line, "* CAPABILITY "); ok {
		h.Caps = strings.Fields(rest)
		return
	}
	if i := strings.Index(line, "[CAPABILITY "); i >= 0 {
		rest := line[i+len("[CAPABILITY "):]
		if j := strings.IndexByte(rest, ']'); j >= 0 {
			h.Caps = strings.Fields(rest[:j])
		}
	}
}

// HasCap reports whether the server announced a capability.
func (h *Conn) HasCap(name string) bool {
	for _, c := range h.Caps {
		if strings.EqualFold(c, name) {
			return true
		}
	}
	return false
}

// Greeting reads the server greeting, reporting whether it's PREAUTH.
func (h *Conn) Greeting() (preauth bool, err error) {
	line, err := h.ReadResponse()
	if err != nil {
		return false, err
	}
	h.noteCaps(line)
	switch {
	case strings.HasPrefix(line, "* OK"):
		return false, nil
	case strings.HasPrefix(line, "* PREAUTH"):
		return true, nil
	}
	return false, fmt.Errorf("unexpected greeting %q", line)
}

// Command sends a command whose args are encoded as IMAP strings, and
// waits for its tagged response, returning an *imap.Error if it isn't
// OK. Atoms must be part of name.
func (h *Conn) Command(name string, args ...string) error {
	h.tag++
	tag := fmt.Sprintf("H%d", h.tag)
	if _, err := io.WriteString(h.Conn, tag+" "+name); err != nil {
		return err
	}
	for _, arg := range args {
		if err := h.WriteString(arg); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(h.Conn, "\r\n"); err != nil {
		return err
	}
	for {
		line, err := h.ReadResponse()
		if err != nil {
			return err
		}
		h.noteCaps(line)
		rest, ok := strings.CutPrefix(line, tag+" ")
		if !ok {
			continue // untagged data
		}
		typ, text, _ := strings.Cut(rest, " ")
		if strings.EqualFold(typ, "OK") {
			return nil
		}
		return &imap.Error{Type: imap.StatusResponseType(strings.ToUpper(typ)), Text: text}
	}
}

// WriteString writes " " and s as a quoted string, or as a literal if it
// can't be quoted.
func (h *Conn) WriteString(s string) error {
	quotable := true
	for i := 0; i < len(s); i++ {
		if c := s[i]; c == '\r' || c == '\n' || c == 0 || c >= 0x80 {
			quotable = false
			break
		}
	}
	if quotable {
		s = strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
		_, err := io.WriteString(h.Conn, ` "`+s+`"`)
		return err
	}
	// Synchronizing literal: wait for the server's go-ahead
	if _, err := fmt.Fprintf(h.Conn, " {%d}\r\n", len(s)); err != nil {
		return err
	}
	line, err := h.ReadResponse()
	if err != nil {
		return err
	}
	if !strings.HasPrefix(line, "+") {
		return fmt.Errorf("server refused literal: %q", line)
	}
	_, err = io.WriteString(h.Conn, s)
	return err
}
