package engine

import (
	"bytes"
	"github.com/emersion/go-imap/v2"
	gomessage "github.com/emersion/go-message"
	"github.com/emersion/go-message/mail"
	"io"
	"strings"
	"time"
)

// MatchMessage is what a search knows of a message besides its contents.
type MatchMessage struct {
	Seq   uint32 // sequence number in the client's view
	UID   imap.UID
	Flags []imap.Flag
	Date  time.Time // internal date
}

// NeedsBody reports whether c looks at anything but flags, dates and
// numbers.
func NeedsBody(c *imap.SearchCriteria) bool {
	if len(c.Header) > 0 || len(c.Body) > 0 || len(c.Text) > 0 ||
		c.Larger != 0 || c.Smaller != 0 || !c.SentSince.IsZero() || !c.SentBefore.IsZero() {
		return true
	}
	for i := range c.Not {
		if NeedsBody(&c.Not[i]) {
			return true
		}
	}
	for i := range c.Or {
		if NeedsBody(&c.Or[i][0]) || NeedsBody(&c.Or[i][1]) {
			return true
		}
	}
	return false
}

// Match reports whether a message matches c. raw is the message clients
// see; it is needed only if NeedsBody(c). The matching follows go-imap's
// imapmemserver (MIT licensed).
func Match(m MatchMessage, raw []byte, c *imap.SearchCriteria) bool {
	for _, set := range c.SeqNum {
		if !set.Contains(m.Seq) {
			return false
		}
	}
	for _, set := range c.UID {
		if !set.Contains(m.UID) {
			return false
		}
	}
	if !matchDate(m.Date, c.Since, c.Before) {
		return false
	}
	for _, f := range c.Flag {
		if !HasFlag(m.Flags, f) {
			return false
		}
	}
	for _, f := range c.NotFlag {
		if HasFlag(m.Flags, f) {
			return false
		}
	}
	if c.Larger != 0 && int64(len(raw)) <= c.Larger {
		return false
	}
	if c.Smaller != 0 && int64(len(raw)) >= c.Smaller {
		return false
	}
	if len(c.Header) > 0 || !c.SentSince.IsZero() || !c.SentBefore.IsZero() {
		h := mail.Header{Header: entity(raw).Header}
		for _, f := range c.Header {
			if !matchHeaderFields(h.FieldsByKey(f.Key), f.Value) {
				return false
			}
		}
		if !c.SentSince.IsZero() || !c.SentBefore.IsZero() {
			t, err := h.Date()
			if err != nil || !matchDate(t, c.SentSince, c.SentBefore) {
				return false
			}
		}
	}
	for _, text := range c.Text {
		if !matchEntity(entity(raw), text, true) {
			return false
		}
	}
	for _, body := range c.Body {
		if !matchEntity(entity(raw), body, false) {
			return false
		}
	}
	for i := range c.Not {
		if Match(m, raw, &c.Not[i]) {
			return false
		}
	}
	for i := range c.Or {
		if !Match(m, raw, &c.Or[i][0]) && !Match(m, raw, &c.Or[i][1]) {
			return false
		}
	}
	return true
}

func entity(raw []byte) *gomessage.Entity {
	e, _ := gomessage.Read(bytes.NewReader(raw))
	if e == nil {
		e, _ = gomessage.New(gomessage.Header{}, bytes.NewReader(nil))
	}
	return e
}

// matchDate compares dates only: RFC 3501 searches ignore time and zone.
func matchDate(t, since, before time.Time) bool {
	t = time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
	if !since.IsZero() && t.Before(since) {
		return false
	}
	if !before.IsZero() && !t.Before(before) {
		return false
	}
	return true
}

func matchHeaderFields(fields gomessage.HeaderFields, pattern string) bool {
	if pattern == "" {
		return fields.Len() > 0
	}
	pattern = strings.ToLower(pattern)
	for fields.Next() {
		v, _ := fields.Text()
		if strings.Contains(strings.ToLower(v), pattern) {
			return true
		}
	}
	return false
}

func matchEntity(e *gomessage.Entity, pattern string, includeHeader bool) bool {
	if pattern == "" {
		return true
	}
	if includeHeader && matchHeaderFields(e.Header.Fields(), pattern) {
		return true
	}
	if mr := e.MultipartReader(); mr != nil {
		for {
			part, err := mr.NextPart()
			if err == io.EOF {
				return false
			} else if err != nil {
				return false
			}
			if matchEntity(part, pattern, includeHeader) {
				return true
			}
		}
	}
	t, _, err := e.Header.ContentType()
	if err != nil && t == "" {
		t = "text/plain"
	}
	if !strings.HasPrefix(t, "text/") && !strings.HasPrefix(t, "message/") {
		return false
	}
	buf, err := io.ReadAll(e.Body)
	if err != nil {
		return false
	}
	return bytes.Contains(bytes.ToLower(buf), bytes.ToLower([]byte(pattern)))
}
