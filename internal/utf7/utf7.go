// Package utf7 is modified UTF-7 (RFC 3501 section 5.1.3), the encoding
// of folder names on the IMAP wire, for the wire-level code that reads and
// writes names itself. go-imap's own codec is internal.
package utf7

import (
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var enc = base64.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,").WithPadding(base64.NoPadding)

// Encode encodes a folder name.
func Encode(s string) string {
	var b strings.Builder
	var run []rune
	flush := func() {
		if len(run) == 0 {
			return
		}
		u := utf16.Encode(run)
		raw := make([]byte, 0, 2*len(u))
		for _, c := range u {
			raw = append(raw, byte(c>>8), byte(c))
		}
		b.WriteByte('&')
		b.WriteString(enc.EncodeToString(raw))
		b.WriteByte('-')
		run = run[:0]
	}
	for _, r := range s {
		switch {
		case r == '&':
			flush()
			b.WriteString("&-")
		case r >= 0x20 && r <= 0x7e:
			flush()
			b.WriteRune(r)
		default:
			run = append(run, r)
		}
	}
	flush()
	return b.String()
}

var errBad = errors.New("bad modified UTF-7")

// Decode decodes a folder name.
func Decode(s string) (string, error) {
	if !strings.Contains(s, "&") {
		return s, nil
	}
	var b strings.Builder
	for len(s) > 0 {
		i := strings.IndexByte(s, '&')
		if i < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:i])
		s = s[i+1:]
		j := strings.IndexByte(s, '-')
		if j < 0 {
			return "", errBad
		}
		if j == 0 {
			b.WriteByte('&')
			s = s[1:]
			continue
		}
		raw, err := enc.DecodeString(s[:j])
		if err != nil || len(raw)%2 != 0 {
			return "", errBad
		}
		u := make([]uint16, len(raw)/2)
		for k := range u {
			u[k] = uint16(raw[2*k])<<8 | uint16(raw[2*k+1])
		}
		for _, r := range utf16.Decode(u) {
			if r == utf8.RuneError {
				return "", errBad
			}
			b.WriteRune(r)
		}
		s = s[j+1:]
	}
	return b.String(), nil
}
