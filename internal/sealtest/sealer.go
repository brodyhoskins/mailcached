// Package sealtest is the tests' Transform, a stand-in for encryption.
package sealtest

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/internal/enginetest"
	"mime"
	"net/textproto"
	"regexp"
)

// Sealer is the tests' Transform, a stand-in for encryption. A sealed
// message has the Content-Type SealedType and the base64 of the real
// message as its body. Read opens it and adds "X-Opened: yes"; it also
// removes X-Opened fields a sender put in. Write seals what is not sealed.
type Sealer struct{}

const SealedType = "application/x-sealed"

func (Sealer) Fields() []string { return []string{"Content-Type", "X-Opened"} }

func (Sealer) Changes(h textproto.MIMEHeader) bool {
	mt, _, _ := mime.ParseMediaType(h.Get("Content-Type"))
	return mt == SealedType || h.Get("X-Opened") != ""
}

var openedField = regexp.MustCompile(`(?mi)^X-Opened:.*\r\n`)

func (Sealer) Read(_ context.Context, raw []byte) ([]byte, engine.ReadStatus) {
	if !IsSealed(raw) {
		return openedField.ReplaceAll(raw, nil), engine.ReadFinal
	}
	_, body, _ := bytes.Cut(raw, []byte("\r\n\r\n"))
	inner, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(body)))
	if err != nil {
		return raw, engine.ReadRetry
	}
	return append([]byte("X-Opened: yes\r\n"), openedField.ReplaceAll(inner, nil)...), engine.ReadFinal
}

func (Sealer) Write(_ context.Context, raw []byte) ([]byte, error) {
	if IsSealed(raw) {
		return raw, nil
	}
	return Seal(raw), nil
}

// Seal wraps msg in a sealed message to User.
func Seal(msg []byte) []byte {
	return []byte("From: " + enginetest.Bob + "\r\nTo: " + enginetest.User + "\r\nSubject: ...\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: " + SealedType + "\r\n\r\n" + base64.StdEncoding.EncodeToString(msg) + "\r\n")
}

// IsSealed reports whether a message is sealed.
func IsSealed(raw []byte) bool {
	hdr, _, _ := bytes.Cut(raw, []byte("\r\n\r\n"))
	h, _ := textproto.NewReader(bufio.NewReader(bytes.NewReader(append(hdr, "\r\n\r\n"...)))).ReadMIMEHeader()
	return Sealer{}.Changes(h) && bytes.Contains(hdr, []byte(SealedType))
}
