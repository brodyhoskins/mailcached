package engine

// COMPRESS=DEFLATE (RFC 4978) toward the provider. go-imap's client can't
// switch a connection to compression part way through, so the proxy logs
// in itself on the raw connection, turns on compression if the provider
// offers it, and hands the (possibly compressed) stream to go-imap behind
// a synthetic "* PREAUTH" greeting so it starts in the authenticated state.

import (
	"bufio"
	"compress/flate"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	imap "github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/internal/imapraw"
	"github.com/brodyhoskins/mailcached/internal/inflate"
)

// openSession logs in on conn, which is already past any implicit TLS,
// and turns on compression if the provider offers it. With starttls set,
// it upgrades the connection first, and a provider without STARTTLS is an
// error, never a plaintext session. With tap, it asks a provider that
// offers NOTIFY to report changes in every folder (notifytap.go), and
// says how in notify.
func openSession(conn net.Conn, starttls bool, tlsConfig *tls.Config, username, password string, tap *notifyTap) (_ net.Conn, compressed bool, notify notifyMode, err error) {
	h := imapraw.New(conn)
	preauth, err := h.Greeting()
	if err != nil {
		return nil, false, 0, fmt.Errorf("IMAP greeting: %w", err)
	}
	if starttls {
		if preauth {
			// RFC 9051 section 7.1.4: PREAUTH before TLS is refused.
			return nil, false, 0, errors.New("IMAP STARTTLS: server sent PREAUTH on an unencrypted connection")
		}
		if err := h.Command("STARTTLS"); err != nil {
			return nil, false, 0, fmt.Errorf("IMAP STARTTLS: %w", err)
		}
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			return nil, false, 0, fmt.Errorf("IMAP STARTTLS: %w", err)
		}
		conn = tlsConn
		h.Conn, h.BR, h.Caps = conn, bufio.NewReader(conn), nil // capabilities may change
	}
	if !preauth {
		if err := h.Command("LOGIN", username, password); err != nil {
			return nil, false, 0, err
		}
	}
	if h.Caps == nil || !h.HasCap("IMAP4rev1") && !h.HasCap("IMAP4rev2") {
		h.Caps = nil
		if err := h.Command("CAPABILITY"); err != nil {
			return nil, false, 0, fmt.Errorf("IMAP capability: %w", err)
		}
	}
	if tap != nil && h.HasCap("NOTIFY") {
		// Before COMPRESS: imapraw speaks only plain IMAP. What the
		// provider reports before go-imap takes over is lost, and the
		// first sweep finds it.
		if notify, err = askNotify(h); err != nil {
			return nil, false, 0, fmt.Errorf("IMAP notify: %w", err)
		}
	}
	sc := &sessionConn{Conn: conn, r: h.BR, w: conn}
	if h.HasCap("COMPRESS=DEFLATE") {
		// The algorithm is an atom, not a string, so it goes in the name.
		if err := h.Command("COMPRESS DEFLATE"); err != nil {
			// A refusal is not fatal: carry on uncompressed.
			var imapErr *imap.Error
			if !errors.As(err, &imapErr) {
				return nil, false, 0, fmt.Errorf("IMAP compress: %w", err)
			}
		} else {
			fw, _ := flate.NewWriter(conn, flate.DefaultCompression)
			sc.inflater = inflate.NewReader(h.BR)
			sc.r = sc.inflater
			sc.w = inflate.NewFlushWriter(fw)
			compressed = true
		}
	}
	// go-imap starts by reading a greeting: give it one saying we're
	// already logged in, with the capabilities we learnt.
	var caps []string
	for _, c := range h.Caps {
		if !strings.HasPrefix(strings.ToUpper(c), "AUTH=") && !strings.EqualFold(c, "COMPRESS=DEFLATE") {
			caps = append(caps, c)
		}
	}
	sc.greeting = []byte("* PREAUTH [CAPABILITY " + strings.Join(caps, " ") + "] mailcached\r\n")
	if notify != notifyOff {
		sc.tap = tap
	}
	return sc, compressed, notify, nil
}

// notifyMode is what a provider's NOTIFY reports.
type notifyMode int

const (
	notifyOff notifyMode = iota
	// notifyMessages: new and expunged messages, and the folder list.
	notifyMessages
	// notifyFlags: flag changes in every folder too, as CONDSTORE is
	// enabled.
	notifyFlags
)

// askNotify asks the provider for NOTIFY: with flag changes if it has
// CONDSTORE, else without. A refusal turns it off.
func askNotify(h *imapraw.Conn) (notifyMode, error) {
	refused := func(err error) bool {
		var ie *imap.Error
		return errors.As(err, &ie)
	}
	if h.HasCap("CONDSTORE") && h.HasCap("ENABLE") {
		err := h.Command("ENABLE CONDSTORE")
		if err == nil {
			if err = h.Command(notifyAll); err == nil {
				return notifyFlags, nil
			}
		}
		if !refused(err) {
			return notifyOff, err
		}
	}
	err := h.Command(notifyNoFlags)
	switch {
	case err == nil:
		return notifyMessages, nil
	case refused(err):
		return notifyOff, nil
	}
	return notifyOff, err
}

// sessionConn is the stream handed to go-imap: a synthetic greeting,
// then the server, possibly through DEFLATE.
type sessionConn struct {
	net.Conn
	inflater *inflate.Reader // nil without compression
	greeting []byte
	r        io.Reader
	w        io.Writer
	tap      *notifyTap // nil without NOTIFY
}

func (c *sessionConn) Read(p []byte) (int, error) {
	if len(c.greeting) > 0 {
		n := copy(p, c.greeting)
		c.greeting = c.greeting[n:]
		return n, nil
	}
	n, err := c.r.Read(p)
	if c.tap != nil && n > 0 {
		c.tap.read(p[:n])
	}
	return n, err
}

func (c *sessionConn) Write(p []byte) (int, error) {
	if c.tap != nil {
		c.tap.wrote(p)
	}
	return c.w.Write(p)
}

func (c *sessionConn) Close() error {
	if c.inflater != nil {
		c.inflater.Close()
	}
	return c.Conn.Close()
}
