// Package imapproxy is an IMAP server for mail clients. It serves each
// account from the engine's local copy (folders, UIDs, flags and cached
// messages), so clients are served at once, whichever protocol the
// provider speaks. An optional Transform changes messages on their way
// through, once per message: the cache keeps its result.
//
// Clients log in with their provider credentials. The proxy keeps them in
// memory only, while it needs them to reach the provider.
package imapproxy

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"

	"github.com/brodyhoskins/mailcached/engine"
)

// Server is the IMAP listener. It serves the accounts of Engine.
type Server struct {
	Engine          *engine.Engine
	TLSConfig       *tls.Config // nil: no TLS (loopback only)
	ImplicitTLS     bool        // TLS from the first byte instead of STARTTLS
	MaxMessageBytes int64
	Log             *slog.Logger
	// Trace logs client commands (without credentials) and the proxy's
	// status replies, for debugging clients.
	Trace bool

	mu    sync.Mutex // guards srv and conns
	srv   *imapserver.Server
	conns map[*Session]struct{}
}

// caps is what go-imap's server advertises. It leaves out anything the
// proxy cannot honor for every provider: no QRESYNC (the change log does
// not keep expunged UIDs), no IMAP4rev2 (it needs LIST-STATUS and
// ESEARCH). The server adds IDLE, UNSELECT, ENABLE and the auth
// capabilities itself. On a connection the wrapper sees in the clear, it
// adds COMPRESS=DEFLATE, OBJECTID, NOTIFY and CONDSTORE, which it does on
// the wire.
var caps = imap.CapSet{
	imap.CapIMAP4rev1:   {},
	imap.CapNamespace:   {},
	imap.CapUIDPlus:     {},
	imap.CapMove:        {},
	imap.CapSpecialUse:  {},
	imap.CapLiteralPlus: {},
}

// Serve accepts connections on l until Close.
func (b *Server) Serve(l net.Listener) error {
	opts := &imapserver.Options{
		NewSession: func(c *imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			s := &Session{b: b, conn: c}
			b.mu.Lock()
			if b.conns == nil {
				b.conns = map[*Session]struct{}{}
			}
			b.conns[s] = struct{}{}
			b.mu.Unlock()
			if cc, ok := c.NetConn().(*compressConn); ok {
				cc.obj.setSession(s)
			}
			return s, nil, nil
		},
		Caps:   caps,
		Logger: slogLogger{b.Log},
	}
	// COMPRESS=DEFLATE needs to see the protocol in the clear, so it sits
	// inside implicit TLS and is not offered with STARTTLS.
	switch {
	case b.TLSConfig == nil:
		// config only allows this with insecure_plaintext.
		opts.InsecureAuth = true
		l = compressListener{Listener: l, offer: true, trace: b.tracer()}
	case b.ImplicitTLS:
		l = compressListener{Listener: tls.NewListener(l, b.TLSConfig), offer: true, trace: b.tracer()}
		// go-imap allows logins only on a *tls.Conn, and compressConn
		// hides the TLS connection it wraps. Every connection on this
		// listener is TLS, so logins are safe.
		opts.InsecureAuth = true
	default:
		opts.TLSConfig = b.TLSConfig
	}
	srv := imapserver.New(opts)
	b.mu.Lock()
	b.srv = srv
	b.mu.Unlock()
	return srv.Serve(l)
}

// Close stops the listener and closes open connections. The Engine is its
// owner's to close. Each client first gets an untagged BYE, which tells it
// that the server is going away: a client that sees only the connection
// drop takes it for a network failure, and may report an error.
func (b *Server) Close() error {
	b.mu.Lock()
	srv := b.srv
	var sessions []*Session
	for s := range b.conns {
		sessions = append(sessions, s)
	}
	b.mu.Unlock()
	if srv == nil {
		return nil
	}
	var wg sync.WaitGroup
	for _, s := range sessions {
		wg.Go(func() {
			// A client that reads nothing must not hold up the shutdown.
			_ = s.conn.NetConn().SetWriteDeadline(time.Now().Add(byeTimeout))
			_ = s.conn.Bye("Server shutting down")
		})
	}
	wg.Wait()
	return srv.Close()
}

// byeTimeout limits the wait to send each client its BYE.
var byeTimeout = 2 * time.Second

// passError hands a provider's NO or BAD to the client unchanged, and
// turns anything else (a dropped connection) into a generic failure.
func passError(err error) error {
	if err == nil {
		return nil
	}
	var ie *imap.Error
	if errors.As(err, &ie) {
		return ie
	}
	return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeUnavailable, Text: "Upstream server unavailable"}
}

type slogLogger struct{ l *slog.Logger }

func (s slogLogger) Printf(format string, v ...any) { s.l.Warn("imap: " + fmt.Sprintf(format, v...)) }

func (b *Server) tracer() *slog.Logger {
	if !b.Trace {
		return nil
	}
	return b.Log
}
