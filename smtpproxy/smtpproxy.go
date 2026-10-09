// Package smtpproxy is an SMTP server that accepts mail from a client and
// submits it to the provider, through an optional Filter that can change
// it (encrypt it, for example). The client's credentials are passed
// through to the provider and never stored.
package smtpproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/brodyhoskins/mailcached/config"
	"github.com/brodyhoskins/mailcached/internal/netbind"
)

// Envelope is one message to submit.
type Envelope struct {
	From string
	To   []string
	Data []byte
}

// Handler takes an envelope on its way to the provider.
type Handler interface {
	Handle(ctx context.Context, env *Envelope) error
}

// HandlerFunc is a function as a Handler.
type HandlerFunc func(ctx context.Context, env *Envelope) error

func (f HandlerFunc) Handle(ctx context.Context, env *Envelope) error { return f(ctx, env) }

// Filter wraps the handler that submits to the provider. It can change an
// envelope, split it into several, or refuse it. An *smtp.SMTPError it
// returns reaches the client unchanged.
type Filter func(next Handler) Handler

// Upstream is a provider's submission server, or a Provider that sends
// another way.
type Upstream struct {
	Addr      string // host:port
	TLS       string // config.TLSImplicit, TLSStartTLS or TLSNone
	TLSConfig *tls.Config
	Helo      string
	Timeout   time.Duration
	// Source is where the connection leaves from: an interface name or a
	// local IP address. Empty: wherever routing says.
	Source string
	// Provider, if not nil, takes the place of the submission server: for
	// a provider that has none (JMAP).
	Provider Provider
}

// Provider checks logins and sends mail for providers without a
// submission server.
type Provider interface {
	// Verify checks a login. A rejection wraps ErrLoginRejected.
	Verify(login, password string) error
	// Send sends a message, after the Filter.
	Send(ctx context.Context, login, password string, env *Envelope) error
}

// ErrLoginRejected is a Provider's rejection of a login.
var ErrLoginRejected = errors.New("login rejected")

// Server is the SMTP listener.
type Server struct {
	// Route picks the provider for a login name. ok is false for a login
	// the proxy does not serve, which is then rejected.
	Route           func(login string) (u Upstream, ok bool)
	Filter          Filter // nil submits as received
	Domain          string
	TLSConfig       *tls.Config // nil: no TLS (loopback only)
	ImplicitTLS     bool        // TLS from the first byte instead of STARTTLS
	MaxMessageBytes int64
	Log             *slog.Logger

	mu    sync.Mutex // guards srv and conns
	srv   *smtp.Server
	conns map[net.Conn]struct{}
}

// Serve accepts connections on l until Close.
func (b *Server) Serve(l net.Listener) error {
	srv := smtp.NewServer(smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
		return &session{b: b, remote: c.Conn().RemoteAddr().String()}, nil
	}))
	srv.Domain = b.Domain
	srv.MaxMessageBytes = b.MaxMessageBytes
	srv.MaxRecipients = 100
	srv.ReadTimeout = 5 * time.Minute
	srv.WriteTimeout = 5 * time.Minute
	srv.ErrorLog = slogLogger{b.Log}
	// Under TLS: go-smtp must see a *tls.Conn to know the connection is
	// secure.
	l = trackListener{l, b}
	if b.TLSConfig == nil {
		// config only allows this with insecure_plaintext.
		srv.AllowInsecureAuth = true
	} else if b.ImplicitTLS {
		l = tls.NewListener(l, b.TLSConfig)
	} else {
		srv.TLSConfig = b.TLSConfig
	}
	b.mu.Lock()
	b.srv = srv
	b.mu.Unlock()
	return srv.Serve(l)
}

// trackListener keeps the open connections in b.conns, for Close.
type trackListener struct {
	net.Listener
	b *Server
}

func (l trackListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	tc := &trackedConn{Conn: c, b: l.b}
	l.b.mu.Lock()
	if l.b.conns == nil {
		l.b.conns = map[net.Conn]struct{}{}
	}
	l.b.conns[tc] = struct{}{}
	l.b.mu.Unlock()
	return tc, nil
}

type trackedConn struct {
	net.Conn
	b *Server
}

func (c *trackedConn) Close() error {
	c.b.mu.Lock()
	delete(c.b.conns, c)
	c.b.mu.Unlock()
	return c.Conn.Close()
}

// drainTimeout limits the wait for submissions in progress at Close.
var drainTimeout = 5 * time.Second

// Close stops the listener and closes open connections. A submission in
// progress gets drainTimeout to finish, so a message is not cut off.
func (b *Server) Close() error {
	b.mu.Lock()
	srv := b.srv
	b.mu.Unlock()
	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()
	err := srv.Shutdown(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		// Shutdown leaves the rest open, and Close does nothing after it.
		b.mu.Lock()
		conns := slices.Collect(maps.Keys(b.conns))
		b.mu.Unlock()
		for _, c := range conns {
			c.Close()
		}
		err = nil
	}
	return err
}

type session struct {
	b        *Server
	remote   string
	username string
	password string
	upstream Upstream
	from     string
	to       []string
}

func (s *session) AuthMechanisms() []string { return []string{sasl.Plain, sasl.Login} }

func (s *session) Auth(mech string) (sasl.Server, error) {
	check := func(identity, username, password string) error {
		if identity != "" && identity != username {
			return smtp.ErrAuthFailed
		}
		u, ok := s.b.Route(username)
		if !ok {
			s.b.Log.Info("smtp: login rejected: no account matches", "user", username, "remote", s.remote)
			return smtp.ErrAuthFailed
		}
		if err := u.verify(username, password); err != nil {
			s.b.Log.Info("smtp: login rejected", "user", username, "upstream", u.Addr, "remote", s.remote, "err", err)
			return authError(err)
		}
		s.username, s.password, s.upstream = username, password, u
		s.b.Log.Info("smtp: login", "user", username, "upstream", u.Addr, "remote", s.remote)
		return nil
	}
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(check), nil
	case sasl.Login:
		return &loginServer{check: check}, nil
	}
	return nil, smtp.ErrAuthUnknownMechanism
}

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	if s.username == "" {
		return smtp.ErrAuthRequired
	}
	s.from = from
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if s.username == "" {
		return smtp.ErrAuthRequired
	}
	s.to = append(s.to, to)
	return nil
}

func (s *session) Data(r io.Reader) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*s.upstream.Timeout)
	defer cancel()

	if err := s.b.submit(ctx, s.upstream, s.username, s.password, &Envelope{From: s.from, To: s.to, Data: data}); err != nil {
		var se *smtp.SMTPError
		if errors.As(err, &se) {
			s.b.Log.Info("smtp: message rejected", "user", s.username, "err", err)
			return se
		}
		s.b.Log.Error("smtp: submission failed", "user", s.username, "err", err)
		return &smtp.SMTPError{Code: 451, EnhancedCode: smtp.EnhancedCode{4, 4, 0}, Message: "Upstream submission failed"}
	}
	return nil
}

// ErrNoAccount means no provider serves the login.
var ErrNoAccount = errors.New("no account matches the login")

// Submit sends a message for login as an SMTP client of the proxy would
// have: through the Filter, then to the provider's submission server with
// the client's credentials. The JMAP side uses it for EmailSubmission. An
// *smtp.SMTPError from the Filter or the provider comes back as it is.
func (b *Server) Submit(ctx context.Context, login, password string, env *Envelope) error {
	u, ok := b.Route(login)
	if !ok {
		return ErrNoAccount
	}
	return b.submit(ctx, u, login, password, env)
}

func (b *Server) submit(ctx context.Context, u Upstream, login, password string, env *Envelope) error {
	sub := &submission{u: &u, username: login, password: password}
	defer sub.close()
	var h Handler = sub
	if u.Provider != nil {
		h = HandlerFunc(func(ctx context.Context, env *Envelope) error { return u.Provider.Send(ctx, login, password, env) })
	}
	if b.Filter != nil {
		h = b.Filter(h)
	}
	if err := h.Handle(ctx, env); err != nil {
		return err
	}
	sub.quit()
	return nil
}

func (s *session) Reset() {
	s.from, s.to = "", nil
}

func (s *session) Logout() error {
	s.password = ""
	return nil
}

// submission is the last handler: it submits each envelope the Filter
// passes on over one authenticated upstream connection.
type submission struct {
	u                  *Upstream
	username, password string
	c                  *smtp.Client
}

func (sub *submission) Handle(ctx context.Context, env *Envelope) error {
	if sub.c == nil {
		c, err := sub.u.dial(ctx)
		if err != nil {
			return err
		}
		sub.c = c
		if err := sub.u.auth(c, sub.username, sub.password); err != nil {
			return err
		}
	}
	c := sub.c
	if err := c.Mail(env.From, nil); err != nil {
		return err
	}
	for _, r := range env.To {
		if err := c.Rcpt(r, nil); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(env.Data); err != nil {
		return err
	}
	return w.Close()
}

// quit ends the upstream session. The messages were already accepted, so a
// failed QUIT changes nothing.
func (sub *submission) quit() {
	if sub.c != nil {
		_ = sub.c.Quit()
		sub.c = nil
	}
}

func (sub *submission) close() {
	if sub.c != nil {
		sub.c.Close()
	}
}

// verify logs in to the provider to check credentials.
func (u *Upstream) verify(username, password string) error {
	if u.Provider != nil {
		err := u.Provider.Verify(username, password)
		if errors.Is(err, ErrLoginRejected) {
			return &smtp.SMTPError{Code: 535, EnhancedCode: smtp.EnhancedCode{5, 7, 8}, Message: "Authentication failed"}
		}
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), u.Timeout)
	defer cancel()
	c, err := u.dial(ctx)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := u.auth(c, username, password); err != nil {
		return err
	}
	_ = c.Quit()
	return nil
}

func (u *Upstream) dial(ctx context.Context) (*smtp.Client, error) {
	d := netbind.Dialer(u.Source, u.Timeout, nil)
	conn, err := d.DialContext(ctx, "tcp", u.Addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", u.Addr, err)
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	tlsCfg := u.TLSConfig
	if tlsCfg == nil {
		host, _, _ := net.SplitHostPort(u.Addr)
		tlsCfg = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	var c *smtp.Client
	switch u.TLS {
	case config.TLSImplicit:
		c = smtp.NewClient(tls.Client(conn, tlsCfg))
	case config.TLSStartTLS:
		if c, err = smtp.NewClientStartTLS(conn, tlsCfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("starttls %s: %w", u.Addr, err)
		}
	default:
		c = smtp.NewClient(conn)
	}
	if err := c.Hello(u.Helo); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// auth logs in with PLAIN, or LOGIN if that is all the provider offers.
func (u *Upstream) auth(c *smtp.Client, username, password string) error {
	ok, mechs := c.Extension("AUTH")
	if !ok {
		return errors.New("upstream does not offer AUTH")
	}
	var client sasl.Client
	for _, m := range bytes.Fields([]byte(mechs)) {
		switch string(bytes.ToUpper(m)) {
		case sasl.Plain:
			client = sasl.NewPlainClient("", username, password)
		case sasl.Login:
			if client == nil {
				client = sasl.NewLoginClient(username, password)
			}
		}
	}
	if client == nil {
		return fmt.Errorf("upstream offers neither PLAIN nor LOGIN (AUTH %s)", mechs)
	}
	return c.Auth(client)
}

// authError maps an upstream failure to the reply our client sees: a
// provider rejection stays a rejection, anything else is temporary.
func authError(err error) error {
	var se *smtp.SMTPError
	if errors.As(err, &se) && se.Code >= 500 {
		return smtp.ErrAuthFailed
	}
	return &smtp.SMTPError{Code: 454, EnhancedCode: smtp.EnhancedCode{4, 7, 0}, Message: "Temporary authentication failure"}
}

// loginServer is the server side of the LOGIN mechanism, which go-sasl only
// implements as a client. Some clients (older Outlook, some phones) offer
// nothing else.
type loginServer struct {
	check              func(identity, username, password string) error
	username, password string
	state              int
}

func (a *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch a.state {
	case 0:
		a.state = 1
		if response == nil {
			return []byte("Username:"), false, nil
		}
		fallthrough
	case 1:
		a.username = string(response)
		a.state = 2
		return []byte("Password:"), false, nil
	case 2:
		a.password = string(response)
		a.state = 3
		return nil, true, a.check("", a.username, a.password)
	}
	return nil, true, errors.New("unexpected client response")
}

type slogLogger struct{ l *slog.Logger }

func (s slogLogger) Printf(format string, v ...any) { s.l.Warn(fmt.Sprintf(format, v...)) }
func (s slogLogger) Println(v ...any)               { s.l.Warn(fmt.Sprint(v...)) }
