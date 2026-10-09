package smtpproxy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/brodyhoskins/mailcached/config"
)

const (
	password = "correct horse"
	alice    = "alice@corp.example"
	bob      = "bob@other.example"
)

// provider is a fake submission server that accepts alice's password.
type provider struct {
	mu   sync.Mutex
	got  []received
	addr string
}

type received struct {
	user, from string
	to         []string
	data       []byte
}

type providerSession struct {
	p    *provider
	user string
	r    received
}

func (s *providerSession) AuthMechanisms() []string { return []string{sasl.Plain} }
func (s *providerSession) Auth(string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(_, user, pass string) error {
		if user != alice || pass != password {
			return smtp.ErrAuthFailed
		}
		s.user = user
		return nil
	}), nil
}
func (s *providerSession) Mail(from string, _ *smtp.MailOptions) error {
	if s.user == "" {
		return smtp.ErrAuthRequired
	}
	s.r = received{user: s.user, from: from}
	return nil
}
func (s *providerSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	s.r.to = append(s.r.to, to)
	return nil
}
func (s *providerSession) Data(r io.Reader) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	s.r.data = b
	s.p.mu.Lock()
	s.p.got = append(s.p.got, s.r)
	s.p.mu.Unlock()
	return nil
}
func (s *providerSession) Reset()        {}
func (s *providerSession) Logout() error { return nil }

func startProvider(t *testing.T) *provider {
	p := &provider{}
	srv := smtp.NewServer(smtp.BackendFunc(func(*smtp.Conn) (smtp.Session, error) {
		return &providerSession{p: p}, nil
	}))
	srv.Domain = "provider.example"
	srv.AllowInsecureAuth = true
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p.addr = l.Addr().String()
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return p
}

func startProxy(t *testing.T, upstream string, filter Filter) string {
	b := &Server{
		Route: func(login string) (Upstream, bool) {
			if login != alice {
				return Upstream{}, false
			}
			return Upstream{Addr: upstream, TLS: config.TLSNone, Helo: "proxy.test", Timeout: 5 * time.Second}, true
		},
		Filter:          filter,
		Domain:          "proxy.test",
		MaxMessageBytes: 1 << 20,
		Log:             slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go b.Serve(l)
	t.Cleanup(func() { b.Close() })
	return l.Addr().String()
}

const msg = "From: Alice <alice@corp.example>\r\n" +
	"To: bob@other.example\r\n" +
	"Subject: Quarterly numbers\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"\r\n" +
	"The secret number is 42.\r\n"

func send(addr, user, pass string) error {
	c, err := smtp.Dial(addr)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Auth(sasl.NewPlainClient("", user, pass)); err != nil {
		return err
	}
	return c.SendMail(alice, []string{bob}, strings.NewReader(msg))
}

func TestSubmitUnchanged(t *testing.T) {
	p := startProvider(t)
	addr := startProxy(t, p.addr, nil)
	if err := send(addr, alice, password); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.got) != 1 {
		t.Fatalf("provider received %d messages, want 1", len(p.got))
	}
	r := p.got[0]
	if r.user != alice || r.from != alice || len(r.to) != 1 || r.to[0] != bob {
		t.Fatalf("envelope = %+v", r)
	}
	if !bytes.Equal(bytes.ReplaceAll(r.data, []byte("\r\n"), []byte("\n")), []byte(strings.ReplaceAll(msg, "\r\n", "\n"))) {
		t.Fatalf("provider received:\n%s", r.data)
	}
}

// TestSubmitFilter checks that a Filter can change a message and send
// several envelopes over one submission.
func TestSubmitFilter(t *testing.T) {
	p := startProvider(t)
	addr := startProxy(t, p.addr, func(next Handler) Handler {
		return HandlerFunc(func(ctx context.Context, env *Envelope) error {
			changed := &Envelope{From: env.From, To: env.To, Data: bytes.ReplaceAll(env.Data, []byte("42"), []byte("**"))}
			if err := next.Handle(ctx, changed); err != nil {
				return err
			}
			return next.Handle(ctx, &Envelope{From: env.From, To: []string{alice}, Data: env.Data})
		})
	})
	if err := send(addr, alice, password); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.got) != 2 {
		t.Fatalf("provider received %d messages, want 2", len(p.got))
	}
	if r := p.got[0]; r.to[0] != bob || strings.Contains(string(r.data), "42") || !strings.Contains(string(r.data), "number is **") {
		t.Fatalf("first envelope = %+v", r)
	}
	if r := p.got[1]; r.to[0] != alice || !strings.Contains(string(r.data), "number is 42") {
		t.Fatalf("second envelope = %+v", r)
	}
}

// TestFilterRejects checks that a Filter's SMTP error reaches the client.
func TestFilterRejects(t *testing.T) {
	p := startProvider(t)
	addr := startProxy(t, p.addr, func(Handler) Handler {
		return HandlerFunc(func(context.Context, *Envelope) error {
			return &smtp.SMTPError{Code: 550, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "No key for bob"}
		})
	})
	err := send(addr, alice, password)
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code != 550 || se.Message != "No key for bob" {
		t.Fatalf("err = %v, want the filter's 550", err)
	}
	if len(p.got) != 0 {
		t.Fatal("message was relayed")
	}
}

func TestBadPasswordRejected(t *testing.T) {
	p := startProvider(t)
	addr := startProxy(t, p.addr, nil)

	err := send(addr, alice, "wrong")
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code != 535 {
		t.Fatalf("err = %v, want 535", err)
	}
	if len(p.got) != 0 {
		t.Fatal("message was relayed")
	}
}

func TestUnknownAccountRejected(t *testing.T) {
	p := startProvider(t)
	addr := startProxy(t, p.addr, nil)
	err := send(addr, "mallory@elsewhere.example", password)
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code != 535 {
		t.Fatalf("err = %v, want 535", err)
	}
}

func TestUnauthenticatedRejected(t *testing.T) {
	p := startProvider(t)
	addr := startProxy(t, p.addr, nil)

	c, err := smtp.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	err = c.SendMail(alice, []string{bob}, strings.NewReader(msg))
	var se *smtp.SMTPError
	if !errors.As(err, &se) || se.Code < 500 {
		t.Fatalf("err = %v, want a permanent rejection", err)
	}
}
