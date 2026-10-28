package daemon

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/smtpproxy"
)

// hookProvider takes one password and cannot send.
type hookProvider struct{}

func (hookProvider) Login(password string) error {
	if password != "pw" {
		return fmt.Errorf("%w: wrong password", engine.ErrLoginRejected)
	}
	return nil
}

func (hookProvider) Conn(engine.Priority, string) (engine.Conn, error) {
	return nil, errors.New("no connections")
}
func (hookProvider) Watch(func()) (engine.WatchConn, error) { return nil, errors.New("no watching") }
func (hookProvider) Close()                                 {}
func (hookProvider) Capacity() int                          { return 0 }

func TestSMTPHookProvider(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng := &engine.Engine{
		Route: func(login string) (engine.Upstream, bool) {
			return engine.Upstream{Provider: "hook"}, login == "alice@example.org"
		},
		NewProvider: func(string, engine.Upstream, []string, func() string) (engine.Provider, bool) {
			return hookProvider{}, true
		},
		Cache: &engine.Cache{},
		Log:   log,
	}
	defer eng.Close()
	srv := &smtpproxy.Server{
		Route: func(string) (smtpproxy.Upstream, bool) {
			return smtpproxy.Upstream{Provider: providerSender{eng}, Timeout: 5 * time.Second}, true
		},
		Domain:          "proxy.test",
		MaxMessageBytes: 1 << 20,
		Log:             log,
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(l)
	defer srv.Close()

	dial := func(pass string) (*smtp.Client, error) {
		c, err := smtp.Dial(l.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if err := c.Auth(sasl.NewPlainClient("", "alice@example.org", pass)); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}
	var se *smtp.SMTPError
	if _, err := dial("wrong"); !errors.As(err, &se) || se.Code != 535 {
		t.Fatalf("wrong password: err = %v, want 535", err)
	}
	c, err := dial("pw")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	err = c.SendMail("alice@example.org", []string{"bob@example.org"}, strings.NewReader("Subject: hi\r\n\r\nhi\r\n"))
	if !errors.As(err, &se) || se.Code != 554 {
		t.Fatalf("send: err = %v, want 554", err)
	}
}
