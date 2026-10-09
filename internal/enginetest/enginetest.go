// Package enginetest runs a mail provider for tests: go-imap's in-memory
// IMAP server, with one user.
package enginetest

import (
	"fmt"
	"log/slog"
	"net"
	"testing"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
	"github.com/emersion/go-imap/v2/imapserver/imapmemserver"
)

// The provider's user, and the other side of the tests' mail.
const (
	User     = "alice@example.org"
	Password = "correct horse"
	Bob      = "bob@other.example"
)

// Listen listens on a free loopback port.
func Listen(t testing.TB) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// IMAP starts a provider with User and an INBOX, and returns its address
// and the user. wrap, if not nil, wraps its listener.
func IMAP(t testing.TB, log *slog.Logger, wrap func(net.Listener) net.Listener) (string, *imapmemserver.User) {
	t.Helper()
	mem := imapmemserver.New()
	u := imapmemserver.NewUser(User, Password)
	if err := u.Create("INBOX", nil); err != nil {
		t.Fatal(err)
	}
	mem.AddUser(u)
	up := imapserver.New(&imapserver.Options{
		NewSession: func(*imapserver.Conn) (imapserver.Session, *imapserver.GreetingData, error) {
			return mem.NewSession(), nil, nil
		},
		Caps:         imap.CapSet{imap.CapIMAP4rev1: {}, imap.CapIMAP4rev2: {}},
		InsecureAuth: true,
		Logger:       logger{log},
	})
	l := Listen(t)
	var served net.Listener = l
	if wrap != nil {
		served = wrap(l)
	}
	go up.Serve(served)
	t.Cleanup(func() { up.Close() })
	return l.Addr().String(), u
}

type logger struct{ l *slog.Logger }

func (s logger) Printf(format string, v ...any) { s.l.Warn("upstream: " + fmt.Sprintf(format, v...)) }
