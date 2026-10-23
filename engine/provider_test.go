package engine_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"testing"
	"time"

	"github.com/brodyhoskins/mailcached/engine"
	"github.com/emersion/go-imap/v2"
)

const fakeRaw = "Message-ID: <1@fake>\r\nSubject: Scan 1\r\n\r\nA letter.\r\n"

// fakeProvider has an INBOX with one message, UID 1, and takes one
// password.
type fakeProvider struct {
	password func() string
	fields   []string
}

func (p *fakeProvider) Login(password string) error {
	if password != "pw" {
		return fmt.Errorf("%w: wrong password", engine.ErrLoginRejected)
	}
	return nil
}

func (p *fakeProvider) Conn(engine.Priority, string) (engine.Conn, error) { return fakeConn{p}, nil }
func (p *fakeProvider) Watch(func()) (engine.WatchConn, error)            { return fakeConn{p}, nil }
func (p *fakeProvider) Close()                                            {}
func (p *fakeProvider) Capacity() int                                     { return 0 }

type fakeConn struct{ p *fakeProvider }

func (fakeConn) List() ([]engine.FolderInfo, error) {
	return []engine.FolderInfo{{Name: "INBOX", Delim: '/', Subscribed: true, Selectable: true}}, nil
}

func (fakeConn) Sync(name string, st engine.SyncState) (*engine.Delta, error) {
	if name != "INBOX" {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "no such folder"}
	}
	if st.Synced && st.Validity == 1 && st.Next == 2 && !st.Force && !st.Stale && !st.RefetchFlags {
		return &engine.Delta{Unchanged: true}, nil
	}
	d := &engine.Delta{Present: map[imap.UID]bool{1: true}, Validity: 1, Next: 2,
		FolderFlags: []imap.Flag{imap.FlagSeen}, PermanentFlags: []imap.Flag{imap.FlagSeen}, FullFlags: true}
	if st.Validity != 1 || !st.Known(1) {
		hdr, _, _ := bytes.Cut([]byte(fakeRaw), []byte("\r\n\r\n"))
		d.Fresh = []engine.FreshMessage{{UID: 1, Date: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC),
			Size: int64(len(fakeRaw)), Header: append(hdr, "\r\n\r\n"...)}}
	}
	return d, nil
}

func (fakeConn) FetchFull(name string, uids []imap.UID, each func(imap.UID, []byte)) error {
	if slices.Contains(uids, 1) {
		each(1, []byte(fakeRaw))
	}
	return nil
}

func (fakeConn) FetchSections(string, []imap.UID, []engine.Section, func(imap.UID, int, []byte)) error {
	return engine.ErrNoPieces
}

func (fakeConn) Search(string, *imap.SearchCriteria) ([]imap.UID, error) {
	return nil, engine.ErrNoSearch
}

func (fakeConn) FetchHeaders(string, []imap.UID) (map[imap.UID]*engine.HeaderEntry, error) {
	return nil, engine.ErrNoPieces
}

func (fakeConn) Store(string, []imap.UID, imap.StoreFlagsOp, []imap.Flag) (map[imap.UID][]imap.Flag, error) {
	return nil, nil
}

func (fakeConn) Copy(string, []imap.UID, string) (map[imap.UID]imap.UID, error) { return nil, refused }
func (fakeConn) Move(string, []imap.UID, string) (map[imap.UID]imap.UID, error) { return nil, refused }
func (fakeConn) Expunge(string, []imap.UID) error                               { return refused }
func (fakeConn) Append(string, []byte, *imap.AppendOptions) (imap.UID, uint32, error) {
	return 0, 0, refused
}
func (fakeConn) Create(string, *imap.CreateOptions) error         { return refused }
func (fakeConn) Delete(string) error                              { return refused }
func (fakeConn) Rename(string, string, *imap.RenameOptions) error { return refused }
func (fakeConn) Subscribe(string, bool) error                     { return nil }
func (fakeConn) Release(error)                                    {}

func (fakeConn) Wait(ctx context.Context, d time.Duration, changed, wake <-chan struct{}) (engine.Wakeup, error) {
	select {
	case <-ctx.Done():
		return engine.Wakeup{}, ctx.Err()
	case <-changed:
		return engine.Wakeup{}, engine.ErrCredentialsChanged
	case <-wake:
	case <-time.After(d):
	}
	return engine.Wakeup{All: true}, nil
}

func (fakeConn) Notifies() bool  { return true }
func (fakeConn) Describe() []any { return nil }

var refused = &imap.Error{Type: imap.StatusResponseTypeNo, Text: "read-only"}

func TestNewProviderHook(t *testing.T) {
	var made *fakeProvider
	eng := &engine.Engine{
		Route: func(login string) (engine.Upstream, bool) {
			return engine.Upstream{Provider: "fake"}, login == "alice@example.org"
		},
		NewProvider: func(login string, u engine.Upstream, fields []string, password func() string) (engine.Provider, bool) {
			if u.Provider != "fake" {
				return nil, false
			}
			made = &fakeProvider{password: password, fields: fields}
			return made, true
		},
		Cache: &engine.Cache{},
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	defer eng.Close()
	a := eng.Account("alice@example.org")
	if err := a.Login("wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
	if err := a.Login("pw"); err != nil {
		t.Fatal(err)
	}
	if made == nil || made.password() != "pw" || !slices.Contains(made.fields, "Message-ID") {
		t.Fatalf("hook got fields %v", made.fields)
	}
	m, err := a.MailboxFor("INBOX")
	if err != nil {
		t.Fatal(err)
	}
	a.Lock()
	msgs := slices.Clone(m.Msgs())
	a.Unlock()
	if len(msgs) != 1 {
		t.Fatalf("INBOX has %d messages, want 1", len(msgs))
	}
	got, err := a.Download(msgs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(got[msgs[0]]) != fakeRaw {
		t.Fatalf("download = %q", got[msgs[0]])
	}
}
