// Package engine keeps each account's local copy of a mail provider: the
// folders, the messages with their flags, and a cache of the messages
// clients read. A sync engine per account keeps the copy current, whether
// or not a client is connected, and a queue takes the changes clients make
// to the provider. The client protocols (imapproxy, jmapproxy) serve from
// it, and the providers (IMAP, JMAP) feed it.
//
// Clients log in with their provider credentials. The engine keeps them
// in memory only, while it needs them to reach the provider.
package engine

import (
	"context"
	"crypto/tls"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
)

// Upstream is a provider's server: IMAP (Addr), JMAP (URL), or ActiveSync
// (ActiveSync).
type Upstream struct {
	Addr      string // IMAP: host:port
	TLS       string // IMAP: config.TLSImplicit, TLSStartTLS or TLSNone
	TLSConfig *tls.Config
	Timeout   time.Duration
	// Source is where connections to the provider leave from: an
	// interface name or a local IP address. Empty: wherever routing says.
	Source string
	// URL is a JMAP provider's session resource, such as
	// https://example.com/.well-known/jmap. It makes the provider JMAP.
	URL string
	// Bearer sends the client's password to a JMAP provider as a Bearer
	// token (an API token), not with Basic auth.
	Bearer bool
	// ActiveSync is an Exchange ActiveSync provider's endpoint, such as
	// https://example.com/Microsoft-Server-ActiveSync. It makes the
	// provider ActiveSync.
	ActiveSync string
}

// String names the provider, for logs and for the state saved for it.
func (u Upstream) String() string {
	if u.URL != "" {
		return u.URL
	}
	if u.ActiveSync != "" {
		return u.ActiveSync
	}
	return u.Addr
}

// Engine holds the accounts.
type Engine struct {
	// Route picks the provider for a login name. ok is false for a login
	// the engine does not serve, which is then rejected.
	Route   func(login string) (u Upstream, ok bool)
	Timeout time.Duration // per upstream operation
	// Transform changes messages between the provider and clients; nil
	// serves them unchanged.
	Transform Transform
	Cache     *Cache
	// Store keeps the mailbox state on disk across restarts; nil keeps it
	// in memory only.
	Store *Store
	// Backfill fills every folder's message list in the background after
	// a login (backfill.go). It needs a Store.
	Backfill bool
	Log      *slog.Logger
	// Name and Version identify the proxy to providers that ask (the IMAP
	// ID command).
	Name, Version string

	syncOnce sync.Once
	syncSec  *imap.FetchItemBodySection // see syncSection

	// inflight holds the cache keys being downloaded, so a client asking
	// for a message the engine is fetching already waits for that
	// download, unless it is a background one (read-ahead, backfill).
	flightMu sync.Mutex
	inflight map[string]*flight

	syncMu     sync.Mutex          // guards accounts and the sync context
	accounts   map[string]*Account // by lowercased login
	syncBase   context.Context
	syncCancel context.CancelFunc
}

// Close ends every account's engine and drops every password.
func (b *Engine) Close() {
	b.stopSync()
}

// id is what the engine sends with the IMAP ID command.
func (b *Engine) id() *imap.IDData {
	return &imap.IDData{Name: b.Name, Version: b.Version}
}

// CanonicalName spells INBOX in capitals (RFC 9051 section 5.1).
func CanonicalName(name string) string {
	if strings.EqualFold(name, "INBOX") {
		return "INBOX"
	}
	return name
}
