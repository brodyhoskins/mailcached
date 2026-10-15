// Package jmapproxy is a JMAP server (RFC 8620, RFC 8621) for mail
// clients. Like imapproxy, it serves each account from the engine's local
// copy, whichever protocol the provider speaks, so clients are answered
// at once; changes go to the provider through the engine's queue.
//
// Clients log in with HTTP Basic auth and their provider credentials,
// which the engine checks with the provider the first time and then keeps
// in memory only.
//
// Responses are compressed with Zstandard or gzip when the client accepts
// it, and compressed request bodies are accepted too.
package jmapproxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/internal/httpenc"
	"github.com/brodyhoskins/mailcached/internal/jmap"
	"github.com/brodyhoskins/mailcached/smtpproxy"
)

// Submit sends a message for a client: the SMTP side's Filter and
// submission (smtpproxy.Server.Submit). The client's credentials go
// along, as an SMTP client's would.
type Submit func(ctx context.Context, login, password string, env *smtpproxy.Envelope) error

// Server is the JMAP listener.
type Server struct {
	Engine    *engine.Engine
	TLSConfig *tls.Config // nil: no TLS (loopback only)
	// MaxMessageBytes limits uploads and stored messages. Default 50 MiB.
	MaxMessageBytes int64
	// Submit sends mail for EmailSubmission; nil refuses to send.
	Submit Submit
	Log    *slog.Logger
	// PushSubject is the contact push services see in VAPID signatures:
	// a mailto: or https: URL.
	PushSubject string
	// PushClient sends PushSubscription pushes; nil for a default one.
	PushClient *http.Client

	push pushes

	uploads uploads
	gates   gates
	subMu   sync.Mutex
	subs    map[string]*submissions // by login

	mu      sync.Mutex
	srv     *http.Server
	quit    chan struct{}  // closed by Close: push streams end
	sockets sync.WaitGroup // WebSockets, which http.Server does not track
}

// Limits the server advertises.
const (
	maxCalls        = 64
	maxObjectsInGet = 1000
	maxObjectsInSet = 1000
	maxRequest      = 10 << 20
)

func (s *Server) maxMessage() int64 {
	if s.MaxMessageBytes > 0 {
		return s.MaxMessageBytes
	}
	return 50 << 20
}

// Handler returns the server's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/jmap", s.auth(s.serveSession))
	mux.HandleFunc("GET /jmap/session", s.auth(s.serveSession))
	mux.HandleFunc("POST /jmap/api", s.auth(s.serveAPI))
	mux.HandleFunc("GET /jmap/download/{account}/{blob}/{name}", s.auth(s.serveDownload))
	mux.HandleFunc("POST /jmap/upload/{account}/", s.auth(s.serveUpload))
	mux.HandleFunc("GET /jmap/eventsource", s.auth(s.serveEvents))
	mux.HandleFunc("GET /jmap/ws", s.serveWebSocket)
	return mux
}

// Serve accepts connections on l until Close.
func (s *Server) Serve(l net.Listener) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       5 * time.Minute,
		ErrorLog:          slog.NewLogLogger(s.Log.Handler(), slog.LevelWarn),
	}
	s.mu.Lock()
	s.srv = srv
	s.mu.Unlock()
	if s.TLSConfig != nil {
		l = tls.NewListener(l, s.TLSConfig)
	}
	err := srv.Serve(l)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// Close stops the listener and closes open connections. The Engine is its
// owner's to close.
//
// Push streams end first, cleanly: an EventSource stream ends, and a
// WebSocket closes with "going away". A client that sees that reconnects
// later, but one that sees the connection drop may report an error. Other
// requests get drainTimeout to finish.
func (s *Server) Close() error {
	s.quitting()
	s.mu.Lock()
	srv := s.srv
	select {
	case <-s.quit:
	default:
		close(s.quit)
	}
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
	defer cancel()
	err := srv.Shutdown(ctx)
	sockets := make(chan struct{})
	go func() { s.sockets.Wait(); close(sockets) }()
	select {
	case <-sockets:
	case <-ctx.Done():
	}
	if err == nil {
		return nil
	}
	return srv.Close()
}

// quitting returns the channel that Close closes.
func (s *Server) quitting() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.quit == nil {
		s.quit = make(chan struct{})
	}
	return s.quit
}

// drainTimeout limits the wait for requests in progress at Close.
var drainTimeout = 5 * time.Second

// client is the logged-in user of a request.
type client struct {
	acct     *engine.Account
	login    string
	password string
	id       jmap.ID // the JMAP account ID
}

type clientKey struct{}

func clientOf(r *http.Request) *client { return r.Context().Value(clientKey{}).(*client) }

// accountID is the JMAP account ID of a login.
func accountID(login string) jmap.ID {
	h := sha256.Sum256([]byte(strings.ToLower(login)))
	return jmap.ID("a" + hex.EncodeToString(h[:8]))
}

// auth checks the request's Basic credentials (authenticate), and
// compresses the response.
func (s *Server) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, ok := s.authenticate(w, r)
		if !ok {
			return
		}
		cw, done := httpenc.Wrap(w, r)
		// Deferred: a handler that panics still gives its room back.
		var after []func()
		defer func() {
			for _, f := range after {
				f()
			}
		}()
		ctx := context.WithValue(r.Context(), clientKey{}, c)
		h(cw, r.WithContext(context.WithValue(ctx, afterKey{}, &after)))
		if err := done(); err != nil {
			s.Log.Debug("jmap: response", "err", err)
		}
	}
}

// authenticate checks the request's Basic credentials
// (engine.Account.Login). It answers a refused request itself.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*client, bool) {
	login, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="JMAP", charset="UTF-8"`)
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return nil, false
	}
	eng := s.Engine
	if _, ok := eng.Route(login); !ok {
		s.Log.Info("jmap: login rejected: no account matches", "user", login, "remote", r.RemoteAddr)
		s.refuse(w)
		return nil, false
	}
	a := eng.Account(login)
	if err := a.Login(password); err != nil {
		if errors.Is(err, engine.ErrLoginRejected) || errors.Is(err, engine.ErrNoAccount) {
			s.Log.Info("jmap: login rejected", "user", login, "remote", r.RemoteAddr)
			s.refuse(w)
			return nil, false
		}
		s.Log.Error("jmap: upstream login failed", "user", login, "err", err)
		http.Error(w, "Upstream server unavailable", http.StatusServiceUnavailable)
		return nil, false
	}
	return &client{acct: a, login: strings.ToLower(login), password: password, id: accountID(login)}, true
}

func (s *Server) refuse(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="JMAP", charset="UTF-8"`)
	http.Error(w, "Authentication failed", http.StatusUnauthorized)
}

// writeJSON writes v as the response.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeProblem writes a request-level error.
func writeProblem(w http.ResponseWriter, p *jmap.ProblemDetails) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// problem writes a request-level error.
func problem(w http.ResponseWriter, status int, typ, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(jmap.ProblemDetails{Type: typ, Status: status, Detail: detail})
}

// wsURL is baseURL for WebSockets.
func wsURL(r *http.Request) string {
	if r.TLS != nil {
		return "wss://" + r.Host
	}
	return "ws://" + r.Host
}

// baseURL is where the client reached the server.
func baseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

func (s *Server) serveSession(w http.ResponseWriter, r *http.Request) {
	c := clientOf(r)
	base := baseURL(r)
	c.acct.Lock()
	state := c.acct.State()
	c.acct.Unlock()
	empty := json.RawMessage("{}")
	n := limit(c)
	sess := jmap.Session{
		Capabilities: map[string]json.RawMessage{
			jmap.CapCore: mustJSON(jmap.CoreCapability{
				MaxSizeUpload: s.maxMessage(), MaxConcurrentUpload: n, MaxSizeRequest: maxRequest,
				MaxConcurrentRequests: n, MaxCallsInRequest: maxCalls, MaxObjectsInGet: maxObjectsInGet,
				MaxObjectsInSet: maxObjectsInSet, CollationAlgorithms: []string{"i;ascii-casemap", "i;unicode-casemap"},
			}),
			jmap.CapMail:       empty,
			jmap.CapSubmission: empty,
			jmap.CapWebSocket:  mustJSON(jmap.WebSocketCapability{URL: wsURL(r) + "/jmap/ws", SupportsPush: true}),
		},
		Accounts: map[jmap.ID]jmap.Account{c.id: {
			Name: c.login, IsPersonal: true,
			AccountCapabilities: map[string]json.RawMessage{
				jmap.CapMail: mustJSON(map[string]any{
					"maxMailboxesPerEmail": nil, "maxMailboxDepth": nil, "maxSizeMailboxName": 490,
					"maxSizeAttachmentsPerEmail": s.maxMessage(), "emailQuerySortOptions": sortOptions,
					"mayCreateTopLevelMailbox": true,
				}),
				jmap.CapSubmission: mustJSON(map[string]any{"maxDelayedSend": 0, "submissionExtensions": map[string]any{}}),
			},
		}},
		PrimaryAccounts: map[string]jmap.ID{jmap.CapMail: c.id, jmap.CapSubmission: c.id},
		Username:        c.login,
		APIURL:          base + "/jmap/api",
		DownloadURL:     base + "/jmap/download/{accountId}/{blobId}/{name}?type={type}",
		UploadURL:       base + "/jmap/upload/{accountId}/",
		EventSourceURL:  base + "/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}",
		State:           jmap.State(sessionState(state, n)),
	}
	if p, err := s.pushState(); err == nil {
		sess.Capabilities[capVAPID] = mustJSON(map[string]string{"applicationServerKey": p.vapid.PublicKey()})
	} else {
		s.Log.Warn("jmap: push subscriptions are off", "err", err)
	}
	writeJSON(w, http.StatusOK, sess)
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
