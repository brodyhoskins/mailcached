// Package easproxy is an Exchange ActiveSync server (MS-ASHTTP, MS-ASCMD,
// version 14.1) for mail, for the phones whose mail apps speak it, the
// iPhone's among them. It serves each account from the engine's local
// copy, like imapproxy and jmapproxy, and its Ping gives those apps push
// for new mail without anything from Apple or Google. It answers
// Autodiscover too, so a device finds it from the address alone.
//
// It serves mail only: no calendar, contacts or tasks. Devices log in
// with HTTP Basic auth and their provider credentials. Device policies
// (Provision) are answered with a policy that asks for nothing.
package easproxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/internal/load"
	"github.com/brodyhoskins/mailcached/smtpproxy"
)

// Submit sends a message for a device, as smtpproxy.Server.Submit does.
type Submit func(ctx context.Context, login, password string, env *smtpproxy.Envelope) error

// Server is the ActiveSync listener.
type Server struct {
	Engine    *engine.Engine
	TLSConfig *tls.Config // nil: no TLS (loopback only)
	// MaxMessageBytes limits messages sent. Default 50 MiB.
	MaxMessageBytes int64
	// Submit sends mail; nil refuses to send.
	Submit Submit
	Log    *slog.Logger

	devs     devices
	devsOnce sync.Once

	mu   sync.Mutex
	srv  *http.Server
	quit chan struct{} // closed by Close: open Pings end
}

// The versions and commands the server offers.
const (
	serverVersion = "14.1"
	versions      = "12.0,12.1,14.0,14.1"
	commands      = "Sync,SendMail,SmartForward,SmartReply,GetAttachment,FolderSync,FolderCreate,FolderDelete," +
		"FolderUpdate,MoveItems,GetItemEstimate,Settings,Ping,ItemOperations,Provision"
	maxRequest = 50 << 20
)

func (s *Server) maxMessage() int64 {
	if s.MaxMessageBytes > 0 {
		return s.MaxMessageBytes
	}
	return 50 << 20
}

func (s *Server) devices() *devices {
	s.devsOnce.Do(func() {
		if st := s.Engine.Store; st != nil && st.Dir != "" {
			s.devs.dir = filepath.Join(st.Dir, "activesync")
		}
	})
	return &s.devs
}

// Handler returns the server's HTTP handler.
func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.ToLower(strings.TrimSuffix(r.URL.Path, "/"))
		switch {
		case path == "/microsoft-server-activesync":
			s.serveEAS(w, r)
		case path == "/autodiscover/autodiscover.xml":
			s.serveAutodiscover(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

// Serve accepts connections on l until Close.
func (s *Server) Serve(l net.Listener) error {
	// No write timeout: a Ping waits up to an hour.
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

// Close stops the listener and closes open connections. The Engine is its
// owner's to close. Open Pings end first, as if their heartbeat expired:
// a device that sees its Ping answered pings again later, but one that
// sees the connection drop may report an error. Other requests get
// drainTimeout to finish.
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
	if err := srv.Shutdown(ctx); err == nil {
		return nil
	}
	return srv.Close()
}

// client is a logged-in device user.
type client struct {
	acct     *engine.Account
	login    string
	password string
}

// authenticate checks the request's Basic credentials. It answers a
// refused request itself.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*client, bool) {
	login, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="ActiveSync"`)
		http.Error(w, "Authentication required", http.StatusUnauthorized)
		return nil, false
	}
	// Some devices send DOMAIN\user.
	if i := strings.LastIndexByte(login, '\\'); i >= 0 {
		login = login[i+1:]
	}
	eng := s.Engine
	refuse := func() (*client, bool) {
		s.Log.Info("activesync: login rejected", "user", login, "remote", r.RemoteAddr)
		w.Header().Set("WWW-Authenticate", `Basic realm="ActiveSync"`)
		http.Error(w, "Authentication failed", http.StatusUnauthorized)
		return nil, false
	}
	if _, ok := eng.Route(login); !ok {
		return refuse()
	}
	a := eng.Account(login)
	if err := a.Login(password); err != nil {
		if errors.Is(err, engine.ErrLoginRejected) || errors.Is(err, engine.ErrNoAccount) {
			return refuse()
		}
		s.Log.Error("activesync: upstream login failed", "user", login, "err", err)
		http.Error(w, "Upstream server unavailable", http.StatusServiceUnavailable)
		return nil, false
	}
	return &client{acct: a, login: strings.ToLower(login), password: password}, true
}

// request is one ActiveSync request.
type request struct {
	s          *Server
	r          *http.Request
	c          *client
	dv         *device
	cmd        string
	deviceID   string
	deviceType string
	version    string
	params     map[string]string // the query's other parameters
	body       []byte
	doc        *node // the WBXML body, nil if none
	held       bool  // the request holds room in the process (load)
}

// idle gives back the request's room in the process while it waits for
// changes.
func (req *request) idle() {
	if req.held {
		load.Default.Leave()
		req.held = false
	}
}

// busy takes room in the process again after a wait.
func (req *request) busy() error {
	if err := load.Default.Enter(req.r.Context()); err != nil {
		return err
	}
	req.held = true
	return nil
}

// errStatus is a command's failure, as the command's own Status.
type errStatus int

func (e errStatus) Error() string { return fmt.Sprintf("status %d", int(e)) }

func (s *Server) serveEAS(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("MS-Server-ActiveSync", serverVersion)
	if r.Method == http.MethodOptions {
		h.Set("MS-ASProtocolVersions", versions)
		h.Set("MS-ASProtocolCommands", commands)
		h.Set("Allow", "OPTIONS,POST")
		h.Set("Public", "OPTIONS,POST")
		// OPTIONS is asked with credentials; check them, as clients
		// test the account this way.
		if _, ok := s.authenticate(w, r); !ok {
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	req, err := parseQuery(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.s, req.r, req.c = s, r, c
	if req.version == "" {
		req.version = r.Header.Get("MS-ASProtocolVersion")
	}
	if req.deviceID == "" {
		http.Error(w, "DeviceId is required", http.StatusBadRequest)
		return
	}
	// A request holds room in the process while it works, from before it
	// reads its body, not while it waits for changes: a Sync gives it back
	// to wait (idle), and a Ping does little else.
	if req.cmd != "Ping" {
		if err := req.busy(); err != nil {
			return
		}
		defer req.idle()
	}
	// A client that stalls its body, or stops reading the answer, cannot
	// keep the room. A Sync or Ping may wait for changes first: its answer
	// gets its deadline once the wait is over.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(5 * time.Minute))
	writeBy := func() { _ = rc.SetWriteDeadline(time.Now().Add(5 * time.Minute)) }
	if req.cmd != "Sync" && req.cmd != "Ping" {
		writeBy()
	}
	defer func() { // not for the connection's next request
		_ = rc.SetReadDeadline(time.Time{})
		_ = rc.SetWriteDeadline(time.Time{})
	}()
	if req.body, err = io.ReadAll(io.LimitReader(r.Body, maxRequest)); err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	if len(req.body) > 0 && strings.Contains(r.Header.Get("Content-Type"), "wbxml") {
		if req.doc, err = decode(req.body); err != nil {
			http.Error(w, "Bad WBXML", http.StatusBadRequest)
			return
		}
	}
	req.dv = s.devices().get(c.login, req.deviceID)

	var out *node
	var raw []byte
	switch req.cmd {
	case "FolderSync":
		out, err = req.folderSync()
	case "FolderCreate":
		out, err = req.folderCreate()
	case "FolderDelete":
		out, err = req.folderDelete()
	case "FolderUpdate":
		out, err = req.folderUpdate()
	case "Sync":
		out, err = req.sync()
	case "GetItemEstimate":
		out, err = req.getItemEstimate()
	case "Ping":
		out, err = req.ping()
	case "MoveItems":
		out, err = req.moveItems()
	case "ItemOperations":
		out, err = req.itemOperations()
	case "GetAttachment":
		raw, err = req.getAttachment(w)
	case "SendMail", "SmartReply", "SmartForward":
		out, err = req.send()
	case "Settings":
		out, err = req.settings()
	case "Provision":
		out, err = req.provision()
	default:
		http.Error(w, "Command not supported", http.StatusNotImplemented)
		return
	}
	writeBy()
	if err != nil {
		var hs httpStatus
		if errors.As(err, &hs) {
			http.Error(w, http.StatusText(int(hs)), int(hs))
			return
		}
		s.Log.Warn("activesync: command failed", "user", c.login, "device", req.deviceID, "cmd", req.cmd, "err", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	if raw != nil {
		_, _ = w.Write(raw)
		return
	}
	if out == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	b, err := encode(out)
	if err != nil {
		s.Log.Error("activesync: encode", "cmd", req.cmd, "err", err)
		http.Error(w, "Server error", http.StatusInternalServerError)
		return
	}
	h.Set("Content-Type", "application/vnd.ms-sync.wbxml")
	_, _ = w.Write(b)
}

// httpStatus is a failure answered with an HTTP status.
type httpStatus int

func (e httpStatus) Error() string { return http.StatusText(int(e)) }

// The commands of the base64 query form (MS-ASHTTP 2.2.1.1.1.1.2).
var commandCodes = map[byte]string{
	0: "Sync", 1: "SendMail", 2: "SmartForward", 3: "SmartReply", 4: "GetAttachment", 9: "FolderSync",
	10: "FolderCreate", 11: "FolderDelete", 12: "FolderUpdate", 13: "MoveItems", 14: "GetItemEstimate",
	15: "MeetingResponse", 16: "Search", 17: "Settings", 18: "Ping", 19: "ItemOperations", 20: "Provision",
	21: "ResolveRecipients", 22: "ValidateCert",
}

// The parameters of the base64 query form.
var paramCodes = map[byte]string{
	0: "AttachmentName", 1: "CollectionId", 3: "ItemId", 4: "LongId", 6: "Occurrence", 7: "Options", 8: "User",
}

// parseQuery reads the query: plain (Cmd=...&DeviceId=...), or the
// base64 form.
func parseQuery(r *http.Request) (*request, error) {
	q := r.URL.Query()
	if cmd := q.Get("Cmd"); cmd != "" {
		req := &request{cmd: cmd, deviceID: q.Get("DeviceId"), deviceType: q.Get("DeviceType"), params: map[string]string{}}
		for k := range q {
			req.params[k] = q.Get(k)
		}
		return req, nil
	}
	b, err := base64.StdEncoding.DecodeString(r.URL.RawQuery)
	if err != nil {
		if b, err = base64.StdEncoding.DecodeString(strings.ReplaceAll(r.URL.RawQuery, "%3D", "=")); err != nil {
			return nil, errors.New("bad query")
		}
	}
	bad := errors.New("bad base64 query")
	if len(b) < 5 {
		return nil, bad
	}
	req := &request{params: map[string]string{}}
	v := b[0]
	req.version = fmt.Sprintf("%d.%d", v/10, v%10)
	req.cmd = commandCodes[b[1]]
	p := b[4:] // the locale is two bytes
	take := func() ([]byte, bool) {
		if len(p) < 1 || len(p) < 1+int(p[0]) {
			return nil, false
		}
		n := int(p[0])
		v := p[1 : 1+n]
		p = p[1+n:]
		return v, true
	}
	id, ok := take()
	if !ok {
		return nil, bad
	}
	req.deviceID = string(id)
	if _, ok = take(); !ok { // the policy key
		return nil, bad
	}
	typ, ok := take()
	if !ok {
		return nil, bad
	}
	req.deviceType = string(typ)
	for len(p) >= 2 {
		tag := p[0]
		p = p[1:]
		v, ok := take()
		if !ok {
			return nil, bad
		}
		if tag == 7 && len(v) > 0 { // Options: flags
			if v[0]&1 != 0 {
				req.params["SaveInSent"] = "T"
			}
			continue
		}
		if name := paramCodes[tag]; name != "" {
			req.params[name] = string(v)
		}
	}
	_ = binary.LittleEndian // the locale, unused
	return req, nil
}

// versionAtLeast reports whether the request's protocol version is v or
// later.
func (req *request) versionAtLeast(v string) bool {
	return versionNum(req.version) >= versionNum(v)
}

func versionNum(v string) int {
	var a, b int
	fmt.Sscanf(v, "%d.%d", &a, &b)
	return a*10 + b
}
