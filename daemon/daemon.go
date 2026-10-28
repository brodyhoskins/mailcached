// Package daemon runs mailcached's IMAP, JMAP, ActiveSync and SMTP servers from a
// config file: the main function of mailcached, and of programs built on it that
// add a Transform and a Filter.
package daemon

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"log/syslog"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/emersion/go-smtp"

	"github.com/brodyhoskins/mailcached/config"
	"github.com/brodyhoskins/mailcached/easproxy"
	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/imapproxy"
	"github.com/brodyhoskins/mailcached/internal/autodetect"
	"github.com/brodyhoskins/mailcached/internal/certs"
	"github.com/brodyhoskins/mailcached/internal/fscompress"
	"github.com/brodyhoskins/mailcached/internal/load"
	"github.com/brodyhoskins/mailcached/internal/netbind"
	"github.com/brodyhoskins/mailcached/jmapproxy"
	"github.com/brodyhoskins/mailcached/smtpproxy"
)

// Program is a program built on mailcached.
type Program struct {
	// Name names the program in logs, in the IMAP ID command and in the
	// User-Agent. In upper case, with "_" for "-", it is also the prefix of
	// its environment variables: MAILCACHED_TRACE, MAILCACHED_PPROF.
	Name    string
	Version string
	Files   config.Files // where the config file is looked for
	// Load reads the config file at path ("" for none). nil: config.Load.
	Load func(path string) (*config.Config, error)
	// Hooks sets up the message changes once the config is loaded and
	// logging works. nil: messages pass through unchanged.
	Hooks func(log *slog.Logger) (Hooks, error)
}

// Hooks change messages on their way through.
type Hooks struct {
	Transform engine.Transform // between the provider and clients
	Filter    smtpproxy.Filter // SMTP: before submission to the provider
	// Authorize, if set, runs after each login (engine.Engine.Authorize).
	Authorize func(a *engine.Account) error
	// NewProvider makes the provider for an account whose config names
	// one (provider: in an account), and may claim other logins too
	// (engine.Engine.NewProvider).
	NewProvider func(login string, u engine.Upstream, fields []string, password func() string) (engine.Provider, bool)
	// Started, if not nil, is called once with the engine, after it is
	// made and before the listeners serve: for a program that calls
	// Engine.Recheck when what its Transform needs changes.
	Started func(eng *engine.Engine)
}

// Main runs p with the command line args and returns the exit status.
func Main(p Program, args []string, stdout, stderr io.Writer) int {
	name := p.Name
	env := strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	token := name + "/" + p.Version
	if p.Load == nil {
		p.Load = config.Load
	}
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cfgPath := fs.String("config", "", "configuration file (default: $"+p.Files.Env+", $CONFIGURATION_DIRECTORY, XDG config dir, "+p.Files.Default+")")
	showVersion := fs.Bool("version", false, "print the version and exit")
	detect := fs.String("detect", "", "print the servers autodetect finds for an email address and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, name, p.Version)
		return 0
	}
	if fs.NArg() > 0 {
		fs.Usage()
		return 2
	}
	if *detect != "" {
		return runDetect(name, token, *detect, stdout, stderr)
	}

	path, how := config.Locate(*cfgPath, p.Files)
	bc, err := p.Load(path)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return 1
	}
	log, closeLog := openLog(name, bc.Log, stderr)
	defer closeLog()
	if path == "" {
		log.Info("no config file, using defaults")
	} else {
		log.Info("config loaded", "path", path, "found_by", how)
	}

	if bc.InsecurePlaintext {
		log.Warn("insecure_plaintext is set: connections configured with tls: none carry passwords and mail in plaintext")
	}

	var hooks Hooks
	if p.Hooks != nil {
		if hooks, err = p.Hooks(log); err != nil {
			log.Error("configuration error", "err", err)
			return 1
		}
	}
	if hooks.NewProvider == nil {
		for _, a := range bc.Accounts {
			if a.Provider != "" {
				log.Error("configuration error", "err", fmt.Errorf("config: %s names provider %q, which %s does not have", a.Match, a.Provider, name))
				return 1
			}
		}
	}

	var reloader *certs.Reloader
	if bc.TLS.CertFile != "" {
		reloader = &certs.Reloader{CertFile: bc.TLS.CertFile, KeyFile: bc.TLS.KeyFile}
		if err := reloader.Load(); err != nil {
			log.Error("tls", "err", err)
			return 1
		}
	}
	// source is where connections to u leave from: its own source, or
	// upstream_source for a server autodetect found.
	source := func(u config.Upstream) []string {
		if len(u.Source) > 0 {
			return u.Source
		}
		return bc.UpstreamSource
	}
	maxConns := func(u config.Upstream) int {
		if u.MaxConnections != 0 {
			return u.MaxConnections
		}
		return bc.UpstreamMaxConnections
	}
	// route picks the provider for a login: the matching account, or else
	// the servers autodetect finds for its domain.
	var detector *autodetect.Detector
	if *bc.Autodetect {
		// Lookups leave from the first source.
		var first string
		if len(bc.UpstreamSource) > 0 {
			first = bc.UpstreamSource[0]
		}
		detector = autodetect.New(log, token, first)
		detector.JMAP = bc.AutodetectJMAP != "off"
		detector.ActiveSync = bc.AutodetectActiveSync != "off"
	}
	route := func(service, login string) (config.Upstream, bool) {
		u, match, ok := bc.Route(service, login)
		if match != "" || detector == nil {
			return u, ok
		}
		r, err := detector.Lookup(login)
		if err != nil {
			log.Info("autodetect failed", "user", login, "err", err)
			return config.Upstream{}, false
		}
		f := r.IMAP
		if service == "smtp" {
			f = r.SMTP
		}
		return f.Upstream, f.Upstream.Upstream != ""
	}

	// mailRoute returns where a login's mail comes from: "provider",
	// "jmap", "activesync" or "imap", and the server (the provider's name
	// for "provider"). An account's own entry
	// says it. For other logins, autodetect_jmap and autodetect_activesync
	// pick among the servers found: a JMAP server they prefer, then an
	// ActiveSync server they prefer, then IMAP, then JMAP, then
	// ActiveSync.
	mailRoute := func(login string) (string, config.Upstream, bool) {
		if _, match, _ := bc.Route("imap", login); match != "" {
			if u, _, ok := bc.Route("provider", login); ok {
				return "provider", u, true
			}
			if u, _, ok := bc.Route("jmap", login); ok {
				return "jmap", u, true
			}
			if u, _, ok := bc.Route("activesync", login); ok {
				return "activesync", u, true
			}
			u, _, ok := bc.Route("imap", login)
			return "imap", u, ok
		}
		if detector == nil {
			return "", config.Upstream{}, false
		}
		r, err := detector.Lookup(login)
		if err != nil {
			log.Info("autodetect failed", "user", login, "err", err)
			return "", config.Upstream{}, false
		}
		jmapU := config.Upstream{Upstream: r.JMAP.Upstream.Upstream, Auth: "basic"}
		easU := config.Upstream{Upstream: r.ActiveSync.Upstream.Upstream}
		hasJMAP := jmapU.Upstream != "" && bc.AutodetectJMAP != "off"
		hasEAS := easU.Upstream != "" && bc.AutodetectActiveSync != "off"
		switch {
		case hasJMAP && bc.AutodetectJMAP == "prefer":
			return "jmap", jmapU, true
		case hasEAS && bc.AutodetectActiveSync == "prefer":
			return "activesync", easU, true
		case r.IMAP.Upstream.Upstream != "":
			return "imap", r.IMAP.Upstream, true
		case hasJMAP:
			return "jmap", jmapU, true
		case hasEAS:
			return "activesync", easU, true
		}
		return "", config.Upstream{}, false
	}

	// tlsFor returns the listener TLS configuration, nil for tls: none.
	tlsFor := func(s config.Service) (*tls.Config, bool) {
		if s.TLS == config.TLSNone {
			return nil, false
		}
		return reloader.Config(), s.TLS == config.TLSImplicit
	}

	// listen listens on every address of a service.
	listen := func(addrs config.Addrs) (net.Listener, error) {
		var ls []net.Listener
		for _, a := range addrs {
			l, err := netbind.Listen(context.Background(), a)
			if err != nil {
				for _, l := range ls {
					l.Close()
				}
				return nil, err
			}
			ls = append(ls, l)
		}
		return netbind.Multi(ls), nil
	}

	type service struct {
		name  string
		l     net.Listener
		serve func(net.Listener) error
		close func() error
	}
	var services []service
	defer func() {
		for _, s := range services {
			s.l.Close()
		}
	}()

	// The engine keeps each account's local copy, for every listener.
	var store *engine.Store
	if bc.CacheDir != "" {
		// Mailbox state (folders, UIDs, flags, message list headers),
		// one database per account, so clients are served at once
		// after a restart.
		if store, err = engine.OpenStore(bc.CacheDir); err != nil {
			log.Error("mailbox state", "err", err)
			return 1
		}
		defer store.Close()
	}
	minPercent, minBytes, _ := config.ParseMinFree(bc.CacheMinFree) // checked by Load
	cache := &engine.Cache{Dir: bc.CacheDir, MaxBytes: bc.CacheMemoryBytes,
		MinFreePercent: minPercent, MinFreeBytes: minBytes, Log: log}
	defer cache.Close()
	if bc.CacheDir != "" {
		why := "cache_compression: " + bc.CacheCompression
		switch bc.CacheCompression {
		case "off":
			cache.Plain = true
		case "auto":
			var fs bool
			if fs, why = fscompress.Compresses(bc.CacheDir); fs {
				cache.Plain = true
			} else {
				why = "the file system does not compress"
			}
		}
		log.Info("cache compression", "zstd", !cache.Plain, "reason", why)
	}
	// The Store's age before any account opens: a backfill must not
	// count reads older than cache_max_age. No database is open yet.
	if _, err := store.Prune(bc.CacheMaxAge); err != nil {
		log.Warn("header prune", "err", err)
	}
	cache.Reads = store
	go pruneCache(cache, store, bc.CacheMaxAge, log)
	eng := &engine.Engine{
		Store: store,
		Route: func(login string) (engine.Upstream, bool) {
			kind, u, ok := mailRoute(login)
			switch kind {
			case "provider":
				return engine.Upstream{Provider: u.Upstream, Timeout: bc.IMAP.Timeout}, ok
			case "jmap":
				return engine.Upstream{URL: u.Upstream, Bearer: u.Auth == "bearer", Sources: source(u), MaxConns: maxConns(u), Timeout: bc.IMAP.Timeout}, ok
			case "activesync":
				return engine.Upstream{ActiveSync: u.Upstream, Sources: source(u), MaxConns: maxConns(u), Timeout: bc.IMAP.Timeout}, ok
			}
			return engine.Upstream{Addr: u.Upstream, TLS: u.UpstreamTLS, Sources: source(u), MaxConns: maxConns(u), Timeout: bc.IMAP.Timeout}, ok
		},
		Authentication: authMode(bc.Authentication),
		Timeout:        bc.IMAP.Timeout,
		Transform:      hooks.Transform,
		NewProvider:    hooks.NewProvider,
		Authorize:      hooks.Authorize,
		Cache:          cache,
		Backfill:       *bc.Backfill,
		Name:           name,
		Version:        p.Version,
		Log:            log,
	}
	defer eng.Close()
	eng.Preload()
	if hooks.Started != nil {
		hooks.Started(eng)
	}

	if s := bc.IMAP; len(s.Listen) > 0 {
		tlsCfg, implicit := tlsFor(s)
		b := &imapproxy.Server{
			Engine:          eng,
			TLSConfig:       tlsCfg,
			ImplicitTLS:     implicit,
			Trace:           os.Getenv(env+"_TRACE") != "",
			MaxMessageBytes: s.MaxMessageBytes,
			Log:             log,
		}
		l, err := listen(s.Listen)
		if err != nil {
			log.Error("imap listen", "err", err)
			return 1
		}
		services = append(services, service{"imap", l, b.Serve, b.Close})
		log.Info("imap listening", "addr", s.Listen, "tls", s.TLS, "cache_dir", bc.CacheDir)
	}
	// The SMTP side also sends for JMAP clients (EmailSubmission) and
	// ActiveSync devices (SendMail), through the same Filter, whether or
	// not it listens.
	smtpSrv := &smtpproxy.Server{
		Route: func(login string) (smtpproxy.Upstream, bool) {
			u, ok := route("smtp", login)
			if !ok {
				// A JMAP, ActiveSync or hook provider without a
				// submission server sends through the provider.
				if kind, _, ok := mailRoute(login); ok && kind != "imap" {
					return smtpproxy.Upstream{Provider: providerSender{eng}, Timeout: bc.SMTP.Timeout}, true
				}
			}
			return smtpproxy.Upstream{Addr: u.Upstream, TLS: u.UpstreamTLS, Sources: source(u), Helo: bc.SMTP.Hostname, Timeout: bc.SMTP.Timeout}, ok
		},
		Filter:          hooks.Filter,
		Domain:          bc.SMTP.Hostname,
		MaxMessageBytes: bc.SMTP.MaxMessageBytes,
		Log:             log,
	}
	if s := bc.JMAP; len(s.Listen) > 0 {
		tlsCfg, _ := tlsFor(s)
		b := &jmapproxy.Server{
			Engine:          eng,
			TLSConfig:       tlsCfg,
			MaxMessageBytes: s.MaxMessageBytes,
			Submit:          smtpSrv.Submit,
			Log:             log,
			PushSubject:     s.PushContact,
		}
		l, err := listen(s.Listen)
		if err != nil {
			log.Error("jmap listen", "err", err)
			return 1
		}
		services = append(services, service{"jmap", l, b.Serve, b.Close})
		log.Info("jmap listening", "addr", s.Listen, "tls", s.TLS)
	}
	if s := bc.ActiveSync; len(s.Listen) > 0 {
		tlsCfg, _ := tlsFor(s)
		b := &easproxy.Server{
			Engine:          eng,
			TLSConfig:       tlsCfg,
			MaxMessageBytes: s.MaxMessageBytes,
			Submit:          smtpSrv.Submit,
			Log:             log,
		}
		l, err := listen(s.Listen)
		if err != nil {
			log.Error("activesync listen", "err", err)
			return 1
		}
		services = append(services, service{"activesync", l, b.Serve, b.Close})
		log.Info("activesync listening", "addr", s.Listen, "tls", s.TLS)
	}
	if s := bc.SMTP; len(s.Listen) > 0 {
		smtpSrv.TLSConfig, smtpSrv.ImplicitTLS = tlsFor(s)
		l, err := listen(s.Listen)
		if err != nil {
			log.Error("smtp listen", "err", err)
			return 1
		}
		services = append(services, service{"smtp", l, smtpSrv.Serve, smtpSrv.Close})
		log.Info("smtp listening", "addr", s.Listen, "tls", s.TLS)
	}
	for _, a := range bc.Accounts {
		log.Info("account", "match", a.Match, "imap", a.IMAP.Upstream, "smtp", a.SMTP.Upstream, "jmap", a.JMAP.Upstream,
			"activesync", a.ActiveSync.Upstream)
	}
	log.Info("autodetect for other logins", "enabled", *bc.Autodetect)
	log.Info("sender authentication", "mode", bc.Authentication)
	if addr := os.Getenv(env + "_PPROF"); addr != "" {
		servePprof(env+"_PPROF", addr, log)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	load.Start(ctx, log)
	if h := netbind.FastOpenHint(); h != "" {
		log.Info("tcp fast open", "hint", h)
	}
	errc := make(chan error, len(services))
	for _, s := range services {
		go func() { errc <- fmt.Errorf("%s: %w", s.name, s.serve(s.l)) }()
	}

	select {
	case err := <-errc:
		log.Error("listener stopped", "err", err)
		return 1
	case <-ctx.Done():
		log.Info("shutting down")
	}
	// Together: each says goodbye to its clients and waits a little for
	// requests in progress.
	errs := make([]error, len(services))
	var wg sync.WaitGroup
	for i, s := range services {
		wg.Go(func() { errs[i] = s.close() })
	}
	wg.Wait()
	if err := errors.Join(errs...); err != nil {
		log.Warn("shutdown", "err", err)
	}
	return 0
}

// runDetect prints what autodetect finds for an address.
func runDetect(name, userAgent, address string, stdout, stderr io.Writer) int {
	d := autodetect.New(slog.New(slog.NewTextHandler(stderr, nil)), userAgent, "")
	d.JMAP = true
	d.ActiveSync = true
	r, err := d.Lookup(address)
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", name, err)
		return 1
	}
	for _, s := range []struct {
		name string
		f    autodetect.Found
	}{{"imap", r.IMAP}, {"smtp", r.SMTP}} {
		if s.f.Upstream.Upstream == "" {
			fmt.Fprintf(stdout, "%s: not found\n", s.name)
			continue
		}
		fmt.Fprintf(stdout, "%s: %s (%s), from %s\n", s.name, s.f.Upstream.Upstream, s.f.UpstreamTLS, s.f.From)
	}
	for _, s := range []struct {
		name string
		f    autodetect.Found
	}{{"jmap", r.JMAP}, {"activesync", r.ActiveSync}} {
		if s.f.Upstream.Upstream == "" {
			fmt.Fprintf(stdout, "%s: not found\n", s.name)
			continue
		}
		fmt.Fprintf(stdout, "%s: %s, from %s\n", s.name, s.f.Upstream.Upstream, s.f.From)
	}
	return 0
}

// openLog opens the log destination: "stderr", "syslog", "none" or a file.
func openLog(name, target string, stderr io.Writer) (*slog.Logger, func()) {
	var w io.Writer
	closer := func() {}
	switch target {
	case "none":
		w = io.Discard
	case "stderr", "":
		w = stderr
	case "syslog":
		sw, err := syslog.New(syslog.LOG_MAIL|syslog.LOG_INFO, name)
		if err != nil {
			w = stderr
			break
		}
		w, closer = sw, func() { sw.Close() }
	default:
		f, err := os.OpenFile(target, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640)
		if err != nil {
			w = stderr
			break
		}
		w, closer = f, func() { f.Close() }
	}
	return slog.New(slog.NewTextHandler(w, nil)), closer
}

// pruneCache deletes cached messages and header entries unread for
// maxAge, at start and then every six hours.
func pruneCache(c *engine.Cache, s *engine.Store, maxAge time.Duration, log *slog.Logger) {
	for {
		if n, err := c.Prune(maxAge); err != nil {
			log.Warn("cache prune", "err", err)
		} else if n > 0 {
			log.Info("cache pruned", "deleted", n, "unread_for", maxAge)
		}
		if n, err := c.Trim(); err != nil {
			log.Warn("cache trim", "err", err)
		} else if n > 0 {
			log.Info("cache: disk nearly full, least recently read messages deleted", "deleted", n)
		}
		if n, err := s.Prune(maxAge); err != nil {
			log.Warn("header prune", "err", err)
		} else if n > 0 {
			log.Info("header entries pruned", "deleted", n, "unread_for", maxAge)
		}
		time.Sleep(6 * time.Hour)
	}
}

// servePprof serves Go's profiles (net/http/pprof) on addr, for debugging
// performance. It accepts loopback addresses only: profiles show what the
// proxy is doing, and memory profiles can hold message data.
func servePprof(envName, addr string, log *slog.Logger) {
	host, _, err := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	if err != nil || (host != "localhost" && (ip == nil || !ip.IsLoopback())) {
		log.Error("pprof: "+envName+" must be a loopback address with a port, such as 127.0.0.1:6060", "addr", addr)
		return
	}
	go func() {
		log.Info("pprof listening", "addr", addr)
		if err := http.ListenAndServe(addr, nil); err != nil {
			log.Error("pprof", "err", err)
		}
	}()
}

// providerSender sends SMTP clients' mail through a JMAP, ActiveSync or
// hook provider. A provider that cannot send refuses the mail.
type providerSender struct{ eng *engine.Engine }

func (j providerSender) Verify(login, password string) error {
	err := j.eng.Account(login).Login(password)
	if errors.Is(err, engine.ErrLoginRejected) || errors.Is(err, engine.ErrNoAccount) {
		return fmt.Errorf("%w: %w", smtpproxy.ErrLoginRejected, err)
	}
	return err
}

func (j providerSender) Send(ctx context.Context, login, _ string, env *smtpproxy.Envelope) error {
	err := j.eng.Account(login).Send(ctx, env.From, env.To, env.Data)
	if errors.Is(err, engine.ErrSendRefused) || errors.Is(err, engine.ErrNoSending) {
		return &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: err.Error()}
	}
	return err
}

func authMode(s string) engine.AuthMode {
	if s == "off" {
		return ""
	}
	return engine.AuthMode(s)
}
