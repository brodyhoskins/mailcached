// Package config loads mailcached.yaml: the listeners, upstream servers,
// cache and TLS certificate. A program built on mailcached can add its own
// settings to the same file (see Decode).
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// DefaultPath is mailcached's system-wide config file. Packagers can change
// it at build time, e.g. for FreeBSD:
//
//	go build -ldflags "-X github.com/brodyhoskins/mailcached/config.DefaultPath=/usr/local/etc/mailcached/mailcached.yaml"
var DefaultPath = "/etc/mailcached/mailcached.yaml"

// Files says where a program looks for its config file.
type Files struct {
	Env     string // environment variable with the path, e.g. MAILCACHED_CONFIG
	Name    string // file name in $CONFIGURATION_DIRECTORY, e.g. mailcached.yaml
	XDG     string // path under the XDG config directory, e.g. mailcached/mailcached.yaml
	Default string // system-wide path
}

// Mailcached is where mailcached itself looks.
func Mailcached() Files {
	return Files{Env: "MAILCACHED_CONFIG", Name: "mailcached.yaml", XDG: "mailcached/mailcached.yaml", Default: DefaultPath}
}

// TLS modes, for listeners and upstream connections.
const (
	TLSImplicit = "implicit"
	TLSStartTLS = "starttls"
	TLSNone     = "none"
)

// Locate finds the config file: the -config flag, the environment variable
// f.Env, systemd's $CONFIGURATION_DIRECTORY, the XDG config directory (not
// as root), then f.Default. It returns "" if no file is found; how says
// which rule matched.
func Locate(flag string, f Files) (path, how string) {
	if flag != "" {
		return flag, "-config"
	}
	if p := os.Getenv(f.Env); p != "" {
		return p, "$" + f.Env
	}
	exists := func(p string) bool { _, err := os.Stat(p); return err == nil }
	if d, _, _ := strings.Cut(os.Getenv("CONFIGURATION_DIRECTORY"), ":"); d != "" {
		if p := filepath.Join(d, f.Name); exists(p) {
			return p, "$CONFIGURATION_DIRECTORY"
		}
	}
	if os.Geteuid() != 0 {
		dir := os.Getenv("XDG_CONFIG_HOME")
		if dir == "" {
			if home, err := os.UserHomeDir(); err == nil {
				dir = filepath.Join(home, ".config")
			}
		}
		if dir != "" {
			if p := filepath.Join(dir, f.XDG); exists(p) {
				return p, "XDG config directory"
			}
		}
	}
	if exists(f.Default) {
		return f.Default, "default"
	}
	return "", "none"
}

type Config struct {
	// CacheDir holds the messages clients read, so each is downloaded
	// once. Empty keeps them in memory only. Defaults to systemd's
	// $CACHE_DIRECTORY.
	CacheDir string `yaml:"cache_dir"`
	// CacheMemoryBytes bounds the in-memory cache. Default 64 MiB.
	CacheMemoryBytes int64 `yaml:"cache_memory_bytes"`
	// CacheMaxAge deletes cached messages no client has read for this
	// long. Default 90 days (2160h).
	CacheMaxAge time.Duration `yaml:"cache_max_age"`
	// CacheCompression is auto (default), zstd or off. auto writes
	// uncompressed copies on a file system that compresses them (Btrfs
	// with compression, zram) and Zstandard ones elsewhere.
	CacheCompression string `yaml:"cache_compression"`
	// CacheMinFree is the free space the cache leaves on its file system:
	// a percentage ("5%") or a size ("2GiB", "500MB"). Below it, cached
	// messages are deleted, least recently read first. Default 5%; "0"
	// turns it off.
	CacheMinFree string `yaml:"cache_min_free"`
	// Log is "stderr", "syslog", "none" or a file path. Default stderr.
	Log string    `yaml:"log"`
	TLS TLSConfig `yaml:"tls"`
	// InsecurePlaintext allows tls: none and upstream_tls: none. Without
	// it, every connection uses TLS, and the proxy never falls back to
	// plaintext. Passwords and mail then cross the network unprotected.
	InsecurePlaintext bool `yaml:"insecure_plaintext"`

	// ListenAddresses are where a service listens when its listen gives
	// only a port (":993"): IP addresses, host names or interface names
	// (eth0, wg0). Empty: every address.
	ListenAddresses []string `yaml:"listen_addresses"`
	// UpstreamSource is where connections to providers leave from, for
	// an upstream without its own source: an interface name or an IP
	// address. Empty: wherever routing says.
	UpstreamSource string `yaml:"upstream_source"`

	IMAP Service `yaml:"imap"`
	SMTP Service `yaml:"smtp"`
	// JMAP serves JMAP clients over HTTPS (or HTTP with tls: none). Its
	// tls is implicit or none.
	JMAP Service `yaml:"jmap"`
	// ActiveSync serves Exchange ActiveSync devices (the iPhone's Mail
	// app, among others) over HTTPS (or HTTP with tls: none), with push.
	// It answers Autodiscover too. Its tls is implicit or none.
	ActiveSync Service `yaml:"activesync"`

	// Accounts says which provider each login goes to. A login that
	// matches no account goes to the servers autodetect finds.
	Accounts []Account `yaml:"accounts"`
	// Autodetect finds the servers for a login that matches no account,
	// from its domain (autoconfig, DNS SRV, Mozilla's ISP database,
	// Exchange Autodiscover). Default true. With false, such a login is
	// rejected without contacting anyone, and accounts is required.
	Autodetect *bool `yaml:"autodetect"`
	// AutodetectJMAP decides when autodetect uses a JMAP server it finds:
	// fallback (default) when it finds no IMAP server, prefer whenever it
	// finds one, off never. A provider that wants an API token for JMAP
	// (Fastmail) needs an account entry with auth: bearer instead.
	AutodetectJMAP string `yaml:"autodetect_jmap"`
	// AutodetectActiveSync decides when autodetect uses an Exchange
	// ActiveSync server it finds, as autodetect_jmap does for JMAP:
	// fallback (default) when it finds no IMAP or JMAP server, prefer
	// over an IMAP server, off never. JMAP wins over ActiveSync.
	AutodetectActiveSync string `yaml:"autodetect_activesync"`
	// Backfill fills every folder's message list in the background after
	// a login: header entries for unchanged mail, whole copies of mail a
	// transform changes. Default true. It needs cache_dir.
	Backfill *bool `yaml:"backfill"`
}

// TLSConfig is the certificate clients see. It is reloaded when the files
// change, so renewals need no restart.
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Service is one protocol, where clients connect.
type Service struct {
	// Listen is one host:port or a list of them. The host is an IP
	// address, a host name or an interface name (eth0:993, which accepts
	// on that interface only); empty means listen_addresses. No listen
	// disables the service.
	Listen Addrs `yaml:"listen"`
	// TLS is implicit (default) or starttls. none needs insecure_plaintext.
	TLS string `yaml:"tls"`
	// Hostname is the SMTP greeting name and EHLO name. Default: the host name.
	Hostname string        `yaml:"hostname"`
	Timeout  time.Duration `yaml:"timeout"` // upstream dial and command timeout; default 1m
	// MaxMessageBytes limits SMTP DATA and IMAP APPEND. Default 50 MiB.
	MaxMessageBytes int64 `yaml:"max_message_bytes"`
	// PushContact (JMAP only) is the contact that push services see on
	// PushSubscription pushes: a mailto: or https: URL.
	PushContact string `yaml:"push_contact"`
}

// Account sends the logins that match it to one provider.
type Account struct {
	// Match is a full address (alice@example.com) or a domain
	// (@example.com), compared with the login name without regard to case.
	// An address match wins over a domain match.
	Match string   `yaml:"match"`
	IMAP  Upstream `yaml:"imap"`
	SMTP  Upstream `yaml:"smtp"`
	// JMAP is a JMAP provider: upstream is its session URL, such as
	// https://api.fastmail.com/jmap/session. With it, the account's mail
	// comes from JMAP and imap is not used. Without smtp, mail clients
	// send through JMAP too.
	JMAP Upstream `yaml:"jmap"`
	// ActiveSync is an Exchange ActiveSync provider: upstream is its
	// URL, such as https://mail.example.com/Microsoft-Server-ActiveSync
	// (the path is added if left out). With it, the account's mail comes
	// from ActiveSync and imap is not used. Without smtp, mail clients
	// send through ActiveSync too, and the provider keeps the Sent copy.
	ActiveSync Upstream `yaml:"activesync"`
}

// Upstream is a provider server.
type Upstream struct {
	// Upstream is host:port. Empty: this account cannot use the service.
	Upstream string `yaml:"upstream"`
	// UpstreamTLS is implicit (default) or starttls. none needs
	// insecure_plaintext. With starttls, a server that does not offer
	// STARTTLS is an error, never a plaintext session. Not for jmap, whose
	// URL says it.
	UpstreamTLS string `yaml:"upstream_tls"`
	// Source is where connections to this server leave from: an
	// interface name (wg0, eth1) or a local IP address. Default:
	// upstream_source.
	Source string `yaml:"source"`
	// Auth is how a JMAP provider gets the client's password: basic
	// (default), or bearer for a provider that wants an API token
	// (Fastmail), which clients then give as their password.
	Auth string `yaml:"auth"`
}

// Addrs is a list of addresses that YAML may give as one string.
type Addrs []string

func (a *Addrs) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*a = nil
		if n.Value != "" {
			*a = Addrs{n.Value}
		}
		return nil
	}
	var l []string
	if err := n.Decode(&l); err != nil {
		return err
	}
	*a = l
	return nil
}

// Route returns the provider server for a login on service ("imap",
// "smtp", "jmap" or "activesync"). ok is false when no account matches or the matching account
// has no server for the service. match is "" when no account matches.
func (c *Config) Route(service, login string) (u Upstream, match string, ok bool) {
	login = strings.ToLower(strings.TrimSpace(login))
	_, domain, found := strings.Cut(login, "@")
	if !found {
		return Upstream{}, "", false
	}
	var acct *Account
	for i := range c.Accounts {
		a := &c.Accounts[i]
		if a.Match == login {
			acct = a
			break
		}
		if acct == nil && a.Match == "@"+domain {
			acct = a
		}
	}
	if acct == nil {
		return Upstream{}, "", false
	}
	switch service {
	case "smtp":
		u = acct.SMTP
	case "jmap":
		u = acct.JMAP
	case "activesync":
		u = acct.ActiveSync
	default:
		u = acct.IMAP
	}
	return u, acct.Match, u.Upstream != ""
}

// Load reads path (empty for none) and applies defaults.
func Load(path string) (*Config, error) {
	var c Config
	if err := Decode(path, &c); err != nil {
		return nil, err
	}
	if err := c.Finish(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Decode reads the YAML file at path (empty for none) into v, rejecting
// unknown settings. A program with settings of its own decodes into a
// struct that embeds Config with `yaml:",inline"`, then calls Finish.
func Decode(path string, v any) error {
	if path == "" {
		return nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("config: %w", err)
	}
	return nil
}

// Finish expands paths, applies defaults and checks the settings.
func (c *Config) Finish() error {
	if err := ExpandPaths(&c.CacheDir, &c.Log, &c.TLS.CertFile, &c.TLS.KeyFile); err != nil {
		return err
	}
	c.applyDefaults()
	return c.validate()
}

// ExpandPaths expands ${VAR} in path settings. An unset variable is an
// error.
func ExpandPaths(paths ...*string) error {
	var missing []string
	for _, p := range paths {
		*p = os.Expand(*p, func(name string) string {
			v, ok := os.LookupEnv(name)
			if !ok {
				missing = append(missing, name)
			}
			return v
		})
	}
	if len(missing) > 0 {
		return fmt.Errorf("config: environment variable(s) not set: %s", strings.Join(slices.Compact(missing), ", "))
	}
	return nil
}

func (c *Config) applyDefaults() {
	if c.CacheDir == "" {
		c.CacheDir, _, _ = strings.Cut(os.Getenv("CACHE_DIRECTORY"), ":")
	}
	if c.CacheMemoryBytes == 0 {
		c.CacheMemoryBytes = 64 << 20
	}
	if c.CacheMaxAge == 0 {
		c.CacheMaxAge = 90 * 24 * time.Hour
	}
	if c.Autodetect == nil {
		t := true
		c.Autodetect = &t
	}
	if c.AutodetectJMAP == "" {
		c.AutodetectJMAP = "fallback"
	}
	if c.AutodetectActiveSync == "" {
		c.AutodetectActiveSync = "fallback"
	}
	if c.CacheMinFree == "" {
		c.CacheMinFree = "5%"
	}
	if c.CacheCompression == "" {
		c.CacheCompression = "auto"
	}
	if c.Backfill == nil {
		t := true
		c.Backfill = &t
	}
	if c.Log == "" {
		c.Log = "stderr"
	}
	host, _ := os.Hostname()
	for _, s := range []*Service{&c.IMAP, &c.SMTP, &c.JMAP, &c.ActiveSync} {
		s.Listen = c.expandListen(s.Listen)
		if s.TLS == "" {
			s.TLS = TLSImplicit
		}
		if s.Hostname == "" {
			s.Hostname = host
		}
		if s.Timeout == 0 {
			s.Timeout = time.Minute
		}
		if s.MaxMessageBytes == 0 {
			s.MaxMessageBytes = 50 << 20
		}
	}
	for i := range c.Accounts {
		a := &c.Accounts[i]
		a.Match = strings.ToLower(strings.TrimSpace(a.Match))
		for _, u := range []*Upstream{&a.IMAP, &a.SMTP} {
			if u.UpstreamTLS == "" {
				u.UpstreamTLS = TLSImplicit
			}
		}
		for _, u := range []*Upstream{&a.IMAP, &a.SMTP, &a.JMAP, &a.ActiveSync} {
			if u.Source == "" {
				u.Source = c.UpstreamSource
			}
		}
		if a.JMAP.Upstream != "" && a.JMAP.Auth == "" {
			a.JMAP.Auth = "basic"
		}
		if u, err := url.Parse(a.ActiveSync.Upstream); err == nil && u.Host != "" && (u.Path == "" || u.Path == "/") {
			u.Path = "/Microsoft-Server-ActiveSync"
			a.ActiveSync.Upstream = u.String()
		}
	}
}

// expandListen puts listen_addresses in each entry that gives only a port.
func (c *Config) expandListen(l Addrs) Addrs {
	if len(c.ListenAddresses) == 0 {
		return l
	}
	var out Addrs
	for _, a := range l {
		host, port, err := net.SplitHostPort(a)
		if err != nil || host != "" {
			out = append(out, a)
			continue
		}
		for _, h := range c.ListenAddresses {
			out = append(out, net.JoinHostPort(h, port))
		}
	}
	return out
}

func (c *Config) validate() error {
	if _, _, err := ParseMinFree(c.CacheMinFree); err != nil {
		return fmt.Errorf("config: cache_min_free: %w", err)
	}
	switch c.AutodetectJMAP {
	case "fallback", "prefer", "off":
	default:
		return fmt.Errorf("config: autodetect_jmap %q: want fallback, prefer or off", c.AutodetectJMAP)
	}
	switch c.AutodetectActiveSync {
	case "fallback", "prefer", "off":
	default:
		return fmt.Errorf("config: autodetect_activesync %q: want fallback, prefer or off", c.AutodetectActiveSync)
	}
	switch c.CacheCompression {
	case "auto", "zstd", "off":
	default:
		return fmt.Errorf("config: cache_compression %q: want auto, zstd or off", c.CacheCompression)
	}
	for _, h := range c.ListenAddresses {
		if h == "" || strings.ContainsAny(h, " /") || strings.Count(h, ":") == 1 {
			return fmt.Errorf("config: listen_addresses: %q: want an IP address, a host name or an interface name, without a port", h)
		}
	}
	if err := checkSource("upstream_source", c.UpstreamSource); err != nil {
		return err
	}
	if len(c.IMAP.Listen) == 0 && len(c.SMTP.Listen) == 0 && len(c.JMAP.Listen) == 0 && len(c.ActiveSync.Listen) == 0 {
		return fmt.Errorf("config: none of imap.listen, smtp.listen, jmap.listen and activesync.listen is set")
	}
	if pc := c.JMAP.PushContact; pc != "" && !strings.HasPrefix(pc, "mailto:") && !strings.HasPrefix(pc, "https://") {
		return fmt.Errorf("config: jmap.push_contact %q: want a mailto: or https: URL", pc)
	}
	if len(c.JMAP.Listen) > 0 && c.JMAP.TLS == TLSStartTLS {
		return fmt.Errorf("config: jmap.tls must be implicit or none: HTTP has no STARTTLS")
	}
	if len(c.ActiveSync.Listen) > 0 && c.ActiveSync.TLS == TLSStartTLS {
		return fmt.Errorf("config: activesync.tls must be implicit or none: HTTP has no STARTTLS")
	}
	needCert := false
	for _, s := range []struct {
		name string
		*Service
	}{{"imap", &c.IMAP}, {"smtp", &c.SMTP}, {"jmap", &c.JMAP}, {"activesync", &c.ActiveSync}} {
		if len(s.Listen) == 0 {
			continue
		}
		for _, a := range s.Listen {
			if _, _, err := net.SplitHostPort(a); err != nil {
				return fmt.Errorf("config: %s.listen: %w", s.name, err)
			}
		}
		if err := c.checkTLS(s.name+".tls", s.TLS); err != nil {
			return err
		}
		if s.TLS != TLSNone {
			needCert = true
		}
	}
	if needCert && (c.TLS.CertFile == "" || c.TLS.KeyFile == "") {
		return fmt.Errorf("config: tls.cert_file and tls.key_file are required unless every listener uses tls: none")
	}

	if len(c.Accounts) == 0 && !*c.Autodetect {
		return fmt.Errorf("config: accounts is empty and autodetect is off; list each address or domain the proxy serves, with its provider's servers")
	}
	seen := map[string]bool{}
	for i, a := range c.Accounts {
		name := fmt.Sprintf("accounts[%d]", i)
		_, domain, ok := strings.Cut(a.Match, "@")
		if !ok || domain == "" || strings.Contains(domain, "@") || strings.ContainsAny(a.Match, " *") {
			return fmt.Errorf("config: %s.match must be an address (alice@example.com) or a domain (@example.com), got %q", name, a.Match)
		}
		if seen[a.Match] {
			return fmt.Errorf("config: %s.match %q is listed twice", name, a.Match)
		}
		seen[a.Match] = true
		if a.IMAP.Upstream == "" && a.SMTP.Upstream == "" && a.JMAP.Upstream == "" && a.ActiveSync.Upstream == "" {
			return fmt.Errorf("config: %s (%s) has none of imap.upstream, smtp.upstream, jmap.upstream and activesync.upstream", name, a.Match)
		}
		for _, u := range []struct {
			svc string
			*Upstream
		}{{"imap", &a.IMAP}, {"smtp", &a.SMTP}, {"jmap", &a.JMAP}, {"activesync", &a.ActiveSync}} {
			if err := checkSource(name+"."+u.svc+".source", u.Source); err != nil {
				return err
			}
		}
		if a.JMAP.Upstream != "" && a.ActiveSync.Upstream != "" {
			return fmt.Errorf("config: %s (%s) has both jmap and activesync: the mail comes from one provider", name, a.Match)
		}
		if a.ActiveSync.Upstream != "" {
			if err := c.checkActiveSync(name+".activesync", a.ActiveSync); err != nil {
				return err
			}
		}
		if a.JMAP.Upstream != "" {
			if err := c.checkJMAP(name+".jmap", a.JMAP); err != nil {
				return err
			}
		}
		for _, u := range []struct {
			svc string
			*Upstream
		}{{"imap", &a.IMAP}, {"smtp", &a.SMTP}} {
			if u.Auth != "" {
				return fmt.Errorf("config: %s.%s.auth is for jmap only", name, u.svc)
			}
		}
		for _, u := range []struct {
			svc string
			*Upstream
		}{{"imap", &a.IMAP}, {"smtp", &a.SMTP}} {
			if u.Upstream.Upstream == "" {
				continue
			}
			if _, _, err := net.SplitHostPort(u.Upstream.Upstream); err != nil {
				return fmt.Errorf("config: %s.%s.upstream: %w", name, u.svc, err)
			}
			if err := c.checkTLS(name+"."+u.svc+".upstream_tls", u.UpstreamTLS); err != nil {
				return err
			}
		}
	}
	return nil
}

// checkJMAP validates a JMAP provider.
func (c *Config) checkJMAP(key string, u Upstream) error {
	parsed, err := url.Parse(u.Upstream)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return fmt.Errorf("config: %s.upstream must be an https:// URL, got %q", key, u.Upstream)
	}
	if parsed.Scheme == "http" && !c.InsecurePlaintext {
		return fmt.Errorf("config: %s.upstream: http sends passwords and mail in plaintext; set insecure_plaintext: true to allow it", key)
	}
	if u.UpstreamTLS != "" {
		return fmt.Errorf("config: %s.upstream_tls: the URL's scheme says it", key)
	}
	if u.Auth != "basic" && u.Auth != "bearer" {
		return fmt.Errorf("config: %s.auth must be basic or bearer", key)
	}
	return nil
}

// checkActiveSync validates an ActiveSync provider.
func (c *Config) checkActiveSync(key string, u Upstream) error {
	parsed, err := url.Parse(u.Upstream)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return fmt.Errorf("config: %s.upstream must be an https:// URL, got %q", key, u.Upstream)
	}
	if parsed.Scheme == "http" && !c.InsecurePlaintext {
		return fmt.Errorf("config: %s.upstream: http sends passwords and mail in plaintext; set insecure_plaintext: true to allow it", key)
	}
	if u.UpstreamTLS != "" {
		return fmt.Errorf("config: %s.upstream_tls: the URL's scheme says it", key)
	}
	if u.Auth != "" {
		return fmt.Errorf("config: %s.auth is for jmap only", key)
	}
	return nil
}

// checkSource validates a source: an interface name or an IP address.
// An interface need not exist yet: it is looked up at each connection.
func checkSource(key, v string) error {
	if v == "" {
		return nil
	}
	if strings.ContainsAny(v, " /") || (strings.Contains(v, ":") && net.ParseIP(v) == nil) {
		return fmt.Errorf("config: %s %q: want an interface name or an IP address, without a port", key, v)
	}
	return nil
}

// checkTLS validates a TLS mode setting.
func (c *Config) checkTLS(key, v string) error {
	if v != TLSImplicit && v != TLSStartTLS && v != TLSNone {
		return fmt.Errorf("config: %s must be implicit, starttls or none", key)
	}
	if v == TLSNone && !c.InsecurePlaintext {
		return fmt.Errorf("config: %s: none sends passwords and mail in plaintext; set insecure_plaintext: true to allow it", key)
	}
	return nil
}

// ParseMinFree reads cache_min_free: a percentage of the file system
// ("5%"), or a size in bytes with an optional unit ("2GiB", "500MB",
// "1048576"). Units are B, KB, MB, GB, TB (powers of 1000) and KiB, MiB,
// GiB, TiB (powers of 1024).
func ParseMinFree(s string) (percent float64, bytes int64, err error) {
	s = strings.TrimSpace(s)
	if p, ok := strings.CutSuffix(s, "%"); ok {
		percent, err = strconv.ParseFloat(strings.TrimSpace(p), 64)
		if err != nil || percent < 0 || percent >= 100 {
			return 0, 0, fmt.Errorf("%q: want a percentage from 0 to 100", s)
		}
		return percent, 0, nil
	}
	i := strings.IndexFunc(s, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	num, unit := s, ""
	if i >= 0 {
		num, unit = strings.TrimSpace(s[:i]), strings.TrimSpace(s[i:])
	}
	mult := map[string]float64{"": 1, "B": 1,
		"KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12,
		"KIB": 1 << 10, "MIB": 1 << 20, "GIB": 1 << 30, "TIB": 1 << 40}[strings.ToUpper(unit)]
	n, perr := strconv.ParseFloat(num, 64)
	if mult == 0 || perr != nil || n < 0 {
		return 0, 0, fmt.Errorf("%q: want a percentage (5%%) or a size (2GiB)", s)
	}
	return 0, int64(n * mult), nil
}
