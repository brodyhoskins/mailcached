// Package autodetect finds a mail provider's IMAP and SMTP servers, and
// its JMAP server, from an email address, the way mail clients set up an
// account. It asks, for the
// address's domain and then for the domain of its mail exchanger (MX):
//
//  1. the provider's own autoconfig file (autoconfig.<domain>, .well-known),
//  2. DNS SRV records (RFC 6186 and RFC 8314),
//  3. Mozilla's ISP database (autoconfig.thunderbird.net),
//  4. Exchange Autodiscover (POX, without credentials).
//
// A JMAP server is looked for in DNS SRV records (_jmap._tcp) and at
// https://<domain>/.well-known/jmap, for the domain and its MX domain. An
// Exchange ActiveSync server is looked for at /Microsoft-Server-ActiveSync
// on the IMAP server's host, mail.<domain>, the domain itself and
// autodiscover.<domain>.
//
// The first server whose TLS certificate is valid for its name wins. Only
// servers that use TLS (implicit or STARTTLS) are taken: detection never
// yields a plaintext server. No password is sent to any of these sources.
package autodetect

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/publicsuffix"

	"github.com/brodyhoskins/mailcached/config"
	"github.com/brodyhoskins/mailcached/internal/fetch"
	"github.com/brodyhoskins/mailcached/internal/netbind"
)

// ISPDB is Mozilla's database of provider settings.
const ISPDB = "https://autoconfig.thunderbird.net/v1.1/"

// ErrNotFound is returned when no source names a usable server.
var ErrNotFound = errors.New("autodetect: no IMAP, SMTP, JMAP or ActiveSync server found")

// Found is a detected server and the source that named it.
type Found struct {
	config.Upstream
	From string // for example "srv kolabnow.com"
}

// Result holds the servers for a domain. An empty Upstream means none was
// found for that service. JMAP's Upstream is its session URL, and
// ActiveSync's its endpoint URL.
type Result struct {
	IMAP, SMTP, JMAP, ActiveSync Found
}

// Detector looks up servers and remembers the results for each domain.
// The function fields default to the network; tests replace them.
type Detector struct {
	Get       func(ctx context.Context, url string) ([]byte, error)
	Post      func(ctx context.Context, url string, body []byte) ([]byte, error)
	LookupSRV func(ctx context.Context, service, proto, name string) ([]*net.SRV, error)
	LookupMX  func(ctx context.Context, name string) ([]*net.MX, error)
	// Usable reports whether a server of service ("imap" or "smtp")
	// completes a TLS handshake with a certificate valid for its name.
	Usable func(ctx context.Context, service string, u config.Upstream) bool
	// JMAP looks for a JMAP server too; UsableJMAP reports whether a
	// session URL answers as one.
	JMAP       bool
	UsableJMAP func(ctx context.Context, url string) bool
	// ActiveSync looks for an ActiveSync server too; UsableActiveSync
	// reports whether an endpoint URL answers as one.
	ActiveSync       bool
	UsableActiveSync func(ctx context.Context, url string) bool
	// Timeout bounds the questions to the sources, and then the
	// connection tests. Default 20s each.
	Timeout time.Duration
	// TTL is how long a result is kept; FailTTL, a failed detection.
	TTL, FailTTL time.Duration
	Log          *slog.Logger

	mu    sync.Mutex
	cache map[string]*entry
}

type entry struct {
	ready   chan struct{}
	res     Result
	err     error
	expires time.Time
}

// New returns a Detector that uses the network. HTTP goes through
// the fetch client (HTTP/2, zstd or gzip, conditional requests):
// a document fetched before is revalidated with its ETag or
// Last-Modified, and reused on 304 Not Modified.
//
// source is where its connections leave from, as for providers: an
// interface name, an IP address, or empty.
func New(log *slog.Logger, userAgent, source string) *Detector {
	hc := &http.Client{
		Timeout:   10 * time.Second,
		Transport: fetch.NewTransport(netbind.Dialer(source, 10*time.Second, nil).DialContext),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to %s refused: not HTTPS", req.URL)
			}
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			return nil
		},
	}
	client := &fetch.Client{HTTP: hc, MaxBody: 1 << 20, UserAgent: userAgent}
	type doc struct {
		v    fetch.Validators
		body []byte
	}
	var mu sync.Mutex
	docs := map[string]doc{} // by URL, documents with validators
	var r net.Resolver
	return &Detector{
		Get: func(ctx context.Context, u string) ([]byte, error) {
			mu.Lock()
			prev := docs[u]
			mu.Unlock()
			res, err := client.Get(ctx, u, prev.v)
			if err != nil {
				return nil, err
			}
			switch res.Status {
			case http.StatusNotModified:
				return prev.body, nil
			case http.StatusOK:
			default:
				return nil, fmt.Errorf("%s: %d", u, res.Status)
			}
			if !res.NoStore && (res.Validators != fetch.Validators{}) {
				mu.Lock()
				docs[u] = doc{res.Validators, res.Body}
				mu.Unlock()
			}
			return res.Body, nil
		},
		// Autodiscover answers a POST, which fetch does not send; it goes
		// over the same transport.
		Post: func(ctx context.Context, u string, body []byte) ([]byte, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
			if err != nil {
				return nil, err
			}
			req.Header.Set("Content-Type", "text/xml")
			req.Header.Set("User-Agent", userAgent)
			resp, err := hc.Do(req)
			if err != nil {
				return nil, err
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("%s: %s", u, resp.Status)
			}
			return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		},
		LookupSRV: func(ctx context.Context, service, proto, name string) ([]*net.SRV, error) {
			_, srvs, err := r.LookupSRV(ctx, service, proto, name)
			return srvs, err
		},
		LookupMX: r.LookupMX,
		Usable: func(ctx context.Context, service string, u config.Upstream) bool {
			return usable(ctx, source, service, u)
		},
		UsableJMAP: usableJMAP(hc),
		// OPTIONS goes over the same transport; redirects are not
		// followed, as an ActiveSync client does not follow them.
		UsableActiveSync: usableActiveSync(&http.Client{Timeout: 10 * time.Second, Transport: hc.Transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}),
		Log: log,
	}
}

// Lookup returns the servers for address. Results are kept per domain, and
// concurrent lookups for one domain share one detection.
func (d *Detector) Lookup(address string) (Result, error) {
	address = strings.ToLower(strings.TrimSpace(address))
	local, domain, ok := strings.Cut(address, "@")
	if !ok || local == "" || domain == "" || strings.ContainsAny(domain, "@/ ") {
		return Result{}, fmt.Errorf("autodetect: %q is not an email address", address)
	}
	d.mu.Lock()
	if d.cache == nil {
		d.cache = map[string]*entry{}
	}
	e := d.cache[domain]
	if e != nil {
		select {
		case <-e.ready:
			if time.Now().After(e.expires) {
				e = nil
			}
		default: // another lookup is detecting it
		}
	}
	if e == nil {
		e = &entry{ready: make(chan struct{})}
		d.cache[domain] = e
		d.mu.Unlock()
		e.res, e.err = d.detect(address, domain)
		ttl := cmp(d.TTL, 6*time.Hour)
		if e.err != nil {
			ttl = cmp(d.FailTTL, 10*time.Minute)
		}
		e.expires = time.Now().Add(ttl)
		close(e.ready)
	} else {
		d.mu.Unlock()
		<-e.ready
	}
	return e.res, e.err
}

func cmp(v, def time.Duration) time.Duration {
	if v == 0 {
		return def
	}
	return v
}

// candidate is a server one source named.
type candidate struct {
	u    config.Upstream
	from string
}

// source finds candidates for the email address in domain dom.
type source func(ctx context.Context, address, dom string) (imap, smtp []candidate)

func (d *Detector) detect(address, domain string) (Result, error) {
	timeout := cmp(d.Timeout, 20*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	domains := []string{domain}
	if mx := d.mxDomain(ctx, domain); mx != "" && mx != domain {
		domains = append(domains, mx)
	}
	sources := []source{d.autoconfig, d.srv, d.ispdb, d.autodiscover}

	// Every source for every domain is asked at once. The answers are
	// then taken in order of trust.
	type answer struct{ imap, smtp []candidate }
	answers := make([]answer, len(domains)*len(sources))
	var wg sync.WaitGroup
	for i, dom := range domains {
		for j, s := range sources {
			wg.Go(func() {
				a := &answers[i*len(sources)+j]
				a.imap, a.smtp = s(ctx, address, dom)
			})
		}
	}
	wg.Wait()
	var imaps, smtps []candidate
	for _, a := range answers {
		imaps = append(imaps, a.imap...)
		smtps = append(smtps, a.smtp...)
	}
	var jmaps []candidate
	if d.JMAP {
		for _, dom := range domains {
			jmaps = append(jmaps, d.jmapCandidates(ctx, dom)...)
		}
	}

	// A slow source must not leave no time to test the servers.
	ctx, cancel = context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var res Result
	res.IMAP = d.pick(ctx, "imap", imaps)
	res.SMTP = d.pick(ctx, "smtp", smtps)
	if d.JMAP {
		res.JMAP = d.pickJMAP(ctx, jmaps)
	}
	if d.ActiveSync {
		res.ActiveSync = d.pickActiveSync(ctx, activeSyncCandidates(hostOf(res.IMAP.Upstream.Upstream), domains))
	}
	if res.IMAP.Upstream.Upstream == "" && res.SMTP.Upstream.Upstream == "" && res.JMAP.Upstream.Upstream == "" &&
		res.ActiveSync.Upstream.Upstream == "" {
		return res, fmt.Errorf("%w for %s", ErrNotFound, domain)
	}
	if d.Log != nil {
		d.Log.Info("autodetect", "domain", domain,
			"imap", res.IMAP.Upstream.Upstream, "imap_tls", res.IMAP.UpstreamTLS, "imap_from", res.IMAP.From,
			"smtp", res.SMTP.Upstream.Upstream, "smtp_tls", res.SMTP.UpstreamTLS, "smtp_from", res.SMTP.From,
			"jmap", res.JMAP.Upstream.Upstream, "jmap_from", res.JMAP.From,
			"activesync", res.ActiveSync.Upstream.Upstream, "activesync_from", res.ActiveSync.From)
	}
	return res, nil
}

// pick returns the first usable candidate.
func (d *Detector) pick(ctx context.Context, service string, cs []candidate) Found {
	tried := map[config.Upstream]bool{}
	for _, c := range cs {
		if tried[c.u] {
			continue
		}
		tried[c.u] = true
		if d.Usable(ctx, service, c.u) {
			return Found{Upstream: c.u, From: c.from}
		}
		if d.Log != nil {
			d.Log.Info("autodetect: server not usable", "addr", c.u.Upstream, "from", c.from)
		}
	}
	return Found{}
}

// usable connects to u and completes the TLS handshake, after STARTTLS if
// u uses it. The certificate must be valid for the host name: a provider
// may name a server its certificate does not cover.
func usable(ctx context.Context, source, service string, u config.Upstream) bool {
	host, _, err := net.SplitHostPort(u.Upstream)
	if err != nil {
		return false
	}
	c, err := netbind.Dialer(source, 5*time.Second, nil).DialContext(ctx, "tcp", u.Upstream)
	if err != nil {
		return false
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	if u.UpstreamTLS == config.TLSStartTLS {
		if err := startTLS(c, service); err != nil {
			return false
		}
	}
	tc := tls.Client(c, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	return tc.HandshakeContext(ctx) == nil
}

// startTLS asks an IMAP or SMTP server to start TLS on c.
func startTLS(c net.Conn, service string) error {
	r := bufio.NewReader(c)
	line := func() (string, error) {
		l, err := r.ReadString('\n')
		return strings.TrimRight(l, "\r\n"), err
	}
	// reply reads an SMTP reply and checks its code.
	reply := func(code string) error {
		for {
			l, err := line()
			if err != nil {
				return err
			}
			if !strings.HasPrefix(l, code) {
				return fmt.Errorf("unexpected reply %q", l)
			}
			if len(l) == 3 || l[3] != '-' {
				return nil
			}
		}
	}
	if service == "smtp" {
		if err := reply("220"); err != nil {
			return err
		}
		fmt.Fprintf(c, "EHLO localhost\r\n")
		if err := reply("250"); err != nil {
			return err
		}
		fmt.Fprintf(c, "STARTTLS\r\n")
		return reply("220")
	}
	if l, err := line(); err != nil || !strings.HasPrefix(l, "* OK") {
		return fmt.Errorf("unexpected greeting %q: %v", l, err)
	}
	fmt.Fprintf(c, "a STARTTLS\r\n")
	for {
		l, err := line()
		if err != nil {
			return err
		}
		if strings.HasPrefix(l, "a ") {
			if !strings.HasPrefix(l, "a OK") {
				return fmt.Errorf("STARTTLS refused: %q", l)
			}
			return nil
		}
	}
}

// mxDomain returns the registered domain of the first mail exchanger, for
// example kolabnow.com for mx01.kolabnow.com. Custom domains hosted by a
// provider are found through it.
func (d *Detector) mxDomain(ctx context.Context, domain string) string {
	mxs, err := d.LookupMX(ctx, domain)
	if err != nil || len(mxs) == 0 {
		return ""
	}
	host := strings.ToLower(strings.TrimSuffix(mxs[0].Host, "."))
	if host == "" {
		return ""
	}
	base, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return base
}

func server(host string, port int, mode string) config.Upstream {
	return config.Upstream{
		Upstream:    net.JoinHostPort(strings.TrimSuffix(host, "."), strconv.Itoa(port)),
		UpstreamTLS: mode,
	}
}

// srv reads RFC 6186 and RFC 8314 records. Implicit TLS comes first.
func (d *Detector) srv(ctx context.Context, _, dom string) (imap, smtp []candidate) {
	look := func(service, mode string) []candidate {
		srvs, err := d.LookupSRV(ctx, service, "tcp", dom)
		if err != nil {
			return nil
		}
		var cs []candidate
		for _, s := range srvs {
			if s.Target == "." || s.Target == "" || s.Port == 0 {
				return nil // "." says the service is not offered
			}
			cs = append(cs, candidate{server(s.Target, int(s.Port), mode), "srv " + dom})
		}
		return cs
	}
	imap = append(look("imaps", config.TLSImplicit), look("imap", config.TLSStartTLS)...)
	smtp = append(look("submissions", config.TLSImplicit), look("submission", config.TLSStartTLS)...)
	return imap, smtp
}

// clientConfig is Mozilla's autoconfig format.
type clientConfig struct {
	Providers []struct {
		Incoming []acServer `xml:"incomingServer"`
		Outgoing []acServer `xml:"outgoingServer"`
	} `xml:"emailProvider"`
}

type acServer struct {
	Type       string   `xml:"type,attr"`
	Hostname   string   `xml:"hostname"`
	Port       int      `xml:"port"`
	SocketType string   `xml:"socketType"`
	Username   string   `xml:"username"`
	Auth       []string `xml:"authentication"`
}

// autoconfig asks the provider's own autoconfig file.
func (d *Detector) autoconfig(ctx context.Context, address, dom string) (imap, smtp []candidate) {
	q := "?emailaddress=" + url.QueryEscape(address)
	for _, u := range []string{
		"https://autoconfig." + dom + "/mail/config-v1.1.xml" + q,
		"https://" + dom + "/.well-known/autoconfig/mail/config-v1.1.xml" + q,
	} {
		if imap, smtp = d.clientConfig(ctx, u, address, "autoconfig "+dom); len(imap)+len(smtp) > 0 {
			return imap, smtp
		}
	}
	return nil, nil
}

// ispdb asks Mozilla's database.
func (d *Detector) ispdb(ctx context.Context, address, dom string) (imap, smtp []candidate) {
	return d.clientConfig(ctx, ISPDB+dom, address, "ispdb "+dom)
}

func (d *Detector) clientConfig(ctx context.Context, u, address, from string) (imap, smtp []candidate) {
	body, err := d.Get(ctx, u)
	if err != nil {
		return nil, nil
	}
	var cc clientConfig
	if err := xml.Unmarshal(body, &cc); err != nil {
		return nil, nil
	}
	local, domain, _ := strings.Cut(address, "@")
	expand := strings.NewReplacer("%EMAILADDRESS%", address, "%EMAILLOCALPART%", local, "%EMAILDOMAIN%", domain)
	conv := func(servers []acServer, typ string) []candidate {
		var cs []candidate
		for _, s := range servers {
			if s.Type != typ || s.Port == 0 || s.Hostname == "" {
				continue
			}
			mode := map[string]string{"SSL": config.TLSImplicit, "STARTTLS": config.TLSStartTLS}[s.SocketType]
			if mode == "" {
				continue // plain
			}
			// The proxy logs in with the address the client used.
			if s.Username != "" && !strings.EqualFold(expand.Replace(s.Username), address) {
				continue
			}
			if len(s.Auth) > 0 && !slices.Contains(s.Auth, "password-cleartext") {
				continue // OAuth2 or other methods the proxy does not use
			}
			cs = append(cs, candidate{server(expand.Replace(s.Hostname), s.Port, mode), from})
		}
		// Implicit TLS first (RFC 8314), otherwise in the file's order.
		slices.SortStableFunc(cs, func(a, b candidate) int {
			return boolRank(a.u.UpstreamTLS != config.TLSImplicit) - boolRank(b.u.UpstreamTLS != config.TLSImplicit)
		})
		return cs
	}
	for _, p := range cc.Providers {
		imap = append(imap, conv(p.Incoming, "imap")...)
		smtp = append(smtp, conv(p.Outgoing, "smtp")...)
	}
	return imap, smtp
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

const autodiscoverRequest = `<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
<Request><EMailAddress>%s</EMailAddress><AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema></Request>
</Autodiscover>`

type adResponse struct {
	Protocols []struct {
		Type       string `xml:"Type"`
		Server     string `xml:"Server"`
		Port       int    `xml:"Port"`
		SSL        string `xml:"SSL"`
		Encryption string `xml:"Encryption"`
		LoginName  string `xml:"LoginName"`
	} `xml:"Response>Account>Protocol"`
}

// autodiscover asks Exchange Autodiscover (the POX form) without
// credentials. Servers that only answer after a login are skipped: the
// password goes to the mail server only.
func (d *Detector) autodiscover(ctx context.Context, address, dom string) (imap, smtp []candidate) {
	var buf bytes.Buffer
	_ = xml.EscapeText(&buf, []byte(address))
	body := []byte(fmt.Sprintf(autodiscoverRequest, buf.String()))
	urls := []string{
		"https://autodiscover." + dom + "/autodiscover/autodiscover.xml",
		"https://" + dom + "/autodiscover/autodiscover.xml",
	}
	if srvs, err := d.LookupSRV(ctx, "autodiscover", "tcp", dom); err == nil {
		for _, s := range srvs {
			if s.Target != "." && s.Target != "" {
				urls = append(urls, "https://"+net.JoinHostPort(strings.TrimSuffix(s.Target, "."), strconv.Itoa(int(s.Port)))+"/autodiscover/autodiscover.xml")
			}
		}
	}
	for _, u := range urls {
		resp, err := d.Post(ctx, u, body)
		if err != nil {
			continue
		}
		var ad adResponse
		if err := xml.Unmarshal(resp, &ad); err != nil {
			continue
		}
		for _, p := range ad.Protocols {
			if p.Server == "" || p.Port == 0 {
				continue
			}
			if p.LoginName != "" && !strings.EqualFold(p.LoginName, address) {
				continue
			}
			var mode string
			switch strings.ToUpper(p.Encryption) {
			case "SSL":
				mode = config.TLSImplicit
			case "TLS":
				mode = config.TLSStartTLS
			case "", "AUTO":
				if strings.EqualFold(p.SSL, "off") {
					continue
				}
				mode = config.TLSStartTLS
				if p.Port == 993 || p.Port == 465 {
					mode = config.TLSImplicit
				}
			default:
				continue // None
			}
			c := candidate{server(p.Server, p.Port, mode), "autodiscover " + dom}
			switch strings.ToUpper(p.Type) {
			case "IMAP":
				imap = append(imap, c)
			case "SMTP":
				smtp = append(smtp, c)
			}
		}
		if len(imap)+len(smtp) > 0 {
			return imap, smtp
		}
	}
	return nil, nil
}
