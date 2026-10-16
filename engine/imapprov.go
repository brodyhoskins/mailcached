package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/brodyhoskins/mailcached/config"
	"github.com/brodyhoskins/mailcached/internal/load"
	"github.com/brodyhoskins/mailcached/internal/netbind"
)

// imapProvider reaches an IMAP provider for one account. Requests share a
// pool of connections; the engine has one more of its own (Watch), which
// idles on INBOX.
type imapProvider struct {
	login   string
	u       Upstream
	id      *imap.IDData
	section func() *imap.FetchItemBodySection // syncSection
	// password returns the password the provider last accepted, "" for
	// none.
	password func() string
	log      *slog.Logger

	// The pool of connections for client requests.
	poolMu      sync.Mutex
	poolCond    *sync.Cond
	idle        []*imapConn
	open        int
	bulkBusy    int           // connections held by bulk requests
	prioWaiting int           // interactive requests waiting
	max         int           // pool connections the configuration allows
	srcs        []*imapSource // where connections leave from
	reaper      *time.Timer   // closes connections idle too long
	logTimer    *time.Timer   // reports the changes to the log
}

// imapSource is one place connections to the provider leave from: an
// interface or a local address. A provider may cap the connections from
// one address, so each source learns its own limit.
type imapSource struct {
	p       *imapProvider
	addr    string      // interface name or IP address; "" for wherever routing says
	host    *imapHost   // the pools of other accounts from here to the server; nil for none
	open    int         // connections from here, the engine's own included
	limit   int         // connections the provider seems to allow from here
	limitAt time.Time   // when limit was lowered
	retry   *time.Timer // wakes the requests that wait once limit expires
	// failedAt is when a dial from here last failed, zero if one worked
	// since.
	failedAt time.Time
	// What the log said last, and why the connections changed since.
	shown, shownLimit int
	why               []string
}

func newIMAPProvider(login string, u Upstream, id *imap.IDData, section func() *imap.FetchItemBodySection, password func() string, log *slog.Logger) *imapProvider {
	p := &imapProvider{login: login, u: u, id: id, section: section, password: password, log: log}
	p.poolCond = sync.NewCond(&p.poolMu)
	// The engine's own connection counts toward the maximum.
	p.max = math.MaxInt
	if u.MaxConns > 0 {
		p.max = max(1, u.MaxConns-1)
	}
	addrs := u.Sources
	if len(addrs) == 0 {
		addrs = []string{""}
	}
	for _, a := range addrs {
		p.srcs = append(p.srcs, &imapSource{p: p, addr: a, limit: math.MaxInt, shownLimit: math.MaxInt})
	}
	return p
}

// login connects to the provider from source, logs in with the client's
// credentials and turns on COMPRESS=DEFLATE if the provider offers it. id names the
// proxy to providers that ask. h receives unsolicited responses. A provider's NO comes back as an *imap.Error.
func (u *Upstream) login(source, username, password string, id *imap.IDData, h *imapclient.UnilateralDataHandler, tap *notifyTap) (c *imapclient.Client, compressed bool, notify notifyMode, err error) {
	tlsCfg := u.TLSConfig
	if tlsCfg == nil {
		host, _, _ := net.SplitHostPort(u.Addr)
		tlsCfg = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	timeout := u.Timeout
	if timeout <= 0 {
		timeout = time.Minute
	}
	// With implicit TLS the client speaks first: TCP Fast Open can carry
	// its hello. With STARTTLS the server does.
	d := netbind.Dialer(source, timeout, dialControl(timeout, u.TLS == config.TLSImplicit))
	tcp, err := d.Dial("tcp", u.Addr)
	if err != nil {
		return nil, false, 0, fmt.Errorf("dial %s: %w", u.Addr, err)
	}
	// A command that gets no answer at all within the timeout closes the
	// connection (watchdog.go).
	var raw net.Conn = newWatchdog(tcp, timeout)
	var conn net.Conn = raw
	if u.TLS == config.TLSImplicit {
		tc := tls.Client(raw, tlsCfg)
		if err := tc.Handshake(); err != nil {
			raw.Close()
			return nil, false, 0, fmt.Errorf("tls %s: %w", u.Addr, err)
		}
		conn = tc
	}
	// The handshake must not hang on a silent server.
	_ = conn.SetDeadline(time.Now().Add(timeout))
	sc, compressed, notify, err := openSession(conn, u.TLS == config.TLSStartTLS, tlsCfg, username, password, tap)
	if err != nil {
		conn.Close()
		return nil, false, 0, err
	}
	_ = conn.SetDeadline(time.Time{})
	c = imapclient.New(sc, &imapclient.Options{UnilateralDataHandler: h})
	if err := c.WaitGreeting(); err != nil {
		c.Close()
		return nil, false, 0, fmt.Errorf("greeting from %s: %w", u.Addr, err)
	}
	// Name the proxy to providers that ask (RFC 2971), as clients do. A
	// refusal does not matter.
	if c.Caps().Has(imap.CapID) && id.Name != "" {
		_, err := c.ID(id).Wait()
		var ie *imap.Error
		if err != nil && !errors.As(err, &ie) {
			c.Close()
			return nil, false, 0, fmt.Errorf("ID to %s: %w", u.Addr, err)
		}
	}
	return c, compressed, notify, nil
}

// dial opens a connection from src with the accepted password.
func (p *imapProvider) dial(src *imapSource, h *imapclient.UnilateralDataHandler, tap *notifyTap) (*imapclient.Client, bool, notifyMode, error) {
	password := p.password()
	if password == "" {
		return nil, false, 0, ErrNoCredentials
	}
	return p.u.login(src.addr, p.login, password, p.id, h, tap)
}

// rejected marks a NO to LOGIN, so callers can tell it from any other NO.
// A NO for too many connections is not a rejection of the credentials.
func rejected(err error) error {
	var ie *imap.Error
	if errors.As(err, &ie) && ie.Type == imap.StatusResponseTypeNo && !tooManyConns(ie) {
		return fmt.Errorf("%w: %w", ErrLoginRejected, ie)
	}
	return err
}

// tooManyConns reports whether a provider's refusal says the account has
// too many connections. The login runs on imapraw, which leaves the
// response code in the text.
func tooManyConns(ie *imap.Error) bool {
	if ie.Code == imap.ResponseCodeLimit || ie.Code == imap.ResponseCodeUnavailable {
		return true
	}
	t := strings.ToLower(ie.Text)
	return strings.HasPrefix(t, "[limit]") || strings.HasPrefix(t, "[unavailable]") ||
		strings.Contains(t, "too many") || strings.Contains(t, "maximum number of connections")
}

// unreached reports whether a dial failed for want of the provider: a
// refusal for too many connections, or any failure to reach it. A
// rejection of the credentials, or another refusal, is not.
func unreached(err error) bool {
	if errors.Is(err, ErrNoCredentials) {
		return false
	}
	var ie *imap.Error
	if errors.As(err, &ie) {
		return tooManyConns(ie)
	}
	return true
}

// crowded reports whether a failed dial may mean the provider allows no
// more connections: a refusal that says so, or a connection refused,
// reset, closed or timed out. A failure to resolve the name, bind the
// source or trust the certificate does not.
func crowded(err error) bool {
	var ie *imap.Error
	if errors.As(err, &ie) {
		return tooManyConns(ie)
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		// The watchdog closed a connection that did not answer.
		errors.Is(err, net.ErrClosed)
}

func (p *imapProvider) Login(password string) error {
	var err error
	for range len(p.srcs) + 1 {
		var gave bool
		gave, err = p.login1(password)
		switch {
		case err == nil || !unreached(err):
			return err
		case gave:
			// Another account gave up a connection: try once more,
			// once the server has seen it close.
			time.Sleep(givenSettle)
		case !p.healthy():
			return err
		}
		// Else another source may reach the provider.
	}
	return err
}

// login1 logs in once. On failure, it reports whether another account
// gave up a connection for another try.
func (p *imapProvider) login1(password string) (gave bool, err error) {
	p.poolMu.Lock()
	src := p.anySource()
	src.open++
	p.poolMu.Unlock()
	c, _, _, err := p.u.login(src.addr, p.login, password, p.id, ignoreUnilateral, nil)
	if err == nil {
		// After Close, as when the provider rejected the last password,
		// the account shares the server again.
		for _, s := range p.srcs {
			if s.host != nil {
				s.host.add(s)
			}
		}
	}
	p.poolMu.Lock()
	if err != nil {
		src.open--
		gave := src.crowdedBy(err)
		p.poolMu.Unlock()
		return gave, rejected(err)
	}
	src.failedAt = time.Time{}
	// Keep the connection for client requests, if the pool has room.
	// The pool keeps one even past the limit, as conn1 would open one.
	room := p.open < p.max && (src.open <= src.poolLimit() || p.open == 0)
	if room {
		p.open++
		src.note("login")
	} else {
		src.open--
	}
	p.poolMu.Unlock()
	if room {
		(&imapConn{p: p, c: c, src: src}).Release(nil)
	} else {
		c.Close()
	}
	return false, nil
}

// --- Pool -----------------------------------------------------------------

// The pool opens a connection when a request finds every one busy, with
// no cap but Upstream's MaxConns, if set, less the engine's own. The
// connections leave from Upstream's Sources, the least used first. A
// provider that allows fewer from a source refuses a connection, or does
// not answer: that source then stops at the connections it has open, for
// connRetryAfter. A connection idle for connIdleClose is closed, except
// the last one used.
var (
	connRetryAfter = 10 * time.Minute
	connIdleClose  = 5 * time.Minute
)

// poolLimit returns the most connections to open from s: s.limit, or no
// limit once connRetryAfter has passed since the provider refused one
// (p.poolMu held).
func (s *imapSource) poolLimit() int {
	if s.limit < math.MaxInt && time.Since(s.limitAt) >= connRetryAfter {
		s.limit = math.MaxInt
		s.note("limit lifted")
	}
	return s.limit
}

// source returns the source with the fewest connections among those
// with room for one more, nil if none has. With any, it returns the one
// with the fewest connections whether it has room or not. A source whose
// last dial failed comes after the others for connRetryAfter (p.poolMu
// held).
func (p *imapProvider) source(any bool) *imapSource {
	var best *imapSource
	for _, s := range p.srcs {
		if !any && s.open >= s.poolLimit() {
			continue
		}
		if best == nil || !s.failing() && best.failing() ||
			s.failing() == best.failing() && s.open < best.open {
			best = s
		}
	}
	return best
}

// anySource returns a source with room if one has, else the least used
// (p.poolMu held).
func (p *imapProvider) anySource() *imapSource {
	if s := p.source(false); s != nil {
		return s
	}
	return p.source(true)
}

// failing reports whether the last dial from s failed, less than
// connRetryAfter ago (p.poolMu held).
func (s *imapSource) failing() bool {
	return !s.failedAt.IsZero() && time.Since(s.failedAt) < connRetryAfter
}

// lower sets the most connections to open from s to n, for
// connRetryAfter, for the reason why. The requests that wait then try
// again (p.poolMu held).
func (s *imapSource) lower(n int, why string) {
	s.limit, s.limitAt = n, time.Now()
	s.note(why)
	if s.retry != nil {
		s.retry.Reset(connRetryAfter)
		return
	}
	p := s.p
	s.retry = time.AfterFunc(connRetryAfter, func() {
		p.poolMu.Lock()
		p.poolCond.Broadcast()
		p.poolMu.Unlock()
	})
}

// capacity returns the most pool connections the sources and the
// configuration allow, the engine's own aside (p.poolMu held).
func (p *imapProvider) capacity() int {
	n := 0
	for _, s := range p.srcs {
		l := s.poolLimit()
		if l == math.MaxInt || n > math.MaxInt-l {
			return p.max
		}
		n += l
	}
	if w := p.watching(); n > w {
		n -= w
	}
	return min(n, p.max)
}

func (p *imapProvider) Capacity() int {
	p.poolMu.Lock()
	defer p.poolMu.Unlock()
	if n := p.capacity(); n < math.MaxInt {
		return n
	}
	return 0
}

// watching counts the engine's own connections (p.poolMu held).
func (p *imapProvider) watching() int {
	n := -p.open
	for _, s := range p.srcs {
		n += s.open
	}
	return max(n, 0)
}

// bulkLimit returns the most connections bulk requests hold: all but one,
// which is kept for interactive requests (p.poolMu held).
func (p *imapProvider) bulkLimit() int { return max(1, p.capacity()-1) }

// crowdedBy handles a failed dial from s (p.poolMu held, and released
// for a while). If the provider was not reached, s goes after the other
// sources for a while. If err may mean the server allows no more
// connections from s, a larger pool of another account there gives one
// up for this one, and crowdedBy reports true. If none can, s stops at
// the connections it has.
func (s *imapSource) crowdedBy(err error) (gave bool) {
	if !unreached(err) {
		return false
	}
	if !crowded(err) {
		s.failedAt = time.Now()
		return false
	}
	p := s.p
	if s.host != nil {
		open := s.open
		p.poolMu.Unlock()
		gave := s.host.giveTo(s, open)
		p.poolMu.Lock()
		if gave {
			return true
		}
	}
	s.failedAt = time.Now()
	n := max(1, s.open)
	if l := s.poolLimit(); n < l {
		p.log.Warn("imap: provider connection limit", "user", p.login, "source", s.addr, "connections", n, "err", err)
	} else {
		n = l
	}
	s.lower(n, "provider limit")
	return false
}

// drop forgets a connection that is closed, or closes it, for the reason
// why (p.poolMu held).
func (p *imapProvider) drop(pc *imapConn, why string) {
	pc.c.Close()
	p.open--
	pc.src.open--
	pc.src.note(why)
}

// logEvery is the most often the log reports an account's connections.
var logEvery = 5 * time.Second

// note records why the connections from s, or its limit, changed. The
// log reports the changes at most every logEvery (p.poolMu held).
func (s *imapSource) note(why string) {
	if !slices.Contains(s.why, why) {
		s.why = append(s.why, why)
	}
	if p := s.p; p.logTimer == nil {
		p.logTimer = time.AfterFunc(logEvery, p.report)
	}
}

// report logs the sources whose connections or limit changed since the
// last report.
func (p *imapProvider) report() {
	p.poolMu.Lock()
	defer p.poolMu.Unlock()
	p.logTimer = nil
	for _, s := range p.srcs {
		limit := s.limit
		if s.open != s.shown || limit != s.shownLimit {
			src := s.addr
			if src == "" {
				src = "default"
			}
			p.log.Info("imap: provider connections", "user", p.login, "source", src,
				"connections", fmt.Sprintf("%d -> %d", s.shown, s.open), "limit", limitText(limit),
				"why", strings.Join(s.why, ", "))
		}
		s.shown, s.shownLimit, s.why = s.open, limit, nil
	}
}

func limitText(n int) string {
	if n == math.MaxInt {
		return "none"
	}
	return strconv.Itoa(n)
}

// ignoreUnilateral consumes unsolicited data on pool connections: the
// engine keeps the mailbox state, not these connections.
var ignoreUnilateral = &imapclient.UnilateralDataHandler{
	Fetch: func(msg *imapclient.FetchMessageData) { _, _ = msg.Collect() },
}

// Requests on the pool are interactive (a client waits on them: opening a
// folder, a few messages, a flag change) or bulk (a large download). Bulk
// requests hold at most bulkLimit connections, so one is left for
// interactive ones when the pool has two or more, and an interactive request that waits is served before
// any waiting bulk request. New mail therefore opens at once even during a
// large download.
type priority bool

const (
	bulk        priority = false
	interactive priority = true
)

// Conn returns a pooled connection. After a dial that failed for want of
// room on the provider, or of an answer, it tries again, as Login does:
// from another source, or on a connection that is open already.
func (p *imapProvider) Conn(prio priority, hint string) (conn, error) {
	var err error
	for range len(p.srcs) + 1 {
		var pc *imapConn
		var gave bool
		pc, gave, err = p.conn1(prio, hint)
		switch {
		case err == nil:
			return pc, nil
		case !unreached(err):
			return nil, err
		case gave:
			time.Sleep(givenSettle)
		}
	}
	return nil, err
}

// givenSettle is how long a retry waits after another account gave up a
// connection for it: the server must see that one close first.
var givenSettle = 250 * time.Millisecond

// healthy reports whether a source's last dial worked, or none failed
// lately.
func (p *imapProvider) healthy() bool {
	p.poolMu.Lock()
	defer p.poolMu.Unlock()
	return slices.ContainsFunc(p.srcs, func(s *imapSource) bool { return !s.failing() })
}

// conn1 tries for a connection once. On failure, gave reports whether
// another account gave one up for the next try.
func (p *imapProvider) conn1(prio priority, hint string) (pc *imapConn, gave bool, err error) {
	p.poolMu.Lock()
	if prio == interactive {
		p.prioWaiting++
	}
	for pc == nil {
		// Bulk waits while interactive requests wait, and never takes the
		// connection reserved for them.
		if prio == bulk && (p.prioWaiting > 0 || p.bulkBusy >= p.bulkLimit()) {
			p.poolCond.Wait()
			continue
		}
		// Prefer a connection with the mailbox selected already.
		i := slices.IndexFunc(p.idle, func(c *imapConn) bool { return c.selected == hint })
		if i < 0 && len(p.idle) > 0 {
			i = len(p.idle) - 1
		}
		if i >= 0 {
			pc = p.idle[i]
			p.idle = slices.Delete(p.idle, i, i+1)
			select {
			case <-pc.c.Closed():
				p.drop(pc, "closed by the provider")
				pc = nil
				continue
			default:
			}
			break
		}
		// Under pressure, the process opens no connection while one is
		// open to wait for.
		// With no connection of its own, the pool tries one even past
		// the learned limit: the engine's connection may hold it, and
		// none would come back to wait for.
		src := p.source(false)
		if src == nil && p.open == 0 {
			src = p.source(true)
		}
		pressed := src != nil && p.open < p.max && p.open > 0 && load.Default.Pressed()
		if src != nil && p.open < p.max && !pressed {
			p.open++
			src.open++
			p.poolMu.Unlock()
			c, _, _, err := p.dial(src, ignoreUnilateral, nil)
			p.poolMu.Lock()
			if err != nil {
				p.open--
				src.open--
				gave := src.crowdedBy(err)
				if prio == interactive {
					p.prioWaiting--
				}
				p.poolCond.Broadcast()
				p.poolMu.Unlock()
				return nil, gave, err
			}
			src.failedAt = time.Time{}
			src.note("demand")
			pc = &imapConn{p: p, c: c, src: src}
			break
		}
		// Nothing wakes the pool when the pressure ends: look again soon.
		if pressed {
			t := time.AfterFunc(time.Second, func() {
				p.poolMu.Lock()
				p.poolCond.Broadcast()
				p.poolMu.Unlock()
			})
			p.poolCond.Wait()
			t.Stop()
			continue
		}
		p.poolCond.Wait()
	}
	if prio == interactive {
		p.prioWaiting--
	} else {
		p.bulkBusy++
	}
	pc.bulk = prio == bulk
	p.poolMu.Unlock()
	return pc, false, nil
}

// Close closes the idle connections. The account is done with the
// provider: it no longer shares the server with the other accounts.
func (p *imapProvider) Close() {
	for _, s := range p.srcs {
		if s.host != nil {
			s.host.remove(s)
		}
	}
	p.poolMu.Lock()
	defer p.poolMu.Unlock()
	for _, s := range p.srcs {
		if s.retry != nil {
			s.retry.Stop()
			s.retry = nil
		}
	}
	p.closeIdle("account closed")
	if p.reaper != nil {
		p.reaper.Stop()
		p.reaper = nil
	}
}

// closeIdle closes the idle connections, for the reason why (p.poolMu
// held).
func (p *imapProvider) closeIdle(why string) {
	for _, pc := range p.idle {
		p.drop(pc, why)
	}
	p.idle = nil
	p.poolCond.Broadcast()
}

// reap closes the connections idle for connIdleClose, except the last one
// used, and runs again when the next one is due.
func (p *imapProvider) reap() {
	p.poolMu.Lock()
	defer p.poolMu.Unlock()
	p.reaper = nil
	newest := len(p.idle) - 1 // Release appends
	now := time.Now()
	var next time.Duration
	keep := p.idle[:0]
	for i, pc := range p.idle {
		if i != newest {
			if left := connIdleClose - now.Sub(pc.idleSince); left <= 0 {
				p.drop(pc, "idle")
				continue
			} else if next == 0 || left < next {
				next = left
			}
		}
		keep = append(keep, pc)
	}
	clear(p.idle[len(keep):])
	p.idle = keep
	if next > 0 {
		p.reaper = time.AfterFunc(next, p.reap)
	}
	p.poolCond.Broadcast()
}

// imapConn is a provider connection: pooled, or the engine's (watch set).
type imapConn struct {
	p        *imapProvider
	c        *imapclient.Client
	selected string // mailbox selected, "" for none
	readOnly bool
	bulk     bool // held by a bulk request
	watch    bool
	src      *imapSource
	released bool // the engine's connection was released
	// idleSince is when the connection went back to the pool.
	idleSince time.Time
}

// Release returns a pooled connection to the pool, or closes it if err
// shows it is broken. The engine's connection is closed.
func (pc *imapConn) Release(err error) {
	p := pc.p
	p.poolMu.Lock()
	defer p.poolMu.Unlock()
	if pc.watch {
		// The sync releases it twice: when it ends, and when its context
		// does.
		if !pc.released {
			pc.released = true
			pc.c.Close()
			pc.src.open--
			pc.src.note("engine's connection closed")
			p.poolCond.Broadcast()
		}
		return
	}
	var ie *imap.Error
	broken := err != nil && !errors.As(err, &ie)
	if pc.bulk {
		pc.bulk = false
		p.bulkBusy--
	}
	// A connection over a lowered limit is closed, but the pool keeps
	// its last one: conn1 opens it past the limit, for want of any other.
	if broken {
		p.drop(pc, "broken")
	} else if p.open > p.max || pc.src.open > pc.src.poolLimit() && p.open > 1 {
		p.drop(pc, "over the limit")
	} else {
		pc.idleSince = time.Now()
		p.idle = append(p.idle, pc)
		if p.reaper == nil && len(p.idle) > 1 {
			p.reaper = time.AfterFunc(connIdleClose, p.reap)
		}
	}
	p.poolCond.Broadcast()
}

// sel selects mailbox, with EXAMINE if readOnly.
func (pc *imapConn) sel(mailbox string, readOnly bool) error {
	if pc.selected == mailbox && (!pc.readOnly || readOnly) {
		return nil
	}
	if _, err := pc.c.Select(mailbox, &imap.SelectOptions{ReadOnly: readOnly}).Wait(); err != nil {
		pc.selected = ""
		return err
	}
	pc.selected, pc.readOnly = mailbox, readOnly
	return nil
}

// unselect closes mailbox if it is selected, before it is deleted or
// renamed.
func (pc *imapConn) unselect(mailbox string) error {
	if !strings.EqualFold(pc.selected, mailbox) {
		return nil
	}
	if err := pc.c.Unselect().Wait(); err != nil {
		return err
	}
	pc.selected = ""
	return nil
}

// --- Folders --------------------------------------------------------------

func (pc *imapConn) List() ([]folderInfo, error) {
	c := pc.c
	opts := &imap.ListOptions{}
	if c.Caps().Has(imap.CapSpecialUse) || c.Caps().Has(imap.CapIMAP4rev2) {
		opts.ReturnSpecialUse = true
	}
	extended := c.Caps().Has(imap.CapListExtended) || c.Caps().Has(imap.CapIMAP4rev2)
	if extended {
		opts.ReturnSubscribed = true
	}
	list, err := c.List("", "*", opts).Collect()
	if err != nil {
		return nil, err
	}
	var subscribed map[string]bool
	if !extended {
		subs, err := c.List("", "*", &imap.ListOptions{SelectSubscribed: true}).Collect()
		if err != nil {
			return nil, err
		}
		subscribed = map[string]bool{}
		for _, s := range subs {
			subscribed[CanonicalName(s.Mailbox)] = true
		}
	}
	out := make([]folderInfo, 0, len(list))
	for _, d := range list {
		f := folderInfo{
			name:  CanonicalName(d.Mailbox),
			delim: d.Delim,
			attrs: slices.DeleteFunc(slices.Clone(d.Attrs), func(x imap.MailboxAttr) bool {
				return strings.EqualFold(string(x), string(imap.MailboxAttrSubscribed))
			}),
			selectable: !HasAttr(d.Attrs, imap.MailboxAttrNoSelect) && !HasAttr(d.Attrs, imap.MailboxAttrNonExistent),
		}
		if extended {
			f.subscribed = HasAttr(d.Attrs, imap.MailboxAttrSubscribed)
		} else {
			f.subscribed = subscribed[f.name]
		}
		out = append(out, f)
	}
	return out, nil
}

func (pc *imapConn) Create(name string, opts *imap.CreateOptions) error {
	return pc.c.Create(name, opts).Wait()
}

func (pc *imapConn) Delete(name string) error {
	if err := pc.unselect(name); err != nil {
		return err
	}
	return pc.c.Delete(name).Wait()
}

func (pc *imapConn) Rename(name, newName string, opts *imap.RenameOptions) error {
	if err := pc.unselect(name); err != nil {
		return err
	}
	return pc.c.Rename(name, newName, opts).Wait()
}

func (pc *imapConn) Subscribe(name string, on bool) error {
	if on {
		return pc.c.Subscribe(name).Wait()
	}
	return pc.c.Unsubscribe(name).Wait()
}

// --- Sync -----------------------------------------------------------------

// Sync is cheap when nothing changed: one STATUS. Otherwise it selects the
// folder read-only and asks for the messages from the last UIDNEXT on
// (their fingerprint fields, never the body), the changed flags of the
// others (with CONDSTORE, or all of them every fullFlagInterval), and,
// when the counts disagree, every UID.
func (pc *imapConn) Sync(name string, st syncState) (*delta, error) {
	c := pc.c
	condstore := c.Caps().Has(imap.CapCondStore)
	s, err := c.Status(name, &imap.StatusOptions{
		NumMessages: true, UIDNext: true, UIDValidity: true, HighestModSeq: condstore,
	}).Wait()
	if err != nil {
		return nil, err
	}
	fullFlags := st.refetchFlags || (!condstore && time.Since(st.flagsFull) > fullFlagInterval)
	if !st.force && !st.stale && st.synced && s.UIDValidity == st.validity && s.UIDNext == st.next &&
		s.NumMessages != nil && int(*s.NumMessages) == st.count &&
		(!condstore || s.HighestModSeq == st.modSeq) && !fullFlags {
		return &delta{unchanged: true}, nil
	}
	reset := st.validity != 0 && s.UIDValidity != st.validity
	start := st.next
	if reset || start == 0 {
		start = 1
	}

	sel, err := c.Select(name, &imap.SelectOptions{ReadOnly: true, CondStore: condstore}).Wait()
	if err != nil {
		pc.selected = ""
		return nil, err
	}
	pc.selected, pc.readOnly = name, true
	fetch := &imap.FetchOptions{
		UID: true, Flags: true, InternalDate: true, RFC822Size: true,
		BodySection: []*imap.FetchItemBodySection{pc.p.section()},
	}

	var got []*imapclient.FetchMessageBuffer
	if sel.NumMessages > 0 {
		all, err := c.Fetch(imap.UIDSet{{Start: start, Stop: 0}}, fetch).Collect()
		if err != nil {
			return nil, err
		}
		for _, f := range all {
			if f.UID >= start {
				got = append(got, f)
			}
		}
	}

	// Changed flags on the messages from before start.
	var changed []*imapclient.FetchMessageBuffer
	if !reset && start > 1 && (condstore && st.modSeq > 0 || fullFlags) {
		opts := &imap.FetchOptions{UID: true, Flags: true}
		if condstore && st.modSeq > 0 && !fullFlags {
			opts.ChangedSince = st.modSeq
		}
		if changed, err = c.Fetch(imap.UIDSet{{Start: 1, Stop: start - 1}}, opts).Collect(); err != nil {
			return nil, err
		}
	}

	// Deleted messages, or ones the proxy never saw: the counts will
	// disagree.
	have, fresh := st.count, 0
	if reset {
		have = 0
	}
	for _, f := range got {
		if reset || !st.known(f.UID) {
			fresh++
		}
	}
	d := &delta{reset: reset, validity: sel.UIDValidity, modSeq: sel.HighestModSeq, fullFlags: fullFlags,
		folderFlags: sel.Flags, permanentFlags: sel.PermanentFlags}
	if uint32(have+fresh) != sel.NumMessages {
		res, err := c.UIDSearch(&imap.SearchCriteria{}, nil).Wait()
		if err != nil {
			return nil, err
		}
		d.present = map[imap.UID]bool{}
		var unseen []imap.UID
		for _, u := range res.AllUIDs() {
			d.present[u] = true
			if u < start && !st.known(u) {
				unseen = append(unseen, u)
			}
		}
		if len(unseen) > 0 {
			more, err := c.Fetch(imap.UIDSetNum(unseen...), fetch).Collect()
			if err != nil {
				return nil, err
			}
			got = append(got, more...)
		}
	}

	d.next = sel.UIDNext
	for _, f := range got {
		d.next = max(d.next, f.UID+1)
		d.fresh = append(d.fresh, freshMessage{uid: f.UID, flags: NonNil(f.Flags), date: f.InternalDate,
			size: f.RFC822Size, header: f.FindBodySection(pc.p.section())})
	}
	for _, f := range changed {
		// Asked for FLAGS: an empty list decodes as nil.
		d.flags = append(d.flags, flagUpdate{f.UID, NonNil(f.Flags)})
	}
	return d, nil
}

// --- Messages -------------------------------------------------------------

func (pc *imapConn) FetchFull(name string, uids []imap.UID, each func(uid imap.UID, raw []byte)) error {
	if err := pc.sel(name, true); err != nil {
		return err
	}
	section := &imap.FetchItemBodySection{Peek: true}
	cmd := pc.c.Fetch(imap.UIDSetNum(uids...), &imap.FetchOptions{UID: true, BodySection: []*imap.FetchItemBodySection{section}})
	defer cmd.Close()
	for {
		msg := cmd.Next()
		if msg == nil {
			break
		}
		buf, err := msg.Collect()
		if err != nil {
			return err
		}
		if raw := buf.FindBodySection(section); raw != nil {
			each(buf.UID, raw)
		}
	}
	return cmd.Close()
}

// FetchSections asks for the sections as they are. A Binary section
// from a provider without BINARY is asked as BODY[part] and decoded here.
func (pc *imapConn) FetchSections(name string, uids []imap.UID, secs []Section, each func(uid imap.UID, i int, data []byte)) error {
	if err := pc.sel(name, true); err != nil {
		return err
	}
	binary := pc.c.Caps().Has(imap.CapBinary)
	opts := &imap.FetchOptions{UID: true}
	type ask struct {
		body *imap.FetchItemBodySection
		bin  *imap.FetchItemBinarySection
	}
	asks := make([]ask, len(secs))
	for i, s := range secs {
		switch {
		case s.Binary && binary:
			asks[i].bin = &imap.FetchItemBinarySection{Part: s.Part, Partial: s.Partial, Peek: true}
			opts.BinarySection = append(opts.BinarySection, asks[i].bin)
		case s.Binary:
			// The whole part, decoded here, then cut.
			asks[i].body = &imap.FetchItemBodySection{Part: s.Part, Peek: true}
			opts.BodySection = append(opts.BodySection, asks[i].body)
		default:
			bs := &imap.FetchItemBodySection{Part: s.Part, Specifier: s.Specifier, Partial: s.Partial, Peek: true}
			if s.NotFields {
				bs.HeaderFieldsNot = s.Fields
			} else {
				bs.HeaderFields = s.Fields
			}
			asks[i].body = bs
			opts.BodySection = append(opts.BodySection, bs)
		}
	}
	cmd := pc.c.Fetch(imap.UIDSetNum(uids...), opts)
	defer cmd.Close()
	for {
		msg := cmd.Next()
		if msg == nil {
			break
		}
		buf, err := msg.Collect()
		if err != nil {
			return err
		}
		for i, a := range asks {
			var data []byte
			if a.bin != nil {
				data = buf.FindBinarySection(a.bin)
			} else {
				data = buf.FindBodySection(a.body)
			}
			if data == nil {
				continue // the message lost the part, or is gone
			}
			if secs[i].Binary && !binary {
				dec, err := decodePart(data, secs[i].Encoding)
				if err != nil {
					continue
				}
				data = applyPartial(dec, secs[i].Partial)
			}
			each(buf.UID, i, data)
		}
	}
	return cmd.Close()
}

// Search asks the provider. Text criteria in a non-ASCII charset go as
// UTF-8.
func (pc *imapConn) Search(name string, c *imap.SearchCriteria) ([]imap.UID, error) {
	if err := pc.sel(name, true); err != nil {
		return nil, err
	}
	res, err := pc.c.UIDSearch(c, nil).Wait()
	if err != nil {
		return nil, err
	}
	return res.AllUIDs(), nil
}

// headerSection is the header asked of the provider for a header entry.
var headerSection = &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader, Peek: true}

func (pc *imapConn) FetchHeaders(name string, uids []imap.UID) (map[imap.UID]*HeaderEntry, error) {
	if err := pc.sel(name, true); err != nil {
		return nil, err
	}
	opts := &imap.FetchOptions{UID: true, RFC822Size: true,
		BodyStructure: &imap.FetchItemBodyStructure{Extended: true},
		BodySection:   []*imap.FetchItemBodySection{headerSection}}
	got, err := pc.c.Fetch(imap.UIDSetNum(uids...), opts).Collect()
	if err != nil {
		return nil, err
	}
	out := map[imap.UID]*HeaderEntry{}
	for _, buf := range got {
		hdr := buf.FindBodySection(headerSection)
		if hdr == nil || buf.BodyStructure == nil {
			continue
		}
		out[buf.UID] = &HeaderEntry{Header: hdr, Size: buf.RFC822Size, Structure: repairStructure(buf.BodyStructure)}
	}
	return out, nil
}

// Store is not silent, so every reply carries FLAGS.
func (pc *imapConn) Store(name string, uids []imap.UID, op imap.StoreFlagsOp, flags []imap.Flag) (map[imap.UID][]imap.Flag, error) {
	if err := pc.sel(name, false); err != nil {
		return nil, err
	}
	res, err := pc.c.Store(imap.UIDSetNum(uids...), &imap.StoreFlags{Op: op, Flags: flags}, nil).Collect()
	if err != nil {
		return nil, err
	}
	out := make(map[imap.UID][]imap.Flag, len(res))
	for _, f := range res {
		// An empty list decodes as nil.
		out[f.UID] = NonNil(f.Flags)
	}
	return out, nil
}

func (pc *imapConn) Copy(name string, uids []imap.UID, dest string) (map[imap.UID]imap.UID, error) {
	if err := pc.sel(name, true); err != nil {
		return nil, err
	}
	data, err := pc.c.Copy(imap.UIDSetNum(uids...), dest).Wait()
	if err != nil {
		return nil, err
	}
	return copyMap(data), nil
}

// Move uses MOVE, or else COPY, STORE \Deleted and UID EXPUNGE of just
// these messages.
func (pc *imapConn) Move(name string, uids []imap.UID, dest string) (map[imap.UID]imap.UID, error) {
	if err := pc.sel(name, false); err != nil {
		return nil, err
	}
	c, set := pc.c, imap.UIDSetNum(uids...)
	if c.Caps().Has(imap.CapMove) || c.Caps().Has(imap.CapIMAP4rev2) {
		md, err := c.Move(set, dest).Wait()
		if err != nil || md.UIDValidity == 0 {
			return nil, err
		}
		src, _ := md.SourceUIDs.(imap.UIDSet)
		dst, _ := md.DestUIDs.(imap.UIDSet)
		return copyMap(&imap.CopyData{UIDValidity: md.UIDValidity, SourceUIDs: src, DestUIDs: dst}), nil
	}
	if !c.Caps().Has(imap.CapUIDPlus) {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeCannot, Text: "The upstream server supports neither MOVE nor UIDPLUS"}
	}
	data, err := c.Copy(set, dest).Wait()
	if err == nil {
		_, err = c.Store(set, &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Collect()
	}
	if err == nil {
		_, err = c.UIDExpunge(set).Collect()
	}
	if err != nil || data.UIDValidity == 0 {
		return nil, err
	}
	return copyMap(data), nil
}

// Expunge sets \Deleted first, as a flag change of the client's may not
// have reached the provider.
func (pc *imapConn) Expunge(name string, uids []imap.UID) error {
	if err := pc.sel(name, false); err != nil {
		return err
	}
	c, set := pc.c, imap.UIDSetNum(uids...)
	_, err := c.Store(set, &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagDeleted}}, nil).Collect()
	if err != nil {
		return err
	}
	if pc.exactExpunge() {
		_, err = c.UIDExpunge(set).Collect()
	} else {
		// Expunges every message with \Deleted; the resync finds any
		// others.
		_, err = c.Expunge().Collect()
	}
	return err
}

func (pc *imapConn) cheapHeaders() bool { return true }

func (pc *imapConn) exactExpunge() bool {
	return pc.c.Caps().Has(imap.CapUIDPlus) || pc.c.Caps().Has(imap.CapIMAP4rev2)
}

func (pc *imapConn) Append(name string, data []byte, opts *imap.AppendOptions) (imap.UID, uint32, error) {
	cmd := pc.c.Append(name, int64(len(data)), opts)
	_, werr := cmd.Write(data)
	cerr := cmd.Close()
	res, err := cmd.Wait()
	if err = errors.Join(werr, cerr, err); err != nil {
		return 0, 0, err
	}
	return res.UID, res.UIDValidity, nil
}

// --- Sharing a server ------------------------------------------------------

// imapHost holds the pools of the accounts that reach one server from
// one source. A server may cap the connections from one address,
// whatever the account: when it refuses one account a connection, the
// largest pool gives one up for it. The server is the host name and port
// configured, whatever addresses it has.
type imapHost struct {
	mu    sync.Mutex
	pools map[*imapSource]bool
}

// imapHost returns the pools that reach the server at addr from source.
func (b *Engine) imapHost(addr, source string) *imapHost {
	b.hostsMu.Lock()
	defer b.hostsMu.Unlock()
	key := [2]string{addr, source}
	h := b.imapHosts[key]
	if h == nil {
		if b.imapHosts == nil {
			b.imapHosts = map[[2]string]*imapHost{}
		}
		h = &imapHost{pools: map[*imapSource]bool{}}
		b.imapHosts[key] = h
	}
	return h
}

func (h *imapHost) add(s *imapSource) {
	h.mu.Lock()
	h.pools[s] = true
	h.mu.Unlock()
}

func (h *imapHost) remove(s *imapSource) {
	h.mu.Lock()
	delete(h.pools, s)
	h.mu.Unlock()
}

// giveTo has the largest other pool give up a connection for s, which
// has open, if that pool has at least two more. It reports whether one
// did. The giver closes an idle connection now, and stops below what it
// had for connRetryAfter.
func (h *imapHost) giveTo(s *imapSource, open int) bool {
	// h.mu, then a pool's poolMu: never the other way round.
	h.mu.Lock()
	defer h.mu.Unlock()
	var giver *imapSource
	most := open + 1
	for q := range h.pools {
		if q == s {
			continue
		}
		q.p.poolMu.Lock()
		n := q.open
		idle := slices.ContainsFunc(q.p.idle, func(pc *imapConn) bool { return pc.src == q })
		q.p.poolMu.Unlock()
		// The giver keeps two: the engine's connection, if it is from
		// here, and one for requests. Only a pool with an idle connection
		// can give one now.
		if idle && n > most && n > 2 {
			giver, most = q, n
		}
	}
	if giver == nil {
		return false
	}
	g := giver.p
	g.poolMu.Lock()
	defer g.poolMu.Unlock()
	if giver.open <= open+1 || giver.open <= 2 {
		return false
	}
	// Only an idle connection is given: one closes now, so the retry
	// after givenSettle finds room. A busy one could take longer.
	i := slices.IndexFunc(g.idle, func(pc *imapConn) bool { return pc.src == giver })
	if i < 0 {
		return false
	}
	g.log.Info("imap: connection given to another account", "user", g.login, "to", s.p.login, "source", giver.addr, "connections", giver.open-1)
	giver.lower(giver.open-1, "given to another account")
	pc := g.idle[i]
	g.idle = slices.Delete(g.idle, i, i+1)
	g.drop(pc, "given to another account")
	return true
}

// --- The engine's connection ----------------------------------------------

// imapWatch is the engine's connection. It idles on INBOX, so new mail
// shows up at once, and asks for NOTIFY, so changes elsewhere do too.
type imapWatch struct {
	*imapConn
	compressed bool
	notify     notifyMode
	tap        *notifyTap
}

func (p *imapProvider) Watch(notify func()) (watchConn, error) {
	tap := newNotifyTap(notify)
	// The engine's connection goes first: it takes a source with room if
	// one has, else the least used.
	p.poolMu.Lock()
	src := p.anySource()
	src.open++
	p.poolMu.Unlock()
	c, compressed, mode, err := p.dial(src, &imapclient.UnilateralDataHandler{
		Expunge: func(uint32) { notify() },
		Mailbox: func(*imapclient.UnilateralDataMailbox) { notify() },
		Fetch: func(msg *imapclient.FetchMessageData) {
			_, _ = msg.Collect()
			notify()
		},
	}, tap)
	if err != nil {
		p.poolMu.Lock()
		src.open--
		// The limit is learned from the connections open when the
		// provider refused one. The engine's connection matters more than
		// idle ones: they then make room for its next try.
		src.crowdedBy(err)
		if crowded(err) {
			p.closeIdle("room for the engine's connection")
		}
		p.poolMu.Unlock()
		return nil, rejected(err)
	}
	p.poolMu.Lock()
	src.failedAt = time.Time{}
	src.note("engine's connection")
	p.poolMu.Unlock()
	return &imapWatch{imapConn: &imapConn{p: p, c: c, watch: true, src: src}, compressed: compressed, notify: mode, tap: tap}, nil
}

func (w *imapWatch) Describe() []any {
	n := "off"
	switch w.notify {
	case notifyMessages:
		n = "messages"
	case notifyFlags:
		n = "messages and flags"
	}
	return []any{"upstream_compress", w.compressed, "idle", hasIdle(w.c), "notify", n}
}

// Notifies reports whether the provider reports every change in every
// folder.
func (w *imapWatch) Notifies() bool { return w.notify == notifyFlags }

// Wait idles on INBOX, or sleeps on a provider without IDLE. Either way
// INBOX is synced next, with the folders NOTIFY reported.
func (w *imapWatch) Wait(ctx context.Context, d time.Duration, changed, wake <-chan struct{}) (wakeup, error) {
	up, err := w.wait(ctx, d, changed, wake)
	if err != nil {
		return up, err
	}
	names, all, list := w.tap.take()
	up.all, up.list = all, list
	for _, n := range names {
		if n != "INBOX" {
			up.names = append(up.names, n)
		}
	}
	return up, nil
}

func (w *imapWatch) wait(ctx context.Context, d time.Duration, changed, wake <-chan struct{}) (wakeup, error) {
	inbox := wakeup{names: []string{"INBOX"}}
	// The sync selects only when something changed; IDLE needs INBOX.
	if w.selected != "INBOX" {
		if err := w.sel("INBOX", true); err != nil {
			return wakeup{}, err
		}
	}
	timer := time.NewTimer(max(d, 0))
	defer timer.Stop()
	if !hasIdle(w.c) {
		select {
		case <-ctx.Done():
			return wakeup{}, ctx.Err()
		case <-changed:
			return wakeup{}, errCredentialsChanged
		case <-wake:
			return inbox, nil
		case <-timer.C:
			return inbox, nil
		}
	}
	idle, err := w.c.Idle()
	if err != nil {
		return wakeup{}, err
	}
	var werr error
	select {
	case <-ctx.Done():
		werr = ctx.Err()
	case <-changed:
		werr = errCredentialsChanged
	case <-wake:
	case <-timer.C:
	case <-w.c.Closed():
		werr = errors.New("connection closed")
	}
	if err := idle.Close(); err != nil && werr == nil {
		werr = err
	}
	if werr != nil {
		return wakeup{}, werr
	}
	return inbox, nil
}

func hasIdle(up *imapclient.Client) bool {
	return up.Caps().Has(imap.CapIdle) || up.Caps().Has(imap.CapIMAP4rev2)
}
