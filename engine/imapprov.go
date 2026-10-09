package engine

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/brodyhoskins/mailcached/config"
	"github.com/brodyhoskins/mailcached/internal/netbind"
)

// imapProvider reaches an IMAP provider for one account. Requests share a
// small pool of connections; the engine has one more of its own (Watch),
// which idles on INBOX.
type imapProvider struct {
	login   string
	u       Upstream
	id      *imap.IDData
	section func() *imap.FetchItemBodySection // syncSection
	// password returns the password the provider last accepted, "" for
	// none.
	password func() string

	// The pool of connections for client requests.
	poolMu      sync.Mutex
	poolCond    *sync.Cond
	idle        []*imapConn
	open        int
	bulkBusy    int // connections held by bulk requests
	prioWaiting int // interactive requests waiting
}

func newIMAPProvider(login string, u Upstream, id *imap.IDData, section func() *imap.FetchItemBodySection, password func() string) *imapProvider {
	p := &imapProvider{login: login, u: u, id: id, section: section, password: password}
	p.poolCond = sync.NewCond(&p.poolMu)
	return p
}

// login connects to the provider, logs in with the client's credentials
// and turns on COMPRESS=DEFLATE if the provider offers it. id names the
// proxy to providers that ask. h receives unsolicited responses. A provider's NO comes back as an *imap.Error.
func (u *Upstream) login(username, password string, id *imap.IDData, h *imapclient.UnilateralDataHandler, tap *notifyTap) (c *imapclient.Client, compressed bool, notify notifyMode, err error) {
	tlsCfg := u.TLSConfig
	if tlsCfg == nil {
		host, _, _ := net.SplitHostPort(u.Addr)
		tlsCfg = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	}
	timeout := u.Timeout
	if timeout <= 0 {
		timeout = time.Minute
	}
	d := netbind.Dialer(u.Source, timeout, dialControl(timeout))
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

// dial opens a connection with the accepted password.
func (p *imapProvider) dial(h *imapclient.UnilateralDataHandler, tap *notifyTap) (*imapclient.Client, bool, notifyMode, error) {
	password := p.password()
	if password == "" {
		return nil, false, 0, ErrNoCredentials
	}
	return p.u.login(p.login, password, p.id, h, tap)
}

// rejected marks a NO to LOGIN, so callers can tell it from any other NO.
func rejected(err error) error {
	var ie *imap.Error
	if errors.As(err, &ie) && ie.Type == imap.StatusResponseTypeNo {
		return fmt.Errorf("%w: %w", ErrLoginRejected, ie)
	}
	return err
}

func (p *imapProvider) Login(password string) error {
	c, _, _, err := p.u.login(p.login, password, p.id, ignoreUnilateral, nil)
	if err != nil {
		return rejected(err)
	}
	// Keep the connection for client requests, if the pool has room.
	p.poolMu.Lock()
	room := p.open < poolSize
	if room {
		p.open++
	}
	p.poolMu.Unlock()
	if room {
		(&imapConn{p: p, c: c}).Release(nil)
	} else {
		c.Close()
	}
	return nil
}

// --- Pool -----------------------------------------------------------------

// poolSize bounds the provider connections bulk requests use. One more is
// kept for interactive requests, beside the engine's own connection.
const poolSize = 4

// ignoreUnilateral consumes unsolicited data on pool connections: the
// engine keeps the mailbox state, not these connections.
var ignoreUnilateral = &imapclient.UnilateralDataHandler{
	Fetch: func(msg *imapclient.FetchMessageData) { _, _ = msg.Collect() },
}

// Requests on the pool are interactive (a client waits on them: opening a
// folder, a few messages, a flag change) or bulk (a large download). Bulk
// requests hold at most poolSize connections, so one is always left for
// interactive ones, and an interactive request that waits is served before
// any waiting bulk request. New mail therefore opens at once even during a
// large download.
type priority bool

const (
	bulk        priority = false
	interactive priority = true
)

// Conn returns a pooled connection. A pooled connection the provider
// dropped while idle is replaced once.
func (p *imapProvider) Conn(prio priority, hint string) (conn, error) {
	pc, err := p.conn1(prio, hint)
	var ie *imap.Error
	if err != nil && !errors.As(err, &ie) && !errors.Is(err, ErrNoCredentials) {
		pc, err = p.conn1(prio, hint)
	}
	if err != nil {
		return nil, err
	}
	return pc, nil
}

func (p *imapProvider) conn1(prio priority, hint string) (*imapConn, error) {
	p.poolMu.Lock()
	if prio == interactive {
		p.prioWaiting++
	}
	var pc *imapConn
	for pc == nil {
		// Bulk waits while interactive requests wait, and never takes the
		// connection reserved for them.
		if prio == bulk && (p.prioWaiting > 0 || p.bulkBusy >= poolSize) {
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
				p.open--
				pc = nil
				continue
			default:
			}
			break
		}
		if p.open < poolSize+1 {
			p.open++
			p.poolMu.Unlock()
			c, _, _, err := p.dial(ignoreUnilateral, nil)
			p.poolMu.Lock()
			if err != nil {
				p.open--
				if prio == interactive {
					p.prioWaiting--
				}
				p.poolCond.Broadcast()
				p.poolMu.Unlock()
				return nil, err
			}
			pc = &imapConn{p: p, c: c}
			break
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
	return pc, nil
}

// Close closes the idle connections.
func (p *imapProvider) Close() {
	p.poolMu.Lock()
	defer p.poolMu.Unlock()
	for _, pc := range p.idle {
		pc.c.Close()
		p.open--
	}
	p.idle = nil
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
}

// Release returns a pooled connection to the pool, or closes it if err
// shows it is broken. The engine's connection is closed.
func (pc *imapConn) Release(err error) {
	if pc.watch {
		pc.c.Close()
		return
	}
	var ie *imap.Error
	broken := err != nil && !errors.As(err, &ie)
	p := pc.p
	p.poolMu.Lock()
	defer p.poolMu.Unlock()
	if pc.bulk {
		pc.bulk = false
		p.bulkBusy--
	}
	if broken {
		pc.c.Close()
		p.open--
	} else {
		p.idle = append(p.idle, pc)
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
	if c.Caps().Has(imap.CapUIDPlus) || c.Caps().Has(imap.CapIMAP4rev2) {
		_, err = c.UIDExpunge(set).Collect()
	} else {
		// Expunges every message with \Deleted; the resync finds any
		// others.
		_, err = c.Expunge().Collect()
	}
	return err
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
	c, compressed, mode, err := p.dial(&imapclient.UnilateralDataHandler{
		Expunge: func(uint32) { notify() },
		Mailbox: func(*imapclient.UnilateralDataMailbox) { notify() },
		Fetch: func(msg *imapclient.FetchMessageData) {
			_, _ = msg.Collect()
			notify()
		},
	}, tap)
	if err != nil {
		return nil, rejected(err)
	}
	return &imapWatch{imapConn: &imapConn{p: p, c: c, watch: true}, compressed: compressed, notify: mode, tap: tap}, nil
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
