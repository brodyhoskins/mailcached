package engine

import (
	"bufio"
	"bytes"
	"cmp"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"maps"
	"net/textproto"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

// The proxy keeps its own copy of each account's mailbox state (folders,
// messages, flags, dates) and serves clients from it. The copy is kept
// current by the account's sync engine (sync.go), whether or not a client
// is connected, and is saved in the Store. Message contents are not part
// of it: a body is fetched from the provider, transformed and cached when a
// client asks for it, or right after new mail arrives (prefetch).
//
// The proxy numbers messages itself. Each message has an ID of its own
// (a UUIDv7) that it keeps when it moves, and a UID in the folder clients
// see it in, which the proxy assigns. It also knows where the provider
// has the message: a folder and the provider's UID there. Usually that is
// the same folder. They differ while a change a client made has not
// reached the provider yet.
//
// Clients never wait on the provider for changes to messages. A flag
// change, copy, move or expunge is made in the proxy's copy at once,
// which every client sees, and queued for the provider (queue.go). The
// queue is saved with the change, so it survives a restart. Folder
// changes and new messages (APPEND) still go to the provider first.

// Account is one provider Account.
type Account struct {
	b      *Engine
	login  string        // lowercased
	loaded chan struct{} // closed once the saved state is restored

	// mu guards the mailbox state below, every mailbox in boxes, and every
	// message.
	mu    sync.Mutex
	delim rune
	boxes map[string]*Mailbox // by name, INBOX in capitals
	// byID holds every message: those clients see, and those expunged
	// whose expunge has not reached the provider yet.
	byID map[uuid.UUID]*Message
	// lastValidity is the last UIDVALIDITY the proxy gave a folder.
	lastValidity uint32
	// emails holds the messages clients see by email ID (EmailID): copies
	// of one message in several folders are one email.
	emails map[string][]*Message
	// log records changes for clients that ask what changed (changes.go).
	log *changeLog
	// since is the cutoff for held messages; holdBusy holds the keys of
	// held messages being read (hold.go).
	since    time.Time
	holdBusy map[string]bool
	authOnce sync.Once
	auth     *authLearn
	tending  atomic.Bool

	// refs counts, per cache key, the messages in all folders that use it
	// (a.mu held). A key no folder uses becomes an orphan; its cached copy
	// is deleted once a full sweep has passed without the key coming back
	// (a message moved elsewhere shows up in its new folder by then).
	refs    map[string]int
	orphans map[string]int // key -> sweep number when it was orphaned
	// checking holds the folders syncLater is checking.
	checking map[string]bool
	sweeps   int // full sweeps completed

	// syncLocks serializes the work on each provider folder: resyncs, and
	// queued changes. Different folders sync in parallel.
	syncLocks sync.Map // name -> *sync.Mutex
	// listMu serializes refreshList, from the read at the provider to the
	// change to a.boxes: a list read before a folder change must not land
	// after the list read since. listedAt is when the folder list was last
	// read from the provider (listMu held).
	listMu   sync.Mutex
	listedAt time.Time

	// The queue of changes for the provider (queue.go), oldest first
	// (a.mu held).
	ops          []*op
	opSeq        int64
	opWake       chan struct{}
	queueRunning atomic.Bool
	// retrying runs the retry of held messages; retryAgain asks for one
	// more.
	retrying, retryAgain atomic.Bool
	// rebinding is set after a switch to another provider, until a sweep
	// has matched the messages there: the queue waits for it.
	rebinding atomic.Bool

	// Credentials from the last successful client login, in memory only,
	// and the provider they reach.
	credMu   sync.Mutex
	password string
	upstream Upstream
	prov     provider      // for upstream; nil before the first login
	running  bool          // the engine is running
	changed  chan struct{} // the credentials changed: reconnect
	notify   chan struct{} // the provider reported a change
	stopped  chan struct{} // closed when the engine ends

	// The backfill (backfill.go): stale is set when there may be messages
	// to backfill.
	backfillStale   atomic.Bool
	backfillRunning atomic.Bool

	// Read-ahead (readahead.go), by folder name.
	raMu sync.Mutex
	ra   map[string]*readAhead

	// Client reads to record (RecordReads): one writer at a time takes
	// the pending keys, so many reads make few transactions.
	readsMu      sync.Mutex
	readsPending map[string]bool
	readsWriting bool
}

// Mailbox is the proxy's copy of one folder.
type Mailbox struct {
	name       string
	jmapID     string // ID for JMAP; kept across renames
	delim      rune
	attrs      []imap.MailboxAttr
	subscribed bool
	// The proxy's numbering, which clients see.
	uidValidity uint32
	uidNext     imap.UID
	// The provider's, as of the last resync.
	pUIDValidity   uint32
	pUIDNext       imap.UID
	highestModSeq  uint64
	flags          []imap.Flag // from the provider's SELECT
	permanentFlags []imap.Flag

	msgs []*Message // what clients see, ordered by UID; a sequence number is index+1
	// atP holds the messages the provider has in this folder, by the
	// provider's UID, whichever folder clients see them in.
	atP     map[imap.UID]*Message
	tracker *imapserver.MailboxTracker

	synced       time.Time // last resync from the provider; zero if never
	flagsFull    time.Time // last full flag comparison (providers without CONDSTORE)
	refetchFlags bool      // compare every flag on the next resync
	// stale is set when clients may see a message the provider has
	// nowhere: the next resync does not stop at STATUS.
	stale      bool
	selectable bool
	// The folder's HIGHESTMODSEQ for clients, and the log's modseq it was
	// computed at (HighestModSeq).
	hms, hmsAt int64
}

type Message struct {
	id  uuid.UUID
	uid imap.UID // in box
	// box is the folder clients see the message in; "" once expunged,
	// until the provider has expunged it too.
	box string
	// pBox and pUID are where the provider has the message; "" and 0 for
	// a copy the provider has not made yet, or a message it lost.
	pBox string
	pUID imap.UID
	// origin is, for a queued copy, the message it copies, which the
	// proxy reads it from until the provider has it.
	origin uuid.UUID
	flags  []imap.Flag
	date   time.Time
	key    string // cache key: fingerprintKey, or idKey without a Message-ID
	// direct is set for a message the proxy does not change (see
	// direct): clients get the provider's copy, through the proxy.
	direct bool
	// pending counts the queued changes that name the message. While it
	// is not zero, the provider's flags do not replace the proxy's.
	pending int
	// held is set for a new message the Transform held (ReadHold): bound
	// at the provider, shown in no folder (box ""), until a Read gives
	// another result (hold.go).
	held bool
}

// account returns the account for login, once its saved state is
// loaded. The load holds no lock of the engine's: other accounts do not
// wait for it, only requests for this one.
func (b *Engine) account(login string) *Account {
	login = strings.ToLower(login)
	b.syncMu.Lock()
	a := b.accounts[login]
	if a != nil {
		b.syncMu.Unlock()
		<-a.loaded
		return a
	}
	a = &Account{b: b, login: login, loaded: make(chan struct{}), boxes: map[string]*Mailbox{}, byID: map[uuid.UUID]*Message{}, delim: '/',
		refs: map[string]int{}, orphans: map[string]int{}, opWake: make(chan struct{}, 1),
		emails: map[string][]*Message{}, log: newChangeLog()}
	a.log.exists = a.exists
	if b.accounts == nil {
		b.accounts = map[string]*Account{}
	}
	b.accounts[login] = a
	b.syncMu.Unlock()
	a.load()
	return a
}

// load restores the account's saved state, then closes a.loaded.
func (a *Account) load() {
	defer close(a.loaded)
	b, login := a.b, a.login
	if b.Store != nil {
		// The provider the state belongs to: state saved for another is
		// dropped.
		var provider string
		if b.Route != nil {
			if u, ok := b.Route(login); ok {
				provider = u.String()
			}
		}
		start := time.Now()
		a.loadSince()
		saved, err := b.Store.load(login, provider)
		if err != nil {
			b.Log.Warn("imap: could not load saved mailbox state", "user", login, "err", err)
		}
		if saved != nil {
			a.restore(saved)
			// The first request for the account after a start waits for
			// this, and every other account's first request with it.
			b.Log.Info("account state loaded", "user", login, "messages", len(a.byID), "took", time.Since(start).Round(time.Millisecond))
		}
	}
}

// isLoaded reports whether the account's saved state is restored.
func (a *Account) isLoaded() bool {
	select {
	case <-a.loaded:
		return true
	default:
		return false
	}
}

// Preload loads, in the background, the saved state of every account
// that has some and that a route still covers, so a client's first login
// after a start does not wait for it. An account whose folder is named by
// a hash is loaded at its first login instead.
func (b *Engine) Preload() {
	if b.Store == nil || b.Route == nil {
		return
	}
	entries, err := os.ReadDir(filepath.Join(b.Store.Dir, "accounts"))
	if err != nil {
		return
	}
	b.preloadWG.Go(func() {
		for _, e := range entries {
			b.syncMu.Lock()
			closing := b.closing
			b.syncMu.Unlock()
			if closing {
				return
			}
			name := e.Name()
			// A hash names the folder of a login that is not safe as a
			// name: the hash is not that login.
			if !e.IsDir() || hashName.MatchString(name) || !safeName.MatchString(name) || accountDir(b.Store.Dir, name) != filepath.Join(b.Store.Dir, "accounts", name) {
				continue
			}
			if _, ok := b.Route(name); ok {
				b.account(name)
			}
		}
	})
}

// restore takes over saved state.
func (a *Account) restore(saved *savedState) {
	if saved.log != nil {
		a.log = saved.log
		a.log.exists = a.exists
	}
	if saved.rebind {
		a.rebinding.Store(true)
		a.b.Log.Info("the account has a new provider: matching its messages to the saved state", "user", a.login)
	}
	for _, s := range saved.boxes {
		if s.jmapID == "" {
			s.jmapID = newMailboxID()
		}
		a.boxes[s.name] = &Mailbox{
			name: s.name, jmapID: s.jmapID, delim: s.delim, attrs: s.attrs, subscribed: s.subscribed,
			uidValidity: s.uidValidity, uidNext: s.uidNext,
			pUIDValidity: s.pUIDValidity, pUIDNext: s.pUIDNext, highestModSeq: s.highestModSeq,
			atP: map[imap.UID]*Message{}, selectable: !HasAttr(s.attrs, imap.MailboxAttrNoSelect),
		}
		a.lastValidity = max(a.lastValidity, s.uidValidity)
		if s.delim != 0 {
			a.delim = s.delim
		}
	}
	for _, msg := range saved.msgs {
		a.byID[msg.id] = msg
		if m := a.boxes[msg.box]; m != nil {
			m.msgs = append(m.msgs, msg)
		} else {
			msg.box = ""
		}
		if m := a.boxes[msg.pBox]; m != nil && msg.pUID != 0 {
			m.atP[msg.pUID] = msg
		} else {
			msg.pBox, msg.pUID = "", 0
		}
	}
	for _, m := range a.boxes {
		m.tracker = imapserver.NewMailboxTracker(uint32(len(m.msgs)))
		a.track(m.msgs, nil)
	}
	a.ops = saved.ops
	for _, o := range a.ops {
		a.opSeq = max(a.opSeq, o.seq)
		for _, id := range o.ids {
			if msg := a.byID[id]; msg != nil {
				msg.pending++
			}
		}
	}
	// Expunged messages nothing waits on any more.
	tx := a.begin()
	for _, msg := range a.byID {
		if msg.box == "" && msg.pending == 0 && !msg.held {
			a.forget(msg, tx)
		}
	}
	if err := tx.commit(); err != nil {
		a.b.Log.Warn("imap: could not save mailbox state", "user", a.login, "err", err)
	}
}

func HasAttr(attrs []imap.MailboxAttr, a imap.MailboxAttr) bool {
	return slices.ContainsFunc(attrs, func(x imap.MailboxAttr) bool { return strings.EqualFold(string(x), string(a)) })
}

// checkPassword reports whether password is the one the provider last
// accepted for this account.
func (a *Account) checkPassword(password string, u Upstream) bool {
	a.credMu.Lock()
	defer a.credMu.Unlock()
	return a.password != "" && a.upstream.same(u) &&
		subtle.ConstantTimeCompare([]byte(a.password), []byte(password)) == 1
}

// setCredentials records credentials the provider accepted and starts the
// engine if it is not running.
func (a *Account) setCredentials(password string, u Upstream) {
	a.credMu.Lock()
	defer a.credMu.Unlock()
	if a.password != password || !a.upstream.same(u) {
		if !a.upstream.same(u) {
			if a.prov != nil {
				a.prov.Close()
			}
			a.prov = a.b.newProvider(a, u)
		}
		a.password, a.upstream = password, u
		if a.running {
			select {
			case a.changed <- struct{}{}:
			default:
			}
		}
	}
	if !a.running {
		a.running = true
		a.changed = make(chan struct{}, 1)
		a.notify = make(chan struct{}, 1)
		a.stopped = make(chan struct{})
		go a.run(a.b.syncCtx())
	}
}

// forgetCredentials drops the password, after the provider rejected it.
func (a *Account) forgetCredentials() {
	a.credMu.Lock()
	a.password = ""
	p := a.prov
	a.credMu.Unlock()
	if p != nil {
		p.Close()
	}
}

func (a *Account) credentials() (string, Upstream) {
	a.credMu.Lock()
	defer a.credMu.Unlock()
	return a.password, a.upstream
}

// ErrNoCredentials means no client has logged in since the provider last
// rejected the password, or since the proxy started.
var ErrNoCredentials = errors.New("no credentials for the account")

// providerFor returns the provider for u, replacing the one for another
// upstream.
func (a *Account) providerFor(u Upstream) provider {
	a.credMu.Lock()
	defer a.credMu.Unlock()
	if a.prov != nil && a.upstream.same(u) {
		return a.prov
	}
	if a.prov != nil {
		a.prov.Close()
	}
	a.prov = a.b.newProvider(a, u)
	a.upstream = u
	if a.password != "" {
		// For the old upstream.
		a.password = ""
	}
	return a.prov
}

// newProvider makes the provider for u.
func (b *Engine) newProvider(a *Account, u Upstream) provider {
	password := func() string {
		a.credMu.Lock()
		defer a.credMu.Unlock()
		if !a.upstream.same(u) {
			return ""
		}
		return a.password
	}
	if u.URL != "" {
		return newJMAPProvider(a, u, password)
	}
	if u.ActiveSync != "" {
		return newEASProvider(a, u, password)
	}
	p := newIMAPProvider(a.login, u, b.id(), b.syncSection, password, b.Log)
	for _, s := range p.srcs {
		s.host = b.imapHost(u.Addr, s.addr)
		s.host.add(s)
	}
	return p
}

// conn returns a provider connection for one request. hint names the
// folder it is about, "" for none. Call its Release.
func (a *Account) conn(p priority, hint string) (conn, error) {
	a.credMu.Lock()
	prov := a.prov
	a.credMu.Unlock()
	if prov == nil {
		return nil, ErrNoCredentials
	}
	return prov.Conn(p, hint)
}

// --- Model changes (a.mu held) --------------------------------------------

// box returns the mailbox, creating an empty one with a new UIDVALIDITY.
func (a *Account) box(name string) *Mailbox {
	name = CanonicalName(name)
	m := a.boxes[name]
	if m == nil {
		m = &Mailbox{name: name, jmapID: newMailboxID(), delim: a.delim, selectable: true, uidValidity: a.newValidity(), uidNext: 1,
			atP: map[imap.UID]*Message{}, tracker: imapserver.NewMailboxTracker(0)}
		a.boxes[name] = m
		a.log.touch(KindMailbox, m.jmapID, false)
	}
	return m
}

// newMailboxID returns a new JMAP ID for a folder.
func newMailboxID() string { return "m" + newEpoch() + newEpoch() }

// EmailID is the JMAP ID of the email with cache key key.
func EmailID(key string) string { return "e" + key[:min(len(key), 24)] }

// newValidity returns a UIDVALIDITY no folder of the account had: the
// time, as Cyrus and Dovecot do, but always larger than the last.
func (a *Account) newValidity() uint32 {
	v := uint32(time.Now().Unix())
	if v <= a.lastValidity {
		v = a.lastValidity + 1
	}
	a.lastValidity = v
	return v
}

// track updates the reference counts and the emails after messages were
// added to folders and removed (a.mu held).
func (a *Account) track(added, removed []*Message) {
	for _, msg := range added {
		a.refs[msg.key]++
		delete(a.orphans, msg.key)
		id := EmailID(msg.key)
		a.emails[id] = append(a.emails[id], msg)
	}
	for _, msg := range removed {
		if a.refs[msg.key]--; a.refs[msg.key] <= 0 {
			delete(a.refs, msg.key)
			a.orphans[msg.key] = a.sweeps
		}
		id := EmailID(msg.key)
		if l := slices.DeleteFunc(a.emails[id], func(x *Message) bool { return x == msg }); len(l) > 0 {
			a.emails[id] = l
		} else {
			delete(a.emails, id)
		}
	}
}

// exists reports whether an object of the change log exists (a.mu held).
func (a *Account) exists(kind, id string) bool {
	switch kind {
	case KindEmail:
		return a.emails[id] != nil
	case KindMailbox:
		return a.mailboxByID(id) != nil
	}
	return false
}

// mailboxByID finds a folder by its JMAP ID (a.mu held).
func (a *Account) mailboxByID(id string) *Mailbox {
	for _, m := range a.boxes {
		if m.jmapID == id {
			return m
		}
	}
	return nil
}

// purgeOrphans deletes cached copies no folder has used since before the
// last full sweep (a.mu held).
func (a *Account) purgeOrphans() {
	var gone []string
	for key, since := range a.orphans {
		if since >= a.sweeps-1 {
			continue
		}
		if err := a.b.Cache.Delete(a.login, key); err != nil {
			a.b.Log.Warn("imap: cache delete failed", "user", a.login, "err", err)
			continue
		}
		delete(a.orphans, key)
		gone = append(gone, key)
	}
	if err := a.b.Store.deleteHeaders(a.login, gone); err != nil {
		a.b.Log.Warn("imap: could not delete header entries", "user", a.login, "err", err)
	}
}

// show adds msg to folder m with the next UID, and tells clients.
func (a *Account) show(m *Mailbox, msg *Message, tx *storeTx) {
	msg.box, msg.uid = m.name, m.uidNext
	m.uidNext++
	m.msgs = append(m.msgs, msg)
	m.tracker.QueueNumMessages(uint32(len(m.msgs)))
	a.track([]*Message{msg}, nil)
	a.log.touch(KindEmail, EmailID(msg.key), false)
	a.log.touch(KindMailbox, m.jmapID, true)
	tx.putMessage(msg)
}

// hide removes the messages gone reports true for from folder m, tells
// clients, and returns them, their box cleared. Saving them is up to the
// caller.
func (a *Account) hide(m *Mailbox, gone func(*Message) bool) []*Message {
	var removed []*Message
	for i := len(m.msgs) - 1; i >= 0; i-- { // high to low keeps numbers valid
		if !gone(m.msgs[i]) {
			continue
		}
		msg := m.msgs[i]
		msg.box = ""
		removed = append(removed, msg)
		m.msgs = slices.Delete(m.msgs, i, i+1)
		m.tracker.QueueExpunge(uint32(i) + 1)
	}
	a.track(nil, removed)
	for _, msg := range removed {
		a.log.touch(KindEmail, EmailID(msg.key), false)
	}
	if len(removed) > 0 {
		a.log.touch(KindMailbox, m.jmapID, true)
	}
	return removed
}

// setFlags records a message's flags. source, if not nil, is the client
// view that made the change and reports it itself.
func (a *Account) setFlags(msg *Message, flags []imap.Flag, source *imapserver.SessionTracker, tx *storeTx) {
	if sameFlags(msg.flags, flags) {
		return
	}
	seen := HasFlag(msg.flags, imap.FlagSeen) != HasFlag(flags, imap.FlagSeen)
	msg.flags = flags
	tx.putMessage(msg)
	m := a.boxes[msg.box]
	if m == nil {
		return
	}
	a.log.touch(KindEmail, EmailID(msg.key), false)
	if seen {
		a.log.touch(KindMailbox, m.jmapID, true)
	}
	if i, ok := m.index(msg.uid); ok {
		m.tracker.QueueMessageFlags(uint32(i)+1, msg.uid, flags, source)
	}
}

// index finds a UID in m.msgs.
func (m *Mailbox) index(uid imap.UID) (int, bool) {
	return slices.BinarySearchFunc(m.msgs, uid, func(x *Message, u imap.UID) int { return cmp.Compare(x.uid, u) })
}

// bind records that the provider has msg in folder name under pUID.
func (a *Account) bind(msg *Message, name string, pUID imap.UID, tx *storeTx) {
	if msg.pUID != 0 {
		if m := a.boxes[msg.pBox]; m != nil && m.atP[msg.pUID] == msg {
			delete(m.atP, msg.pUID)
		}
	}
	msg.pBox, msg.pUID, msg.origin = name, pUID, uuid.Nil()
	a.box(name).atP[pUID] = msg
	tx.putMessage(msg)
}

// lose records that the provider no longer has msg where the proxy
// thought. An expunged message nothing waits on is forgotten; one clients
// see stays until the queue or a resync settles it.
func (a *Account) lose(msg *Message, tx *storeTx) {
	if m := a.boxes[msg.pBox]; m != nil && msg.pUID != 0 && m.atP[msg.pUID] == msg {
		delete(m.atP, msg.pUID)
	}
	if m := a.boxes[msg.box]; m != nil && msg.box != msg.pBox {
		m.stale = true
	}
	msg.pBox, msg.pUID = "", 0
	if msg.box == "" && msg.pending == 0 {
		a.forget(msg, tx)
		return
	}
	tx.putMessage(msg)
}

// forget drops a message clients no longer see.
func (a *Account) forget(msg *Message, tx *storeTx) {
	if m := a.boxes[msg.pBox]; m != nil && msg.pUID != 0 && m.atP[msg.pUID] == msg {
		delete(m.atP, msg.pUID)
	}
	delete(a.byID, msg.id)
	tx.deleteMessage(msg)
}

func sameFlags(a, b []imap.Flag) bool {
	if len(a) != len(b) {
		return false
	}
	for _, f := range a {
		if !HasFlag(b, f) {
			return false
		}
	}
	return true
}

// --- Resync ---------------------------------------------------------------

// lockFolders takes the sync locks of the folders, in name order, and
// returns the function that releases them.
func (a *Account) lockFolders(names ...string) func() {
	for i := range names {
		names[i] = CanonicalName(names[i])
	}
	slices.Sort(names)
	names = slices.Compact(names)
	locks := make([]*sync.Mutex, len(names))
	for i, name := range names {
		l, _ := a.syncLocks.LoadOrStore(name, &sync.Mutex{})
		locks[i] = l.(*sync.Mutex)
		locks[i].Lock()
	}
	return func() {
		for i := len(locks) - 1; i >= 0; i-- {
			locks[i].Unlock()
		}
	}
}

// resync brings the proxy's copy of one folder up to date over c. Cheap
// when nothing changed.
func (a *Account) resync(c conn, name string) error {
	defer a.lockFolders(name)()
	return a.resyncLocked(c, CanonicalName(name), false)
}

// resyncLocked is resync with the folder's sync lock held. force skips the
// check that nothing changed.
//
// A message the provider has and the proxy does not know is matched, by
// its cache key, with a message clients see in the folder that the
// provider has nowhere yet: a queued copy, or one whose move the provider
// made without saying where to. Only messages left over are new. Messages
// clients see that the provider has nowhere and no queued change will
// bring are then removed.
func (a *Account) resyncLocked(c conn, name string, force bool) error {
	a.mu.Lock()
	m := a.box(name)
	st := syncState{
		validity: m.pUIDValidity, next: m.pUIDNext, modSeq: m.highestModSeq, count: len(m.atP),
		synced: !m.synced.IsZero(), stale: m.stale, force: force,
		refetchFlags: m.refetchFlags, flagsFull: m.flagsFull,
		known: func(u imap.UID) bool {
			a.mu.Lock()
			defer a.mu.Unlock()
			m := a.boxes[name]
			return m != nil && m.atP[u] != nil
		},
	}
	a.mu.Unlock()
	// The account lock and the database are never held while waiting on
	// the provider.
	d, err := c.Sync(name, st)
	if err != nil {
		return err
	}
	a.awaitNewMail(name, d.fresh, d.reset)

	a.mu.Lock()
	defer a.mu.Unlock()
	m = a.box(name)
	if d.unchanged {
		m.synced = time.Now()
		return nil
	}
	// Mail that arrives after the folder's first sync is new: downloaded
	// right away, before clients are told if it takes no longer than
	// NewMailWait (newmail.go), after if it does.
	known := !d.reset && m.pUIDNext > 0
	tx := a.begin()
	if d.reset {
		for _, msg := range m.atP {
			a.lose(msg, tx)
		}
	}
	if d.present != nil {
		for u, msg := range m.atP {
			if !d.present[u] {
				a.lose(msg, tx)
			}
		}
	}
	for _, u := range d.gone {
		if msg := m.atP[u]; msg != nil {
			a.lose(msg, tx)
		}
	}
	for _, f := range d.flags {
		if msg := m.atP[f.uid]; msg != nil && msg.pending == 0 {
			a.setFlags(msg, f.flags, nil, tx)
		}
	}

	fresh := slices.Clone(d.fresh)
	slices.SortFunc(fresh, func(x, y freshMessage) int { return cmp.Compare(x.uid, y.uid) })
	var unbound map[string][]*Message
	var added, held, ahead []*Message
	for _, f := range fresh {
		if m.atP[f.uid] != nil {
			continue
		}
		key := a.keyFor(f)
		if unbound == nil {
			unbound = map[string][]*Message{}
			for _, msg := range m.msgs {
				if msg.pUID == 0 {
					unbound[msg.key] = append(unbound[msg.key], msg)
				}
			}
		}
		if l := unbound[key]; key != "" && len(l) > 0 {
			msg := l[0]
			unbound[key] = l[1:]
			a.bind(msg, name, f.uid, tx)
			if msg.pending == 0 {
				a.setFlags(msg, f.flags, nil, tx)
			}
			continue
		}
		msg := &Message{id: uuid.NewV7(), flags: f.flags, date: f.date, key: key, direct: a.b.direct(f.header)}
		if key == "" {
			msg.key = idKey(a.login, msg.id)
		}
		a.byID[msg.id] = msg
		a.bind(msg, name, f.uid, tx)
		if a.mustCheck(msg) {
			// New mail the Transform changes: read before clients see it.
			msg.held = true
			tx.putMessage(msg)
			held = append(held, msg)
			continue
		}
		a.show(m, msg, tx)
		added = append(added, msg)
		// New mail is downloaded ahead of clients, but a large message
		// the proxy does not change waits: a client may read only part of
		// it (piece.go).
		if !msg.direct || f.size <= PieceWhole {
			ahead = append(ahead, msg)
		}
	}
	if len(held) > 0 {
		go a.checkHeld(held)
	}
	// What clients see here that the provider has nowhere, and no queued
	// change will bring.
	for _, msg := range a.hide(m, func(msg *Message) bool { return msg.pUID == 0 && msg.pending == 0 }) {
		a.forget(msg, tx)
	}
	if len(added) > 0 {
		a.backfillStale.Store(true)
	}
	if known && len(ahead) > 0 {
		go a.prefetch(ahead)
	}

	m.pUIDValidity, m.pUIDNext, m.highestModSeq = d.validity, d.next, d.modSeq
	if !sameFlags(m.flags, d.folderFlags) {
		m.flags = d.folderFlags
		m.tracker.QueueMailboxFlags(d.folderFlags)
	}
	// A read-only SELECT reports no permanent flags; clients still change
	// flags through the proxy, which does it read-write.
	m.permanentFlags = d.permanentFlags
	if len(m.permanentFlags) == 0 {
		m.permanentFlags = append(slices.Clone(d.folderFlags), imap.FlagWildcard)
	}
	m.synced, m.stale = time.Now(), false
	if d.fullFlags {
		m.flagsFull, m.refetchFlags = m.synced, false
	}
	tx.putMailbox(m)
	if err := tx.commit(); err != nil {
		a.b.Log.Warn("imap: could not save mailbox state", "user", a.login, "mailbox", name, "err", err)
	}
	return nil
}

// syncSection fetches the header fields the sync needs: Message-ID, and
// those the Transform needs to say whether it changes the message.
func (b *Engine) syncSection() *imap.FetchItemBodySection {
	b.syncOnce.Do(func() {
		fields := []string{"Message-ID"}
		if b.Transform != nil {
			fields = append(fields, b.Transform.Fields()...)
		}
		b.syncSec = &imap.FetchItemBodySection{Specifier: imap.PartSpecifierHeader, HeaderFields: fields, Peek: true}
	})
	return b.syncSec
}

// keyFor computes a message's cache key: its fingerprint, or "" without a
// Message-ID.
func (a *Account) keyFor(f freshMessage) string {
	if id := parseHeader(f.header).Get("Message-Id"); id != "" && f.size > 0 {
		return fingerprintKey(a.login, strings.TrimSpace(id), f.size, f.date)
	}
	return ""
}

// parseHeader parses a block of header fields, unfolding continuation
// lines.
func parseHeader(hdr []byte) textproto.MIMEHeader {
	// A copy: hdr may share its array, and append would write into it.
	h, _ := textproto.NewReader(bufio.NewReader(bytes.NewReader(append(hdr[:len(hdr):len(hdr)], "\r\n"...)))).ReadMIMEHeader()
	return h
}

// direct reports, from a message's syncSection fields, whether the proxy
// leaves it as it is. Such a message is served as the provider has it,
// without downloading it whole.
func (b *Engine) direct(hdr []byte) bool {
	return b.Transform == nil || !b.Transform.Changes(parseHeader(hdr))
}

// fullFlagInterval is how often flags are compared in full on providers
// without CONDSTORE, which cannot say which flags changed.
var fullFlagInterval = 10 * time.Minute

// refreshList reads the folder list from the provider.
func (a *Account) refreshList(c conn) error {
	a.listMu.Lock()
	defer a.listMu.Unlock()
	list, err := c.List()
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	tx := a.begin()
	seen := map[string]bool{}
	for _, f := range list {
		seen[f.name] = true
		if f.delim != 0 {
			a.delim = f.delim
		}
		m := a.box(f.name)
		if m.delim != f.delim || !slices.Equal(m.attrs, f.attrs) || m.selectable != f.selectable || m.subscribed != f.subscribed {
			a.log.touch(KindMailbox, m.jmapID, false)
		}
		m.delim, m.attrs, m.selectable, m.subscribed = f.delim, f.attrs, f.selectable, f.subscribed
		tx.putMailbox(m)
	}
	for name, m := range a.boxes {
		if !seen[name] {
			for _, msg := range m.atP {
				a.lose(msg, tx)
			}
			for _, msg := range a.hide(m, func(*Message) bool { return true }) {
				if msg.pending == 0 {
					a.forget(msg, tx)
				} else {
					tx.putMessage(msg)
				}
			}
			tx.deleteMailbox(name)
			delete(a.boxes, name)
			a.log.touch(KindMailbox, m.jmapID, false)
		}
	}
	a.listedAt = time.Now()
	if err := tx.commit(); err != nil {
		a.b.Log.Warn("imap: could not save folder list", "user", a.login, "err", err)
	}
	return nil
}

// syncNow refreshes one folder over a pool connection, for a client that
// needs it current (after a change, or on SELECT).
// syncLater checks a folder at the provider in the background, once at a
// time per folder.
func (a *Account) syncLater(name string) {
	a.mu.Lock()
	if a.checking == nil {
		a.checking = map[string]bool{}
	}
	if a.checking[name] {
		a.mu.Unlock()
		return
	}
	a.checking[name] = true
	a.mu.Unlock()
	go func() {
		defer func() {
			a.mu.Lock()
			delete(a.checking, name)
			a.mu.Unlock()
		}()
		if err := a.syncNow(name); err != nil && !errors.Is(err, ErrNoCredentials) {
			a.b.Log.Warn("sync: could not check folder", "user", a.login, "mailbox", name, "err", err)
		}
	}()
}

func (a *Account) syncNow(name string) error {
	c, err := a.conn(interactive, "")
	if err != nil {
		return err
	}
	err = a.resync(c, name)
	c.Release(err)
	return err
}

// listNow refreshes the folder list over a pool connection.
func (a *Account) listNow() error {
	c, err := a.conn(interactive, "")
	if err != nil {
		return err
	}
	err = a.refreshList(c)
	c.Release(err)
	return err
}

// syncCtx is cancelled when the proxy closes.
func (b *Engine) syncCtx() context.Context {
	b.syncMu.Lock()
	defer b.syncMu.Unlock()
	if b.syncCancel == nil {
		b.syncBase, b.syncCancel = context.WithCancel(context.Background())
	}
	return b.syncBase
}

// stopSync ends every engine and drops every password.
func (b *Engine) stopSync() {
	b.syncMu.Lock()
	cancel, accounts := b.syncCancel, slices.Collect(maps.Values(b.accounts))
	b.syncMu.Unlock()
	// An account may still be loading for a login: Close returns only
	// once the Store is no longer in use.
	for _, a := range accounts {
		<-a.loaded
	}
	if cancel != nil {
		cancel()
	}
	for _, a := range accounts {
		a.credMu.Lock()
		running, stopped := a.running, a.stopped
		a.credMu.Unlock()
		if running {
			<-stopped
		}
		a.forgetCredentials()
	}
}

func (a *Account) String() string { return fmt.Sprintf("account %s", a.login) }
