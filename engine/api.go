package engine

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"
	"uuid"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"
)

// This file is what the client protocols use. The read accessors of
// Account, Mailbox and Message need the account lock (Lock); the other
// methods take it themselves.
//
// The changes to messages (flags, copies, moves, expunges) are made in the
// proxy's copy at once, which every client sees, and queued for the
// provider (queue.go): clients never wait on it.

var (
	// ErrNoAccount means no provider serves the login.
	ErrNoAccount = errors.New("no account matches the login")
	// ErrNoMailbox means the folder does not exist, or cannot hold
	// messages.
	ErrNoMailbox = errors.New("no such mailbox")
)

// Account returns the account for login, loading its saved state.
func (b *Engine) Account(login string) *Account { return b.account(login) }

// Lock takes the account lock, which the read accessors need.
func (a *Account) Lock() { a.mu.Lock() }

// Unlock releases the account lock.
func (a *Account) Unlock() { a.mu.Unlock() }

// User returns the login name, lowercased.
func (a *Account) User() string { return a.login }

// Mailbox returns a folder, or nil (lock held).
func (a *Account) Mailbox(name string) *Mailbox { return a.boxes[CanonicalName(name)] }

// Mailboxes returns every folder, in no order (lock held).
func (a *Account) Mailboxes() []*Mailbox {
	out := make([]*Mailbox, 0, len(a.boxes))
	for _, m := range a.boxes {
		out = append(out, m)
	}
	return out
}

// Delim returns the hierarchy delimiter (lock held).
func (a *Account) Delim() rune { return a.delim }

// Message returns a message by its ID, or nil (lock held). An expunged
// message the provider has not expunged yet has Box "".
func (a *Account) Message(id uuid.UUID) *Message { return a.byID[id] }

// Mailbox accessors (lock held).

func (m *Mailbox) Name() string                        { return m.name }
func (m *Mailbox) Delim() rune                         { return m.delim }
func (m *Mailbox) Attrs() []imap.MailboxAttr           { return m.attrs }
func (m *Mailbox) Subscribed() bool                    { return m.subscribed }
func (m *Mailbox) Selectable() bool                    { return m.selectable }
func (m *Mailbox) UIDValidity() uint32                 { return m.uidValidity }
func (m *Mailbox) UIDNext() imap.UID                   { return m.uidNext }
func (m *Mailbox) Flags() []imap.Flag                  { return m.flags }
func (m *Mailbox) PermanentFlags() []imap.Flag         { return m.permanentFlags }
func (m *Mailbox) Tracker() *imapserver.MailboxTracker { return m.tracker }

// Synced returns when the folder was last synced; zero if never.
func (m *Mailbox) Synced() time.Time { return m.synced }

// Msgs returns the messages clients see, by UID. A sequence number is the
// index plus one. The caller must not change the slice.
func (m *Mailbox) Msgs() []*Message { return m.msgs }

// Index finds a message by UID in Msgs.
func (m *Mailbox) Index(uid imap.UID) (int, bool) { return m.index(uid) }

// Message accessors. ID, Date, Key and Direct never change; the others
// need the lock.

func (msg *Message) ID() uuid.UUID      { return msg.id }
func (msg *Message) Date() time.Time    { return msg.date }
func (msg *Message) UID() imap.UID      { return msg.uid }
func (msg *Message) Box() string        { return msg.box }
func (msg *Message) Flags() []imap.Flag { return msg.flags }

// Key is the message's cache key. Copies of a message share it.
func (msg *Message) Key() string { return msg.key }

// Direct says the Transform leaves the message as the provider has it.
func (msg *Message) Direct() bool { return msg.direct }

// --- Login and folders ----------------------------------------------------

// Login checks the credentials against the provider, unless the provider
// already accepted the same password for this account. The first login
// after a restart, or after a password change, always goes to the
// provider. It returns ErrNoAccount, an error that wraps
// ErrLoginRejected, or the error that kept it from the provider.
func (a *Account) Login(password string) error {
	u, ok := a.b.Route(a.login)
	if !ok {
		return ErrNoAccount
	}
	if !a.checkPassword(password, u) {
		if err := a.providerFor(u).Login(password); err != nil {
			return err
		}
		a.b.Log.Info("login checked with the provider", "user", a.login, "upstream", u.String())
		a.setCredentials(password, u)
	}
	a.mu.Lock()
	empty := len(a.boxes) == 0
	a.mu.Unlock()
	if empty {
		// First login ever: the folder list cannot wait for the engine.
		if err := a.listNow(); err != nil {
			a.b.Log.Warn("could not read folders", "user", a.login, "err", err)
		}
	}
	return nil
}

// SelectFresh is how old a folder's state may be when a client opens it
// before the engine checks the provider again.
var SelectFresh = 5 * time.Second

// SelectWaits makes opening a folder synced before wait for the check;
// tests set it. Otherwise the client gets the engine's state at once, and
// what the check finds reaches it as updates, as for any change at the
// provider. A client that switches folders often, as Apple Mail does,
// would otherwise wait on the provider every time.
var SelectWaits = false

// MailboxFor returns the folder, checking it at the provider if its state
// is older than selectFresh: before returning for a folder never synced
// (or if SelectWaits), in the background otherwise. It returns
// ErrNoMailbox for a folder that does not exist or cannot hold messages,
// or the provider's error for one never synced.
func (a *Account) MailboxFor(name string) (*Mailbox, error) {
	a.mu.Lock()
	m := a.boxes[CanonicalName(name)]
	stale := m == nil || time.Since(m.synced) > SelectFresh
	wait := m == nil || m.synced.IsZero() || SelectWaits
	a.mu.Unlock()
	if stale && !wait {
		a.syncLater(name)
	} else if stale {
		if err := a.syncNow(name); err != nil {
			if m == nil || m.synced.IsZero() {
				return nil, err
			}
			// Serve the saved state if the provider is unreachable.
			a.b.Log.Warn("serving saved state", "user", a.login, "mailbox", name, "err", err)
		}
		a.mu.Lock()
		m = a.boxes[CanonicalName(name)]
		a.mu.Unlock()
	}
	if m == nil || !m.selectable {
		return nil, ErrNoMailbox
	}
	return m, nil
}

// SyncNow brings a folder up to date with the provider.
func (a *Account) SyncNow(name string) error { return a.syncNow(name) }

// folderFlush is how long a folder change waits for the queue.
var folderFlush = 30 * time.Second

// folderOp makes a folder change at the provider, after the queued changes
// to messages, which name folders as they were, and reads the folder list
// again.
func (a *Account) folderOp(do func(c conn) error) error {
	if err := a.flushQueue(folderFlush); err != nil {
		return err
	}
	c, err := a.conn(interactive, "")
	if err != nil {
		return err
	}
	err = do(c)
	c.Release(err)
	if err != nil {
		return err
	}
	if err := a.listNow(); err != nil {
		a.b.Log.Warn("could not reread folders", "user", a.login, "err", err)
	}
	return nil
}

func (a *Account) CreateFolder(name string, opts *imap.CreateOptions) error {
	return a.folderOp(func(c conn) error { return c.Create(name, opts) })
}

func (a *Account) DeleteFolder(name string) error {
	return a.folderOp(func(c conn) error { return c.Delete(name) })
}

// RenameFolder renames a folder and the folders under it. Their messages
// keep their UIDs.
func (a *Account) RenameFolder(name, newName string, opts *imap.RenameOptions) error {
	return a.folderOp(func(c conn) error {
		if err := c.Rename(name, newName, opts); err != nil {
			return err
		}
		a.renameLocal(name, newName)
		return nil
	})
}

func (a *Account) Subscribe(name string, on bool) error {
	return a.folderOp(func(c conn) error { return c.Subscribe(name, on) })
}

// renameLocal renames a folder and the folders under it in the proxy's
// copy, so their messages keep their UIDs. Renaming INBOX moves its
// messages to a new folder instead, which the sync finds.
func (a *Account) renameLocal(name, newName string) {
	name, newName = CanonicalName(name), CanonicalName(newName)
	if name == "INBOX" {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	tx := a.begin()
	prefix := name + string(a.delim)
	for old, m := range a.boxes {
		if old != name && !strings.HasPrefix(old, prefix) {
			continue
		}
		renamed := newName + strings.TrimPrefix(old, name)
		delete(a.boxes, old)
		m.name = renamed
		a.boxes[renamed] = m
		for _, msg := range m.msgs {
			msg.box = renamed
		}
		for _, msg := range m.atP {
			msg.pBox = renamed
		}
		tx.renameMailbox(old, renamed)
		a.log.touch(KindMailbox, m.jmapID, false)
	}
	if err := tx.commit(); err != nil {
		a.b.Log.Warn("could not save mailbox state", "user", a.login, "err", err)
	}
}

// --- Messages -------------------------------------------------------------

// ErrTransform means the Transform refused a message a client stores.
var ErrTransform = errors.New("message could not be stored")

// Append stores a message in a folder at the provider, after the
// Transform turns it into the message the provider stores, and syncs the
// folder. It returns the message clients see, or nil if the provider did
// not say which it is.
func (a *Account) Append(name string, data []byte, opts *imap.AppendOptions) (*Message, error) {
	if a.b.Transform != nil {
		ctx, cancel := context.WithTimeout(context.Background(), a.b.Timeout)
		out, err := a.b.Transform.Write(ctx, data)
		cancel()
		if err != nil {
			a.b.Log.Error("append: transform failed", "user", a.login, "mailbox", name, "err", err)
			return nil, ErrTransform
		}
		data = out
	}
	c, err := a.conn(interactive, "")
	if err != nil {
		return nil, err
	}
	uid, validity, err := c.Append(name, data, opts)
	c.Release(err)
	if err != nil {
		return nil, err
	}
	if err := a.syncNow(name); err != nil {
		a.b.Log.Warn("could not resync after a change", "user", a.login, "mailbox", name, "err", err)
	}
	if uid == 0 {
		return nil, nil // the provider has no UIDPLUS
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	m := a.boxes[CanonicalName(name)]
	if m == nil || m.pUIDValidity != validity || m.atP[uid] == nil {
		return nil, nil
	}
	msg := m.atP[uid]
	if msg.held {
		// A client wrote it: it is not held from clients (hold.go).
		msg.held = false
		tx := a.begin()
		a.show(m, msg, tx)
		if err := tx.commit(); err != nil {
			a.b.Log.Warn("could not save mailbox state", "user", a.login, "err", err)
		}
	}
	if msg.box != m.name {
		return nil, nil
	}
	return msg, nil
}

// SetFlags changes the flags of msgs and queues the change. Messages no
// longer in folder in are skipped; with in "", those expunged are. Every
// view but source hears of the change through its mailbox tracker;
// source, if not nil, reports it itself.
func (a *Account) SetFlags(msgs []*Message, in string, flagOp imap.StoreFlagsOp, flags []imap.Flag, source *imapserver.SessionTracker) {
	a.mu.Lock()
	tx := a.begin()
	var ids []uuid.UUID
	for _, msg := range msgs {
		if msg.box == "" || (in != "" && msg.box != in) {
			continue // moved or expunged meanwhile
		}
		after := ApplyFlags(msg.flags, flagOp, flags)
		if sameFlags(after, msg.flags) {
			continue
		}
		a.setFlags(msg, after, source, tx)
		ids = append(ids, msg.id)
	}
	if len(ids) > 0 {
		a.enqueue(&op{kind: opFlags, ids: ids, flagOp: flagOp, flags: flags}, tx)
	}
	err := tx.commit()
	a.mu.Unlock()
	if err != nil {
		a.b.Log.Warn("could not save flags", "user", a.login, "err", err)
	}
	a.wakeQueue()
}

// Expunge removes the messages of folder m that gone reports true for, and
// returns them. gone runs with the lock held.
func (a *Account) Expunge(m *Mailbox, gone func(*Message) bool) []*Message {
	a.mu.Lock()
	tx := a.begin()
	removed := a.hide(m, gone)
	ids := make([]uuid.UUID, len(removed))
	for i, msg := range removed {
		tx.putMessage(msg)
		ids[i] = msg.id
	}
	if len(ids) > 0 {
		a.enqueue(&op{kind: opExpunge, ids: ids}, tx)
	}
	err := tx.commit()
	a.mu.Unlock()
	if err != nil {
		a.b.Log.Warn("could not save mailbox state", "user", a.login, "err", err)
	}
	a.wakeQueue()
	return removed
}

// destination returns the folder a copy or move goes to (lock held).
func (a *Account) destination(name string) (*Mailbox, error) {
	m := a.boxes[CanonicalName(name)]
	if m == nil || !m.selectable {
		return nil, ErrNoMailbox
	}
	return m, nil
}

// Copied is a message and its copy, or a message before and after a move.
type Copied struct {
	From, To *Message
	// FromUID and ToUID are the UIDs before and after.
	FromUID, ToUID imap.UID
}

// Copy copies msgs to folder dest. Messages no longer in folder in are
// skipped; with in "", those expunged are. It returns the copies, and the
// UIDVALIDITY of dest.
func (a *Account) Copy(msgs []*Message, in, dest string) ([]Copied, uint32, error) {
	a.mu.Lock()
	dm, err := a.destination(dest)
	if err != nil {
		a.mu.Unlock()
		return nil, 0, err
	}
	tx := a.begin()
	var out []Copied
	var ids []uuid.UUID
	for _, msg := range msgs {
		if msg.box == "" || (in != "" && msg.box != in) {
			continue
		}
		c := &Message{id: uuid.NewV7(), origin: msg.id, flags: slices.Clone(msg.flags), date: msg.date, key: msg.key, direct: msg.direct}
		a.byID[c.id] = c
		a.show(dm, c, tx)
		out = append(out, Copied{From: msg, To: c, FromUID: msg.uid, ToUID: c.uid})
		ids = append(ids, c.id)
	}
	if len(ids) > 0 {
		a.enqueue(&op{kind: opCopy, ids: ids, dest: dm.name}, tx)
	}
	validity := dm.uidValidity
	err = tx.commit()
	a.mu.Unlock()
	if err != nil {
		a.b.Log.Warn("could not save mailbox state", "user", a.login, "err", err)
	}
	a.wakeQueue()
	return out, validity, nil
}

// Move moves the messages of folder m that in reports true for to folder
// dest, lowest UID first. in runs with the lock held. It returns the moved
// messages (From and To are the same message), and the UIDVALIDITY of
// dest.
func (a *Account) Move(m *Mailbox, in func(*Message) bool, dest string) ([]Copied, uint32, error) {
	a.mu.Lock()
	dm, err := a.destination(dest)
	if err != nil {
		a.mu.Unlock()
		return nil, 0, err
	}
	tx := a.begin()
	moved := a.hide(m, in)
	slices.Reverse(moved) // lowest UID first
	out := make([]Copied, len(moved))
	ids := make([]uuid.UUID, len(moved))
	for i, msg := range moved {
		from := msg.uid
		a.show(dm, msg, tx)
		out[i] = Copied{From: msg, To: msg, FromUID: from, ToUID: msg.uid}
		ids[i] = msg.id
	}
	if len(ids) > 0 {
		a.enqueue(&op{kind: opMove, ids: ids, dest: dm.name}, tx)
	}
	validity := dm.uidValidity
	err = tx.commit()
	a.mu.Unlock()
	if err != nil {
		a.b.Log.Warn("could not save mailbox state", "user", a.login, "err", err)
	}
	a.wakeQueue()
	return out, validity, nil
}

// Download returns the messages clients see, from the cache or by
// fetching and transforming them. A message the provider no longer has is
// missing from the result. st, if not nil, counts where they came from.
func (a *Account) Download(msgs []*Message, st *FetchStats) (map[*Message][]byte, error) {
	out := make(map[*Message][]byte, len(msgs))
	if err := a.download(msgs, out, false, st); err != nil {
		return nil, err
	}
	return out, nil
}

// NoteRead tells read-ahead that a client read messages of a folder.
func (a *Account) NoteRead(name string, uids []imap.UID) { a.noteRead(name, uids) }

// HeaderEntries finds the header entries of msgs: in the Store, from their
// cached copies (whose entries are then saved), or, for messages the proxy
// does not change, from the provider, which is asked for the entries
// alone. The messages left to answer from whole messages (downloaded and
// transformed, which saves their entries) are returned as rest.
func (a *Account) HeaderEntries(msgs []*Message, st *FetchStats) (out map[*Message]*HeaderEntry, rest []*Message, err error) {
	if st == nil {
		st = &FetchStats{}
	}
	keys := make([]string, len(msgs))
	for i, msg := range msgs {
		keys[i] = msg.key
	}
	saved := a.b.Store.Headers(a.login, keys)
	out = map[*Message]*HeaderEntry{}
	var missing []*Message
	save := map[string]*HeaderEntry{}
	for _, msg := range msgs {
		if h := saved[msg.key]; h != nil {
			out[msg] = h
			continue
		}
		if data, from := a.b.Cache.get(a.login, msg.key); data != nil {
			h := EntryOf(data)
			out[msg] = h
			if from == fromDisk { // only final copies reach the disk
				save[msg.key] = h
			}
			if from == fromMemory {
				st.Memory++
			} else {
				st.Disk++
			}
			continue
		}
		if msg.direct {
			missing = append(missing, msg)
		} else {
			rest = append(rest, msg)
		}
	}
	if err := a.b.Store.putHeaders(a.login, save); err != nil {
		a.b.Log.Warn("could not save header entries", "user", a.login, "err", err)
	}
	if len(missing) == 0 {
		return out, rest, nil
	}
	st.Provider += len(missing)
	// Small, quick, and what the client shows first: interactive.
	fetched, err := a.fetchHeaders(missing, interactive)
	if err != nil {
		return nil, nil, err
	}
	for msg, h := range fetched {
		out[msg] = h
	}
	return out, rest, nil
}

// --- For clients that keep their own copy (JMAP) --------------------------

// ID returns the folder's JMAP ID, which it keeps when renamed.
func (m *Mailbox) ID() string { return m.jmapID }

// MailboxByID finds a folder by its JMAP ID, or nil (lock held).
func (a *Account) MailboxByID(id string) *Mailbox { return a.mailboxByID(id) }

// Email returns the messages clients see that make the email with JMAP ID
// id (EmailID): the same message in one or more folders. nil if there are
// none (lock held).
func (a *Account) Email(id string) []*Message { return a.emails[id] }

// EmailIDs returns every email's JMAP ID, in no order (lock held).
func (a *Account) EmailIDs() []string {
	out := make([]string, 0, len(a.emails))
	for id := range a.emails {
		out = append(out, id)
	}
	return out
}

// State returns the account's state: it changes whenever anything a
// client sees does (lock held).
func (a *Account) State() string { return a.log.state(a.log.modseq) }

// Changes returns what changed in objects of kind (KindEmail,
// KindMailbox) since state, at most max (0 for no limit). It returns
// ErrCannotCalculateChanges for a state it cannot answer from (lock held).
func (a *Account) Changes(kind, since string, max int) (*Changes, error) {
	return a.log.changes(kind, since, max)
}

// ModSeq is a message's mod-sequence for IMAP CONDSTORE clients (lock
// held): its email's last change in the log. A change to any copy of the
// email counts, so a copy's ModSeq may rise with no change of its own,
// which CONDSTORE allows. It is at least 1.
func (a *Account) ModSeq(msg *Message) uint64 {
	if st := a.log.entries[KindEmail][EmailID(msg.key)]; st != nil {
		return uint64(max(st.created, st.changed, 1))
	}
	return 1
}

// HighestModSeq is a folder's HIGHESTMODSEQ for CONDSTORE clients (lock
// held): the highest ModSeq of its messages, or the folder's own last
// change (a message added or expunged), whichever is higher. It rises with
// every change in the folder.
func (a *Account) HighestModSeq(m *Mailbox) uint64 {
	if m.hmsAt == a.log.modseq && m.hms > 0 {
		return uint64(m.hms)
	}
	h := int64(1)
	if st := a.log.entries[KindMailbox][m.jmapID]; st != nil {
		h = max(h, st.created, st.changed, st.counts)
	}
	for _, msg := range m.msgs {
		if st := a.log.entries[KindEmail][EmailID(msg.key)]; st != nil {
			h = max(h, st.created, st.changed)
		}
	}
	m.hms, m.hmsAt = h, a.log.modseq
	return uint64(h)
}

// Changed returns a channel that is closed at the next change (lock
// held).
func (a *Account) Changed() <-chan struct{} { return a.log.wake }

// ErrNoSending means the account's provider has no way to send through
// the engine: an IMAP provider's mail goes to its submission server.
var ErrNoSending = errors.New("the provider does not send through the engine")

// Send sends a message through the account's provider, for providers that
// send without a submission server (JMAP, ActiveSync). It needs
// credentials the provider accepted (Login). An ActiveSync provider keeps
// a copy in the Sent folder; a JMAP provider does not.
func (a *Account) Send(ctx context.Context, from string, to []string, data []byte) error {
	a.credMu.Lock()
	prov := a.prov
	a.credMu.Unlock()
	switch p := prov.(type) {
	case *jmapProvider:
		return p.send(ctx, from, to, data)
	case *easProvider:
		return p.send(ctx, to, data)
	}
	return ErrNoSending
}
