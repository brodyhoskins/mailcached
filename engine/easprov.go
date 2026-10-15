package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/internal/eas"
	"github.com/brodyhoskins/mailcached/internal/netbind"
	"github.com/brodyhoskins/mailcached/internal/wbxml"
)

// easProvider reaches an Exchange ActiveSync provider for one account.
// ActiveSync names messages by server IDs in a folder, and keeps, for
// each device and folder, what the device has as of a sync key: a Sync
// returns what changed since. The provider is one device to the server.
// It gives each message a UID of its own, and answers the engine's Sync
// from its model of the account, which ActiveSync Syncs keep current.
// Ping pushes changes in every folder.
//
// ActiveSync knows only whether a message is read and flagged. The
// provider keeps the other flags (\Answered, \Draft, \Deleted, keywords)
// itself. It cannot store a message in a folder (APPEND) or copy one:
// those are refused, except a copy to the Sent folder, which the server
// keeps of what is sent through it (Account.Send).
type easProvider struct {
	a        *Account
	u        Upstream
	password func() string

	mu       sync.Mutex // guards what follows
	client   *eas.Client
	clientPw string
	loaded   bool
	deviceID string
	// policyKey is the key the server gave the device.
	policyKey string
	// folderKey is the FolderSync key, "" before the first.
	folderKey string
	// modseq goes up with every change to the model.
	modseq  int64
	folders map[string]*efolder // by server ID
	// touched holds the folders that changed since the engine's last
	// Wait; listChanged says the folder list did.
	touched     map[string]bool
	listChanged bool
	// The rows to save.
	dirtyFolders map[string]bool
	dirtyItems   map[[2]string]bool // folder and server ID
	pinged       bool               // a Ping worked

	listMu sync.Mutex // one FolderSync, or folder change, at a time
}

// efolder is a folder at the provider.
type efolder struct {
	id, parent, display string
	typ                 int
	name                string // the folder name the engine uses
	syncKey             string // "" before the first Sync
	validity            uint32
	next                imap.UID
	uidOf               map[string]imap.UID
	items               map[imap.UID]*eitem

	syncMu sync.Mutex // one Sync at a time: each uses the last key
}

// eitem is a message at the provider.
type eitem struct {
	sid string
	// flags are the flags the engine sees: \Seen and \Flagged as the
	// provider says, and the others kept here.
	flags []imap.Flag
	seq   int64 // modseq of the last change
	// What the sync saw of a message, for the engine's first sight of
	// it. Not saved: after a restart it is asked for again if needed.
	date   time.Time
	size   int64
	header []byte
}

// The folder types of ActiveSync that hold mail.
const (
	easUserGeneric = 1
	easInbox       = 2
	easDrafts      = 3
	easTrash       = 4
	easSent        = 5
	easOutbox      = 6
	easUserMail    = 12
)

func easMail(t int) bool {
	return t == easUserGeneric || t == easInbox || t == easDrafts || t == easTrash || t == easSent || t == easUserMail
}

// easHeaderBytes is how much of a message a Sync asks for, for its header.
const easHeaderBytes = 16 << 10

func newEASProvider(a *Account, u Upstream, password func() string) *easProvider {
	return &easProvider{a: a, u: u, password: password, folders: map[string]*efolder{}, touched: map[string]bool{},
		dirtyFolders: map[string]bool{}, dirtyItems: map[[2]string]bool{}}
}

func (p *easProvider) timeout() time.Duration {
	if p.u.Timeout > 0 {
		return p.u.Timeout
	}
	return time.Minute
}

func (p *easProvider) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), p.timeout())
}

func (p *easProvider) newClient(password string) *eas.Client {
	tr := &http.Transport{
		DialContext:         netbind.NewSpread(p.u.Sources, p.timeout(), dialControl(p.timeout(), true)).DialContext,
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     p.u.TLSConfig,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		MaxConnsPerHost:     p.u.MaxConns,
	}
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	ua := p.a.b.Name
	if p.a.b.Version != "" {
		ua += "/" + p.a.b.Version
	}
	p.mu.Lock()
	id, key := p.deviceID, p.policyKey
	p.mu.Unlock()
	c := &eas.Client{URL: p.u.ActiveSync, User: p.a.login, Password: password, DeviceID: id, DeviceType: "mailcached",
		UserAgent: ua, HTTP: &http.Client{Transport: tr}, PolicyKeySaved: p.savePolicyKey, MaxConcurrent: p.u.MaxConns}
	c.SetPolicyKey(key)
	return c
}

// rejected turns a refusal of the credentials into ErrLoginRejected.
func easRejected(err error) error {
	switch {
	case errors.Is(err, eas.ErrUnauthorized):
		return fmt.Errorf("%w: %w", ErrLoginRejected, err)
	case errors.Is(err, eas.ErrForbidden), errors.Is(err, eas.ErrRemoteWipe), errors.Is(err, eas.ErrNoVersion):
		return fmt.Errorf("%w: %w", ErrLoginRejected, err)
	}
	return err
}

// easRefused turns a command's refusal into an *imap.Error, which the
// engine treats as the provider saying no.
func easRefused(err error) error {
	var se *eas.StatusError
	if errors.As(err, &se) {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: se.Error()}
	}
	return err
}

func (p *easProvider) Login(password string) error {
	if err := p.ensureLoaded(); err != nil {
		return err
	}
	ctx, cancel := p.ctx()
	defer cancel()
	c := p.newClient(password)
	if err := c.Options(ctx); err != nil {
		return easRejected(err)
	}
	p.mu.Lock()
	p.client, p.clientPw = c, password
	p.mu.Unlock()
	return nil
}

// session returns the client for the accepted password.
func (p *easProvider) session(ctx context.Context) (*eas.Client, error) {
	if err := p.ensureLoaded(); err != nil {
		return nil, err
	}
	pw := p.password()
	if pw == "" {
		return nil, ErrNoCredentials
	}
	p.mu.Lock()
	if p.client != nil && p.clientPw == pw {
		c := p.client
		p.mu.Unlock()
		return c, nil
	}
	p.mu.Unlock()
	c := p.newClient(pw)
	if err := c.Options(ctx); err != nil {
		return nil, easRejected(err)
	}
	p.mu.Lock()
	p.client, p.clientPw = c, pw
	p.mu.Unlock()
	return c, nil
}

// do sends a command, turning a refusal of the credentials into
// ErrLoginRejected.
func (p *easProvider) do(ctx context.Context, cmd string, doc *wbxml.Node) (*wbxml.Node, error) {
	c, err := p.session(ctx)
	if err != nil {
		return nil, err
	}
	n, err := c.Do(ctx, cmd, nil, doc)
	if errors.Is(err, eas.ErrRemoteWipe) {
		p.a.b.Log.Error("activesync: the provider asked for a remote wipe; nothing was wiped", "user", p.a.login)
	}
	return n, easRejected(err)
}

func (p *easProvider) Conn(priority, string) (conn, error) { return &easConn{p: p}, nil }

func (p *easProvider) Close() {}

// Capacity leaves out the Ping that waits for changes.
func (p *easProvider) Capacity() int { return max(0, p.u.MaxConns-1) }

// --- The model -------------------------------------------------------------

func (p *easProvider) ensureLoaded() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.loaded {
		return nil
	}
	if err := p.load(); err != nil {
		return err
	}
	if p.deviceID == "" {
		var b [15]byte
		_, _ = rand.Read(b[:])
		p.deviceID = "MC" + strings.ToUpper(hex.EncodeToString(b[:]))
		p.saveMeta("eas_device_id", p.deviceID)
	}
	return nil
}

// load reads the saved model (p.mu held).
func (p *easProvider) load() error {
	p.loaded = true
	s := p.a.b.Store
	if s == nil {
		return nil
	}
	db, err := s.db(p.a.login)
	if err != nil {
		return err
	}
	rows, err := db.Query(`SELECT id, parent, display, type, sync_key, validity, next FROM eas_folders`)
	if err != nil {
		return err
	}
	for rows.Next() {
		f := newEFolder("")
		var next uint32
		if err := rows.Scan(&f.id, &f.parent, &f.display, &f.typ, &f.syncKey, &f.validity, &next); err != nil {
			rows.Close()
			return err
		}
		f.next = imap.UID(next)
		p.folders[f.id] = f
	}
	rows.Close()
	rows, err = db.Query(`SELECT folder, sid, uid, flags FROM eas_items`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var folder, sid, flags string
		var uid uint32
		if err := rows.Scan(&folder, &sid, &uid, &flags); err != nil {
			rows.Close()
			return err
		}
		if f := p.folders[folder]; f != nil {
			it := &eitem{sid: sid}
			for _, fl := range strings.Fields(flags) {
				it.flags = append(it.flags, imap.Flag(fl))
			}
			f.uidOf[sid], f.items[imap.UID(uid)] = imap.UID(uid), it
		}
	}
	rows.Close()
	meta := func(name string) string {
		var v string
		_ = db.QueryRow(`SELECT value FROM meta WHERE name = ?`, name).Scan(&v)
		return v
	}
	p.deviceID, p.policyKey, p.folderKey = meta("eas_device_id"), meta("eas_policy_key"), meta("eas_folder_key")
	p.modseq, _ = strconv.ParseInt(meta("eas_modseq"), 10, 64)
	p.names()
	return nil
}

func newEFolder(id string) *efolder {
	return &efolder{id: id, next: 1, uidOf: map[string]imap.UID{}, items: map[imap.UID]*eitem{}}
}

// saveMeta writes one meta value (p.mu held).
func (p *easProvider) saveMeta(name, value string) {
	s := p.a.b.Store
	if s == nil {
		return
	}
	db, err := s.db(p.a.login)
	if err == nil {
		_, err = db.Exec(`INSERT INTO meta (name, value) VALUES (?, ?)
			ON CONFLICT (name) DO UPDATE SET value = excluded.value`, name, value)
	}
	if err != nil {
		p.a.b.Log.Warn("activesync: could not save the provider's state", "user", p.a.login, "err", err)
	}
}

func (p *easProvider) savePolicyKey(key string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.policyKey = key
	p.saveMeta("eas_policy_key", key)
}

// save writes what changed (p.mu held).
func (p *easProvider) save() {
	s := p.a.b.Store
	if s == nil {
		clear(p.dirtyFolders)
		clear(p.dirtyItems)
		return
	}
	err := func() error {
		db, err := s.db(p.a.login)
		if err != nil {
			return err
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		exec := func(q string, args ...any) {
			if err == nil {
				_, err = tx.Exec(q, args...)
			}
		}
		for id := range p.dirtyFolders {
			if f := p.folders[id]; f != nil {
				exec(`INSERT INTO eas_folders (id, parent, display, type, sync_key, validity, next) VALUES (?, ?, ?, ?, ?, ?, ?)
					ON CONFLICT (id) DO UPDATE SET parent = excluded.parent, display = excluded.display, type = excluded.type,
					sync_key = excluded.sync_key, validity = excluded.validity, next = excluded.next`,
					f.id, f.parent, f.display, f.typ, f.syncKey, f.validity, uint32(f.next))
			} else {
				exec(`DELETE FROM eas_folders WHERE id = ?`, id)
				exec(`DELETE FROM eas_items WHERE folder = ?`, id)
			}
		}
		for k := range p.dirtyItems {
			f := p.folders[k[0]]
			var it *eitem
			var uid imap.UID
			if f != nil {
				if uid = f.uidOf[k[1]]; uid != 0 {
					it = f.items[uid]
				}
			}
			if it == nil {
				exec(`DELETE FROM eas_items WHERE folder = ? AND sid = ?`, k[0], k[1])
				continue
			}
			flags := make([]string, len(it.flags))
			for i, fl := range it.flags {
				flags[i] = string(fl)
			}
			exec(`INSERT INTO eas_items (folder, sid, uid, flags) VALUES (?, ?, ?, ?)
				ON CONFLICT (folder, sid) DO UPDATE SET uid = excluded.uid, flags = excluded.flags`,
				k[0], k[1], uint32(uid), strings.Join(flags, " "))
		}
		exec(`INSERT INTO meta (name, value) VALUES ('eas_folder_key', ?), ('eas_modseq', ?)
			ON CONFLICT (name) DO UPDATE SET value = excluded.value`, p.folderKey, strconv.FormatInt(p.modseq, 10))
		if err != nil {
			return errors.Join(err, tx.Rollback())
		}
		return tx.Commit()
	}()
	if err != nil {
		p.a.b.Log.Warn("activesync: could not save the provider's state", "user", p.a.login, "err", err)
		return
	}
	clear(p.dirtyFolders)
	clear(p.dirtyItems)
}

// names gives each mail folder the name the engine uses: INBOX for the
// inbox, the path of display names for the others (p.mu held).
func (p *easProvider) names() {
	taken := map[string]bool{}
	var path func(f *efolder, depth int) string
	path = func(f *efolder, depth int) string {
		leaf := strings.ReplaceAll(f.display, "/", "-")
		if f.typ == easInbox {
			return "INBOX"
		}
		parent := p.folders[f.parent]
		if parent == nil || depth > 32 {
			return leaf
		}
		return path(parent, depth+1) + "/" + leaf
	}
	ids := make([]string, 0, len(p.folders))
	for id := range p.folders {
		ids = append(ids, id)
	}
	// The inbox and the shorter paths first, so they keep their names.
	slices.SortFunc(ids, func(x, y string) int {
		fx, fy := p.folders[x], p.folders[y]
		if (fx.typ == easInbox) != (fy.typ == easInbox) {
			if fx.typ == easInbox {
				return -1
			}
			return 1
		}
		return strings.Compare(fx.id, fy.id)
	})
	for _, id := range ids {
		f := p.folders[id]
		name := CanonicalName(path(f, 0))
		for i := 2; taken[name]; i++ {
			name = CanonicalName(path(f, 0)) + " (" + strconv.Itoa(i) + ")"
		}
		taken[name] = true
		if f.name != name && f.name != "" {
			p.listChanged = true
		}
		f.name = name
	}
}

// box returns the mail folder with an engine name (p.mu held).
func (p *easProvider) box(name string) *efolder {
	name = CanonicalName(name)
	for _, f := range p.folders {
		if f.name == name && easMail(f.typ) {
			return f
		}
	}
	return nil
}

func (p *easProvider) boxOrErr(name string) (*efolder, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if f := p.box(name); f != nil {
		return f, nil
	}
	return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNonExistent, Text: "No such folder"}
}

// newValidity returns a UIDVALIDITY for a new folder (p.mu held).
func (p *easProvider) newValidity() uint32 {
	v := uint32(time.Now().Unix())
	for _, f := range p.folders {
		v = max(v, f.validity+1)
	}
	return v
}

// folderSync brings the folder list up to date.
func (p *easProvider) folderSync(ctx context.Context) error {
	p.listMu.Lock()
	defer p.listMu.Unlock()
	return p.folderSyncLocked(ctx)
}

func (p *easProvider) folderSyncLocked(ctx context.Context) error {
	if err := p.ensureLoaded(); err != nil {
		return err
	}
	p.mu.Lock()
	key := p.folderKey
	p.mu.Unlock()
	if key == "" {
		key = "0"
	}
	for try := 0; ; try++ {
		n, err := p.do(ctx, "FolderSync", wbxml.El("FolderHierarchy:FolderSync", wbxml.Tx("FolderHierarchy:SyncKey", key)))
		if err != nil {
			return err
		}
		if n == nil {
			return &eas.StatusError{Cmd: "FolderSync"}
		}
		status := n.Value("Status")
		if status == "9" && key != "0" && try == 0 {
			// The server forgot the device: start over. A new start of
			// the folders is one of every folder too; the next Syncs say
			// again what each has, and the model keeps the UIDs of
			// the messages it knew by their server IDs.
			key = "0"
			p.mu.Lock()
			for _, f := range p.folders {
				f.syncKey = ""
				p.dirtyFolders[f.id] = true
			}
			p.mu.Unlock()
			continue
		}
		if status != "1" {
			return easRefused(&eas.StatusError{Cmd: "FolderSync", Status: atoiOr0(status)})
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if key == "0" {
			// Everything comes again: what does not is gone.
			seen := map[string]bool{}
			for _, k := range n.Child("Changes").All() {
				if k.Is("Add") || k.Is("Update") {
					seen[k.Value("ServerId")] = true
				}
			}
			for id := range p.folders {
				if !seen[id] {
					delete(p.folders, id)
					p.dirtyFolders[id] = true
				}
			}
			p.listChanged = true
		}
		for _, k := range n.Child("Changes").All() {
			id := k.Value("ServerId")
			switch {
			case k.Is("Add"), k.Is("Update"):
				f := p.folders[id]
				if f == nil {
					f = newEFolder(id)
					f.validity = p.newValidity()
					p.folders[id] = f
				}
				f.parent, f.display, f.typ = k.Value("ParentId"), k.Value("DisplayName"), atoiOr0(k.Value("Type"))
				p.dirtyFolders[id] = true
				p.listChanged = true
			case k.Is("Delete"):
				delete(p.folders, id)
				p.dirtyFolders[id] = true
				p.listChanged = true
			}
		}
		p.folderKey = n.Value("SyncKey")
		p.names()
		p.save()
		return nil
	}
}

func atoiOr0(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// headerOf returns the header of a message, or of its start.
func headerOf(data []byte) []byte {
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		return bytes.Clone(data[:i+4])
	}
	if i := bytes.Index(data, []byte("\n\n")); i >= 0 {
		return bytes.Clone(data[:i+2])
	}
	return bytes.Clone(data)
}

// easFlags are the flags the provider keeps for a message: what the
// server says, and the others it had.
func easFlags(old []imap.Flag, read, flagged *bool, verb string) []imap.Flag {
	out := slices.DeleteFunc(slices.Clone(old), func(f imap.Flag) bool {
		return (read != nil && strings.EqualFold(string(f), string(imap.FlagSeen))) ||
			(flagged != nil && strings.EqualFold(string(f), string(imap.FlagFlagged)))
	})
	if read != nil && *read {
		out = append(out, imap.FlagSeen)
	}
	if flagged != nil && *flagged {
		out = append(out, imap.FlagFlagged)
	}
	switch verb {
	case "1", "2":
		if !HasFlag(out, imap.FlagAnswered) {
			out = append(out, imap.FlagAnswered)
		}
	case "3":
		if !HasFlag(out, "$Forwarded") {
			out = append(out, "$Forwarded")
		}
	}
	return out
}

// applyItem takes what the server says of a message: an Add or a
// Change (p.mu held). It reports whether the model changed.
func (p *easProvider) applyItem(f *efolder, k *wbxml.Node, add bool) bool {
	sid := k.Value("ServerId")
	ad := k.Child("ApplicationData")
	var read, flagged *bool
	if r := ad.Child("Email:Read"); r != nil {
		v := r.Text == "1"
		read = &v
	}
	if fl := ad.Child("Email:Flag"); fl != nil {
		v := fl.Value("FlagStatus") == "2"
		flagged = &v
	}
	verb := ad.Value("Email2:LastVerbExecuted")
	uid, known := f.uidOf[sid]
	if !known && !add {
		return false // a change to a message the model never had
	}
	if !known {
		uid = f.next
		f.next++
		f.uidOf[sid] = uid
		f.items[uid] = &eitem{sid: sid}
		p.dirtyFolders[f.id] = true
	}
	it := f.items[uid]
	flags := easFlags(it.flags, read, flagged, verb)
	changed := !known || !sameFlags(flags, it.flags)
	it.flags = flags
	if add {
		if d, err := time.Parse("2006-01-02T15:04:05.000Z", ad.Value("Email:DateReceived")); err == nil {
			it.date = d
		}
		body := ad.Child("AirSyncBase:Body")
		it.size, _ = strconv.ParseInt(body.Value("EstimatedDataSize"), 10, 64)
		if data := body.Value("Data"); data != "" {
			it.header = headerOf([]byte(data))
		}
	}
	if changed {
		it.seq = p.modseq
		p.dirtyItems[[2]string{f.id, sid}] = true
	}
	return changed
}

// removeItem takes a message out of the model (p.mu held).
func (p *easProvider) removeItem(f *efolder, sid string) bool {
	uid, ok := f.uidOf[sid]
	if !ok {
		return false
	}
	delete(f.uidOf, sid)
	delete(f.items, uid)
	p.dirtyItems[[2]string{f.id, sid}] = true
	return true
}

// syncOptions are the Options of the provider's Syncs: every message,
// with the start of its MIME message for the header.
func (p *easProvider) syncOptions() *wbxml.Node {
	return wbxml.El("AirSync:Options", wbxml.Tx("AirSync:FilterType", "0"), wbxml.Tx("AirSync:MIMESupport", "2"),
		wbxml.El("AirSyncBase:BodyPreference", wbxml.Tx("AirSyncBase:Type", "4"),
			wbxml.Tx("AirSyncBase:TruncationSize", strconv.Itoa(easHeaderBytes))))
}

// syncFolder brings a folder's model up to date (f.syncMu held). It
// reports whether the model of the folder changed.
func (p *easProvider) syncFolder(ctx context.Context, f *efolder) (bool, error) {
	changed := false
	retried := false
	var seen map[string]bool // in a full sync: the messages the server has
	for {
		p.mu.Lock()
		key := f.syncKey
		p.mu.Unlock()
		if key == "" {
			n, err := p.syncCall(ctx, f, "0", false, nil)
			if err != nil {
				return changed, err
			}
			p.mu.Lock()
			f.syncKey = n.Value("SyncKey")
			p.dirtyFolders[f.id] = true
			p.mu.Unlock()
			seen = map[string]bool{}
			continue
		}
		n, err := p.syncCall(ctx, f, key, true, nil)
		var se *eas.StatusError
		if errors.As(err, &se) && se.Status == 3 && !retried {
			// The server forgot the key: everything again.
			retried = true
			p.mu.Lock()
			f.syncKey = ""
			p.mu.Unlock()
			continue
		}
		if err != nil {
			return changed, err
		}
		p.mu.Lock()
		p.modseq++
		for _, k := range n.Child("Commands").All() {
			switch {
			case k.Is("Add"), k.Is("Change"):
				if seen != nil {
					seen[k.Value("ServerId")] = true
				}
				if p.applyItem(f, k, k.Is("Add")) {
					changed = true
				}
			case k.Is("Delete"), k.Is("SoftDelete"):
				if p.removeItem(f, k.Value("ServerId")) {
					changed = true
				}
			}
		}
		if k := n.Value("SyncKey"); k != "" {
			f.syncKey = k
			p.dirtyFolders[f.id] = true
		}
		more := n.Child("MoreAvailable") != nil
		if !more && seen != nil {
			for sid := range f.uidOf {
				if !seen[sid] && p.removeItem(f, sid) {
					changed = true
				}
			}
		}
		if changed {
			p.touched[f.name] = true
		}
		p.save()
		p.mu.Unlock()
		if !more {
			return changed, nil
		}
	}
}

// syncCall sends one Sync for a folder and returns its collection.
// commands, if not nil, are the device's changes.
func (p *easProvider) syncCall(ctx context.Context, f *efolder, key string, getChanges bool, commands []*wbxml.Node) (*wbxml.Node, error) {
	kids := []*wbxml.Node{wbxml.Tx("AirSync:SyncKey", key), wbxml.Tx("AirSync:CollectionId", f.id)}
	c, err := p.session(ctx)
	if err != nil {
		return nil, err
	}
	if !c.AtLeast("14.0") {
		kids = append([]*wbxml.Node{wbxml.Tx("AirSync:Class", "Email")}, kids...)
	}
	if key != "0" {
		if getChanges {
			kids = append(kids, wbxml.El("AirSync:GetChanges"), wbxml.Tx("AirSync:WindowSize", "100"))
		} else {
			kids = append(kids, wbxml.Tx("AirSync:GetChanges", "0"))
		}
		kids = append(kids, p.syncOptions())
	}
	if len(commands) > 0 {
		kids = append(kids, wbxml.Tx("AirSync:DeletesAsMoves", "0"), wbxml.El("AirSync:Commands", commands...))
	}
	n, err := p.do(ctx, "Sync", wbxml.El("AirSync:Sync", wbxml.El("AirSync:Collections", wbxml.El("AirSync:Collection", kids...))))
	if err != nil {
		return nil, err
	}
	if n == nil {
		// An empty answer: no changes, the same key.
		return wbxml.El("AirSync:Collection", wbxml.Tx("AirSync:SyncKey", key), wbxml.Tx("AirSync:Status", "1")), nil
	}
	if st := n.Value("Status"); st != "" && st != "1" {
		return nil, &eas.StatusError{Cmd: "Sync", Status: atoiOr0(st)}
	}
	coll := n.Child("Collections").Child("Collection")
	if coll == nil {
		return nil, &eas.StatusError{Cmd: "Sync"}
	}
	if st := coll.Value("Status"); st != "1" {
		if st == "12" {
			p.mu.Lock()
			p.listChanged = true
			p.mu.Unlock()
		}
		return nil, &eas.StatusError{Cmd: "Sync", Status: atoiOr0(st)}
	}
	return coll, nil
}

// itemFetch fetches messages whole, or their first max bytes (0 for
// all), and calls each with every one.
func (p *easProvider) itemFetch(ctx context.Context, f *efolder, sids map[imap.UID]string, limit int, each func(uid imap.UID, raw []byte)) error {
	byID := map[string]imap.UID{}
	var batch []*wbxml.Node
	flush := func() error {
		if len(batch) == 0 {
			return nil
		}
		n, err := p.do(ctx, "ItemOperations", wbxml.El("ItemOperations:ItemOperations", batch...))
		batch = nil
		if err != nil {
			return err
		}
		if n == nil || n.Value("Status") != "1" {
			return easRefused(&eas.StatusError{Cmd: "ItemOperations", Status: atoiOr0(n.Value("Status"))})
		}
		for _, r := range n.Child("Response").Children("Fetch") {
			uid, ok := byID[r.Value("AirSync:ServerId")]
			if !ok || r.Value("Status") != "1" {
				continue // gone
			}
			body := r.Child("Properties").Child("AirSyncBase:Body")
			each(uid, []byte(body.Value("Data")))
		}
		return nil
	}
	for uid, sid := range sids {
		byID[sid] = uid
		pref := []*wbxml.Node{wbxml.Tx("AirSyncBase:Type", "4")}
		if limit > 0 {
			pref = append(pref, wbxml.Tx("AirSyncBase:TruncationSize", strconv.Itoa(limit)))
		}
		batch = append(batch, wbxml.El("ItemOperations:Fetch", wbxml.Tx("ItemOperations:Store", "Mailbox"),
			wbxml.Tx("AirSync:CollectionId", f.id), wbxml.Tx("AirSync:ServerId", sid),
			wbxml.El("ItemOperations:Options", wbxml.Tx("AirSync:MIMESupport", "2"),
				wbxml.El("AirSyncBase:BodyPreference", pref...))))
		if len(batch) == 20 {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

// --- The engine's view -------------------------------------------------------

// easConn is the provider seen as a connection: every request is HTTP.
type easConn struct {
	p *easProvider
}

func (c *easConn) Release(error) {}

func (c *easConn) List() ([]folderInfo, error) {
	ctx, cancel := c.p.ctx()
	defer cancel()
	p := c.p
	if err := p.folderSync(ctx); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	attrs := map[int]imap.MailboxAttr{easDrafts: imap.MailboxAttrDrafts, easTrash: imap.MailboxAttrTrash, easSent: imap.MailboxAttrSent}
	var out []folderInfo
	for _, f := range p.folders {
		if !easMail(f.typ) {
			continue
		}
		fi := folderInfo{name: f.name, delim: '/', subscribed: true, selectable: true}
		if a, ok := attrs[f.typ]; ok {
			fi.attrs = []imap.MailboxAttr{a}
		}
		out = append(out, fi)
	}
	return out, nil
}

// easFlagsAll are the flags a folder supports: those of the server and
// those the provider keeps.
var easFlagsAll = []imap.Flag{imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged, imap.FlagDraft, imap.FlagDeleted}

func (c *easConn) Sync(name string, st syncState) (*delta, error) {
	p := c.p
	if err := p.ensureLoaded(); err != nil {
		return nil, err
	}
	p.mu.Lock()
	needList := p.folderKey == ""
	p.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 4*p.timeout())
	defer cancel()
	if needList {
		if err := p.folderSync(ctx); err != nil {
			return nil, err
		}
	}
	f, err := p.boxOrErr(name)
	if err != nil {
		return nil, err
	}
	f.syncMu.Lock()
	_, err = p.syncFolder(ctx, f)
	f.syncMu.Unlock()
	if err != nil {
		return nil, easRefused(err)
	}

	p.mu.Lock()
	reset := st.validity != 0 && st.validity != f.validity
	unchanged := !st.force && !st.stale && !st.refetchFlags && st.synced && !reset && st.validity == f.validity &&
		st.next == f.next && st.count == len(f.items) && st.modSeq == uint64(p.modseq)
	if unchanged {
		p.mu.Unlock()
		return &delta{unchanged: true}, nil
	}
	all := make([]imap.UID, 0, len(f.items))
	for u := range f.items {
		all = append(all, u)
	}
	p.mu.Unlock()

	var fresh, changed []imap.UID
	var needHeader map[imap.UID]string
	for _, u := range all {
		switch {
		case reset || st.validity == 0 || u >= st.next || !st.known(u):
			fresh = append(fresh, u)
			p.mu.Lock()
			if it := f.items[u]; it != nil && it.header == nil {
				if needHeader == nil {
					needHeader = map[imap.UID]string{}
				}
				needHeader[u] = it.sid
			}
			p.mu.Unlock()
		case st.refetchFlags:
			changed = append(changed, u)
		default:
			p.mu.Lock()
			if it := f.items[u]; it != nil && it.seq > int64(st.modSeq) {
				changed = append(changed, u)
			}
			p.mu.Unlock()
		}
	}
	if len(needHeader) > 0 {
		// Messages the model has from before a restart, which the engine
		// does not know: their headers are not saved.
		got := map[imap.UID][]byte{}
		err := p.itemFetch(ctx, f, needHeader, easHeaderBytes, func(uid imap.UID, raw []byte) { got[uid] = raw })
		if err != nil {
			return nil, easRefused(err)
		}
		p.mu.Lock()
		for uid, raw := range got {
			if it := f.items[uid]; it != nil {
				it.header = headerOf(raw)
				if it.size == 0 {
					it.size = int64(len(raw))
				}
			}
		}
		p.mu.Unlock()
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	d := &delta{reset: reset, present: map[imap.UID]bool{}, validity: f.validity, next: f.next, modSeq: uint64(p.modseq),
		folderFlags: easFlagsAll, permanentFlags: append(slices.Clone(easFlagsAll), imap.FlagWildcard),
		fullFlags: reset || st.refetchFlags}
	for _, u := range all {
		d.present[u] = true
	}
	for _, u := range fresh {
		it := f.items[u]
		if it == nil || it.header == nil {
			delete(d.present, u) // gone meanwhile
			continue
		}
		date := it.date
		if date.IsZero() {
			if m, err := mail.ReadMessage(bytes.NewReader(it.header)); err == nil {
				date, _ = m.Header.Date()
			}
		}
		d.fresh = append(d.fresh, freshMessage{uid: u, flags: slices.Clone(it.flags), date: date, size: it.size, header: it.header})
	}
	for _, u := range changed {
		if it := f.items[u]; it != nil {
			d.flags = append(d.flags, flagUpdate{u, slices.Clone(it.flags)})
		}
	}
	return d, nil
}

// sids returns the server IDs of messages in a folder, by UID.
func (p *easProvider) sids(f *efolder, uids []imap.UID) map[imap.UID]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[imap.UID]string{}
	for _, u := range uids {
		if it := f.items[u]; it != nil {
			out[u] = it.sid
		}
	}
	return out
}

// FetchSections: ActiveSync has no byte ranges of a MIME message.
func (c *easConn) FetchSections(string, []imap.UID, []Section, func(imap.UID, int, []byte)) error {
	return errNoPieces
}

// Search: ActiveSync's Search could, but the proxy reads the messages.
func (c *easConn) Search(string, *imap.SearchCriteria) ([]imap.UID, error) {
	return nil, errNoSearch
}

func (c *easConn) FetchFull(name string, uids []imap.UID, each func(uid imap.UID, raw []byte)) error {
	p := c.p
	f, err := p.boxOrErr(name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*p.timeout())
	defer cancel()
	return p.itemFetch(ctx, f, p.sids(f, uids), 0, each)
}

// FetchHeaders downloads the messages: ActiveSync has no body structure.
func (c *easConn) FetchHeaders(name string, uids []imap.UID) (map[imap.UID]*HeaderEntry, error) {
	out := map[imap.UID]*HeaderEntry{}
	err := c.FetchFull(name, uids, func(u imap.UID, raw []byte) { out[u] = EntryOf(raw) })
	return out, err
}

// commands sends the device's changes to a folder in a Sync, and returns
// the server IDs it refused.
func (p *easProvider) commands(ctx context.Context, f *efolder, cmds []*wbxml.Node) (map[string]bool, error) {
	f.syncMu.Lock()
	defer f.syncMu.Unlock()
	p.mu.Lock()
	key := f.syncKey
	p.mu.Unlock()
	if key == "" {
		if _, err := p.syncFolder(ctx, f); err != nil {
			return nil, err
		}
		p.mu.Lock()
		key = f.syncKey
		p.mu.Unlock()
	}
	n, err := p.syncCall(ctx, f, key, false, cmds)
	if err != nil {
		return nil, err
	}
	refused := map[string]bool{}
	for _, r := range n.Child("Responses").All() {
		if r.Value("Status") != "1" {
			refused[r.Value("ServerId")] = true
		}
	}
	p.mu.Lock()
	if k := n.Value("SyncKey"); k != "" {
		f.syncKey = k
		p.dirtyFolders[f.id] = true
	}
	p.mu.Unlock()
	return refused, nil
}

func (c *easConn) Store(name string, uids []imap.UID, op imap.StoreFlagsOp, flags []imap.Flag) (map[imap.UID][]imap.Flag, error) {
	p := c.p
	f, err := p.boxOrErr(name)
	if err != nil {
		return nil, err
	}
	ctx, cancel := p.ctx()
	defer cancel()
	type change struct {
		uid   imap.UID
		sid   string
		after []imap.Flag
	}
	var changes []change
	var cmds []*wbxml.Node
	p.mu.Lock()
	for _, u := range uids {
		it := f.items[u]
		if it == nil {
			continue
		}
		after := ApplyFlags(it.flags, op, flags)
		changes = append(changes, change{u, it.sid, after})
		var ad []*wbxml.Node
		if r := HasFlag(after, imap.FlagSeen); r != HasFlag(it.flags, imap.FlagSeen) {
			ad = append(ad, wbxml.Tx("Email:Read", map[bool]string{true: "1", false: "0"}[r]))
		}
		if fl := HasFlag(after, imap.FlagFlagged); fl != HasFlag(it.flags, imap.FlagFlagged) {
			if fl {
				ad = append(ad, wbxml.El("Email:Flag", wbxml.Tx("Email:FlagStatus", "2"),
					wbxml.Tx("Email:FlagType", "Flag for follow up")))
			} else {
				ad = append(ad, wbxml.El("Email:Flag"))
			}
		}
		if len(ad) > 0 {
			cmds = append(cmds, wbxml.El("AirSync:Change", wbxml.Tx("AirSync:ServerId", it.sid),
				wbxml.El("AirSync:ApplicationData", ad...)))
		}
	}
	p.mu.Unlock()
	refused := map[string]bool{}
	if len(cmds) > 0 {
		if refused, err = p.commands(ctx, f, cmds); err != nil {
			return nil, easRefused(err)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.modseq++
	out := map[imap.UID][]imap.Flag{}
	for _, ch := range changes {
		it := f.items[ch.uid]
		if it == nil || refused[ch.sid] {
			continue
		}
		it.flags, it.seq = ch.after, p.modseq
		p.dirtyItems[[2]string{f.id, ch.sid}] = true
		out[ch.uid] = slices.Clone(ch.after)
	}
	p.save()
	return out, nil
}

// errNoCopy refuses what ActiveSync cannot do.
func easCannot(what string) error {
	return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeCannot,
		Text: "ActiveSync providers cannot " + what}
}

func (c *easConn) Copy(string, []imap.UID, string) (map[imap.UID]imap.UID, error) {
	return nil, easCannot("copy messages")
}

func (c *easConn) Move(name string, uids []imap.UID, dest string) (map[imap.UID]imap.UID, error) {
	p := c.p
	f, err := p.boxOrErr(name)
	if err != nil {
		return nil, err
	}
	df, err := p.boxOrErr(dest)
	if err != nil {
		return nil, err
	}
	ctx, cancel := p.ctx()
	defer cancel()
	sids := p.sids(f, uids)
	if len(sids) == 0 {
		return map[imap.UID]imap.UID{}, nil
	}
	var moves []*wbxml.Node
	uidOf := map[string]imap.UID{}
	for u, sid := range sids {
		uidOf[sid] = u
		moves = append(moves, wbxml.El("Move:Move", wbxml.Tx("Move:SrcMsgId", sid), wbxml.Tx("Move:SrcFldId", f.id),
			wbxml.Tx("Move:DstFldId", df.id)))
	}
	n, err := p.do(ctx, "MoveItems", wbxml.El("Move:MoveItems", moves...))
	if err != nil {
		return nil, err
	}
	if n == nil {
		return nil, easRefused(&eas.StatusError{Cmd: "MoveItems"})
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.modseq++
	out := map[imap.UID]imap.UID{}
	for _, r := range n.Children("Response") {
		sid := r.Value("SrcMsgId")
		u, ok := uidOf[sid]
		if !ok || r.Value("Status") != "3" {
			continue
		}
		it := f.items[u]
		p.removeItem(f, sid)
		dsid := r.Value("DstMsgId")
		if dsid == "" {
			continue // the destination's next Sync reports it
		}
		nu, known := df.uidOf[dsid]
		if !known {
			nu = df.next
			df.next++
			df.uidOf[dsid] = nu
			p.dirtyFolders[df.id] = true
		}
		moved := &eitem{sid: dsid, seq: p.modseq}
		if it != nil {
			moved.flags, moved.date, moved.size, moved.header = it.flags, it.date, it.size, it.header
		}
		df.items[nu] = moved
		p.dirtyItems[[2]string{df.id, dsid}] = true
		out[u] = nu
	}
	p.touched[f.name], p.touched[df.name] = true, true
	p.save()
	if len(out) == 0 {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Text: "The provider moved no message"}
	}
	return out, nil
}

func (c *easConn) Expunge(name string, uids []imap.UID) error {
	p := c.p
	f, err := p.boxOrErr(name)
	if err != nil {
		return err
	}
	ctx, cancel := p.ctx()
	defer cancel()
	sids := p.sids(f, uids)
	var cmds []*wbxml.Node
	for _, sid := range sids {
		cmds = append(cmds, wbxml.El("AirSync:Delete", wbxml.Tx("AirSync:ServerId", sid)))
	}
	if len(cmds) == 0 {
		return nil
	}
	if _, err := p.commands(ctx, f, cmds); err != nil {
		return easRefused(err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.modseq++
	for _, sid := range sids {
		p.removeItem(f, sid)
	}
	p.touched[f.name] = true
	p.save()
	return nil
}

// Append keeps nothing: a copy for the Sent folder is the one the server
// made when the message was sent through it (Account.Send). Elsewhere
// it is refused: ActiveSync stores no message a client gives it.
func (c *easConn) Append(name string, _ []byte, _ *imap.AppendOptions) (imap.UID, uint32, error) {
	p := c.p
	f, err := p.boxOrErr(name)
	if err != nil {
		return 0, 0, err
	}
	if f.typ == easSent {
		return 0, f.validity, nil
	}
	return 0, 0, easCannot("store messages")
}

// folderCmd sends a folder command with the folder key, and syncs the
// folder list again after.
func (p *easProvider) folderCmd(cmd string, kids ...*wbxml.Node) error {
	ctx, cancel := p.ctx()
	defer cancel()
	p.listMu.Lock()
	defer p.listMu.Unlock()
	for try := 0; ; try++ {
		p.mu.Lock()
		key := p.folderKey
		p.mu.Unlock()
		if key == "" {
			if err := p.folderSyncLocked(ctx); err != nil {
				return err
			}
			continue
		}
		page := "FolderHierarchy:"
		n, err := p.do(ctx, cmd, wbxml.El(page+cmd, append([]*wbxml.Node{wbxml.Tx(page+"SyncKey", key)}, kids...)...))
		if err != nil {
			return err
		}
		if n == nil {
			return easRefused(&eas.StatusError{Cmd: cmd})
		}
		st := n.Value("Status")
		if st == "9" && try == 0 {
			if err := p.folderSyncLocked(ctx); err != nil {
				return err
			}
			continue
		}
		if st != "1" {
			return easRefused(&eas.StatusError{Cmd: cmd, Status: atoiOr0(st)})
		}
		// The change came with a new key, but the list is read again
		// from the old one, so the change shows as the server has it.
		return p.folderSyncLocked(ctx)
	}
}

// parentOf returns the server ID of the parent of an engine name and its
// own display name.
func (p *easProvider) parentOf(name string) (string, string, error) {
	i := strings.LastIndexByte(name, '/')
	if i < 0 {
		return "0", name, nil
	}
	pf, err := p.boxOrErr(name[:i])
	if err != nil {
		return "", "", err
	}
	return pf.id, name[i+1:], nil
}

func (c *easConn) Create(name string, _ *imap.CreateOptions) error {
	parent, leaf, err := c.p.parentOf(name)
	if err != nil {
		return err
	}
	return c.p.folderCmd("FolderCreate", wbxml.Tx("FolderHierarchy:ParentId", parent),
		wbxml.Tx("FolderHierarchy:DisplayName", leaf), wbxml.Tx("FolderHierarchy:Type", strconv.Itoa(easUserMail)))
}

func (c *easConn) Delete(name string) error {
	f, err := c.p.boxOrErr(name)
	if err != nil {
		return err
	}
	return c.p.folderCmd("FolderDelete", wbxml.Tx("FolderHierarchy:ServerId", f.id))
}

func (c *easConn) Rename(name, newName string, _ *imap.RenameOptions) error {
	f, err := c.p.boxOrErr(name)
	if err != nil {
		return err
	}
	parent, leaf, err := c.p.parentOf(newName)
	if err != nil {
		return err
	}
	return c.p.folderCmd("FolderUpdate", wbxml.Tx("FolderHierarchy:ServerId", f.id),
		wbxml.Tx("FolderHierarchy:ParentId", parent), wbxml.Tx("FolderHierarchy:DisplayName", leaf))
}

// Subscribe: ActiveSync shows every folder.
func (c *easConn) Subscribe(string, bool) error { return nil }

// --- Push ------------------------------------------------------------------

// Ping heartbeat limits, in seconds.
const (
	easMinHeartbeat = 60
	easMaxHeartbeat = 1680
)

type easWatch struct {
	easConn
	maxFolders int
	heartbeat  int // the server's limit, 0 if it gave none
}

func (p *easProvider) Watch(func()) (watchConn, error) {
	ctx, cancel := p.ctx()
	defer cancel()
	if _, err := p.session(ctx); err != nil {
		return nil, err
	}
	return &easWatch{easConn: easConn{p: p}}, nil
}

func (w *easWatch) Describe() []any {
	w.p.mu.Lock()
	defer w.p.mu.Unlock()
	return []any{"activesync_push", w.p.pinged}
}

func (w *easWatch) Notifies() bool {
	w.p.mu.Lock()
	defer w.p.mu.Unlock()
	return w.p.pinged
}

// Wait sends a Ping for every mail folder the model synced, which
// returns when one of them changes, or after d.
func (w *easWatch) Wait(ctx context.Context, d time.Duration, changed, wake <-chan struct{}) (wakeup, error) {
	p := w.p
	p.mu.Lock()
	var ids []string
	inbox := ""
	for _, f := range p.folders {
		if easMail(f.typ) && f.syncKey != "" {
			if f.typ == easInbox {
				inbox = f.id
			} else {
				ids = append(ids, f.id)
			}
		}
	}
	slices.Sort(ids)
	if inbox != "" {
		ids = append([]string{inbox}, ids...)
	}
	if w.maxFolders > 0 && len(ids) > w.maxFolders {
		ids = ids[:w.maxFolders]
	}
	list := p.listChanged
	p.listChanged = false
	p.mu.Unlock()

	pctx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopped := make(chan error, 1)
	go func() {
		select {
		case <-changed:
			stopped <- errCredentialsChanged
			cancel()
		case <-wake:
			stopped <- nil
			cancel()
		case <-pctx.Done():
		}
	}()
	result := func(n wakeup, err error) (wakeup, error) {
		cancel()
		select {
		case e := <-stopped:
			if e != nil {
				return wakeup{}, e
			}
		default:
		}
		return n, err
	}
	if len(ids) == 0 || list {
		// Nothing to ping yet: wait, and have the engine sync.
		t := time.NewTimer(max(d, 0))
		defer t.Stop()
		select {
		case <-pctx.Done():
		case <-t.C:
		}
		return result(wakeup{list: list}, ctx.Err())
	}
	hb := min(max(int(d/time.Second), easMinHeartbeat), easMaxHeartbeat)
	if w.heartbeat > 0 {
		hb = min(hb, w.heartbeat)
	}
	var folders []*wbxml.Node
	for _, id := range ids {
		folders = append(folders, wbxml.El("Ping:Folder", wbxml.Tx("Ping:Id", id), wbxml.Tx("Ping:Class", "Email")))
	}
	// The answer comes within the heartbeat: a connection that stays
	// silent past it is dead.
	rctx, rcancel := context.WithTimeout(pctx, time.Duration(hb)*time.Second+p.timeout())
	defer rcancel()
	n, err := p.do(rctx, "Ping", wbxml.El("Ping:Ping", wbxml.Tx("Ping:HeartbeatInterval", strconv.Itoa(hb)),
		wbxml.El("Ping:Folders", folders...)))
	if pctx.Err() != nil && ctx.Err() == nil {
		return result(wakeup{}, nil) // ended for the engine
	}
	if err != nil {
		return result(wakeup{}, err)
	}
	if n == nil {
		return result(wakeup{}, nil)
	}
	switch n.Value("Status") {
	case "1": // the heartbeat passed
		p.mu.Lock()
		p.pinged = true
		p.mu.Unlock()
		return result(wakeup{}, nil)
	case "2":
		p.mu.Lock()
		p.pinged = true
		var names []string
		for _, id := range n.Child("Folders").Children("Folder") {
			if f := p.folders[id.Text]; f != nil {
				names = append(names, f.name)
			}
		}
		p.mu.Unlock()
		return result(wakeup{names: names}, nil)
	case "5":
		w.heartbeat = atoiOr0(n.Value("HeartbeatInterval"))
		return result(wakeup{}, nil)
	case "6":
		w.maxFolders = atoiOr0(n.Value("MaxFolders"))
		return result(wakeup{}, nil)
	case "7":
		return result(wakeup{list: true}, nil)
	case "3", "4":
		return result(wakeup{all: true}, nil)
	default:
		return result(wakeup{}, &eas.StatusError{Cmd: "Ping", Status: atoiOr0(n.Value("Status"))})
	}
}

// --- Sending -----------------------------------------------------------------

// send sends a message through the server, which keeps a copy in the Sent
// folder. Recipients the message's header does not name are added to it
// as Bcc, which the server removes: ActiveSync sends to the header's
// recipients.
func (p *easProvider) send(ctx context.Context, to []string, data []byte) error {
	c, err := p.session(ctx)
	if err != nil {
		return err
	}
	data = withEnvelopeBcc(data, to)
	if c.AtLeast("14.0") {
		var id [12]byte
		_, _ = rand.Read(id[:])
		n, err := c.Do(ctx, "SendMail", nil, wbxml.El("ComposeMail:SendMail",
			wbxml.Tx("ComposeMail:ClientId", hex.EncodeToString(id[:])), wbxml.El("ComposeMail:SaveInSentItems"),
			wbxml.Op("ComposeMail:Mime", data)))
		if err != nil {
			return easRejected(err)
		}
		if n != nil && n.Value("Status") != "" && n.Value("Status") != "1" {
			return fmt.Errorf("%w: status %s", ErrSendRefused, n.Value("Status"))
		}
		return nil
	}
	_, err = c.DoRaw(ctx, "SendMail", url.Values{"SaveInSent": {"T"}}, data, "message/rfc822")
	var he *eas.HTTPError
	if errors.As(err, &he) && he.Code >= 400 && he.Code < 500 {
		return fmt.Errorf("%w: %w", ErrSendRefused, err)
	}
	return easRejected(err)
}

// withEnvelopeBcc adds the recipients the header does not name as Bcc.
func withEnvelopeBcc(data []byte, to []string) []byte {
	m, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return data
	}
	named := map[string]bool{}
	for _, f := range []string{"To", "Cc", "Bcc"} {
		l, _ := m.Header.AddressList(f)
		for _, a := range l {
			named[strings.ToLower(a.Address)] = true
		}
	}
	var bcc []string
	for _, r := range to {
		if !named[strings.ToLower(r)] {
			bcc = append(bcc, r)
		}
	}
	if len(bcc) == 0 {
		return data
	}
	return append([]byte("Bcc: "+strings.Join(bcc, ", ")+"\r\n"), data...)
}
