package engine

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/internal/jmap"
	"github.com/brodyhoskins/mailcached/internal/netbind"
)

// jmapProvider reaches a JMAP provider for one account. JMAP names emails
// by IDs, and an email can be in several mailboxes; the engine names
// messages by a folder and a UID. The provider gives each (mailbox,
// email) pair a UID of its own, which it keeps in the account's database
// with its sync states, and answers the engine's per-folder Sync from its
// model of the account, which Mailbox/get and Email/changes keep current.
//
// JMAP has no \Deleted keyword: the provider keeps that flag itself, and
// an expunge removes the email from the folder (or destroys it, when it is
// in no other).
type jmapProvider struct {
	a        *Account
	u        Upstream
	password func() string

	mu sync.Mutex // guards what follows
	// The client for the last password, and the account at the provider.
	client   *jmap.Client
	clientPw string
	acct     jmap.ID
	loaded   bool // the model was read from the database
	// The provider's states the model is current with ("" before the
	// first full read), and the provider's own modseq, which goes up with
	// every change to the model.
	emailState jmap.State
	modseq     int64
	boxes      map[jmap.ID]*jbox
	byName     map[string]*jbox
	// emails holds what the provider said of the emails it reported, as
	// far as the sync needs it. It is not saved: after a restart an email
	// is asked for again when the sync needs it.
	emails map[jmap.ID]*jemail
	// dirty says the provider pushed a change.
	dirty       bool
	refreshedAt time.Time
	// touched holds the folders that changed since the engine's last
	// Wait.
	touched map[string]bool
	// listChanged says the mailbox list changed since the last Wait.
	listChanged bool
	// rows holds the UID mappings to save: a UID, or 0 to delete.
	rows    map[[2]jmap.ID]imap.UID
	boxRows map[jmap.ID]bool

	refreshMu sync.Mutex // one refresh at a time
}

// jbox is a mailbox at the provider.
type jbox struct {
	id         jmap.ID
	name       string // the folder name the engine uses
	leaf       string
	parent     jmap.ID
	role       string
	subscribed bool
	validity   uint32
	next       imap.UID
	uidOf      map[jmap.ID]imap.UID
	emailAt    map[imap.UID]jmap.ID
	// seq is the provider modseq at which a member's flags last changed.
	seq     map[imap.UID]int64
	deleted map[imap.UID]bool // \Deleted, which JMAP has no keyword for
}

// jemail is what the sync needs of an email.
type jemail struct {
	mailboxes map[jmap.ID]bool
	keywords  map[string]bool
	size      int64
	received  time.Time
	header    []byte // the syncSection fields
	blob      jmap.ID
}

// jmapRefreshMin is the shortest time between two reads of the provider's
// changes, unless it pushed one.
var jmapRefreshMin = time.Second

func newJMAPProvider(a *Account, u Upstream, password func() string) *jmapProvider {
	return &jmapProvider{a: a, u: u, password: password, boxes: map[jmap.ID]*jbox{}, byName: map[string]*jbox{},
		emails: map[jmap.ID]*jemail{}, touched: map[string]bool{}, rows: map[[2]jmap.ID]imap.UID{}, boxRows: map[jmap.ID]bool{}}
}

func (p *jmapProvider) timeout() time.Duration {
	if p.u.Timeout > 0 {
		return p.u.Timeout
	}
	return time.Minute
}

func (p *jmapProvider) newClient(password string) *jmap.Client {
	tr := &http.Transport{
		DialContext:         netbind.NewSpread(p.u.Sources, p.timeout(), dialControl(p.timeout(), true)).DialContext,
		ForceAttemptHTTP2:   true,
		TLSClientConfig:     p.u.TLSConfig,
		TLSHandshakeTimeout: 10 * time.Second,
		IdleConnTimeout:     90 * time.Second,
		MaxConnsPerHost:     p.u.MaxConns,
		// The client asks for zstd and gzip itself.
		DisableCompression: true,
	}
	if tr.TLSClientConfig == nil {
		tr.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	ua := p.a.b.Name
	if p.a.b.Version != "" {
		ua += "/" + p.a.b.Version
	}
	c := &jmap.Client{HTTP: &http.Client{Transport: tr}, SessionURL: p.u.URL, User: p.a.login, Secret: password,
		Bearer: p.u.Bearer, UserAgent: ua}
	if p.u.MaxConns > 0 {
		// The push stream holds one of the connections.
		c.MaxConcurrent = max(1, p.u.MaxConns-1)
	}
	return c
}

func (p *jmapProvider) Login(password string) error {
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout())
	defer cancel()
	c := p.newClient(password)
	s, err := c.RefreshSession(ctx)
	if errors.Is(err, jmap.ErrUnauthorized) {
		return fmt.Errorf("%w: %w", ErrLoginRejected, err)
	}
	if err != nil {
		return err
	}
	if s.MailAccount() == "" {
		return fmt.Errorf("%w: the JMAP account has no mail", ErrLoginRejected)
	}
	p.mu.Lock()
	p.client, p.clientPw, p.acct = c, password, s.MailAccount()
	p.mu.Unlock()
	return nil
}

// session returns the client for the accepted password.
func (p *jmapProvider) session(ctx context.Context) (*jmap.Client, jmap.ID, error) {
	pw := p.password()
	if pw == "" {
		return nil, "", ErrNoCredentials
	}
	p.mu.Lock()
	if p.client != nil && p.clientPw == pw {
		c, acct := p.client, p.acct
		p.mu.Unlock()
		return c, acct, nil
	}
	p.mu.Unlock()
	c := p.newClient(pw)
	s, err := c.Session(ctx)
	if errors.Is(err, jmap.ErrUnauthorized) {
		return nil, "", fmt.Errorf("%w: %w", ErrLoginRejected, err)
	}
	if err != nil {
		return nil, "", err
	}
	p.mu.Lock()
	p.client, p.clientPw, p.acct = c, pw, s.MailAccount()
	p.mu.Unlock()
	return c, s.MailAccount(), nil
}

func (p *jmapProvider) Conn(priority, string) (conn, error) { return &jmapConn{p: p}, nil }

func (p *jmapProvider) Close() {}

func (p *jmapProvider) Capacity() int {
	p.mu.Lock()
	c := p.client
	p.mu.Unlock()
	if c == nil {
		return max(0, p.u.MaxConns-1)
	}
	return c.Capacity()
}

// refused turns a JMAP refusal into an *imap.Error, which the engine
// treats as the provider saying no. Anything else stays an error to retry.
func refused(err error) error {
	var me *jmap.MethodError
	if errors.As(err, &me) && me.Type != jmap.ErrServerFail && me.Type != jmap.ErrServerUnavailable {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: me.Error()}
	}
	var se jmap.SetError
	if errors.As(err, &se) {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Text: se.Error()}
	}
	return err
}

// --- The model -------------------------------------------------------------

// load reads the saved UID mappings and states (p.mu held).
func (p *jmapProvider) load() error {
	p.loaded = true
	s := p.a.b.Store
	if s == nil {
		return nil
	}
	db, err := s.db(p.a.login)
	if err != nil {
		return err
	}
	rows, err := db.Query(`SELECT id, validity, next FROM jmap_boxes`)
	if err != nil {
		return err
	}
	for rows.Next() {
		b := newJBox("")
		var next uint32
		if err := rows.Scan(&b.id, &b.validity, &next); err != nil {
			rows.Close()
			return err
		}
		b.next = imap.UID(next)
		p.boxes[b.id] = b
	}
	rows.Close()
	rows, err = db.Query(`SELECT box, email, uid FROM jmap_uids`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var box, email jmap.ID
		var uid uint32
		if err := rows.Scan(&box, &email, &uid); err != nil {
			rows.Close()
			return err
		}
		if b := p.boxes[box]; b != nil {
			b.uidOf[email], b.emailAt[imap.UID(uid)] = imap.UID(uid), email
		}
	}
	rows.Close()
	var state, modseq string
	_ = db.QueryRow(`SELECT value FROM meta WHERE name = 'jmap_email_state'`).Scan(&state)
	_ = db.QueryRow(`SELECT value FROM meta WHERE name = 'jmap_modseq'`).Scan(&modseq)
	p.emailState = jmap.State(state)
	p.modseq, _ = strconv.ParseInt(modseq, 10, 64)
	return nil
}

// save writes what changed (p.mu held).
func (p *jmapProvider) save() {
	s := p.a.b.Store
	if s == nil || (len(p.rows) == 0 && len(p.boxRows) == 0) {
		clear(p.rows)
		clear(p.boxRows)
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
		for id := range p.boxRows {
			if b := p.boxes[id]; b != nil {
				exec(`INSERT INTO jmap_boxes (id, validity, next) VALUES (?, ?, ?)
					ON CONFLICT (id) DO UPDATE SET validity = excluded.validity, next = excluded.next`, b.id, b.validity, uint32(b.next))
			} else {
				exec(`DELETE FROM jmap_boxes WHERE id = ?`, id)
				exec(`DELETE FROM jmap_uids WHERE box = ?`, id)
			}
		}
		for k, uid := range p.rows {
			if uid == 0 {
				exec(`DELETE FROM jmap_uids WHERE box = ? AND email = ?`, k[0], k[1])
			} else {
				exec(`INSERT INTO jmap_uids (box, email, uid) VALUES (?, ?, ?)
					ON CONFLICT (box, email) DO UPDATE SET uid = excluded.uid`, k[0], k[1], uint32(uid))
			}
		}
		exec(`INSERT INTO meta (name, value) VALUES ('jmap_email_state', ?), ('jmap_modseq', ?)
			ON CONFLICT (name) DO UPDATE SET value = excluded.value`, string(p.emailState), strconv.FormatInt(p.modseq, 10))
		if err != nil {
			return errors.Join(err, tx.Rollback())
		}
		return tx.Commit()
	}()
	if err != nil {
		p.a.b.Log.Warn("jmap: could not save the provider's state", "user", p.a.login, "err", err)
		return
	}
	clear(p.rows)
	clear(p.boxRows)
}

func newJBox(id jmap.ID) *jbox {
	return &jbox{id: id, uidOf: map[jmap.ID]imap.UID{}, emailAt: map[imap.UID]jmap.ID{}, seq: map[imap.UID]int64{},
		deleted: map[imap.UID]bool{}, next: 1}
}

// listSig sums up the mailbox list, to tell when it changed (p.mu held).
func (p *jmapProvider) listSig() string {
	var parts []string
	for id, b := range p.boxes {
		parts = append(parts, fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%v", id, b.leaf, b.parent, b.role, b.subscribed))
	}
	slices.Sort(parts)
	return strings.Join(parts, "\x01")
}

// newValidity returns a UIDVALIDITY for a new box (p.mu held).
func (p *jmapProvider) newValidity() uint32 {
	v := uint32(time.Now().Unix())
	for _, b := range p.boxes {
		v = max(v, b.validity+1)
	}
	return v
}

// place puts email in box with a new UID, or removes it (p.mu held).
func (p *jmapProvider) place(b *jbox, email jmap.ID, in bool) {
	uid, has := b.uidOf[email]
	switch {
	case in && !has:
		uid = b.next
		b.next++
		b.uidOf[email], b.emailAt[uid], b.seq[uid] = uid, email, p.modseq
		p.rows[[2]jmap.ID{b.id, email}] = uid
		p.boxRows[b.id] = true
	case !in && has:
		delete(b.uidOf, email)
		delete(b.emailAt, uid)
		delete(b.seq, uid)
		delete(b.deleted, uid)
		p.rows[[2]jmap.ID{b.id, email}] = 0
	default:
		return
	}
	p.touched[b.name] = true
}

// apply takes what the provider says of an email (p.mu held).
func (p *jmapProvider) apply(id jmap.ID, e *jemail) {
	old := p.emails[id]
	p.emails[id] = e
	for bid, b := range p.boxes {
		p.place(b, id, e.mailboxes[bid])
		if uid, ok := b.uidOf[id]; ok && (old == nil || !maps.Equal(old.keywords, e.keywords)) {
			b.seq[uid] = p.modseq
			p.touched[b.name] = true
		}
	}
}

// destroy removes an email everywhere (p.mu held).
func (p *jmapProvider) destroy(id jmap.ID) {
	delete(p.emails, id)
	for _, b := range p.boxes {
		p.place(b, id, false)
	}
}

// names computes the folder names: the path of mailbox names, with "/",
// and INBOX for the inbox (p.mu held).
func (p *jmapProvider) names() {
	clear(p.byName)
	var path func(b *jbox, depth int) string
	path = func(b *jbox, depth int) string {
		name := b.leaf
		if b.role == jmap.RoleInbox && b.parent == "" {
			name = "INBOX"
		}
		if parent := p.boxes[b.parent]; parent != nil && depth < 32 {
			return path(parent, depth+1) + "/" + name
		}
		return name
	}
	for _, b := range p.boxes {
		name := path(b, 0)
		for p.byName[name] != nil {
			name += "_"
		}
		if b.name != name {
			p.touched[b.name] = true
			b.name = name
		}
		p.byName[name] = b
	}
}

// syncProperties are what Email/get asks for the sync.
func (p *jmapProvider) syncProperties() []string {
	props := []string{"mailboxIds", "keywords", "receivedAt", "size", "blobId", "header:Message-ID:asRaw"}
	if t := p.a.b.Transform; t != nil {
		for _, f := range t.Fields() {
			props = append(props, "header:"+f+":asRaw")
		}
	}
	return props
}

// jemailOf turns an Email/get result into what the sync keeps.
func (p *jmapProvider) jemailOf(e *jmap.Email) *jemail {
	out := &jemail{mailboxes: e.MailboxIDs, keywords: map[string]bool{}, size: e.Size, blob: e.BlobID}
	for k, on := range e.Keywords {
		if on {
			out.keywords[strings.ToLower(k)] = true
		}
	}
	if e.ReceivedAt != nil {
		out.received = *e.ReceivedAt
	}
	var hdr strings.Builder
	fields := []string{"Message-ID"}
	if t := p.a.b.Transform; t != nil {
		fields = append(fields, t.Fields()...)
	}
	for _, f := range fields {
		if v := e.HeaderRaw(f + ":asRaw"); v != "" {
			hdr.WriteString(f + ":" + v + "\r\n")
		}
	}
	out.header = []byte(hdr.String())
	return out
}

// getEmails asks for the emails ids, in batches, and applies them.
func (p *jmapProvider) getEmails(ctx context.Context, c *jmap.Client, acct jmap.ID, ids []jmap.ID) error {
	s, err := c.Session(ctx)
	if err != nil {
		return err
	}
	for chunk := range slices.Chunk(ids, min(s.Core().MaxObjectsInGet, 500)) {
		b := c.NewBatch(jmap.CapMail)
		g := b.Add("Email/get", jmap.GetArgs{AccountID: acct, IDs: chunk, Properties: p.syncProperties()})
		res, err := b.Do(ctx)
		if err != nil {
			return err
		}
		var got jmap.GetResponse[jmap.Email]
		if err := res.Get(g, "Email/get", &got); err != nil {
			return err
		}
		p.mu.Lock()
		for i := range got.List {
			p.apply(got.List[i].ID, p.jemailOf(&got.List[i]))
		}
		for _, id := range got.NotFound {
			p.destroy(id)
		}
		p.mu.Unlock()
	}
	return nil
}

// refresh brings the model up to date with the provider: the mailboxes,
// then the emails' changes since the saved state, or every email when
// there is none (or the provider cannot say). Unless force, it does
// nothing within jmapRefreshMin of the last time, if nothing was pushed.
func (p *jmapProvider) refresh(ctx context.Context, force bool) error {
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()
	p.mu.Lock()
	if !p.loaded {
		if err := p.load(); err != nil {
			p.a.b.Log.Warn("jmap: could not load the provider's state", "user", p.a.login, "err", err)
		}
	}
	if !force && !p.dirty && time.Since(p.refreshedAt) < jmapRefreshMin && p.emailState != "" {
		p.mu.Unlock()
		return nil
	}
	p.dirty = false
	since := p.emailState
	p.mu.Unlock()

	c, acct, err := p.session(ctx)
	if err != nil {
		return err
	}
	// The mailboxes, and the email changes, in one request.
	b := c.NewBatch(jmap.CapMail)
	mg := b.Add("Mailbox/get", jmap.GetArgs{AccountID: acct,
		Properties: []string{"id", "name", "parentId", "role", "isSubscribed"}})
	var ch string
	if since != "" {
		ch = b.Add("Email/changes", jmap.ChangesArgs{AccountID: acct, SinceState: since, MaxChanges: 500})
	} else {
		ch = b.Add("Email/get", jmap.GetArgs{AccountID: acct, IDs: []jmap.ID{}})
	}
	res, err := b.Do(ctx)
	if err != nil {
		return err
	}
	var boxes jmap.GetResponse[jmap.Mailbox]
	if err := res.Get(mg, "Mailbox/get", &boxes); err != nil {
		return err
	}
	p.mu.Lock()
	p.modseq++
	before := p.listSig()
	seen := map[jmap.ID]bool{}
	for _, m := range boxes.List {
		seen[m.ID] = true
		bx := p.boxes[m.ID]
		if bx == nil {
			bx = newJBox(m.ID)
			bx.validity = p.newValidity()
			p.boxes[m.ID] = bx
			p.boxRows[m.ID] = true
		}
		bx.leaf, bx.subscribed = m.Name, m.IsSubscribed
		bx.parent, bx.role = "", ""
		if m.ParentID != nil {
			bx.parent = *m.ParentID
		}
		if m.Role != nil {
			bx.role = *m.Role
		}
	}
	for id, bx := range p.boxes {
		if !seen[id] {
			p.touched[bx.name] = true
			delete(p.boxes, id)
			p.boxRows[id] = true
		}
	}
	p.names()
	if p.listSig() != before {
		p.listChanged = true
	}
	p.mu.Unlock()

	if since == "" {
		var st jmap.GetResponse[jmap.Email]
		if err := res.Get(ch, "Email/get", &st); err != nil {
			return err
		}
		if err := p.readAll(ctx, c, acct); err != nil {
			return err
		}
		p.mu.Lock()
		p.emailState = st.State
	} else {
		for {
			var changes jmap.ChangesResponse
			err := res.Get(ch, "Email/changes", &changes)
			var me *jmap.MethodError
			if errors.As(err, &me) && me.Type == jmap.ErrCannotCalculateChanges {
				p.mu.Lock()
				p.emailState = ""
				p.mu.Unlock()
				return p.refreshAll(ctx, c, acct)
			}
			if err != nil {
				return err
			}
			if err := p.getEmails(ctx, c, acct, append(changes.Created, changes.Updated...)); err != nil {
				return err
			}
			p.mu.Lock()
			for _, id := range changes.Destroyed {
				p.destroy(id)
			}
			p.emailState = changes.NewState
			p.mu.Unlock()
			if !changes.HasMoreChanges {
				break
			}
			b := c.NewBatch(jmap.CapMail)
			ch = b.Add("Email/changes", jmap.ChangesArgs{AccountID: acct, SinceState: changes.NewState, MaxChanges: 500})
			if res, err = b.Do(ctx); err != nil {
				return err
			}
		}
		p.mu.Lock()
	}
	p.refreshedAt = time.Now()
	p.save()
	p.mu.Unlock()
	return nil
}

// refreshAll reads every email again, after the provider could not say
// what changed. UIDs of emails still in their mailboxes stay.
func (p *jmapProvider) refreshAll(ctx context.Context, c *jmap.Client, acct jmap.ID) error {
	b := c.NewBatch(jmap.CapMail)
	g := b.Add("Email/get", jmap.GetArgs{AccountID: acct, IDs: []jmap.ID{}})
	res, err := b.Do(ctx)
	if err != nil {
		return err
	}
	var st jmap.GetResponse[jmap.Email]
	if err := res.Get(g, "Email/get", &st); err != nil {
		return err
	}
	if err := p.readAll(ctx, c, acct); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.emailState = st.State
	p.refreshedAt = time.Now()
	p.save()
	return nil
}

// readAll reads every email, oldest first, so new UIDs follow the
// order mail arrived in, and drops what the provider no longer has.
func (p *jmapProvider) readAll(ctx context.Context, c *jmap.Client, acct jmap.ID) error {
	s, err := c.Session(ctx)
	if err != nil {
		return err
	}
	page := min(s.Core().MaxObjectsInGet, 500)
	var ids []jmap.ID
	for pos := 0; ; pos += page {
		b := c.NewBatch(jmap.CapMail)
		t := true
		q := b.Add("Email/query", jmap.QueryArgs{AccountID: acct, Position: pos, Limit: &page,
			Sort: []jmap.Comparator{{Property: "receivedAt", IsAscending: &t}}})
		res, err := b.Do(ctx)
		if err != nil {
			return err
		}
		var got jmap.QueryResponse
		if err := res.Get(q, "Email/query", &got); err != nil {
			return err
		}
		ids = append(ids, got.IDs...)
		if len(got.IDs) < page {
			break
		}
	}
	if err := p.getEmails(ctx, c, acct, ids); err != nil {
		return err
	}
	have := map[jmap.ID]bool{}
	for _, id := range ids {
		have[id] = true
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, b := range p.boxes {
		for id := range b.uidOf {
			if !have[id] {
				p.destroy(id)
			}
		}
	}
	return nil
}

// ensure makes sure the model knows the emails at uids in box, asking the
// provider for those it does not.
func (p *jmapProvider) ensure(ctx context.Context, b *jbox, uids []imap.UID) error {
	p.mu.Lock()
	var missing []jmap.ID
	for _, u := range uids {
		if id, ok := b.emailAt[u]; ok && p.emails[id] == nil {
			missing = append(missing, id)
		}
	}
	p.mu.Unlock()
	if len(missing) == 0 {
		return nil
	}
	c, acct, err := p.session(ctx)
	if err != nil {
		return err
	}
	return p.getEmails(ctx, c, acct, missing)
}

// box returns the mailbox with folder name, or a NO.
func (p *jmapProvider) box(name string) (*jbox, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if b := p.byName[CanonicalName(name)]; b != nil {
		return b, nil
	}
	return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNonExistent, Text: "No such mailbox"}
}

var jmapFlags = []imap.Flag{imap.FlagSeen, imap.FlagAnswered, imap.FlagFlagged, imap.FlagDraft, imap.FlagDeleted}

// flagsOf is the IMAP flags of an email in a box (p.mu held).
func flagsOf(e *jemail, b *jbox, uid imap.UID) []imap.Flag {
	out := []imap.Flag{}
	for k := range e.keywords {
		switch k {
		case "$seen":
			out = append(out, imap.FlagSeen)
		case "$flagged":
			out = append(out, imap.FlagFlagged)
		case "$answered":
			out = append(out, imap.FlagAnswered)
		case "$draft":
			out = append(out, imap.FlagDraft)
		case "$forwarded":
			out = append(out, "$Forwarded")
		default:
			out = append(out, imap.Flag(k))
		}
	}
	if b.deleted[uid] {
		out = append(out, imap.FlagDeleted)
	}
	slices.Sort(out)
	return out
}

// keywordOf is the JMAP keyword for an IMAP flag; "" for \Deleted and
// \Recent, which have none.
func keywordOf(f imap.Flag) string {
	switch strings.ToLower(string(f)) {
	case `\seen`:
		return "$seen"
	case `\flagged`:
		return "$flagged"
	case `\answered`:
		return "$answered"
	case `\draft`:
		return "$draft"
	}
	if strings.HasPrefix(string(f), `\`) {
		return ""
	}
	return strings.ToLower(string(f))
}

// --- Connections -----------------------------------------------------------

// jmapConn is the provider seen as a connection. JMAP needs none: every
// request is HTTP, over the client's pool.
type jmapConn struct {
	p *jmapProvider
}

func (c *jmapConn) Release(error) {}

func (c *jmapConn) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), c.p.timeout())
}

func (c *jmapConn) List() ([]folderInfo, error) {
	ctx, cancel := c.ctx()
	defer cancel()
	p := c.p
	if err := p.refresh(ctx, true); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	attrs := map[string]imap.MailboxAttr{"all": imap.MailboxAttrAll, "archive": imap.MailboxAttrArchive,
		"drafts": imap.MailboxAttrDrafts, "flagged": imap.MailboxAttrFlagged, "junk": imap.MailboxAttrJunk,
		"sent": imap.MailboxAttrSent, "trash": imap.MailboxAttrTrash}
	out := make([]folderInfo, 0, len(p.boxes))
	for _, b := range p.boxes {
		f := folderInfo{name: b.name, delim: '/', subscribed: b.subscribed, selectable: true}
		if a, ok := attrs[b.role]; ok {
			f.attrs = []imap.MailboxAttr{a}
		}
		out = append(out, f)
	}
	return out, nil
}

func (c *jmapConn) Sync(name string, st syncState) (*delta, error) {
	ctx, cancel := c.ctx()
	defer cancel()
	p := c.p
	if err := p.refresh(ctx, st.force); err != nil {
		return nil, err
	}
	b, err := p.box(name)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	reset := st.validity != 0 && st.validity != b.validity
	unchanged := !st.force && !st.stale && !st.refetchFlags && st.synced && !reset && st.validity == b.validity &&
		st.next == b.next && st.count == len(b.emailAt) && st.modSeq == uint64(p.modseq)
	if unchanged {
		p.mu.Unlock()
		return &delta{unchanged: true}, nil
	}
	all := make([]imap.UID, 0, len(b.emailAt))
	for u := range b.emailAt {
		all = append(all, u)
	}
	p.mu.Unlock()

	// The messages the engine may not know, and those whose flags changed.
	var fresh, changed []imap.UID
	for _, u := range all {
		switch {
		case reset || st.validity == 0 || u >= st.next || !st.known(u):
			fresh = append(fresh, u)
		case st.refetchFlags:
			changed = append(changed, u)
		default:
			p.mu.Lock()
			if b.seq[u] > int64(st.modSeq) {
				changed = append(changed, u)
			}
			p.mu.Unlock()
		}
	}
	if err := p.ensure(ctx, b, append(slices.Clone(fresh), changed...)); err != nil {
		return nil, err
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	d := &delta{reset: reset, present: map[imap.UID]bool{}, validity: b.validity, next: b.next, modSeq: uint64(p.modseq),
		folderFlags: jmapFlags, permanentFlags: append(slices.Clone(jmapFlags), imap.FlagWildcard),
		fullFlags: reset || st.refetchFlags}
	for _, u := range all {
		d.present[u] = true
	}
	for _, u := range fresh {
		e := p.emails[b.emailAt[u]]
		if e == nil {
			delete(d.present, u) // gone meanwhile
			continue
		}
		d.fresh = append(d.fresh, freshMessage{uid: u, flags: flagsOf(e, b, u), date: e.received, size: e.size, header: e.header})
	}
	for _, u := range changed {
		if e := p.emails[b.emailAt[u]]; e != nil {
			d.flags = append(d.flags, flagUpdate{u, flagsOf(e, b, u)})
		}
	}
	return d, nil
}

// blobs returns the blob of each UID in box.
func (c *jmapConn) blobs(ctx context.Context, name string, uids []imap.UID) (*jbox, map[imap.UID]jmap.ID, error) {
	p := c.p
	b, err := p.box(name)
	if err != nil {
		return nil, nil, err
	}
	if err := p.ensure(ctx, b, uids); err != nil {
		return nil, nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[imap.UID]jmap.ID{}
	for _, u := range uids {
		if e := p.emails[b.emailAt[u]]; e != nil && e.blob != "" {
			out[u] = e.blob
		}
	}
	return b, out, nil
}

// FetchSections: JMAP has no byte ranges, and its part downloads are
// decoded, so messages are read whole.
func (c *jmapConn) FetchSections(string, []imap.UID, []Section, func(imap.UID, int, []byte)) error {
	return errNoPieces
}

// Search: JMAP's Email/query could, but the proxy reads the messages.
func (c *jmapConn) Search(string, *imap.SearchCriteria) ([]imap.UID, error) {
	return nil, errNoSearch
}

func (c *jmapConn) FetchFull(name string, uids []imap.UID, each func(uid imap.UID, raw []byte)) error {
	ctx, cancel := c.ctx()
	defer cancel()
	_, blobs, err := c.blobs(ctx, name, uids)
	if err != nil {
		return err
	}
	cl, acct, err := c.p.session(ctx)
	if err != nil {
		return err
	}
	for _, u := range uids {
		blob, ok := blobs[u]
		if !ok {
			continue
		}
		data, err := cl.Download(ctx, acct, blob)
		if errors.Is(err, jmap.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		each(u, data)
	}
	return nil
}

// FetchHeaders downloads the messages: a JMAP provider describes a body
// structure in its own terms, not with what IMAP clients need (encodings,
// line counts).
func (c *jmapConn) FetchHeaders(name string, uids []imap.UID) (map[imap.UID]*HeaderEntry, error) {
	out := map[imap.UID]*HeaderEntry{}
	err := c.FetchFull(name, uids, func(u imap.UID, raw []byte) { out[u] = EntryOf(raw) })
	return out, err
}

// set sends an Email/set of updates and destroys, and returns the first
// refusal.
func (c *jmapConn) set(ctx context.Context, update map[jmap.ID]jmap.PatchObject, destroy []jmap.ID) error {
	if len(update)+len(destroy) == 0 {
		return nil
	}
	cl, acct, err := c.p.session(ctx)
	if err != nil {
		return err
	}
	b := cl.NewBatch(jmap.CapMail)
	s := b.Add("Email/set", jmap.SetArgs[json.RawMessage]{AccountID: acct, Update: update, Destroy: destroy})
	res, err := b.Do(ctx)
	if err != nil {
		return err
	}
	var got jmap.SetResponse[json.RawMessage]
	if err := res.Get(s, "Email/set", &got); err != nil {
		return refused(err)
	}
	for _, e := range got.NotUpdated {
		if e.Type != jmap.SetNotFound {
			return refused(e)
		}
	}
	for _, e := range got.NotDestroyed {
		if e.Type != jmap.SetNotFound {
			return refused(e)
		}
	}
	return nil
}

func jsonTrue() json.RawMessage { return json.RawMessage("true") }
func jsonNull() json.RawMessage { return json.RawMessage("null") }

func (c *jmapConn) Store(name string, uids []imap.UID, op imap.StoreFlagsOp, flags []imap.Flag) (map[imap.UID][]imap.Flag, error) {
	ctx, cancel := c.ctx()
	defer cancel()
	p := c.p
	b, err := p.box(name)
	if err != nil {
		return nil, err
	}
	deleted := slices.ContainsFunc(flags, func(f imap.Flag) bool { return strings.EqualFold(string(f), string(imap.FlagDeleted)) })
	update := map[jmap.ID]jmap.PatchObject{}
	p.mu.Lock()
	for _, u := range uids {
		id, ok := b.emailAt[u]
		if !ok {
			continue
		}
		switch op {
		case imap.StoreFlagsAdd:
			if deleted {
				b.deleted[u] = true
			}
		case imap.StoreFlagsDel:
			if deleted {
				delete(b.deleted, u)
			}
		case imap.StoreFlagsSet:
			if deleted {
				b.deleted[u] = true
			} else {
				delete(b.deleted, u)
			}
		}
		patch := jmap.PatchObject{}
		if op == imap.StoreFlagsSet {
			kw := map[string]bool{}
			for _, f := range flags {
				if k := keywordOf(f); k != "" {
					kw[k] = true
				}
			}
			raw, _ := json.Marshal(kw)
			patch["keywords"] = raw
		} else {
			for _, f := range flags {
				k := keywordOf(f)
				if k == "" {
					continue
				}
				if op == imap.StoreFlagsAdd {
					patch["keywords/"+k] = jsonTrue()
				} else {
					patch["keywords/"+k] = jsonNull()
				}
			}
		}
		if len(patch) > 0 {
			update[id] = patch
		}
	}
	p.mu.Unlock()
	// The engine keeps its own flags; the next sync brings the provider's.
	return nil, c.set(ctx, update, nil)
}

// mailboxPatch moves emails in or out of mailboxes, and waits until the
// model has the result; it returns the UIDs the emails have in dest.
func (c *jmapConn) mailboxPatch(name string, uids []imap.UID, dest string, leave bool) (map[imap.UID]imap.UID, error) {
	ctx, cancel := c.ctx()
	defer cancel()
	p := c.p
	src, err := p.box(name)
	if err != nil {
		return nil, err
	}
	dst, err := p.box(dest)
	if err != nil {
		return nil, err
	}
	update := map[jmap.ID]jmap.PatchObject{}
	ids := map[imap.UID]jmap.ID{}
	p.mu.Lock()
	for _, u := range uids {
		id, ok := src.emailAt[u]
		if !ok {
			continue
		}
		ids[u] = id
		patch := jmap.PatchObject{"mailboxIds/" + string(dst.id): jsonTrue()}
		if leave && src != dst {
			patch["mailboxIds/"+string(src.id)] = jsonNull()
		}
		update[id] = patch
	}
	p.mu.Unlock()
	if err := c.set(ctx, update, nil); err != nil {
		return nil, err
	}
	if err := p.refresh(ctx, true); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := map[imap.UID]imap.UID{}
	for u, id := range ids {
		if nu, ok := dst.uidOf[id]; ok {
			out[u] = nu
		}
	}
	return out, nil
}

func (c *jmapConn) Copy(name string, uids []imap.UID, dest string) (map[imap.UID]imap.UID, error) {
	return c.mailboxPatch(name, uids, dest, false)
}

func (c *jmapConn) Move(name string, uids []imap.UID, dest string) (map[imap.UID]imap.UID, error) {
	return c.mailboxPatch(name, uids, dest, true)
}

// Expunge takes the emails out of the folder, and destroys those in no
// other.
func (c *jmapConn) Expunge(name string, uids []imap.UID) error {
	ctx, cancel := c.ctx()
	defer cancel()
	p := c.p
	b, err := p.box(name)
	if err != nil {
		return err
	}
	if err := p.ensure(ctx, b, uids); err != nil {
		return err
	}
	update := map[jmap.ID]jmap.PatchObject{}
	var destroy []jmap.ID
	p.mu.Lock()
	for _, u := range uids {
		id, ok := b.emailAt[u]
		if !ok {
			continue
		}
		e := p.emails[id]
		if e == nil || len(e.mailboxes) <= 1 {
			destroy = append(destroy, id)
		} else {
			update[id] = jmap.PatchObject{"mailboxIds/" + string(b.id): jsonNull()}
		}
	}
	p.mu.Unlock()
	if err := c.set(ctx, update, destroy); err != nil {
		return err
	}
	return p.refresh(ctx, true)
}

func (c *jmapConn) Append(name string, data []byte, opts *imap.AppendOptions) (imap.UID, uint32, error) {
	ctx, cancel := c.ctx()
	defer cancel()
	p := c.p
	b, err := p.box(name)
	if err != nil {
		return 0, 0, err
	}
	cl, acct, err := p.session(ctx)
	if err != nil {
		return 0, 0, err
	}
	up, err := cl.Upload(ctx, acct, "message/rfc822", data)
	if err != nil {
		return 0, 0, err
	}
	imp := jmap.EmailImport{BlobID: up.BlobID, MailboxIDs: map[jmap.ID]bool{b.id: true}, Keywords: map[string]bool{}}
	deleted := false
	if opts != nil {
		for _, f := range opts.Flags {
			if k := keywordOf(f); k != "" {
				imp.Keywords[k] = true
			}
			deleted = deleted || strings.EqualFold(string(f), string(imap.FlagDeleted))
		}
		if !opts.Time.IsZero() {
			t := opts.Time.UTC()
			imp.ReceivedAt = &t
		}
	}
	batch := cl.NewBatch(jmap.CapMail)
	i := batch.Add("Email/import", jmap.ImportArgs{AccountID: acct, Emails: map[jmap.ID]jmap.EmailImport{"m": imp}})
	res, err := batch.Do(ctx)
	if err != nil {
		return 0, 0, err
	}
	var got jmap.ImportResponse
	if err := res.Get(i, "Email/import", &got); err != nil {
		return 0, 0, refused(err)
	}
	if e, ok := got.NotCreated["m"]; ok {
		return 0, 0, refused(e)
	}
	if err := p.refresh(ctx, true); err != nil {
		return 0, 0, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	uid, ok := b.uidOf[got.Created["m"].ID]
	if !ok {
		return 0, 0, nil
	}
	if deleted {
		b.deleted[uid] = true
	}
	return uid, b.validity, nil
}

// mailboxSet sends a Mailbox/set and reads the folders again.
func (c *jmapConn) mailboxSet(args jmap.SetArgs[map[string]any]) error {
	ctx, cancel := c.ctx()
	defer cancel()
	cl, acct, err := c.p.session(ctx)
	if err != nil {
		return err
	}
	args.AccountID = acct
	b := cl.NewBatch(jmap.CapMail)
	s := b.Add("Mailbox/set", args)
	res, err := b.Do(ctx)
	if err != nil {
		return err
	}
	var got jmap.SetResponse[json.RawMessage]
	if err := res.Get(s, "Mailbox/set", &got); err != nil {
		return refused(err)
	}
	for _, m := range []map[jmap.ID]jmap.SetError{got.NotCreated, got.NotUpdated, got.NotDestroyed} {
		for _, e := range m {
			return refused(e)
		}
	}
	return c.p.refresh(ctx, true)
}

// parentOf splits a folder name into its parent mailbox ID and its own
// name.
func (c *jmapConn) parentOf(name string) (any, string, error) {
	i := strings.LastIndexByte(name, '/')
	if i < 0 {
		return nil, name, nil
	}
	parent, err := c.p.box(name[:i])
	if err != nil {
		return nil, "", err
	}
	return parent.id, name[i+1:], nil
}

func (c *jmapConn) Create(name string, _ *imap.CreateOptions) error {
	parent, leaf, err := c.parentOf(name)
	if err != nil {
		return err
	}
	return c.mailboxSet(jmap.SetArgs[map[string]any]{Create: map[jmap.ID]map[string]any{
		"new": {"name": leaf, "parentId": parent}}})
}

func (c *jmapConn) Delete(name string) error {
	b, err := c.p.box(name)
	if err != nil {
		return err
	}
	return c.mailboxSet(jmap.SetArgs[map[string]any]{Destroy: []jmap.ID{b.id}, OnDestroyRemoveEmails: true})
}

func (c *jmapConn) Rename(name, newName string, _ *imap.RenameOptions) error {
	b, err := c.p.box(name)
	if err != nil {
		return err
	}
	parent, leaf, err := c.parentOf(newName)
	if err != nil {
		return err
	}
	return c.mailboxSet(jmap.SetArgs[map[string]any]{Update: map[jmap.ID]jmap.PatchObject{
		b.id: {"name": mustRaw(leaf), "parentId": mustRaw(parent)}}})
}

func (c *jmapConn) Subscribe(name string, on bool) error {
	b, err := c.p.box(name)
	if err != nil {
		return err
	}
	return c.mailboxSet(jmap.SetArgs[map[string]any]{Update: map[jmap.ID]jmap.PatchObject{
		b.id: {"isSubscribed": mustRaw(on)}}})
}

func mustRaw(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// --- The engine's connection: push ----------------------------------------

type jmapWatch struct {
	jmapConn
	cancel context.CancelFunc
	pushed bool   // the provider pushes changes
	push   string // how: "websocket", "eventsource" or "none"
}

func (p *jmapProvider) Watch(notify func()) (watchConn, error) {
	ctx, cancel := context.WithCancel(context.Background())
	c, _, err := p.session(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	s, err := c.Session(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	w := &jmapWatch{jmapConn: jmapConn{p: p}, cancel: cancel}
	// Push over a WebSocket (RFC 8887) if the provider has it, else the
	// event source (RFC 8620 section 7.3).
	ws := s.WebSocketCap()
	w.push = "none"
	switch {
	case ws != nil && ws.SupportsPush:
		w.push = "websocket"
	case s.EventSourceURL != "":
		w.push = "eventsource"
	}
	if w.push != "none" {
		w.pushed = true
		changed := func(jmap.StateChange) {
			p.mu.Lock()
			p.dirty = true
			p.mu.Unlock()
			notify()
		}
		mode := w.push
		go func() {
			for ctx.Err() == nil {
				var err error
				if mode == "websocket" {
					err = c.WebSocketPush(ctx, []string{"Email", "Mailbox"}, changed)
				} else {
					err = c.Events(ctx, []string{"Email", "Mailbox"}, 60, changed)
				}
				if ctx.Err() != nil {
					return
				}
				// The connection may have missed changes.
				changed(jmap.StateChange{})
				p.a.b.Log.Info("jmap: push ended, reconnecting", "user", p.a.login, "push", mode, "err", err)
				if mode == "websocket" && s.EventSourceURL != "" {
					// A WebSocket the network will not carry, perhaps.
					mode = "eventsource"
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(5 * time.Second):
				}
			}
		}()
	}
	return w, nil
}

func (w *jmapWatch) Release(error) { w.cancel() }

func (w *jmapWatch) Describe() []any { return []any{"jmap_push", w.push} }

// Wait returns when the provider pushed a change, or after d, with the
// folders that changed.
func (w *jmapWatch) Wait(ctx context.Context, d time.Duration, changed, wake <-chan struct{}) (wakeup, error) {
	timer := time.NewTimer(max(d, 0))
	defer timer.Stop()
	force := false
	select {
	case <-ctx.Done():
		return wakeup{}, ctx.Err()
	case <-changed:
		return wakeup{}, errCredentialsChanged
	case <-wake:
	case <-timer.C:
		force = !w.pushed
	}
	rctx, cancel := context.WithTimeout(ctx, w.p.timeout())
	defer cancel()
	if err := w.p.refresh(rctx, force); err != nil {
		return wakeup{}, err
	}
	p := w.p
	p.mu.Lock()
	defer p.mu.Unlock()
	var names []string
	for name := range p.touched {
		if p.byName[name] != nil {
			names = append(names, name)
		}
	}
	clear(p.touched)
	slices.Sort(names)
	list := p.listChanged
	p.listChanged = false
	return wakeup{names: names, list: list}, nil
}

// Notifies reports whether the provider pushes changes: it pushes every
// change, in every mailbox.
func (w *jmapWatch) Notifies() bool { return w.pushed }

// ErrSendRefused means the provider refused to send a message.
var ErrSendRefused = errors.New("the provider refused the message")

// send hands a message to the provider (EmailSubmission). It is stored
// first, as JMAP needs, in the drafts mailbox (or sent, or the inbox), and
// destroyed once sent: the client keeps its own Sent copy.
func (p *jmapProvider) send(ctx context.Context, from string, to []string, data []byte) error {
	if err := p.refresh(ctx, false); err != nil {
		return err
	}
	p.mu.Lock()
	var box *jbox
	for _, role := range []string{jmap.RoleDrafts, jmap.RoleSent, jmap.RoleInbox} {
		for _, b := range p.boxes {
			if b.role == role && box == nil {
				box = b
			}
		}
	}
	p.mu.Unlock()
	if box == nil {
		return fmt.Errorf("%w: no mailbox to store it in", ErrSendRefused)
	}
	c, acct, err := p.session(ctx)
	if err != nil {
		return err
	}
	b := c.NewBatch(jmap.CapSubmission)
	ig := b.Add("Identity/get", jmap.GetArgs{AccountID: acct})
	res, err := b.Do(ctx)
	if err != nil {
		return err
	}
	var ids jmap.GetResponse[jmap.Identity]
	if err := res.Get(ig, "Identity/get", &ids); err != nil {
		return refused(err)
	}
	var identity jmap.ID
	for _, id := range ids.List {
		if strings.EqualFold(id.Email, from) || identity == "" {
			identity = id.ID
		}
	}
	if identity == "" {
		return fmt.Errorf("%w: the account has no identity to send as", ErrSendRefused)
	}
	up, err := c.Upload(ctx, acct, "message/rfc822", data)
	if err != nil {
		return err
	}
	env := &jmap.Envelope{MailFrom: jmap.Address{Email: from}}
	for _, r := range to {
		env.RcptTo = append(env.RcptTo, jmap.Address{Email: r})
	}
	b = c.NewBatch(jmap.CapMail, jmap.CapSubmission)
	imp := b.Add("Email/import", jmap.ImportArgs{AccountID: acct, Emails: map[jmap.ID]jmap.EmailImport{
		"m": {BlobID: up.BlobID, MailboxIDs: map[jmap.ID]bool{box.id: true}, Keywords: map[string]bool{"$seen": true}}}})
	sub := b.Add("EmailSubmission/set", map[string]any{"accountId": acct,
		"create":                map[string]any{"s": map[string]any{"identityId": identity, "emailId": "#m", "envelope": env}},
		"onSuccessDestroyEmail": []string{"#s"}})
	if res, err = b.Do(ctx); err != nil {
		return err
	}
	var ir jmap.ImportResponse
	if err := res.Get(imp, "Email/import", &ir); err != nil {
		return refused(err)
	}
	if e, ok := ir.NotCreated["m"]; ok {
		return fmt.Errorf("%w: %s", ErrSendRefused, e.Error())
	}
	var sr jmap.SetResponse[json.RawMessage]
	if err := res.Get(sub, "EmailSubmission/set", &sr); err != nil {
		return refused(err)
	}
	if e, ok := sr.NotCreated["s"]; ok {
		// Not sent: the stored copy goes.
		_ = (&jmapConn{p: p}).set(ctx, nil, []jmap.ID{ir.Created["m"].ID})
		return fmt.Errorf("%w: %s", ErrSendRefused, e.Error())
	}
	return nil
}
