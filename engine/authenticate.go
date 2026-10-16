package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"net/mail"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-msgauth/authres"
	"golang.org/x/net/publicsuffix"
)

// Sender authentication: act on the provider's DMARC/SPF verdict
// (Authentication-Results) before clients see new mail. The provider's
// authserv-id (its stamp) is learned from INBOX, since senders can forge
// the field too. Until it is known, new mail waits in Junk (ReadDefer).
// Mail the user moves back out of Junk passes, and confirms the stamp.

// AuthMode is how hard the engine acts on the provider's verdicts.
type AuthMode string

const (
	// AuthStandard follows the DMARC policy (reject deletes, quarantine
	// junks). Without a DMARC pass, SPF fail deletes and softfail junks.
	AuthStandard AuthMode = "standard"
	// AuthStrict deletes any SPF fail or softfail, and junks any DMARC
	// failure.
	AuthStrict AuthMode = "strict"
)

// AuthAction is what happens to a new message.
type AuthAction string

const (
	AuthNone   AuthAction = ""       // shown
	AuthJunk   AuthAction = "junk"   // moved to the folder with \Junk
	AuthTrash  AuthAction = "trash"  // moved to the folder with \Trash
	AuthDelete AuthAction = "delete" // deleted at the provider
)

// severity orders actions: the harder one wins.
func (x AuthAction) severity() int {
	return map[AuthAction]int{AuthJunk: 1, AuthTrash: 2, AuthDelete: 3}[x]
}

func spfFailed(v string) bool {
	return v == string(authres.ResultFail) || v == string(authres.ResultSoftFail)
}

func (m AuthMode) action(r AuthResult) AuthAction {
	if r.Rescued {
		return AuthNone
	}
	if m == AuthStrict && spfFailed(r.SPF) {
		return AuthDelete
	}
	if r.Status == AuthUnknown {
		return AuthNone
	}
	byPolicy := map[string]AuthAction{"reject": AuthDelete, "quarantine": AuthJunk, "none": AuthNone}
	switch m {
	case AuthStrict:
		if r.Status == AuthFail {
			if r.DMARCPolicy == "reject" {
				return AuthDelete
			}
			return AuthJunk
		}
	case AuthStandard:
		act := AuthNone
		if r.Status == AuthFail {
			var ok bool
			if act, ok = byPolicy[r.DMARCPolicy]; !ok {
				act = AuthJunk // record unreadable
			}
		}
		if r.Status != AuthPass {
			bySPF := map[string]AuthAction{string(authres.ResultFail): AuthDelete, string(authres.ResultSoftFail): AuthJunk}
			if spf := bySPF[r.SPF]; spf.severity() > act.severity() {
				act = spf
			}
		}
		return act
	}
	return AuthNone
}

// AuthStatus is the verdict on a message.
type AuthStatus string

const (
	AuthPass     AuthStatus = "pass" // or rescued by the user
	AuthFail     AuthStatus = "fail"
	AuthNoPolicy AuthStatus = "none"    // no DMARC record, or permerror
	AuthUnknown  AuthStatus = "unknown" // no usable verdict
)

// AuthResult is the verdict on one message.
type AuthResult struct {
	Status                  AuthStatus
	From                    string // lowercased; "" unless exactly one
	DKIMAligned, SPFAligned bool
	DMARC, DKIM, SPF        string // as reported; "" if none
	DKIMDomains             []string
	SPFDomain               string
	DMARCPolicy             string // on failure; "" if unreadable
	Rescued                 bool   // moved back by the user
	Learning                bool   // stamp not known yet
	// New marks mail not yet shown, which ReadJunk and the others can move
	// away. Otherwise they act as ReadRetry.
	New    bool
	Reason string // for logs
}

type authKey struct{}

// AuthResultFrom returns the verdict on the message being read, if any.
func AuthResultFrom(ctx context.Context) (r AuthResult, ok bool) {
	r, ok = ctx.Value(authKey{}).(AuthResult)
	return r, ok
}

// WithAuthResult returns ctx carrying r, for Transform tests.
func WithAuthResult(ctx context.Context, r AuthResult) context.Context {
	return context.WithValue(ctx, authKey{}, r)
}

// AuthState is what the engine knows of an account's provider stamp.
type AuthState struct {
	Stamp []string // trusted names; empty while learning
	// Candidates are names on authShare of a full window that are not
	// learned for want of senders: the provider stamps its verdicts, but
	// its mail comes from too few domains to tell it from a forger's.
	Candidates  []string
	Examined    int
	LastStamped time.Time
}

// AuthState returns the account's stamp state.
func (a *Account) AuthState() AuthState {
	l := a.learning()
	l.mu.Lock()
	defer l.mu.Unlock()
	st := AuthState{Stamp: l.trusted(), Examined: l.Examined, LastStamped: l.LastStamped}
	for _, id := range l.common() {
		if !slices.Contains(st.Stamp, id) {
			st.Candidates = append(st.Candidates, id)
		}
	}
	return st
}

func (a *Account) withVerdict(ctx context.Context, raw []byte) context.Context {
	if a.b.Authentication == "" {
		return ctx
	}
	hdr := headerOf(raw)
	if a.rescued(hdr) {
		return WithAuthResult(ctx, rescuedResult)
	}
	return WithAuthResult(ctx, a.b.verdict(ctx, a.stamp(), hdr))
}

var rescuedResult = AuthResult{Status: AuthPass, Rescued: true, Reason: "moved back by the user"}

func (a *Account) stamp() []string {
	l := a.learning()
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.trusted()
}

// --- Verdict ---------------------------------------------------------------

// verdict uses the provider's DMARC result, or works one out from its
// DKIM and SPF results.
func (b *Engine) verdict(ctx context.Context, stamp []string, hdr []byte) (r AuthResult) {
	h := parseHeader(hdr)
	if froms := h.Values("From"); len(froms) == 1 {
		if l, err := mail.ParseAddressList(froms[0]); err == nil && len(l) == 1 {
			r.From = strings.ToLower(l[0].Address)
		}
	}
	if len(stamp) == 0 {
		r.Status, r.Learning, r.Reason = AuthUnknown, true, "the provider's stamp is not known yet"
		return r
	}
	res := providerResults(hdr, stamp)
	domain := domainOf(r.From)
	for _, d := range res.dkimPass {
		r.DKIMAligned = r.DKIMAligned || aligned(d, domain)
	}
	r.SPFAligned = res.spfPass != "" && aligned(res.spfPass, domain)
	r.DKIM, r.SPF, r.DKIMDomains, r.SPFDomain = string(res.dkim), string(res.spf), res.dkimPass, res.spfPass
	defer func() {
		switch r.Status {
		case AuthPass, AuthFail:
			r.DMARC = string(r.Status)
		case AuthNoPolicy:
			r.DMARC = "none"
		}
	}()
	switch {
	case res.dmarc != "":
		switch res.dmarc {
		case authres.ResultPass:
			r.Status = AuthPass
		case authres.ResultFail:
			r.Status = AuthFail
		case authres.ResultNone, authres.ResultPermError:
			r.Status = AuthNoPolicy
		default:
			r.Status = AuthUnknown
		}
		r.Reason = "provider: dmarc=" + string(res.dmarc)
	case !res.checked:
		r.Status, r.Reason = AuthUnknown, "no verdict from the provider"
	case domain == "":
		r.Status, r.Reason = AuthNoPolicy, "no single From address"
	default:
		r.Status, r.Reason = b.evaluateDMARC(ctx, domain, res)
	}
	if r.Status == AuthFail {
		r.DMARCPolicy = b.dmarcPolicy(ctx, domain)
	}
	return r
}

// stampsOf returns the authserv-ids in the provider's part of hdr.
func stampsOf(hdr []byte) []string {
	var out []string
	for _, f := range providerPart(headerFields(hdr)) {
		if f.name != "Authentication-Results" {
			continue
		}
		name, rs, err := parseAuthResults(f.value)
		if err != nil {
			continue
		}
		name = strings.ToLower(name)
		if slices.ContainsFunc(rs, isCheck) && !slices.Contains(out, name) {
			out = append(out, name)
		}
	}
	return out
}

// identity is the Message-ID, or else copyOf.
func identity(hdr []byte) string {
	h := parseHeader(hdr)
	if id := strings.TrimSpace(h.Get("Message-Id")); id != "" {
		return id
	}
	if c := copyOf(hdr); c != "" {
		return "received:" + c
	}
	return ""
}

// copyOf hashes the topmost Received field, which names one delivery:
// moves keep it, a resend changes it.
func copyOf(hdr []byte) string {
	if rcv := parseHeader(hdr).Values("Received"); len(rcv) > 0 {
		sum := sha256.Sum256([]byte(rcv[0]))
		return hex.EncodeToString(sum[:12])
	}
	return ""
}

type authRef struct{ id, copy string }

// key indexes authLearn.Moved: one record per delivery and origin folder.
func (r authRef) key(origin string) string { return r.prefix() + origin }

func (r authRef) prefix() string { return r.id + "\n" + r.copy + "\n" }

func refOf(hdr []byte) authRef { return authRef{identity(hdr), copyOf(hdr)} }

// domainOf splits at the last @: a quoted local part may contain one.
func domainOf(addr string) string {
	if i := strings.LastIndexByte(addr, '@'); i >= 0 {
		return addr[i+1:]
	}
	return ""
}

// aligned is DMARC relaxed alignment: same organizational domain.
func aligned(d, from string) bool {
	d, from = strings.TrimSuffix(strings.ToLower(d), "."), strings.TrimSuffix(strings.ToLower(from), ".")
	if d == "" || from == "" {
		return false
	}
	if d == from {
		return true
	}
	od, err1 := publicsuffix.EffectiveTLDPlusOne(d)
	of, err2 := publicsuffix.EffectiveTLDPlusOne(from)
	return err1 == nil && err2 == nil && od == of
}

// --- Learning the provider's stamp -----------------------------------------

// A name is learned when it is on authShare of the last authWindow INBOX
// messages, from authSenders domains, or on authConfirm rescues. A learned
// name stays learned while it is on authShare of the window, whoever sent
// it: a run of mail from few senders does not forget it.
const (
	authWindow  = 20
	authShare   = 0.9
	authSenders = 3
	authConfirm = 3
)

// authLearn is an account's persisted authentication state (authFile).
type authLearn struct {
	mu          sync.Mutex
	Seen        []authSeen `json:"seen"` // oldest first
	Examined    int        `json:"examined"`
	Learned     []string   `json:"learned,omitempty"` // as of the last observe
	LastStamped time.Time  `json:"last_stamped,omitzero"`
	// KnownSince: deferred mail from before this is released.
	KnownSince time.Time             `json:"known_since,omitzero"`
	Moved      map[string]*authMoved `json:"moved,omitempty"`   // by authRef.key
	Rescues    map[string][]string   `json:"rescues,omitempty"` // identities, by name
	Confirmed  []string              `json:"confirmed,omitempty"`
}

type authSeen struct {
	ID     string    `json:"id"`
	Date   time.Time `json:"date"`
	Stamps []string  `json:"stamps"`
	Domain string    `json:"domain"`
}

// authMoved records a message moved away.
type authMoved struct {
	Action   AuthAction `json:"action"`
	Folder   string     `json:"folder"` // "" if deleted
	Origin   string     `json:"origin"`
	Copy     string     `json:"copy,omitempty"`
	At       time.Time  `json:"at"`
	Defer    bool       `json:"defer,omitempty"`    // release once the stamp is known
	Strict   bool       `json:"strict,omitempty"`   // by the Transform: rescue confirms nothing
	Learning bool       `json:"learning,omitempty"` // moved while learning
	Rescued  bool       `json:"rescued,omitempty"`
	// Pending: the move may not have happened. Never a rescue; dropped
	// once the message shows up in Origin.
	Pending bool `json:"pending,omitempty"`
}

const (
	authFile     = "authentication" // in the account's folder
	authMovedMax = 10000
)

func (a *Account) learning() *authLearn {
	a.authOnce.Do(func() {
		l := &authLearn{}
		if s := a.b.Store; s != nil {
			if b, err := os.ReadFile(filepath.Join(accountDir(s.Dir, a.login), authFile)); err == nil {
				if err := json.Unmarshal(b, l); err != nil {
					a.b.Log.Warn("could not read sender authentication state", "user", a.login, "err", err)
				}
			}
		}
		if l.Moved == nil {
			l.Moved = map[string]*authMoved{}
		}
		if l.Rescues == nil {
			l.Rescues = map[string][]string{}
		}
		a.auth = l
	})
	return a.auth
}

// saveLearning prunes and persists l (l.mu held).
func (a *Account) saveLearning(l *authLearn) error {
	if len(l.Moved) > authMovedMax {
		ids := make([]string, 0, len(l.Moved))
		for id := range l.Moved {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return l.Moved[ids[i]].At.Before(l.Moved[ids[j]].At) })
		for _, id := range ids[:len(ids)-authMovedMax] {
			if !l.Moved[id].Defer {
				delete(l.Moved, id)
			}
		}
	}
	s := a.b.Store
	if s == nil {
		return nil
	}
	b, err := json.Marshal(l)
	if err == nil {
		dir := accountDir(s.Dir, a.login)
		if err = os.MkdirAll(dir, 0o700); err == nil {
			tmp := filepath.Join(dir, authFile+".tmp")
			if err = os.WriteFile(tmp, b, 0o600); err == nil {
				err = os.Rename(tmp, filepath.Join(dir, authFile))
			}
		}
	}
	if err != nil {
		a.b.Log.Warn("could not save sender authentication state", "user", a.login, "err", err)
	}
	return err
}

func (l *authLearn) trusted() []string {
	var out []string
	for _, id := range slices.Concat(l.learned(), l.Confirmed) {
		if !slices.ContainsFunc(out, func(s string) bool { return strings.EqualFold(s, id) }) {
			out = append(out, strings.ToLower(id))
		}
	}
	return out
}

func (l *authLearn) learned() []string {
	return l.onWindow(func(id string, senders int) bool {
		return senders >= authSenders || slices.Contains(l.Learned, id)
	})
}

// common returns the names on authShare of a full window, whatever their
// senders.
func (l *authLearn) common() []string {
	return l.onWindow(func(string, int) bool { return true })
}

// onWindow returns the names on authShare of a full window for which ok
// holds, given how many sender domains they came from.
func (l *authLearn) onWindow(ok func(id string, senders int) bool) []string {
	if len(l.Seen) < authWindow {
		return nil
	}
	count := map[string]int{}
	senders := map[string]map[string]bool{}
	for _, s := range l.Seen {
		for _, id := range s.Stamps {
			count[id]++
			if senders[id] == nil {
				senders[id] = map[string]bool{}
			}
			senders[id][s.Domain] = true
		}
	}
	var out []string
	for id, n := range count {
		if float64(n) >= authShare*float64(len(l.Seen)) && ok(id, len(senders[id])) {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

// observe reports whether id was new (l.mu held).
func (l *authLearn) observe(id string, date time.Time, hdr []byte) bool {
	if id == "" || slices.ContainsFunc(l.Seen, func(s authSeen) bool { return s.ID == id }) {
		return false
	}
	h := parseHeader(hdr)
	s := authSeen{ID: id, Date: date, Stamps: stampsOf(hdr)}
	if froms := h.Values("From"); len(froms) == 1 {
		if addr, err := mail.ParseAddress(froms[0]); err == nil {
			s.Domain = strings.ToLower(domainOf(addr.Address))
		}
	}
	l.Seen = append(l.Seen, s)
	sort.SliceStable(l.Seen, func(i, j int) bool { return l.Seen[i].Date.Before(l.Seen[j].Date) })
	if len(l.Seen) > authWindow {
		l.Seen = l.Seen[len(l.Seen)-authWindow:]
	}
	l.Examined++
	l.Learned = l.learned()
	if slices.ContainsFunc(s.Stamps, func(n string) bool { return slices.Contains(l.Learned, n) }) {
		l.LastStamped = time.Now()
	}
	return true
}

func (a *Account) learn(date time.Time, hdr []byte) {
	l := a.learning()
	l.mu.Lock()
	defer l.mu.Unlock()
	before := l.learned()
	if l.observe(identity(hdr), date, hdr) {
		a.logStamp(l, before, l.learned())
		a.saveLearning(l)
	}
}

// seedLearning fills the window from existing INBOX mail.
func (a *Account) seedLearning() {
	l := a.learning()
	l.mu.Lock()
	full := len(l.Seen) >= authWindow
	l.mu.Unlock()
	if full {
		return
	}
	a.mu.Lock()
	var msgs []*Message
	if m := a.boxes["INBOX"]; m != nil {
		msgs = slices.Clone(m.msgs)
	}
	a.mu.Unlock()
	slices.SortFunc(msgs, func(x, y *Message) int { return y.date.Compare(x.date) })
	if len(msgs) > authWindow {
		msgs = msgs[:authWindow]
	}
	if len(msgs) == 0 {
		return
	}
	headers := map[*Message][]byte{}
	keys := make([]string, len(msgs))
	for i, msg := range msgs {
		keys[i] = msg.key
	}
	entries := a.b.Store.Headers(a.login, keys)
	var missing []*Message
	for _, msg := range msgs {
		// Transformed entries lack the provider's header.
		if e := entries[msg.key]; e != nil && msg.direct {
			headers[msg] = e.Header
		} else {
			missing = append(missing, msg)
		}
	}
	for box, at := range a.locate(missing) {
		c, err := a.conn(bulk, box)
		if err != nil {
			break
		}
		got, err := c.FetchHeaders(box, at.uids())
		c.Release(err)
		if err != nil {
			a.b.Log.Warn("could not read headers to learn the provider's stamp", "user", a.login, "err", err)
			break
		}
		for uid, e := range got {
			for _, msg := range at[uid] {
				headers[msg] = e.Header
			}
		}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	before := l.learned()
	added := false
	for msg, hdr := range headers {
		if l.observe(identity(hdr), msg.date, hdr) {
			added = true
		}
	}
	if added {
		a.logStamp(l, before, l.learned())
		a.saveLearning(l)
	}
}

// logStamp logs stamp changes and sets KnownSince (l.mu held).
func (a *Account) logStamp(l *authLearn, before, after []string) {
	if len(before) == 0 && len(after) > 0 && len(l.Confirmed) == 0 {
		l.KnownSince = time.Now()
	}
	switch {
	case slices.Equal(before, after):
	case len(after) == 0:
		a.b.Log.Warn("the provider no longer stamps its verdict as before; learning again", "user", a.login, "was", before)
	default:
		a.b.Log.Info("learned the provider's verdict stamp", "user", a.login, "stamp", after)
	}
}

// --- Moving back -----------------------------------------------------------

// rescue reports whether hdr is a delivery the engine moved away, now back
// in its origin box: the user vouched for it.
func (a *Account) rescue(hdr []byte, box string) bool {
	return a.rescueIf(hdr, func(l *authLearn, key string, m *authMoved) bool {
		if m.Pending && m.Origin == box {
			// Never left, or came back: no rescue.
			delete(l.Moved, key)
			a.saveLearning(l)
			return false
		}
		return !m.Pending && m.Origin == box
	})
}

// rescueMove is rescue for a client's move out of from, to any folder.
func (a *Account) rescueMove(hdr []byte, from string) bool {
	return a.rescueIf(hdr, func(_ *authLearn, _ string, m *authMoved) bool { return m.Folder == from })
}

// movingBack returns the headers to rescueMove after a client moves or
// copies uids out of Junk or Trash into a checked folder; nil otherwise.
func (a *Account) movingBack(c conn, box, dest string, uids []imap.UID) (map[imap.UID]*HeaderEntry, error) {
	a.mu.Lock()
	back := box != "" && a.authChecks(dest) &&
		(box == a.roleFolder(imap.MailboxAttrJunk) || box == a.roleFolder(imap.MailboxAttrTrash))
	a.mu.Unlock()
	if !back {
		return nil, nil
	}
	return c.FetchHeaders(box, uids)
}

func (a *Account) rescueIf(hdr []byte, ok func(l *authLearn, key string, m *authMoved) bool) bool {
	ref := refOf(hdr)
	if ref.id == "" {
		return false
	}
	l := a.learning()
	l.mu.Lock()
	defer l.mu.Unlock()
	var m *authMoved
	for _, key := range l.keysOf(ref) {
		if c := l.Moved[key]; c.Action != AuthDelete && ok(l, key, c) {
			m = c
			break
		}
	}
	if m == nil {
		return false
	}
	m.Pending = false
	if m.Rescued {
		return true
	}
	id := ref.id
	m.Rescued, m.Defer = true, false
	a.b.Log.Info("message moved back by the user", "user", a.login, "from", m.Folder)
	if !m.Strict {
		for _, name := range stampsOf(hdr) {
			if slices.Contains(l.Rescues[name], id) {
				continue
			}
			l.Rescues[name] = append(l.Rescues[name], id)
			if len(l.Rescues[name]) >= authConfirm && !slices.Contains(l.Confirmed, name) {
				if len(l.Confirmed) == 0 && len(l.learned()) == 0 {
					l.KnownSince = time.Now()
				}
				l.Confirmed = append(l.Confirmed, name)
				a.b.Log.Info("provider stamp confirmed by messages moved back", "user", a.login, "stamp", name)
			}
		}
	}
	a.saveLearning(l)
	return true
}

func (a *Account) rescued(hdr []byte) bool {
	ref := refOf(hdr)
	if ref.id == "" {
		return false
	}
	l := a.learning()
	l.mu.Lock()
	defer l.mu.Unlock()
	return slices.ContainsFunc(l.keysOf(ref), func(key string) bool { return l.Moved[key].Rescued })
}

func (l *authLearn) keysOf(ref authRef) []string {
	var out []string
	for key := range l.Moved {
		if strings.HasPrefix(key, ref.prefix()) {
			out = append(out, key)
		}
	}
	slices.Sort(out)
	return out
}

// renameAuth applies a folder rename to the records (a.mu held).
func (a *Account) renameAuth(name, newName string) {
	if a.b.Authentication == "" {
		return
	}
	ren := func(box string) (string, bool) {
		if box != "" && (box == name || strings.HasPrefix(box, name+string(a.delim))) {
			return newName + strings.TrimPrefix(box, name), true
		}
		return box, false
	}
	l := a.learning()
	l.mu.Lock()
	defer l.mu.Unlock()
	changed := false
	for _, key := range slices.Collect(maps.Keys(l.Moved)) {
		m := l.Moved[key]
		folder, f := ren(m.Folder)
		origin, o := ren(m.Origin)
		if !f && !o {
			continue
		}
		m.Folder, m.Origin, changed = folder, origin, true
		if o {
			delete(l.Moved, key)
			l.Moved[key[:strings.LastIndexByte(key, '\n')+1]+origin] = m
		}
	}
	if changed {
		a.saveLearning(l)
	}
}

// --- Which folders are checked ---------------------------------------------

// authChecks reports whether new mail in box is checked (a.mu held).
func (a *Account) authChecks(box string) bool {
	if a.b.Authentication == "" || a.boxes[box] == nil {
		return false
	}
	skip := []imap.MailboxAttr{imap.MailboxAttrSent, imap.MailboxAttrDrafts, imap.MailboxAttrAll, imap.MailboxAttrFlagged,
		imap.MailboxAttrJunk, imap.MailboxAttrTrash}
	return !slices.ContainsFunc(skip, func(attr imap.MailboxAttr) bool { return a.hasRole(box, attr) })
}

// authCopies reports whether box is All Mail or Flagged, whose new mail
// is held but never moved (a.mu held).
func (a *Account) authCopies(box string) bool {
	return a.b.Authentication != "" && a.boxes[box] != nil &&
		(a.hasRole(box, imap.MailboxAttrAll) || a.hasRole(box, imap.MailboxAttrFlagged))
}

func (x AuthAction) attr() imap.MailboxAttr {
	switch x {
	case AuthTrash:
		return imap.MailboxAttrTrash
	case AuthJunk:
		return imap.MailboxAttrJunk
	}
	return ""
}

func (x AuthAction) status() ReadStatus {
	switch x {
	case AuthTrash:
		return ReadTrash
	case AuthJunk:
		return ReadJunk
	case AuthDelete:
		return ReadDelete
	}
	return ReadFinal
}

// roleNames are fallbacks for providers without SPECIAL-USE.
var roleNames = map[imap.MailboxAttr][]string{
	imap.MailboxAttrSent:   {"Sent", "Sent Messages", "Sent Items", "Sent Mail"},
	imap.MailboxAttrDrafts: {"Drafts", "Draft"},
	imap.MailboxAttrTrash:  {"Trash", "Deleted Messages", "Deleted Items", "Deleted"},
	imap.MailboxAttrJunk:   {"Junk", "Spam", "Junk E-mail", "Junk Mail", "Bulk Mail"},
}

// roleFolder returns the folder with attr, else the best-ranked usual
// name, deterministically (a.mu held).
func (a *Account) roleFolder(attr imap.MailboxAttr) string {
	byName, rank := "", len(roleNames[attr])
	for _, name := range slices.Sorted(maps.Keys(a.boxes)) {
		m := a.boxes[name]
		if !m.selectable {
			continue
		}
		if HasAttr(m.attrs, attr) {
			return name
		}
		if i := slices.IndexFunc(roleNames[attr], func(n string) bool { return strings.EqualFold(n, name) }); i >= 0 && i < rank {
			byName, rank = name, i
		}
	}
	return byName
}

func (a *Account) hasRole(box string, attr imap.MailboxAttr) bool {
	if m := a.boxes[box]; m != nil && HasAttr(m.attrs, attr) {
		return true
	}
	return a.roleFolder(attr) == box
}

// --- Moving away -----------------------------------------------------------

type moveAway struct {
	act                        AuthAction
	deferred, strict, learning bool
}

// discard moves or deletes held messages at the provider. Failures stay
// held for the next sweep.
func (a *Account) discard(how moveAway, msgs []*Message, refs map[string]authRef) {
	a.mu.Lock()
	dest := ""
	if attr := how.act.attr(); attr != "" {
		dest = a.roleFolder(attr)
	}
	trash := a.roleFolder(imap.MailboxAttrTrash)
	other := map[string]bool{} // keys with a copy outside All Mail/Flagged
	for _, msg := range msgs {
		other[msg.key] = other[msg.key] || !a.authCopies(msg.pBox)
	}
	// With All Mail, deleting from one folder can leave a copy.
	shared := false
	for name := range a.boxes {
		shared = shared || a.authCopies(name)
	}
	boxes := map[string][]*Message{}
	for _, msg := range msgs {
		// The provider drops All Mail copies with the original.
		if !msg.held || msg.pUID == 0 || other[msg.key] && a.authCopies(msg.pBox) {
			continue
		}
		boxes[msg.pBox] = append(boxes[msg.pBox], msg)
	}
	a.mu.Unlock()
	if how.act != AuthDelete && dest == "" {
		a.b.Log.Warn("no folder to move failed mail to; holding it", "user", a.login, "action", how.act, "count", len(msgs))
		return
	}
	for box, msgs := range boxes {
		a.discardIn(how, box, dest, trash, msgs, refs, shared)
	}
}

// discardIn handles one folder, under folder locks so UIDs stay valid.
func (a *Account) discardIn(how moveAway, box, dest, trash string, msgs []*Message, refs map[string]authRef,
	shared bool) {
	var names []string
	for _, name := range []string{box, dest, trash} {
		if name != "" {
			names = append(names, name)
		}
	}
	defer a.lockFolders(names...)()
	a.mu.Lock()
	byUID := map[imap.UID]*Message{}
	for _, msg := range msgs {
		if msg.held && msg.pBox == box && msg.pUID != 0 {
			byUID[msg.pUID] = msg
		}
	}
	a.mu.Unlock()
	if len(byUID) == 0 {
		return
	}
	uids := slices.Sorted(maps.Keys(byUID))
	c, err := a.conn(interactive, box)
	if err != nil {
		if !errors.Is(err, ErrNoCredentials) {
			a.b.Log.Warn("could not move away messages", "user", a.login, "mailbox", box, "action", how.act, "err", err)
		}
		return
	}
	act, to := how.act, dest
	if act == AuthDelete && (!exactExpunge(c) || shared) {
		// Plain EXPUNGE would remove all \Deleted mail, and All Mail would
		// keep a copy: use Trash.
		act, to = AuthTrash, trash
		if to == "" {
			c.Release(nil)
			a.b.Log.Warn("cannot delete only failed mail, and no Trash folder; holding it", "user", a.login,
				"mailbox", box, "count", len(uids))
			return
		}
	}
	// Saved as pending first, to survive a crash mid-move.
	l := a.learning()
	l.mu.Lock()
	now := time.Now()
	for _, msg := range byUID {
		if ref := refs[msg.key]; ref.id != "" {
			l.Moved[ref.key(box)] = &authMoved{Action: act, Folder: to, Origin: box, Copy: ref.copy, At: now,
				Defer: how.deferred, Strict: how.strict, Learning: how.learning, Pending: true}
		}
	}
	if err := a.saveLearning(l); err != nil {
		for _, msg := range byUID {
			delete(l.Moved, refs[msg.key].key(box))
		}
		l.mu.Unlock()
		c.Release(nil)
		return
	}
	l.mu.Unlock()
	var failed map[imap.UID]bool
	var moved map[imap.UID]imap.UID
	if act == AuthDelete {
		err = c.Expunge(box, uids)
	} else {
		moved, err = c.Move(box, uids, to)
	}
	known := true
	if err != nil || act != AuthDelete {
		// Errors and partial moves both happen: check what stayed.
		var verr error
		failed, verr = stayed(c, box, uids, moved)
		if known = verr == nil; !known {
			err = errors.Join(err, verr)
			failed = map[imap.UID]bool{}
			for _, uid := range uids {
				failed[uid] = true
			}
		}
	}
	c.Release(err)
	l.mu.Lock()
	for uid, msg := range byUID {
		key := refs[msg.key].key(box)
		switch {
		case !failed[uid]:
			if m := l.Moved[key]; m != nil {
				m.Pending = false
			}
		case known:
			delete(l.Moved, key)
		case l.Moved[key] != nil:
			l.Moved[key].Pending = true
		}
	}
	a.saveLearning(l)
	l.mu.Unlock()
	if err != nil && !errors.Is(err, ErrNoCredentials) {
		a.b.Log.Warn("could not move away messages", "user", a.login, "mailbox", box, "action", how.act, "err", err)
	}
	if len(failed) == len(uids) {
		return
	}
	a.b.Log.Info("messages moved away", "user", a.login, "mailbox", box, "action", act, "to", to,
		"count", len(uids)-len(failed), "read_again", how.deferred)
	a.mu.Lock()
	tx := a.begin()
	for uid, msg := range byUID {
		if msg.pBox == box && msg.pUID == uid && !failed[uid] {
			a.lose(msg, tx)
		}
	}
	if err := tx.commit(); err != nil {
		a.b.Log.Warn("could not save mailbox state", "user", a.login, "err", err)
	}
	a.mu.Unlock()
	for uid, msg := range byUID {
		if !failed[uid] {
			_ = a.b.Cache.Delete(a.login, holdKey(msg.key))
		}
	}
}

// stayed returns the uids not in moved that box still has.
func stayed(c conn, box string, uids []imap.UID, moved map[imap.UID]imap.UID) (map[imap.UID]bool, error) {
	var unsure []imap.UID
	for _, uid := range uids {
		if _, ok := moved[uid]; !ok {
			unsure = append(unsure, uid)
		}
	}
	if len(unsure) == 0 {
		return nil, nil
	}
	left, err := c.FetchHeaders(box, unsure)
	if err != nil {
		return nil, err
	}
	out := map[imap.UID]bool{}
	for _, uid := range unsure {
		if _, there := left[uid]; there {
			out[uid] = true
		}
	}
	return out, nil
}

// cheapHeaders reports whether FetchHeaders skips bodies.
func cheapHeaders(c conn) bool {
	x, ok := c.(interface{ cheapHeaders() bool })
	return ok && x.cheapHeaders()
}

// exactExpunge reports whether Expunge is limited to the given UIDs.
func exactExpunge(c conn) bool {
	x, ok := c.(interface{ exactExpunge() bool })
	return !ok || x.exactExpunge()
}

// releaseDeferred returns deferred mail to its origin once the stamp is
// known, to be checked again as new mail.
func (a *Account) releaseDeferred() {
	if a.b.Authentication == "" {
		return
	}
	l := a.learning()
	l.mu.Lock()
	byFolder := map[string]map[string]string{} // folder -> key -> origin
	ids := map[string]bool{}
	settled := map[string]bool{} // not pending at snapshot
	if len(l.trusted()) > 0 {
		for key, m := range l.Moved {
			if m.Defer && m.Folder != "" && (m.Learning || m.At.Before(l.KnownSince)) {
				if byFolder[m.Folder] == nil {
					byFolder[m.Folder] = map[string]string{}
				}
				byFolder[m.Folder][key] = m.Origin
				id, _, _ := strings.Cut(key, "\n")
				ids[id] = true
				settled[key] = !m.Pending
			}
		}
	}
	l.mu.Unlock()
	for folder, origins := range byFolder {
		c, err := a.conn(bulk, folder)
		if err != nil {
			return
		}
		d, err := c.Sync(folder, syncState{known: func(imap.UID) bool { return false }})
		if err != nil {
			c.Release(err)
			a.b.Log.Warn("could not read mail to release", "user", a.login, "mailbox", folder, "err", err)
			continue
		}
		// Full headers are needed for copyOf.
		var whole []imap.UID
		for _, f := range d.fresh {
			if id := identity(f.header); id == "" || ids[id] {
				whole = append(whole, f.uid)
			}
		}
		headers := map[imap.UID][]byte{}
		if len(whole) > 0 {
			got, err := c.FetchHeaders(folder, whole)
			if err != nil {
				c.Release(err)
				a.b.Log.Warn("could not read mail to release", "user", a.login, "mailbox", folder, "err", err)
				continue
			}
			for uid, e := range got {
				headers[uid] = e.Header
			}
		}
		// One record per message, so copies return to separate origins.
		byPrefix := map[string][]string{}
		for key := range origins {
			id, rest, _ := strings.Cut(key, "\n")
			cp, _, _ := strings.Cut(rest, "\n")
			p := authRef{id, cp}.prefix()
			byPrefix[p] = append(byPrefix[p], key)
		}
		for _, keys := range byPrefix {
			slices.Sort(keys)
		}
		back := map[string][]imap.UID{} // by origin
		idOf := map[imap.UID]string{}   // record keys
		here := map[string]bool{}
		for _, uid := range slices.Sorted(maps.Keys(headers)) {
			p := refOf(headers[uid]).prefix()
			if keys := byPrefix[p]; len(keys) > 0 {
				key := keys[0]
				byPrefix[p] = keys[1:]
				back[origins[key]] = append(back[origins[key]], uid)
				idOf[uid], here[key] = key, true
			}
		}
		// Stop looking for mail that is gone, but keep the record so a
		// move back still counts as a rescue.
		if len(headers) == len(whole) {
			l.mu.Lock()
			gone := 0
			for key := range origins {
				if m := l.Moved[key]; !here[key] && settled[key] && m != nil && !m.Pending {
					m.Defer = false
					gone++
				}
			}
			if gone > 0 {
				a.saveLearning(l)
			}
			l.mu.Unlock()
		}
		c.Release(nil)
		for origin, uids := range back {
			if !a.releaseTo(folder, origin, uids, idOf) {
				break
			}
		}
	}
}

// releaseTo moves uids back to origin under folder locks. It reports
// whether to continue.
func (a *Account) releaseTo(folder, origin string, uids []imap.UID, idOf map[imap.UID]string) bool {
	defer a.lockFolders(folder, origin)()
	c, err := a.conn(bulk, folder)
	if err != nil {
		return false
	}
	l := a.learning()
	// Recheck under the locks: the UIDs may name other mail now.
	got, err := c.FetchHeaders(folder, uids)
	if err != nil {
		c.Release(err)
		return false
	}
	mine := map[imap.UID]*authMoved{}
	l.mu.Lock()
	var still []imap.UID
	for _, uid := range uids {
		if e := got[uid]; e == nil || !strings.HasPrefix(idOf[uid], refOf(e.Header).prefix()) {
			continue
		}
		if m := l.Moved[idOf[uid]]; m != nil && m.Defer && !m.Rescued {
			m.Pending = true
			mine[uid] = m
			still = append(still, uid)
		}
	}
	uids = still
	if len(uids) == 0 {
		l.mu.Unlock()
		c.Release(nil)
		return true
	}
	if a.saveLearning(l) != nil {
		for _, m := range mine {
			m.Pending = false
		}
		l.mu.Unlock()
		c.Release(nil)
		return false
	}
	l.mu.Unlock()
	moved, err := c.Move(folder, uids, origin)
	// Only touch our own records; another move may have replaced them.
	failed, verr := stayed(c, folder, uids, moved)
	known := verr == nil
	err = errors.Join(err, verr)
	c.Release(err)
	l.mu.Lock()
	for uid, m := range mine {
		switch {
		case l.Moved[idOf[uid]] != m || !known:
		case failed[uid]:
			m.Pending = false
		default:
			delete(l.Moved, idOf[uid])
		}
	}
	a.saveLearning(l)
	l.mu.Unlock()
	if err != nil {
		a.b.Log.Warn("could not release mail", "user", a.login, "mailbox", folder, "to", origin, "err", err)
		return false
	}
	a.b.Log.Info("released mail to read again", "user", a.login, "from", folder, "to", origin, "count", len(uids)-len(failed))
	return true
}
