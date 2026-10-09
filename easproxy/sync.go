package easproxy

// Sync and GetItemEstimate. A device names a folder's state by a sync
// key; the server keeps, for each key, which messages the device has and
// their read and flag state (state.go), and answers with the difference
// between that and the folder now, a window at a time.

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/engine"
)

// Limits on a Sync.
const (
	defaultWindow = 100
	maxWindow     = 100
	// maxWait is the longest a Sync with Wait or HeartbeatInterval waits
	// for a change.
	maxWait = 59 * time.Minute
)

// recOf is what a device knows of a message (lock held).
func recOf(msg *engine.Message) itemRec {
	var r itemRec
	for _, f := range msg.Flags() {
		switch {
		case strings.EqualFold(string(f), string(imap.FlagSeen)):
			r.Read = true
		case strings.EqualFold(string(f), string(imap.FlagFlagged)):
			r.Flagged = true
		case strings.EqualFold(string(f), string(imap.FlagAnswered)):
			r.Answered = true
		case strings.EqualFold(string(f), "$Forwarded"):
			r.Forwarded = true
		}
	}
	return r
}

func deleted(msg *engine.Message) bool {
	return slices.ContainsFunc(msg.Flags(), func(f imap.Flag) bool { return strings.EqualFold(string(f), string(imap.FlagDeleted)) })
}

// cutoff returns the oldest date a FilterType lets through; zero for all.
func cutoff(filter int, now time.Time) time.Time {
	days := map[int]int{1: 1, 2: 3, 3: 7, 4: 14, 5: 31, 6: 92, 7: 183}[filter]
	if days == 0 {
		return time.Time{}
	}
	return now.AddDate(0, 0, -days)
}

// visible returns the messages a device sees in a folder (lock held): not
// \Deleted, and no older than the filter allows.
func visible(m *engine.Mailbox, filter int) map[imap.UID]*engine.Message {
	from := cutoff(filter, time.Now())
	out := map[imap.UID]*engine.Message{}
	for _, msg := range m.Msgs() {
		if deleted(msg) || (!from.IsZero() && msg.Date().Before(from)) {
			continue
		}
		out[msg.UID()] = msg
	}
	return out
}

// parseOptions reads a collection's Options; nil if it has none.
func parseOptions(n *node) *syncOptions {
	if n == nil {
		return nil
	}
	o := &syncOptions{FilterType: atoi(n.Value("FilterType")), MIMESupport: atoi(n.Value("MIMESupport"))}
	for _, bp := range n.Children("AirSyncBase:BodyPreference") {
		p := bodyPref{Type: atoi(bp.Value("Type")), Preview: atoi(bp.Value("Preview")), AllOrNone: bp.Value("AllOrNone") == "1"}
		p.Truncation, _ = strconv.ParseInt(bp.Value("TruncationSize"), 10, 64)
		o.Prefs = append(o.Prefs, p)
	}
	return o
}

// syncReq is one collection of a Sync request.
type syncReq struct {
	id, key    string
	getChanges bool
	window     int
	asMoves    bool
	opts       *syncOptions
	commands   *node
}

func (req *request) sync() (*node, error) {
	dv := req.dv
	var colls []*syncReq
	window := defaultWindow
	var wait time.Duration
	if req.doc == nil {
		// An empty request repeats the last one.
		dv.mu.Lock()
		for _, id := range dv.st.SyncFolders {
			if cs := dv.coll(id); cs != nil {
				colls = append(colls, &syncReq{id: id, key: strconv.Itoa(cs.Key), getChanges: true, window: defaultWindow, asMoves: true})
			}
		}
		dv.mu.Unlock()
		if len(colls) == 0 {
			return el("AirSync:Sync", tx("AirSync:Status", "13")), nil
		}
	} else {
		if w := atoi(req.doc.Value("WindowSize")); w > 0 {
			window = min(w, maxWindow)
		}
		if w := atoi(req.doc.Value("Wait")); w > 0 {
			wait = time.Duration(w) * time.Minute
		}
		if h := atoi(req.doc.Value("HeartbeatInterval")); h > 0 {
			wait = time.Duration(h) * time.Second
		}
		for _, c := range req.doc.Child("Collections").Children("Collection") {
			sr := &syncReq{id: c.Value("CollectionId"), key: c.Value("SyncKey"), window: window,
				asMoves: c.Value("DeletesAsMoves") != "0", opts: parseOptions(c.Child("Options")), commands: c.Child("Commands")}
			// GetChanges is on by default, except for a first sync.
			gc := c.Child("GetChanges")
			sr.getChanges = sr.key != "0" && (gc == nil || gc.Text != "0")
			if w := atoi(c.Value("WindowSize")); w > 0 {
				sr.window = min(w, maxWindow)
			}
			if sr.id == "" || sr.key == "" {
				return el("AirSync:Sync", tx("AirSync:Status", "4")), nil
			}
			colls = append(colls, sr)
		}
		if req.doc.Child("Partial") != nil {
			// The collections left out are synced as last time.
			dv.mu.Lock()
			for _, id := range dv.st.SyncFolders {
				if cs := dv.coll(id); cs != nil && !slices.ContainsFunc(colls, func(c *syncReq) bool { return c.id == id }) {
					colls = append(colls, &syncReq{id: id, key: strconv.Itoa(cs.Key), getChanges: true, window: window, asMoves: true})
				}
			}
			dv.mu.Unlock()
		}
		if len(colls) == 0 {
			return el("AirSync:Sync", tx("AirSync:Status", "13")), nil
		}
		dv.mu.Lock()
		dv.st.SyncFolders = nil
		for _, c := range colls {
			dv.st.SyncFolders = append(dv.st.SyncFolders, c.id)
		}
		dv.mu.Unlock()
	}
	if wait > 0 && (wait < time.Minute || wait > maxWait) {
		limit := strconv.Itoa(int(maxWait / time.Minute))
		return el("AirSync:Sync", tx("AirSync:Status", "14"), tx("AirSync:Limit", limit)), nil
	}

	a := req.c.acct
	deadline := time.Now().Add(wait)
	for first := true; ; first = false {
		a.Lock()
		changed := a.Changed()
		a.Unlock()
		var out []*node
		sentAny := false
		for _, c := range colls {
			if !first {
				c.commands = nil
			}
			n, sent, err := req.syncCollection(c)
			if err != nil {
				return nil, err
			}
			sentAny = sentAny || sent
			out = append(out, n)
		}
		if sentAny || wait == 0 || !req.versionAtLeast("12.1") {
			return el("AirSync:Sync", el("AirSync:Collections", out...)), nil
		}
		// Nothing yet: wait for a change.
		t := time.NewTimer(time.Until(deadline))
		select {
		case <-changed:
			t.Stop()
			// Let a burst of changes settle.
			time.Sleep(time.Second)
		case <-t.C:
			return nil, nil // an empty answer: no changes
		case <-req.s.quitting():
			t.Stop()
			return nil, nil
		case <-req.r.Context().Done():
			t.Stop()
			return nil, nil
		}
	}
}

// syncCollection answers one collection. sent reports whether the answer
// says anything: a new key, commands or responses.
func (req *request) syncCollection(sr *syncReq) (n *node, sent bool, err error) {
	a := req.c.acct
	dv := req.dv
	collNode := func(status int, key string, kids ...*node) *node {
		var head []*node
		if !req.versionAtLeast("14.0") {
			head = append(head, tx("AirSync:Class", "Email"))
		}
		head = append(head, tx("AirSync:SyncKey", key), tx("AirSync:CollectionId", sr.id), tx("AirSync:Status", strconv.Itoa(status)))
		return el("AirSync:Collection", append(head, kids...)...)
	}

	a.Lock()
	m := folderByID(a, sr.id)
	var name string
	if m != nil {
		name = m.Name()
	}
	a.Unlock()
	if m == nil {
		return collNode(12, sr.key), true, nil
	}
	// Check the provider now if the folder is stale.
	if m2, err := a.MailboxFor(name); err == nil {
		m = m2
	}

	dv.mu.Lock()
	defer dv.mu.Unlock()
	cs := dv.coll(sr.id)
	if sr.key == "0" {
		a.Lock()
		validity := m.UIDValidity()
		a.Unlock()
		cs = &collState{Key: 1, Items: map[imap.UID]itemRec{}, Validity: validity, Options: sr.opts}
		dv.st.Collections[sr.id] = cs
		if err := dv.save(); err != nil {
			return nil, false, err
		}
		return collNode(1, "1"), true, nil
	}
	var base map[imap.UID]itemRec
	switch {
	case cs == nil:
		return collNode(3, "0"), true, nil
	case sr.key == strconv.Itoa(cs.Key):
		base = cs.Items
	case sr.key == strconv.Itoa(cs.PrevKey) && cs.PrevKey > 0:
		base = cs.Prev
	default:
		return collNode(3, "0"), true, nil
	}
	a.Lock()
	validity := m.UIDValidity()
	a.Unlock()
	if validity != cs.Validity {
		// The folder was renumbered: the device starts again.
		delete(dv.st.Collections, sr.id)
		_ = dv.save()
		return collNode(3, "0"), true, nil
	}
	if sr.opts != nil {
		cs.Options = sr.opts
	}
	opts := cs.Options
	if opts == nil {
		opts = &syncOptions{}
	}
	items := cloneItems(base)

	responses := req.syncCommands(sr, m, items, opts)

	var commands []*node
	more := false
	var hms uint64
	if sr.getChanges {
		commands, more, hms, err = req.syncChanges(m, items, opts, sr.window-len(responses))
		if err != nil {
			return nil, false, err
		}
	}

	key := sr.key
	// The device's own changes are a new state too.
	if len(commands) > 0 || len(responses) > 0 || (sr.commands != nil && len(sr.commands.Kids) > 0) || sr.key != strconv.Itoa(cs.Key) {
		cs.PrevKey, cs.Prev = atoi(sr.key), base
		cs.Key++
		cs.Items = items
		key = strconv.Itoa(cs.Key)
		sent = true
	}
	if sr.getChanges && !more {
		cs.HMS = hms
	}
	if err := dv.save(); err != nil {
		return nil, false, err
	}
	var kids []*node
	if more {
		kids = append(kids, el("AirSync:MoreAvailable"))
	}
	if len(commands) > 0 {
		kids = append(kids, el("AirSync:Commands", commands...))
	}
	if len(responses) > 0 {
		kids = append(kids, el("AirSync:Responses", responses...))
	}
	return collNode(1, key, kids...), sent, nil
}

// syncCommands makes the changes the device sends, and records them in
// items, which is what the device has. It returns the Responses.
func (req *request) syncCommands(sr *syncReq, m *engine.Mailbox, items map[imap.UID]itemRec, opts *syncOptions) []*node {
	if sr.commands == nil {
		return nil
	}
	a := req.c.acct
	var responses []*node
	var gone []imap.UID
	for _, c := range sr.commands.Kids {
		id := c.Value("ServerId")
		_, uid, ok := parseItemID(id)
		switch {
		case c.Is("Change"):
			msg := messageAt(a, m, uid)
			if !ok || msg == nil {
				responses = append(responses, el("AirSync:Change", tx("AirSync:ServerId", id), tx("AirSync:Status", "8")))
				continue
			}
			rec := req.applyChange(msg, m.Name(), c.Child("ApplicationData"))
			if _, known := items[uid]; known {
				items[uid] = rec
			}
		case c.Is("Delete"):
			if ok {
				delete(items, uid)
				gone = append(gone, uid)
			}
		case c.Is("Fetch"):
			msg := messageAt(a, m, uid)
			if !ok || msg == nil {
				responses = append(responses, el("AirSync:Fetch", tx("AirSync:ServerId", id), tx("AirSync:Status", "8")))
				continue
			}
			data, err := req.appData(msg, opts, sr.id)
			if err != nil {
				responses = append(responses, el("AirSync:Fetch", tx("AirSync:ServerId", id), tx("AirSync:Status", "5")))
				continue
			}
			responses = append(responses, el("AirSync:Fetch", tx("AirSync:ServerId", id), tx("AirSync:Status", "1"), data))
		case c.Is("Add"):
			// Devices add mail only in ActiveSync 16 (drafts).
			responses = append(responses, el("AirSync:Add", tx("AirSync:ClientId", c.Value("ClientId")), tx("AirSync:Status", "6")))
		}
	}
	if len(gone) > 0 {
		req.deleteMessages(m, gone, sr.asMoves)
	}
	return responses
}

// messageAt returns a folder's message by UID, or nil.
func messageAt(a *engine.Account, m *engine.Mailbox, uid imap.UID) *engine.Message {
	a.Lock()
	defer a.Unlock()
	i, ok := m.Index(uid)
	if !ok {
		return nil
	}
	return m.Msgs()[i]
}

// applyChange sets the read and flag state a device sends, and returns
// the message's state after.
func (req *request) applyChange(msg *engine.Message, box string, ad *node) itemRec {
	a := req.c.acct
	set := func(on bool, f imap.Flag) {
		op := imap.StoreFlagsDel
		if on {
			op = imap.StoreFlagsAdd
		}
		a.SetFlags([]*engine.Message{msg}, box, op, []imap.Flag{f}, nil)
	}
	if r := ad.Child("Email:Read"); r != nil {
		set(r.Text == "1", imap.FlagSeen)
	}
	if f := ad.Child("Email:Flag"); f != nil {
		set(f.Value("FlagStatus") == "2", imap.FlagFlagged)
	}
	a.Lock()
	defer a.Unlock()
	return recOf(msg)
}

// deleteMessages deletes messages a device deleted: to the Trash, unless
// asMoves is off or they are in the Trash.
func (req *request) deleteMessages(m *engine.Mailbox, uids []imap.UID, asMoves bool) {
	a := req.c.acct
	in := func(msg *engine.Message) bool { return slices.Contains(uids, msg.UID()) }
	a.Lock()
	trash := ""
	if asMoves && folderTypeOf(a, m) != typeTrash {
		trash = specialFolderName(a, typeTrash)
	}
	a.Unlock()
	if trash != "" {
		if moved, _, err := a.Move(m, in, trash); err == nil {
			req.noteMoved(moved, trash)
			return
		}
	}
	a.Expunge(m, in)
}

// noteMoved records in the device's state for dest that it has the moved
// messages, which it learns of from the move itself (dv.mu held).
func (req *request) noteMoved(moved []engine.Copied, dest string) {
	a := req.c.acct
	a.Lock()
	dm := a.Mailbox(dest)
	var id string
	if dm != nil {
		id = dm.ID()
	}
	recs := make(map[imap.UID]itemRec, len(moved))
	for _, c := range moved {
		recs[c.ToUID] = recOf(c.To)
	}
	a.Unlock()
	if cs := req.dv.coll(id); cs != nil {
		for uid, r := range recs {
			cs.Items[uid] = r
		}
	}
}

// syncChanges finds what changed in a folder since items, at most window
// of it, newest message first, and records what it sends in items. It
// returns the commands, whether more is left, and the folder's
// HIGHESTMODSEQ when it looked.
func (req *request) syncChanges(m *engine.Mailbox, items map[imap.UID]itemRec, opts *syncOptions, window int) ([]*node, bool, uint64, error) {
	a := req.c.acct
	window = max(window, 1)
	a.Lock()
	now := visible(m, opts.FilterType)
	hms := a.HighestModSeq(m)
	recs := make(map[imap.UID]itemRec, len(now))
	for uid, msg := range now {
		recs[uid] = recOf(msg)
	}
	a.Unlock()

	var deletes, changes []imap.UID
	var adds []*engine.Message
	for uid := range items {
		if _, ok := now[uid]; !ok {
			deletes = append(deletes, uid)
		}
	}
	for uid, msg := range now {
		old, ok := items[uid]
		switch {
		case !ok:
			adds = append(adds, msg)
		case old != recs[uid]:
			changes = append(changes, uid)
		}
	}
	slices.Sort(deletes)
	slices.Sort(changes)
	slices.SortFunc(adds, func(x, y *engine.Message) int {
		if c := y.Date().Compare(x.Date()); c != 0 {
			return c
		}
		return int(y.UID()) - int(x.UID())
	})

	var out []*node
	more := len(deletes)+len(changes)+len(adds) > window
	for _, uid := range deletes {
		if len(out) >= window {
			return out, true, hms, nil
		}
		out = append(out, el("AirSync:Delete", tx("AirSync:ServerId", itemID(m.ID(), uid))))
		delete(items, uid)
	}
	for _, uid := range changes {
		if len(out) >= window {
			return out, true, hms, nil
		}
		out = append(out, el("AirSync:Change", tx("AirSync:ServerId", itemID(m.ID(), uid)),
			el("AirSync:ApplicationData", req.flagNodes(recs[uid])...)))
		items[uid] = recs[uid]
	}
	if n := window - len(out); len(adds) > n {
		adds = adds[:n]
	}
	if len(adds) == 0 {
		return out, more, hms, nil
	}
	data, err := a.Download(adds, nil)
	if err != nil {
		return nil, false, 0, err
	}
	for _, msg := range adds {
		raw, ok := data[msg]
		if !ok {
			continue // the provider lost it
		}
		ad := req.appDataOf(msg, raw, recs[msg.UID()], opts, m.ID())
		out = append(out, el("AirSync:Add", tx("AirSync:ServerId", itemID(m.ID(), msg.UID())), ad))
		items[msg.UID()] = recs[msg.UID()]
	}
	return out, more, hms, nil
}

// getItemEstimate answers GetItemEstimate: how many changes a Sync of
// each folder would send.
func (req *request) getItemEstimate() (*node, error) {
	if req.doc == nil {
		return el("GetItemEstimate:GetItemEstimate", tx("GetItemEstimate:Status", "2")), nil
	}
	a := req.c.acct
	dv := req.dv
	var out []*node
	for _, c := range req.doc.Child("Collections").Children("Collection") {
		id := c.Value("CollectionId")
		key := c.Value("AirSync:SyncKey")
		resp := func(status int, estimate int) *node {
			kids := []*node{tx("GetItemEstimate:Status", strconv.Itoa(status))}
			coll := []*node{tx("GetItemEstimate:CollectionId", id)}
			if status == 1 {
				coll = append(coll, tx("GetItemEstimate:Estimate", strconv.Itoa(estimate)))
			}
			return el("GetItemEstimate:Response", append(kids, el("GetItemEstimate:Collection", coll...))...)
		}
		a.Lock()
		m := folderByID(a, id)
		a.Unlock()
		if m == nil {
			out = append(out, resp(2, 0))
			continue
		}
		dv.mu.Lock()
		cs := dv.coll(id)
		var base map[imap.UID]itemRec
		opts := &syncOptions{}
		if cs != nil {
			if cs.Options != nil {
				opts = cs.Options
			}
			switch {
			case key == "" || key == strconv.Itoa(cs.Key):
				base = cloneItems(cs.Items)
			case key == strconv.Itoa(cs.PrevKey):
				base = cloneItems(cs.Prev)
			}
		}
		dv.mu.Unlock()
		if o := parseOptions(c.Child("AirSync:Options")); o != nil {
			opts = o
		}
		if o := c.Value("AirSync:FilterType"); o != "" {
			opts = &syncOptions{FilterType: atoi(o)}
		}
		if base == nil {
			out = append(out, resp(4, 0))
			continue
		}
		a.Lock()
		n := 0
		now := visible(m, opts.FilterType)
		for uid, msg := range now {
			if r, ok := base[uid]; !ok || r != recOf(msg) {
				n++
			}
		}
		for uid := range base {
			if _, ok := now[uid]; !ok {
				n++
			}
		}
		a.Unlock()
		out = append(out, resp(1, n))
	}
	return el("GetItemEstimate:GetItemEstimate", out...), nil
}
