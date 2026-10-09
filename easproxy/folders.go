package easproxy

// The folder commands: FolderSync, FolderCreate, FolderDelete and
// FolderUpdate. A folder's ServerId is its engine ID (Mailbox.ID), which
// it keeps when renamed.

import (
	"cmp"
	"errors"
	"strconv"
	"strings"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/engine"
)

// The folder types of MS-ASCMD 2.2.3.186.3.
const (
	typeUserGeneric = 1
	typeInbox       = 2
	typeDrafts      = 3
	typeTrash       = 4
	typeSent        = 5
	typeUserMail    = 12
)

// specialNames are the usual names of the special folders, for a
// provider that does not mark them (SPECIAL-USE).
var specialNames = map[int][]string{
	typeDrafts: {"Drafts"},
	typeTrash:  {"Trash", "Deleted Items", "Deleted Messages"},
	typeSent:   {"Sent", "Sent Items", "Sent Messages"},
}

// folderTypes returns the type of each special folder, by name (lock
// held). A folder marked with a special use is that type; a type no folder
// is marked with goes to a folder with a usual name for it.
func folderTypes(a *engine.Account) map[string]int {
	out := map[string]int{"INBOX": typeInbox}
	marked := map[int]bool{}
	for _, m := range a.Mailboxes() {
		if !m.Selectable() || m.Name() == "INBOX" {
			continue
		}
		for _, attr := range m.Attrs() {
			t := 0
			switch {
			case strings.EqualFold(string(attr), string(imap.MailboxAttrDrafts)):
				t = typeDrafts
			case strings.EqualFold(string(attr), string(imap.MailboxAttrTrash)):
				t = typeTrash
			case strings.EqualFold(string(attr), string(imap.MailboxAttrSent)):
				t = typeSent
			}
			if t != 0 && !marked[t] {
				out[m.Name()], marked[t] = t, true
			}
		}
	}
	for t, names := range specialNames {
		if marked[t] {
			continue
		}
	next:
		for _, n := range names {
			for _, m := range a.Mailboxes() {
				if _, taken := out[m.Name()]; !taken && m.Selectable() && strings.EqualFold(m.Name(), n) {
					out[m.Name()] = t
					break next
				}
			}
		}
	}
	return out
}

// folderTypeOf returns a folder's type (lock held).
func folderTypeOf(a *engine.Account, m *engine.Mailbox) int {
	if t := folderTypes(a)[m.Name()]; t != 0 {
		return t
	}
	return typeUserMail
}

// specialFolderName returns the folder of a special type, "" if none (lock
// held).
func specialFolderName(a *engine.Account, t int) string {
	for name, ft := range folderTypes(a) {
		if ft == t {
			return name
		}
	}
	return ""
}

// specialFolder reports whether a type is one the device may not change.
func specialFolder(t int) bool { return t != typeUserMail && t != typeUserGeneric }

// currentFolders returns the account's folders as a device sees them
// (lock held). A folder's parent is its nearest ancestor that is shown,
// "0" for none.
func currentFolders(a *engine.Account) map[string]folderRec {
	shown := map[string]*engine.Mailbox{}
	for _, m := range a.Mailboxes() {
		if m.Selectable() {
			shown[m.Name()] = m
		}
	}
	types := folderTypes(a)
	out := make(map[string]folderRec, len(shown))
	for name, m := range shown {
		parent, leaf := "0", name
		if d := m.Delim(); d != 0 {
			for p := name; ; {
				i := strings.LastIndex(p, string(d))
				if i <= 0 {
					break
				}
				p = p[:i]
				if pm := shown[p]; pm != nil {
					parent, leaf = pm.ID(), name[len(p)+len(string(d)):]
					break
				}
			}
		}
		out[m.ID()] = folderRec{Name: leaf, Parent: parent, Type: cmp.Or(types[name], typeUserMail)}
	}
	return out
}

// folderByID returns a folder by its ServerId, or nil (lock held).
func folderByID(a *engine.Account, id string) *engine.Mailbox {
	m := a.MailboxByID(id)
	if m == nil || !m.Selectable() {
		return nil
	}
	return m
}

// folderChanges lists what changed from old to now.
func folderChanges(old, now map[string]folderRec) []*node {
	var adds, updates, deletes []*node
	for id, f := range now {
		o, ok := old[id]
		if ok && o == f {
			continue
		}
		name := "FolderHierarchy:Add"
		if ok {
			name = "FolderHierarchy:Update"
		}
		n := el(name, tx("FolderHierarchy:ServerId", id), tx("FolderHierarchy:ParentId", f.Parent),
			tx("FolderHierarchy:DisplayName", f.Name), tx("FolderHierarchy:Type", strconv.Itoa(f.Type)))
		if ok {
			updates = append(updates, n)
		} else {
			adds = append(adds, n)
		}
	}
	for id := range old {
		if _, ok := now[id]; !ok {
			deletes = append(deletes, el("FolderHierarchy:Delete", tx("FolderHierarchy:ServerId", id)))
		}
	}
	// Parents before their children, so a device can place each folder.
	sortByDepth(adds, now)
	return append(append(deletes, adds...), updates...)
}

// sortByDepth orders folder Adds so that parents come first.
func sortByDepth(ns []*node, folders map[string]folderRec) {
	depth := func(n *node) int {
		d := 0
		for id := n.Value("ServerId"); d < 64; d++ {
			f, ok := folders[id]
			if !ok || f.Parent == "0" {
				break
			}
			id = f.Parent
		}
		return d
	}
	for i := 1; i < len(ns); i++ {
		for j := i; j > 0 && depth(ns[j]) < depth(ns[j-1]); j-- {
			ns[j], ns[j-1] = ns[j-1], ns[j]
		}
	}
}

// folderSync answers FolderSync.
func (req *request) folderSync() (*node, error) {
	key := req.doc.Value("SyncKey")
	fail := func(status int) (*node, error) {
		return el("FolderHierarchy:FolderSync", tx("FolderHierarchy:Status", strconv.Itoa(status))), nil
	}
	if req.doc == nil || key == "" {
		return fail(10)
	}
	a := req.c.acct
	a.Lock()
	now := currentFolders(a)
	a.Unlock()

	dv := req.dv
	dv.mu.Lock()
	defer dv.mu.Unlock()
	var base map[string]folderRec
	switch {
	case key == "0":
		// A new start: everything the device knew is gone.
		dv.st.Collections = map[string]*collState{}
		dv.st.PingFolders, dv.st.SyncFolders = nil, nil
	case key == strconv.Itoa(dv.st.FolderKey) && dv.st.FolderKey > 0:
		base = dv.st.Folders
	case key == strconv.Itoa(dv.st.PrevKey) && dv.st.PrevKey > 0:
		base = dv.st.PrevFolders
	default:
		return fail(9)
	}
	changes := folderChanges(base, now)
	newKey := dv.st.FolderKey
	if key == "0" || len(changes) > 0 || key != strconv.Itoa(dv.st.FolderKey) {
		dv.st.PrevKey, dv.st.PrevFolders = atoi(key), base
		dv.st.FolderKey++
		newKey = dv.st.FolderKey
		dv.st.Folders = now
		// A folder that is gone takes its sync state with it.
		for id := range dv.st.Collections {
			if _, ok := now[id]; !ok {
				delete(dv.st.Collections, id)
			}
		}
		if err := dv.save(); err != nil {
			return nil, err
		}
	}
	out := el("FolderHierarchy:Changes", append([]*node{tx("FolderHierarchy:Count", strconv.Itoa(len(changes)))}, changes...)...)
	return el("FolderHierarchy:FolderSync", tx("FolderHierarchy:Status", "1"),
		tx("FolderHierarchy:SyncKey", strconv.Itoa(newKey)), out), nil
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// folderOp checks a folder command's SyncKey, makes the change, and
// answers it with the device's new folder key. The change returns the
// ServerId to report ("" for none) and a status other than 1 on failure.
func (req *request) folderOp(cmd string, do func(a *engine.Account) (id string, status int)) (*node, error) {
	page := "FolderHierarchy:"
	fail := func(status int) (*node, error) {
		return el(page+cmd, tx(page+"Status", strconv.Itoa(status))), nil
	}
	if req.doc == nil {
		return fail(10)
	}
	dv := req.dv
	dv.mu.Lock()
	key := dv.st.FolderKey
	dv.mu.Unlock()
	if k := req.doc.Value("SyncKey"); k != strconv.Itoa(key) || key == 0 {
		return fail(9)
	}
	a := req.c.acct
	id, status := do(a)
	if status != 1 {
		return fail(status)
	}
	a.Lock()
	now := currentFolders(a)
	a.Unlock()
	dv.mu.Lock()
	defer dv.mu.Unlock()
	// The device makes the change itself: it is in the state it has, not
	// a change to send it.
	dv.st.PrevKey, dv.st.PrevFolders = dv.st.FolderKey, dv.st.Folders
	dv.st.FolderKey++
	dv.st.Folders = now
	for cid := range dv.st.Collections {
		if _, ok := now[cid]; !ok {
			delete(dv.st.Collections, cid)
		}
	}
	if err := dv.save(); err != nil {
		return nil, err
	}
	kids := []*node{tx(page+"Status", "1"), tx(page+"SyncKey", strconv.Itoa(dv.st.FolderKey))}
	if id != "" {
		kids = append(kids, tx(page+"ServerId", id))
	}
	return el(page+cmd, kids...), nil
}

// folderStatus turns a folder change's error into a status: exists is the
// status for a name in use.
func (req *request) folderStatus(err error, exists int) int {
	var ie *imap.Error
	switch {
	case err == nil:
		return 1
	case errors.Is(err, engine.ErrNoMailbox):
		return 4
	case errors.As(err, &ie) && ie.Code == imap.ResponseCodeAlreadyExists:
		return exists
	case errors.As(err, &ie):
		req.s.Log.Info("activesync: folder change refused", "user", req.c.login, "cmd", req.cmd, "err", err)
		return 6
	default:
		req.s.Log.Warn("activesync: folder change failed", "user", req.c.login, "cmd", req.cmd, "err", err)
		return 6
	}
}

// childName returns the full name of a folder named leaf under the folder
// with ServerId parent ("0" for the top), or a status.
func childName(a *engine.Account, parent, leaf string) (string, int) {
	if leaf == "" {
		return "", 10
	}
	a.Lock()
	defer a.Unlock()
	if parent == "0" || parent == "" {
		return leaf, 1
	}
	p := folderByID(a, parent)
	if p == nil {
		return "", 5
	}
	d := p.Delim()
	if d == 0 {
		d = a.Delim()
	}
	if d == 0 {
		return "", 5
	}
	return p.Name() + string(d) + leaf, 1
}

func (req *request) folderCreate() (*node, error) {
	return req.folderOp("FolderCreate", func(a *engine.Account) (string, int) {
		name, status := childName(a, req.doc.Value("ParentId"), req.doc.Value("DisplayName"))
		if status != 1 {
			return "", status
		}
		a.Lock()
		exists := a.Mailbox(name) != nil
		a.Unlock()
		if exists {
			return "", 2
		}
		if status := req.folderStatus(a.CreateFolder(name, nil), 2); status != 1 {
			return "", status
		}
		a.Lock()
		defer a.Unlock()
		m := a.Mailbox(name)
		if m == nil {
			return "", 6
		}
		return m.ID(), 1
	})
}

func (req *request) folderDelete() (*node, error) {
	return req.folderOp("FolderDelete", func(a *engine.Account) (string, int) {
		a.Lock()
		m := folderByID(a, req.doc.Value("ServerId"))
		var name string
		special := false
		if m != nil {
			name, special = m.Name(), specialFolder(folderTypeOf(a, m))
		}
		a.Unlock()
		switch {
		case m == nil:
			return "", 4
		case special:
			return "", 3
		}
		return "", req.folderStatus(a.DeleteFolder(name), 6)
	})
}

func (req *request) folderUpdate() (*node, error) {
	return req.folderOp("FolderUpdate", func(a *engine.Account) (string, int) {
		a.Lock()
		m := folderByID(a, req.doc.Value("ServerId"))
		var old string
		special := false
		if m != nil {
			old, special = m.Name(), specialFolder(folderTypeOf(a, m))
		}
		a.Unlock()
		switch {
		case m == nil:
			return "", 4
		case special:
			return "", 3
		}
		name, status := childName(a, req.doc.Value("ParentId"), req.doc.Value("DisplayName"))
		if status != 1 {
			return "", status
		}
		if name == old {
			return "", 1
		}
		return "", req.folderStatus(a.RenameFolder(old, name, nil), 2)
	})
}
