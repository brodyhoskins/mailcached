package jmapproxy

import (
	"cmp"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/internal/jmap"
)

// --- Keywords --------------------------------------------------------------

// keywordOf is the JMAP keyword for an IMAP flag; "" for flags JMAP has no
// keyword for (\Deleted, \Recent).
func keywordOf(f imap.Flag) string {
	switch strings.ToLower(string(f)) {
	case `\seen`:
		return jmap.KeywordSeen
	case `\flagged`:
		return jmap.KeywordFlagged
	case `\answered`:
		return jmap.KeywordAnswered
	case `\draft`:
		return jmap.KeywordDraft
	case `\deleted`, `\recent`, "":
		return ""
	}
	if strings.HasPrefix(string(f), `\`) {
		return ""
	}
	return strings.ToLower(string(f))
}

// flagOf is the IMAP flag for a JMAP keyword.
func flagOf(k string) imap.Flag {
	switch strings.ToLower(k) {
	case jmap.KeywordSeen:
		return imap.FlagSeen
	case jmap.KeywordFlagged:
		return imap.FlagFlagged
	case jmap.KeywordAnswered:
		return imap.FlagAnswered
	case jmap.KeywordDraft:
		return imap.FlagDraft
	case jmap.KeywordForwarded:
		return "$Forwarded"
	}
	return imap.Flag(k)
}

// validKeyword reports whether k may be a keyword (RFC 8621 section
// 4.1.1: IMAP atom characters, no backslash).
func validKeyword(k string) bool {
	if k == "" || len(k) > 255 {
		return false
	}
	for _, r := range k {
		if r <= ' ' || r >= 0x7f || strings.ContainsRune(`(){]%*"\`, r) {
			return false
		}
	}
	return true
}

func keywordsOf(flags []imap.Flag) map[string]bool {
	out := map[string]bool{}
	for _, f := range flags {
		if k := keywordOf(f); k != "" {
			out[k] = true
		}
	}
	return out
}

// --- Mailbox/get -----------------------------------------------------------

// roles maps special-use attributes to roles.
var roles = map[imap.MailboxAttr]string{
	imap.MailboxAttrAll: jmap.RoleAll, imap.MailboxAttrArchive: jmap.RoleArchive, imap.MailboxAttrDrafts: jmap.RoleDrafts,
	imap.MailboxAttrFlagged: jmap.RoleFlagged, imap.MailboxAttrJunk: jmap.RoleJunk, imap.MailboxAttrSent: jmap.RoleSent,
	imap.MailboxAttrTrash: jmap.RoleTrash,
}

func roleOf(m *engine.Mailbox) *string {
	if m.Name() == "INBOX" {
		r := jmap.RoleInbox
		return &r
	}
	for _, a := range m.Attrs() {
		for attr, role := range roles {
			if strings.EqualFold(string(a), string(attr)) {
				return &role
			}
		}
	}
	return nil
}

// parentOf returns a folder's parent folder and its own name under it;
// nil and the full name for a top-level folder, or one whose parent does
// not exist (lock held).
func parentOf(a *engine.Account, m *engine.Mailbox) (*engine.Mailbox, string) {
	d := m.Delim()
	if d == 0 {
		return nil, m.Name()
	}
	i := strings.LastIndexByte(m.Name(), byte(d))
	if i <= 0 || d > 0x7f {
		return nil, m.Name()
	}
	p := a.Mailbox(m.Name()[:i])
	if p == nil {
		return nil, m.Name()
	}
	return p, m.Name()[i+1:]
}

// mailboxOf describes a folder (lock held).
func mailboxOf(a *engine.Account, m *engine.Mailbox) jmap.Mailbox {
	seen := map[string]bool{}
	unread := map[string]bool{}
	for _, msg := range m.Msgs() {
		id := engine.EmailID(msg.Key())
		seen[id] = true
		if !engine.HasFlag(msg.Flags(), imap.FlagSeen) {
			unread[id] = true
		}
	}
	out := jmap.Mailbox{
		ID: jmap.ID(m.ID()), Role: roleOf(m), TotalEmails: len(seen), UnreadEmails: len(unread),
		TotalThreads: len(seen), UnreadThreads: len(unread), MyRights: jmap.AllRights, IsSubscribed: m.Subscribed(),
	}
	if !m.Selectable() {
		out.MyRights = jmap.MailboxRights{MayCreateChild: true, MayRename: true, MayDelete: true}
	}
	if m.Name() == "INBOX" {
		out.MyRights.MayRename, out.MyRights.MayDelete = false, false
	}
	p, name := parentOf(a, m)
	out.Name = name
	if p != nil {
		id := jmap.ID(p.ID())
		out.ParentID = &id
	}
	if out.Role != nil {
		out.SortOrder = slices.Index([]string{jmap.RoleInbox, jmap.RoleDrafts, jmap.RoleSent, jmap.RoleArchive,
			jmap.RoleJunk, jmap.RoleTrash}, *out.Role) + 1
	}
	return out
}

// filterProps keeps the properties asked for, and the ID.
func filterProps(v any, props []string) (any, error) {
	if props == nil {
		return v, nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, err
	}
	out := map[string]json.RawMessage{"id": all["id"]}
	for _, p := range props {
		if val, ok := all[p]; ok {
			out[p] = val
		}
	}
	return out, nil
}

func mailboxGet(c *call) (any, error) {
	var args jmap.GetArgs
	if err := c.decode(&args); err != nil {
		return nil, err
	}
	if len(args.IDs) > maxObjectsInGet {
		return nil, &jmap.MethodError{Type: jmap.ErrRequestTooLarge}
	}
	for _, p := range args.Properties {
		if !slices.Contains(mailboxProps, p) {
			return nil, invalid("unknown property " + p)
		}
	}
	a := c.c.acct
	a.Lock()
	defer a.Unlock()
	resp := jmap.GetResponse[any]{AccountID: c.c.id, State: jmap.State(a.State()), List: []any{}, NotFound: []jmap.ID{}}
	var boxes []*engine.Mailbox
	if args.IDs == nil {
		boxes = a.Mailboxes()
		slices.SortFunc(boxes, func(x, y *engine.Mailbox) int { return cmp.Compare(x.Name(), y.Name()) })
	} else {
		for _, id := range args.IDs {
			if m := a.MailboxByID(string(c.resolve(id))); m != nil {
				boxes = append(boxes, m)
			} else {
				resp.NotFound = append(resp.NotFound, id)
			}
		}
	}
	for _, m := range boxes {
		v, err := filterProps(mailboxOf(a, m), args.Properties)
		if err != nil {
			return nil, err
		}
		resp.List = append(resp.List, v)
	}
	return resp, nil
}

var mailboxProps = []string{"id", "name", "parentId", "role", "sortOrder", "totalEmails", "unreadEmails",
	"totalThreads", "unreadThreads", "myRights", "isSubscribed"}

// changes answers a /changes call from the change log.
func changes(c *call, kind string, countsAs []string) (any, error) {
	var args jmap.ChangesArgs
	if err := c.decode(&args); err != nil {
		return nil, err
	}
	a := c.c.acct
	a.Lock()
	ch, err := a.Changes(kind, string(args.SinceState), args.MaxChanges)
	a.Unlock()
	if errors.Is(err, engine.ErrCannotCalculateChanges) {
		return nil, &jmap.MethodError{Type: jmap.ErrCannotCalculateChanges}
	}
	if err != nil {
		return nil, err
	}
	ids := func(l []string) []jmap.ID {
		out := make([]jmap.ID, len(l))
		for i, s := range l {
			out[i] = jmap.ID(s)
		}
		return out
	}
	resp := jmap.ChangesResponse{AccountID: c.c.id, OldState: args.SinceState, NewState: jmap.State(ch.NewState),
		HasMoreChanges: ch.HasMore, Created: ids(ch.Created), Updated: ids(ch.Updated), Destroyed: ids(ch.Destroyed)}
	if ch.CountsOnly && countsAs != nil {
		resp.UpdatedProperties = countsAs
	}
	return resp, nil
}

func mailboxChanges(c *call) (any, error) {
	return changes(c, engine.KindMailbox, []string{"totalEmails", "unreadEmails", "totalThreads", "unreadThreads"})
}

// --- Mailbox/query ---------------------------------------------------------

func matchMailbox(f *jmap.MailboxFilter, m jmap.Mailbox) bool {
	switch f.Operator {
	case "AND":
		for i := range f.Conditions {
			if !matchMailbox(&f.Conditions[i], m) {
				return false
			}
		}
		return true
	case "OR":
		for i := range f.Conditions {
			if matchMailbox(&f.Conditions[i], m) {
				return true
			}
		}
		return false
	case "NOT":
		for i := range f.Conditions {
			if matchMailbox(&f.Conditions[i], m) {
				return false
			}
		}
		return true
	}
	if f.ParentID != nil && (m.ParentID == nil && *f.ParentID != "" || m.ParentID != nil && *m.ParentID != *f.ParentID) {
		return false
	}
	if f.Name != "" && !strings.Contains(strings.ToLower(m.Name), strings.ToLower(f.Name)) {
		return false
	}
	if f.Role != nil && (m.Role == nil || *m.Role != *f.Role) {
		return false
	}
	if f.HasAnyRole != nil && *f.HasAnyRole != (m.Role != nil) {
		return false
	}
	if f.IsSubscribed != nil && *f.IsSubscribed != m.IsSubscribed {
		return false
	}
	return true
}

// window applies position, anchor and limit to ids (RFC 8620 section
// 5.5).
func window(args *jmap.QueryArgs, ids []jmap.ID) ([]jmap.ID, int, error) {
	pos := args.Position
	if args.Anchor != "" {
		i := slices.Index(ids, args.Anchor)
		if i < 0 {
			return nil, 0, &jmap.MethodError{Type: jmap.ErrAnchorNotFound}
		}
		pos = max(i+args.AnchorOffset, 0)
	} else if pos < 0 {
		pos = max(len(ids)+pos, 0)
	}
	pos = min(pos, len(ids))
	end := len(ids)
	if args.Limit != nil {
		if *args.Limit < 0 {
			return nil, 0, invalid("negative limit")
		}
		end = min(pos+*args.Limit, len(ids))
	}
	return ids[pos:end], pos, nil
}

func mailboxQuery(c *call) (any, error) {
	var args jmap.QueryArgs
	if err := c.decode(&args); err != nil {
		return nil, err
	}
	var filter *jmap.MailboxFilter
	if len(args.Filter) > 0 && string(args.Filter) != "null" {
		filter = &jmap.MailboxFilter{}
		if err := json.Unmarshal(args.Filter, filter); err != nil {
			return nil, invalid(err.Error())
		}
	}
	for _, s := range args.Sort {
		if s.Property != "name" && s.Property != "sortOrder" {
			return nil, &jmap.MethodError{Type: jmap.ErrUnsupportedSort, Description: s.Property}
		}
	}
	a := c.c.acct
	a.Lock()
	state := a.State()
	var list []jmap.Mailbox
	for _, m := range a.Mailboxes() {
		mb := mailboxOf(a, m)
		if filter == nil || matchMailbox(filter, mb) {
			list = append(list, mb)
		}
	}
	a.Unlock()
	slices.SortFunc(list, func(x, y jmap.Mailbox) int {
		for _, s := range args.Sort {
			var d int
			if s.Property == "sortOrder" {
				d = cmp.Compare(x.SortOrder, y.SortOrder)
			} else {
				d = cmp.Compare(strings.ToLower(x.Name), strings.ToLower(y.Name))
			}
			if !s.Ascending() {
				d = -d
			}
			if d != 0 {
				return d
			}
		}
		return cmp.Compare(x.ID, y.ID)
	})
	ids := make([]jmap.ID, len(list))
	for i, m := range list {
		ids[i] = m.ID
	}
	total := len(ids)
	ids, pos, err := window(&args, ids)
	if err != nil {
		return nil, err
	}
	resp := jmap.QueryResponse{AccountID: c.c.id, QueryState: jmap.State(state), Position: pos, IDs: ids}
	if args.CalculateTotal {
		resp.Total = &total
	}
	return resp, nil
}

// --- Mailbox/set -----------------------------------------------------------

// setError turns an error from the engine or the provider into a SetError.
func setError(err error) jmap.SetError {
	var ie *imap.Error
	switch {
	case errors.As(err, &ie):
		return jmap.SetError{Type: jmap.SetForbidden, Description: ie.Text}
	case errors.Is(err, engine.ErrNoMailbox):
		return jmap.SetError{Type: jmap.SetInvalidProperties, Properties: []string{"mailboxIds"}}
	}
	return jmap.SetError{Type: jmap.SetForbidden, Description: err.Error()}
}

func mailboxSet(c *call) (any, error) {
	var args jmap.SetArgs[json.RawMessage]
	if err := c.decode(&args); err != nil {
		return nil, err
	}
	if len(args.Create)+len(args.Update)+len(args.Destroy) > maxObjectsInSet {
		return nil, &jmap.MethodError{Type: jmap.ErrRequestTooLarge}
	}
	a := c.c.acct
	a.Lock()
	old := a.State()
	a.Unlock()
	if args.IfInState != "" && string(args.IfInState) != old {
		return nil, &jmap.MethodError{Type: jmap.ErrStateMismatch}
	}
	resp := jmap.SetResponse[any]{AccountID: c.c.id, OldState: jmap.State(old)}
	notCreated, notUpdated, notDestroyed := map[jmap.ID]jmap.SetError{}, map[jmap.ID]jmap.SetError{}, map[jmap.ID]jmap.SetError{}
	created, updated := map[jmap.ID]any{}, map[jmap.ID]*any{}

	// fullName is the folder name for a JMAP name under parent (none if
	// nil or "").
	fullName := func(name string, parent *jmap.ID) (string, *jmap.SetError) {
		if name == "" || strings.ContainsAny(name, "\x00\r\n") {
			return "", &jmap.SetError{Type: jmap.SetInvalidProperties, Properties: []string{"name"}}
		}
		if parent == nil || *parent == "" {
			return name, nil
		}
		a.Lock()
		defer a.Unlock()
		p := a.MailboxByID(string(c.resolve(*parent)))
		if p == nil {
			return "", &jmap.SetError{Type: jmap.SetInvalidProperties, Properties: []string{"parentId"}}
		}
		if p.Delim() == 0 {
			return "", &jmap.SetError{Type: jmap.SetInvalidProperties, Properties: []string{"parentId"},
				Description: "The server has no folder hierarchy"}
		}
		return p.Name() + string(p.Delim()) + name, nil
	}

	for cid, raw := range args.Create {
		var mb struct {
			Name         string   `json:"name"`
			ParentID     *jmap.ID `json:"parentId"`
			IsSubscribed *bool    `json:"isSubscribed"`
			Role         *string  `json:"role"`
		}
		if err := json.Unmarshal(raw, &mb); err != nil {
			notCreated[cid] = jmap.SetError{Type: jmap.SetInvalidProperties, Description: err.Error()}
			continue
		}
		if mb.Role != nil {
			notCreated[cid] = jmap.SetError{Type: jmap.SetInvalidProperties, Properties: []string{"role"},
				Description: "Roles come from the provider"}
			continue
		}
		name, serr := fullName(mb.Name, mb.ParentID)
		if serr != nil {
			notCreated[cid] = *serr
			continue
		}
		if err := a.CreateFolder(name, nil); err != nil {
			notCreated[cid] = setError(err)
			continue
		}
		if mb.IsSubscribed == nil || *mb.IsSubscribed {
			if err := a.Subscribe(name, true); err != nil {
				c.s.Log.Info("jmap: could not subscribe a new folder", "user", c.c.login, "mailbox", name, "err", err)
			}
		}
		a.Lock()
		m := a.Mailbox(name)
		var v any
		if m != nil {
			v = mailboxOf(a, m)
			c.created[cid] = jmap.ID(m.ID())
		}
		a.Unlock()
		if m == nil {
			notCreated[cid] = jmap.SetError{Type: jmap.SetForbidden, Description: "The provider did not create it"}
			continue
		}
		created[cid] = v
	}

	for id, patch := range args.Update {
		id = c.resolve(id)
		a.Lock()
		m := a.MailboxByID(string(id))
		var cur jmap.Mailbox
		var oldName string
		if m != nil {
			cur, oldName = mailboxOf(a, m), m.Name()
		}
		a.Unlock()
		if m == nil {
			notUpdated[id] = jmap.SetError{Type: jmap.SetNotFound}
			continue
		}
		name, parent := cur.Name, cur.ParentID
		var sub *bool
		var bad []string
		for k, v := range patch {
			switch k {
			case "name":
				if json.Unmarshal(v, &name) != nil {
					bad = append(bad, k)
				}
			case "parentId":
				parent = nil
				if string(v) != "null" && json.Unmarshal(v, &parent) != nil {
					bad = append(bad, k)
				}
			case "isSubscribed":
				var b bool
				if json.Unmarshal(v, &b) != nil {
					bad = append(bad, k)
				}
				sub = &b
			case "sortOrder":
				// Not kept: the order comes from the roles.
			default:
				bad = append(bad, k)
			}
		}
		if len(bad) > 0 {
			notUpdated[id] = jmap.SetError{Type: jmap.SetInvalidProperties, Properties: bad}
			continue
		}
		newName, serr := fullName(name, parent)
		if serr != nil {
			notUpdated[id] = *serr
			continue
		}
		if newName != oldName {
			if oldName == "INBOX" {
				notUpdated[id] = jmap.SetError{Type: jmap.SetForbidden, Description: "INBOX cannot be renamed"}
				continue
			}
			if err := a.RenameFolder(oldName, newName, nil); err != nil {
				notUpdated[id] = setError(err)
				continue
			}
		}
		if sub != nil && *sub != cur.IsSubscribed {
			if err := a.Subscribe(newName, *sub); err != nil {
				notUpdated[id] = setError(err)
				continue
			}
		}
		updated[id] = nil
	}

	for _, id := range args.Destroy {
		id = c.resolve(id)
		a.Lock()
		m := a.MailboxByID(string(id))
		var name string
		var hasChild, hasMail bool
		if m != nil {
			name = m.Name()
			hasMail = len(m.Msgs()) > 0
			for _, x := range a.Mailboxes() {
				if p, _ := parentOf(a, x); p == m {
					hasChild = true
				}
			}
		}
		a.Unlock()
		switch {
		case m == nil:
			notDestroyed[id] = jmap.SetError{Type: jmap.SetNotFound}
			continue
		case name == "INBOX":
			notDestroyed[id] = jmap.SetError{Type: jmap.SetForbidden, Description: "INBOX cannot be deleted"}
			continue
		case hasChild:
			notDestroyed[id] = jmap.SetError{Type: jmap.SetMailboxHasChild}
			continue
		case hasMail && !args.OnDestroyRemoveEmails:
			notDestroyed[id] = jmap.SetError{Type: jmap.SetMailboxHasEmail}
			continue
		}
		if err := a.DeleteFolder(name); err != nil {
			notDestroyed[id] = setError(err)
			continue
		}
		resp.Destroyed = append(resp.Destroyed, id)
	}

	a.Lock()
	resp.NewState = jmap.State(a.State())
	a.Unlock()
	if len(created) > 0 {
		resp.Created = created
	}
	if len(updated) > 0 {
		resp.Updated = updated
	}
	if len(notCreated) > 0 {
		resp.NotCreated = notCreated
	}
	if len(notUpdated) > 0 {
		resp.NotUpdated = notUpdated
	}
	if len(notDestroyed) > 0 {
		resp.NotDestroyed = notDestroyed
	}
	return resp, nil
}
