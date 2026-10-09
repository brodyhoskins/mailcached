package jmapproxy

import (
	"cmp"
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/internal/jmap"
)

// IDs: an email is "e" and a hash, its thread "t" and the same hash, the
// whole message as a blob "b" and the same hash, and a part of it that
// blob, "-", and its IMAP section with "-" for ".".

func threadID(email string) string  { return "t" + email[1:] }
func emailBlob(email string) string { return "b" + email[1:] }

func partBlob(email jmap.ID, partID string) string {
	return "b" + string(email[1:]) + "-" + strings.ReplaceAll(partID, ".", "-")
}

// emailOfBlob splits a message blob ID: the email ID and the part, "" for
// the whole message.
func emailOfBlob(blob string) (email, partID string, ok bool) {
	if !strings.HasPrefix(blob, "b") || len(blob) < 2 {
		return "", "", false
	}
	h, p, _ := strings.Cut(blob[1:], "-")
	return "e" + h, strings.ReplaceAll(p, "-", "."), true
}

// emailInfo is what the engine says of an email (taken with the lock).
type emailInfo struct {
	id        string
	msgs      []*engine.Message
	mailboxes map[jmap.ID]bool
	keywords  map[string]bool
	received  time.Time
}

func infoOf(a *engine.Account, id string) *emailInfo {
	msgs := a.Email(id)
	if len(msgs) == 0 {
		return nil
	}
	in := &emailInfo{id: id, msgs: slices.Clone(msgs), mailboxes: map[jmap.ID]bool{}, keywords: map[string]bool{},
		received: msgs[0].Date()}
	for _, m := range msgs {
		if mb := a.Mailbox(m.Box()); mb != nil {
			in.mailboxes[jmap.ID(mb.ID())] = true
		}
		for k := range keywordsOf(m.Flags()) {
			in.keywords[k] = true
		}
	}
	return in
}

// Properties.
var (
	defaultEmailProps = []string{"id", "blobId", "threadId", "mailboxIds", "keywords", "size", "receivedAt",
		"messageId", "inReplyTo", "references", "sender", "from", "to", "cc", "bcc", "replyTo", "subject", "sentAt",
		"hasAttachment", "preview", "bodyValues", "textBody", "htmlBody", "attachments"}
	allEmailProps    = append(slices.Clone(defaultEmailProps), "headers", "bodyStructure")
	defaultBodyProps = []string{"partId", "blobId", "size", "name", "type", "charset", "disposition", "cid", "language", "location"}
	allBodyProps     = append(slices.Clone(defaultBodyProps), "headers", "subParts")
	headerEmailProps = []string{"messageId", "inReplyTo", "references", "sender", "from", "to", "cc", "bcc", "replyTo", "subject", "sentAt", "headers"}
	structEmailProps = []string{"hasAttachment", "textBody", "htmlBody", "attachments", "bodyStructure"}
	sortOptions      = []string{"receivedAt", "size", "from", "to", "subject", "sentAt", "hasKeyword", "allInThreadHaveKeyword", "someInThreadHaveKeyword"}
)

func validEmailProp(p string) bool {
	return slices.Contains(allEmailProps, p) || strings.HasPrefix(p, "header:")
}

func validBodyProp(p string) bool {
	return slices.Contains(allBodyProps, p) || strings.HasPrefix(p, "header:")
}

// content is what Email/get read of one email.
type content struct {
	entry  *engine.HeaderEntry
	raw    []byte
	fields []field
	root   *part
}

// load reads what props need of the emails: header entries, and whole
// messages if wantRaw says so.
func load(a *engine.Account, infos []*emailInfo, needEntry bool, wantRaw func(*engine.HeaderEntry) bool) (map[string]*content, error) {
	out := map[string]*content{}
	if !needEntry {
		return out, nil
	}
	reps := make([]*engine.Message, len(infos))
	byMsg := map[*engine.Message]string{}
	for i, in := range infos {
		reps[i] = in.msgs[0]
		byMsg[in.msgs[0]] = in.id
		out[in.id] = &content{}
	}
	entries, rest, err := a.HeaderEntries(reps, nil)
	if err != nil {
		return nil, err
	}
	var raws []*engine.Message
	for m, e := range entries {
		out[byMsg[m]].entry = e
		if wantRaw(e) {
			raws = append(raws, m)
		}
	}
	raws = append(raws, rest...)
	if len(raws) > 0 {
		got, err := a.Download(raws, nil)
		if err != nil {
			return nil, err
		}
		for m, raw := range got {
			c := out[byMsg[m]]
			c.raw = raw
			if c.entry == nil {
				c.entry = engine.EntryOf(raw)
			}
		}
	}
	for id, c := range out {
		if c.entry == nil {
			delete(out, id) // gone at the provider meanwhile
			continue
		}
		c.fields = splitHeader(c.entry.Header)
		if c.raw != nil {
			c.root = partsOfRaw(c.raw)
		} else {
			c.root = partsOfStructure(c.entry.Structure)
		}
	}
	return out, nil
}

func emailGet(c *call) (any, error) {
	var args jmap.GetArgs
	if err := c.decode(&args); err != nil {
		return nil, err
	}
	props := args.Properties
	if props == nil {
		props = defaultEmailProps
	}
	bodyProps := args.BodyProperties
	if bodyProps == nil {
		bodyProps = defaultBodyProps
	}
	for _, p := range props {
		if !validEmailProp(p) {
			return nil, invalid("unknown property " + p)
		}
	}
	for _, p := range bodyProps {
		if !validBodyProp(p) {
			return nil, invalid("unknown body property " + p)
		}
	}
	a := c.c.acct
	a.Lock()
	state := a.State()
	ids := args.IDs
	if ids == nil {
		for _, id := range a.EmailIDs() {
			ids = append(ids, jmap.ID(id))
		}
	}
	if len(ids) > maxObjectsInGet {
		a.Unlock()
		return nil, &jmap.MethodError{Type: jmap.ErrRequestTooLarge}
	}
	var infos []*emailInfo
	var notFound []jmap.ID
	for _, id := range ids {
		if in := infoOf(a, string(c.resolve(id))); in != nil {
			infos = append(infos, in)
		} else {
			notFound = append(notFound, id)
		}
	}
	a.Unlock()

	needEntry := slices.ContainsFunc(props, func(p string) bool {
		return p == "size" || p == "preview" || p == "bodyValues" || strings.HasPrefix(p, "header:") ||
			slices.Contains(headerEmailProps, p) || slices.Contains(structEmailProps, p)
	})
	partHeaders := slices.ContainsFunc(bodyProps, func(p string) bool { return p == "headers" || strings.HasPrefix(p, "header:") })
	bodyParts := slices.ContainsFunc(props, func(p string) bool { return slices.Contains(structEmailProps, p) && p != "hasAttachment" })
	values := args.FetchTextBodyValues || args.FetchHTMLBodyValues || args.FetchAllBodyValues
	wantRaw := func(e *engine.HeaderEntry) bool {
		return values || (partHeaders && bodyParts) || (slices.Contains(props, "preview") && e.Preview == nil)
	}
	loaded, err := load(a, infos, needEntry, wantRaw)
	if err != nil {
		return nil, err
	}

	list := []any{}
	for _, in := range infos {
		ct := loaded[in.id]
		if needEntry && ct == nil {
			notFound = append(notFound, jmap.ID(in.id))
			continue
		}
		list = append(list, emailObject(in, ct, props, bodyProps, &args))
	}
	if notFound == nil {
		notFound = []jmap.ID{}
	}
	return jmap.GetResponse[any]{AccountID: c.c.id, State: jmap.State(state), List: list, NotFound: notFound}, nil
}

// emailObject builds the email with the properties asked for.
func emailObject(in *emailInfo, ct *content, props, bodyProps []string, args *jmap.GetArgs) map[string]any {
	id := jmap.ID(in.id)
	out := map[string]any{"id": id}
	var text, html, att []*part
	if ct != nil {
		text, html, att = bodies(ct.root)
	}
	header := func(name string, conv func(string) any) any {
		v := fieldsNamed(ct.fields, name)
		if len(v) == 0 {
			return nil
		}
		return conv(v[len(v)-1])
	}
	parts := func(ps []*part) []any {
		out := make([]any, len(ps))
		for i, p := range ps {
			out[i] = bodyPart(p, id, bodyProps)
		}
		return out
	}
	for _, p := range props {
		switch p {
		case "id":
		case "blobId":
			out[p] = emailBlob(in.id)
		case "threadId":
			out[p] = threadID(in.id)
		case "mailboxIds":
			out[p] = in.mailboxes
		case "keywords":
			out[p] = in.keywords
		case "receivedAt":
			out[p] = in.received.UTC().Format(time.RFC3339)
		case "size":
			out[p] = ct.entry.Size
		case "messageId", "inReplyTo", "references":
			name := map[string]string{"messageId": "Message-ID", "inReplyTo": "In-Reply-To", "references": "References"}[p]
			out[p] = header(name, func(r string) any { return asMessageIDs(r) })
		case "sender", "from", "to", "cc", "bcc", "replyTo":
			name := map[string]string{"sender": "Sender", "from": "From", "to": "To", "cc": "Cc", "bcc": "Bcc", "replyTo": "Reply-To"}[p]
			out[p] = header(name, func(r string) any { return asAddresses(r) })
		case "subject":
			out[p] = header("Subject", func(r string) any { return asText(r) })
		case "sentAt":
			out[p] = header("Date", func(r string) any {
				if t := asDate(r); t != nil {
					return t.Format(time.RFC3339)
				}
				return nil
			})
		case "headers":
			hs := make([]jmap.EmailHeader, len(ct.fields))
			for i, f := range ct.fields {
				hs[i] = jmap.EmailHeader{Name: f.name, Value: f.raw}
			}
			out[p] = hs
		case "hasAttachment":
			out[p] = len(att) > 0
		case "preview":
			switch {
			case ct.entry.Preview != nil:
				out[p] = *ct.entry.Preview
			case ct.raw != nil:
				out[p] = engine.Preview(ct.raw)
			default:
				out[p] = ""
			}
		case "bodyStructure":
			out[p] = bodyPart(ct.root, id, append(slices.Clone(bodyProps), "subParts"))
		case "textBody":
			out[p] = parts(text)
		case "htmlBody":
			out[p] = parts(html)
		case "attachments":
			out[p] = parts(att)
		case "bodyValues":
			vals := map[string]jmap.EmailBodyValue{}
			if ct.raw != nil {
				add := func(ps []*part) {
					for _, x := range ps {
						if strings.HasPrefix(x.typ, "text/") && x.partID != "" {
							vals[x.partID] = bodyValue(x, args.MaxBodyValueBytes)
						}
					}
				}
				if args.FetchTextBodyValues || args.FetchAllBodyValues {
					add(text)
				}
				if args.FetchHTMLBodyValues || args.FetchAllBodyValues {
					add(html)
				}
				if args.FetchAllBodyValues {
					add(att)
				}
			}
			out[p] = vals
		default:
			if v, ok := headerProperty(ct.fields, p); ok {
				out[p] = v
			}
		}
	}
	return out
}

func emailChanges(c *call) (any, error) { return changes(c, engine.KindEmail, nil) }

// --- Threads: one email each ----------------------------------------------

func threadGet(c *call) (any, error) {
	var args jmap.GetArgs
	if err := c.decode(&args); err != nil {
		return nil, err
	}
	a := c.c.acct
	a.Lock()
	defer a.Unlock()
	resp := jmap.GetResponse[jmap.Thread]{AccountID: c.c.id, State: jmap.State(a.State()), List: []jmap.Thread{}, NotFound: []jmap.ID{}}
	ids := args.IDs
	if ids == nil {
		for _, e := range a.EmailIDs() {
			ids = append(ids, jmap.ID(threadID(e)))
		}
	}
	for _, id := range ids {
		if len(id) > 1 && id[0] == 't' && a.Email("e"+string(id[1:])) != nil {
			resp.List = append(resp.List, jmap.Thread{ID: id, EmailIDs: []jmap.ID{jmap.ID("e" + string(id[1:]))}})
		} else {
			resp.NotFound = append(resp.NotFound, id)
		}
	}
	return resp, nil
}

func threadChanges(c *call) (any, error) {
	r, err := changes(c, engine.KindEmail, nil)
	if err != nil {
		return nil, err
	}
	resp := r.(jmap.ChangesResponse)
	for _, l := range []*[]jmap.ID{&resp.Created, &resp.Updated, &resp.Destroyed} {
		for i, id := range *l {
			(*l)[i] = jmap.ID(threadID(string(id)))
		}
	}
	return resp, nil
}

// --- Email/query -----------------------------------------------------------

// needs says what a filter needs beyond the engine's state.
func needs(f *jmap.EmailFilter) (entry, raw bool) {
	if f == nil {
		return false, false
	}
	for i := range f.Conditions {
		e, r := needs(&f.Conditions[i])
		entry, raw = entry || e, raw || r
	}
	if f.Text != "" || f.Body != "" {
		raw = true
	}
	if f.From != "" || f.To != "" || f.Cc != "" || f.Bcc != "" || f.Subject != "" || len(f.Header) > 0 ||
		f.MinSize > 0 || f.MaxSize > 0 || f.HasAttachment != nil {
		entry = true
	}
	return entry || raw, raw
}

// matchEmail evaluates a filter.
func matchEmail(f *jmap.EmailFilter, in *emailInfo, ct *content) bool {
	switch f.Operator {
	case "AND":
		for i := range f.Conditions {
			if !matchEmail(&f.Conditions[i], in, ct) {
				return false
			}
		}
		return true
	case "OR":
		for i := range f.Conditions {
			if matchEmail(&f.Conditions[i], in, ct) {
				return true
			}
		}
		return false
	case "NOT":
		for i := range f.Conditions {
			if matchEmail(&f.Conditions[i], in, ct) {
				return false
			}
		}
		return true
	}
	if f.InMailbox != "" && !in.mailboxes[f.InMailbox] {
		return false
	}
	if len(f.InMailboxOtherThan) > 0 {
		other := false
		for mb := range in.mailboxes {
			if !slices.Contains(f.InMailboxOtherThan, mb) {
				other = true
			}
		}
		if !other {
			return false
		}
	}
	if f.Before != nil && !in.received.Before(*f.Before) {
		return false
	}
	if f.After != nil && in.received.Before(*f.After) {
		return false
	}
	for _, k := range []string{f.HasKeyword, f.AllInThreadHaveKeyword, f.SomeInThreadHaveKeyword} {
		if k != "" && !in.keywords[strings.ToLower(k)] {
			return false
		}
	}
	for _, k := range []string{f.NotKeyword, f.NoneInThreadHaveKeyword} {
		if k != "" && in.keywords[strings.ToLower(k)] {
			return false
		}
	}
	if ct == nil {
		return true
	}
	if f.MinSize > 0 && ct.entry.Size < f.MinSize || f.MaxSize > 0 && ct.entry.Size >= f.MaxSize {
		return false
	}
	if f.HasAttachment != nil {
		_, _, att := bodies(ct.root)
		if (len(att) > 0) != *f.HasAttachment {
			return false
		}
	}
	// Text conditions are IMAP SEARCH criteria, on the message as clients
	// see it.
	crit := &imap.SearchCriteria{}
	for _, h := range []struct{ key, value string }{{"From", f.From}, {"To", f.To}, {"Cc", f.Cc}, {"Bcc", f.Bcc}, {"Subject", f.Subject}} {
		if h.value != "" {
			crit.Header = append(crit.Header, imap.SearchCriteriaHeaderField{Key: h.key, Value: h.value})
		}
	}
	if len(f.Header) > 0 {
		hf := imap.SearchCriteriaHeaderField{Key: f.Header[0]}
		if len(f.Header) > 1 {
			hf.Value = f.Header[1]
		}
		crit.Header = append(crit.Header, hf)
	}
	if f.Text != "" {
		crit.Text = []string{f.Text}
	}
	if f.Body != "" {
		crit.Body = []string{f.Body}
	}
	if len(crit.Header)+len(crit.Text)+len(crit.Body) == 0 {
		return true
	}
	src := ct.raw
	if src == nil {
		src = ct.entry.Header
	}
	return engine.Match(engine.MatchMessage{}, src, crit)
}

func emailQuery(c *call) (any, error) {
	var args jmap.QueryArgs
	if err := c.decode(&args); err != nil {
		return nil, err
	}
	var filter *jmap.EmailFilter
	if len(args.Filter) > 0 && string(args.Filter) != "null" {
		filter = &jmap.EmailFilter{}
		if err := json.Unmarshal(args.Filter, filter); err != nil {
			return nil, invalid(err.Error())
		}
	}
	for _, s := range args.Sort {
		if !slices.Contains(sortOptions, s.Property) {
			return nil, &jmap.MethodError{Type: jmap.ErrUnsupportedSort, Description: s.Property}
		}
	}
	a := c.c.acct
	a.Lock()
	state := a.State()
	var infos []*emailInfo
	for _, id := range a.EmailIDs() {
		infos = append(infos, infoOf(a, id))
	}
	a.Unlock()

	needEntry, needRaw := needs(filter)
	sortEntry := slices.ContainsFunc(args.Sort, func(s jmap.Comparator) bool {
		return s.Property != "receivedAt" && !strings.HasSuffix(s.Property, "Keyword")
	})
	// The state-only conditions first, so the rest reads fewer messages.
	if filter != nil {
		infos = slices.DeleteFunc(infos, func(in *emailInfo) bool { return !matchEmail(filter, in, nil) })
	}
	loaded := map[string]*content{}
	if needEntry || sortEntry {
		var err error
		if loaded, err = load(a, infos, true, func(*engine.HeaderEntry) bool { return needRaw }); err != nil {
			return nil, err
		}
		infos = slices.DeleteFunc(infos, func(in *emailInfo) bool { return loaded[in.id] == nil })
	}
	if filter != nil && needEntry {
		infos = slices.DeleteFunc(infos, func(in *emailInfo) bool { return !matchEmail(filter, in, loaded[in.id]) })
	}

	sortKey := func(in *emailInfo, prop string) string {
		ct := loaded[in.id]
		if ct == nil {
			return ""
		}
		first := func(name string) string {
			v := fieldsNamed(ct.fields, name)
			if len(v) == 0 {
				return ""
			}
			return v[len(v)-1]
		}
		switch prop {
		case "from", "to":
			name := map[string]string{"from": "From", "to": "To"}[prop]
			if l := asAddresses(first(name)); len(l) > 0 {
				if l[0].Name != nil {
					return strings.ToLower(*l[0].Name)
				}
				return strings.ToLower(l[0].Email)
			}
			return ""
		case "subject":
			return strings.ToLower(baseSubject(asText(first("Subject"))))
		case "sentAt":
			if t := asDate(first("Date")); t != nil {
				return t.UTC().Format(time.RFC3339)
			}
		}
		return ""
	}
	slices.SortStableFunc(infos, func(x, y *emailInfo) int {
		sorts := args.Sort
		if len(sorts) == 0 {
			f := false
			sorts = []jmap.Comparator{{Property: "receivedAt", IsAscending: &f}}
		}
		for _, s := range sorts {
			var d int
			switch s.Property {
			case "receivedAt":
				d = x.received.Compare(y.received)
			case "size":
				d = cmp.Compare(loaded[x.id].entry.Size, loaded[y.id].entry.Size)
			case "hasKeyword", "allInThreadHaveKeyword", "someInThreadHaveKeyword":
				k := strings.ToLower(s.Keyword)
				d = cmp.Compare(boolInt(x.keywords[k]), boolInt(y.keywords[k]))
			default:
				d = cmp.Compare(sortKey(x, s.Property), sortKey(y, s.Property))
			}
			if !s.Ascending() {
				d = -d
			}
			if d != 0 {
				return d
			}
		}
		return cmp.Compare(x.id, y.id)
	})
	ids := make([]jmap.ID, len(infos))
	for i, in := range infos {
		ids[i] = jmap.ID(in.id)
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
	if args.Limit != nil {
		l := len(ids)
		if l < *args.Limit {
			l = *args.Limit
		}
		resp.Limit = &l
	}
	return resp, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// baseSubject strips reply and forward prefixes, for sorting.
func baseSubject(s string) string {
	for {
		t := strings.TrimSpace(s)
		lower := strings.ToLower(t)
		cut := false
		for _, p := range []string{"re:", "fw:", "fwd:", "aw:", "wg:", "sv:"} {
			if strings.HasPrefix(lower, p) {
				t, cut = t[len(p):], true
				break
			}
		}
		if !cut {
			return t
		}
		s = t
	}
}

// --- SearchSnippet/get: no highlighting ------------------------------------

func snippetGet(c *call) (any, error) {
	var args struct {
		AccountID jmap.ID   `json:"accountId"`
		EmailIDs  []jmap.ID `json:"emailIds"`
	}
	if err := c.decode(&args); err != nil {
		return nil, err
	}
	a := c.c.acct
	a.Lock()
	defer a.Unlock()
	list := []jmap.SearchSnippet{}
	notFound := []jmap.ID{}
	for _, id := range args.EmailIDs {
		if a.Email(string(id)) != nil {
			list = append(list, jmap.SearchSnippet{EmailID: id})
		} else {
			notFound = append(notFound, id)
		}
	}
	return map[string]any{"accountId": c.c.id, "list": list, "notFound": notFound}, nil
}
