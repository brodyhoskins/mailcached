package imapproxy

// OBJECTID (RFC 8474) toward mail clients: stable IDs for folders
// (MAILBOXID) and messages (EMAILID, THREADID). They are the engine's JMAP
// IDs, so an IMAP client and a JMAP client of one account see the same
// ones. go-imap's server knows none of it, so the connection wrapper
// (compress.go) does it on the wire:
//
//   - In commands, EMAILID and THREADID leave a FETCH's items (UID takes
//     their place, so every response names its message), MAILBOXID leaves
//     a STATUS's, and SEARCH EMAILID and THREADID become UID sets.
//   - In responses, the IDs go into the FETCH and STATUS responses of
//     those commands, MAILBOXID into the end of a SELECT or EXAMINE (an
//     untagged OK) and into the OK of a CREATE.
//
// Like COMPRESS, it needs the protocol in the clear: it is offered with
// implicit TLS (or none), not with STARTTLS.

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/engine"
)

// objectIDs is what the wrapper asks the session.
type objectIDs interface {
	// emailIDs returns the EMAILID and THREADID of the message with UID
	// uid in the selected folder.
	emailIDs(uid imap.UID) (email, thread string, ok bool)
	// mailboxID returns the MAILBOXID of a folder.
	mailboxID(name string) (string, bool)
	// uidsOf returns the UIDs in the selected folder of the messages with
	// EMAILID (or, with thread, THREADID) id.
	uidsOf(id string, thread bool) []imap.UID
	// CONDSTORE (condstore.go).
	condStore
}

// objectState is a connection's OBJECTID work in progress.
type objectState struct {
	mu   sync.Mutex
	ids  objectIDs // the session, once it exists
	tags map[string]*objectCmd
	// fetch is the FETCH that asked for IDs and has not completed.
	fetch *objectCmd
	// status is the STATUS that asked for MAILBOXID.
	status *objectCmd
	// condstore is set once the client enabled CONDSTORE (RFC 7162
	// section 3.1): every FETCH with FLAGS then carries MODSEQ.
	condstore bool
}

// objectCmd is a command the wrapper changed.
type objectCmd struct {
	kind          string // "fetch", "status", "select", "create", "enable", "search", "store"
	email, thread bool   // fetch: the items asked for
	name          string // create: the folder
	// CONDSTORE: fetch: MODSEQ asked for, CHANGEDSINCE; status:
	// MAILBOXID, HIGHESTMODSEQ asked for; search: MODSEQ searched, by UID;
	// store: the MODIFIED set.
	modseq       bool
	changedSince uint64
	mailboxID    bool
	highest      bool
	uid          bool
	modified     string
}

func (o *objectState) session() objectIDs {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.ids
}

func (o *objectState) setSession(ids objectIDs) {
	o.mu.Lock()
	o.ids = ids
	o.mu.Unlock()
}

var (
	objCmdRe    = regexp.MustCompile(`(?i)^(\S+) (?:(UID) )?(FETCH|STATUS|SELECT|EXAMINE|CREATE|SEARCH|ENABLE|STORE)\b`)
	objFetchRe  = regexp.MustCompile(`(?i)\b(EMAILID|THREADID|MODSEQ)\b`)
	objStatusRe = regexp.MustCompile(`(?i)\b(MAILBOXID|HIGHESTMODSEQ)\b`)
	objSearchRe = regexp.MustCompile(`(?i)\b(EMAILID|THREADID) ([A-Za-z0-9_-]{1,255})\b`)
)

// command changes a command line, and notes what its responses need. A
// line that announces a literal is left alone: the folder names and
// search strings that need one are not worth the trouble.
func (o *objectState) command(line []byte) []byte {
	m := objCmdRe.FindSubmatch(line)
	if m == nil || literalSize(line) > 0 {
		return line
	}
	tag, cmd := string(m[1]), strings.ToUpper(string(m[3]))
	rest := line[len(m[0]):]
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.tags == nil {
		o.tags = map[string]*objectCmd{}
	}
	switch cmd {
	case "FETCH":
		c := &objectCmd{kind: "fetch"}
		if m := changedSinceRe.FindSubmatchIndex(rest); m != nil {
			c.changedSince, _ = strconv.ParseUint(string(rest[m[2]:m[3]]), 10, 64)
			c.modseq = true
			o.condstore = true
			rest = append(rest[:m[0]:m[0]], rest[m[1]:]...)
		}
		items := outsideQuotes(rest, objFetchRe)
		for i := len(items) - 1; i >= 0; i-- {
			loc := items[i]
			switch strings.ToUpper(string(rest[loc[0]:loc[1]])) {
			case "EMAILID":
				c.email = true
			case "THREADID":
				c.thread = true
			case "MODSEQ":
				c.modseq = true
				o.condstore = true
			}
			// UID in its place: every response then names its message.
			rest = append(rest[:loc[0]:loc[0]], append([]byte("UID"), rest[loc[1]:]...)...)
		}
		if !c.email && !c.thread && !c.modseq {
			return line
		}
		o.tags[tag] = c
		return append(append([]byte{}, line[:len(m[0])]...), rest...)
	case "STATUS":
		items := outsideQuotes(rest, objStatusRe)
		if len(items) == 0 {
			return line
		}
		c := &objectCmd{kind: "status"}
		for i := len(items) - 1; i >= 0; i-- {
			loc := items[i]
			if strings.EqualFold(string(rest[loc[0]:loc[1]]), "HIGHESTMODSEQ") {
				c.highest = true
				o.condstore = true
			} else {
				c.mailboxID = true
			}
			// MESSAGES in its place: a STATUS needs an item, and an
			// extra one does no harm.
			rest = append(rest[:loc[0]:loc[0]], append([]byte("MESSAGES"), rest[loc[1]:]...)...)
		}
		o.tags[tag] = c
		return append(append([]byte{}, line[:len(m[0])]...), rest...)
	case "SELECT", "EXAMINE":
		o.tags[tag] = &objectCmd{kind: "select"}
		if loc := selectCondStoreRe.FindIndex(rest); loc != nil {
			o.condstore = true
			return append(append(append([]byte{}, line[:len(m[0])]...), rest[:loc[0]]...), "\r\n"...)
		}
	case "ENABLE":
		if bytes.Contains(bytes.ToUpper(rest), []byte("CONDSTORE")) {
			o.tags[tag] = &objectCmd{kind: "enable"}
		}
	case "STORE":
		return o.store(tag, m[2] != nil, line[:len(m[0])], rest)
	case "CREATE":
		o.tags[tag] = &objectCmd{kind: "create", name: firstArg(rest)}
	case "SEARCH":
		ids := o.ids
		if ids == nil {
			return line
		}
		if ms := outsideQuotes(rest, searchModSeqRe); len(ms) > 0 {
			o.condstore = true
			o.tags[tag] = &objectCmd{kind: "search", uid: m[2] != nil}
			for i := len(ms) - 1; i >= 0; i-- {
				loc := ms[i]
				sm := searchModSeqRe.FindSubmatch(rest[loc[0]:loc[1]])
				n, _ := strconv.ParseUint(string(sm[1]), 10, 64)
				uids := ids.modSeqAtLeast(n)
				set := "4294967295"
				if len(uids) > 0 {
					set = imap.UIDSetNum(uids...).String()
				}
				rest = append(rest[:loc[0]:loc[0]], append([]byte("UID "+set), rest[loc[1]:]...)...)
			}
		}
		found := outsideQuotes(rest, objSearchRe)
		for i := len(found) - 1; i >= 0; i-- {
			loc := found[i]
			sm := objSearchRe.FindSubmatch(rest[loc[0]:loc[1]])
			uids := ids.uidsOf(string(sm[2]), strings.EqualFold(string(sm[1]), "THREADID"))
			set := "4294967295" // no message: a UID no folder reaches
			if len(uids) > 0 {
				set = imap.UIDSetNum(uids...).String()
			}
			rest = append(rest[:loc[0]:loc[0]], append([]byte("UID "+set), rest[loc[1]:]...)...)
		}
		return append(append([]byte{}, line[:len(m[0])]...), rest...)
	}
	return line
}

// outsideQuotes returns the matches of re in line that are not inside a
// quoted string.
func outsideQuotes(line []byte, re *regexp.Regexp) [][]int {
	var out [][]int
	for _, loc := range re.FindAllIndex(line, -1) {
		if !quotedAt(line, loc[0]) {
			out = append(out, loc)
		}
	}
	return out
}

// quotedAt reports whether position i of line is inside a quoted string.
func quotedAt(line []byte, i int) bool {
	in := false
	for j := 0; j < i; j++ {
		switch {
		case line[j] == '\\' && in:
			j++
		case line[j] == '"':
			in = !in
		}
	}
	return in
}

// firstArg returns the first argument of a command: an atom or a quoted
// string.
func firstArg(rest []byte) string {
	s := strings.TrimRight(strings.TrimLeft(string(rest), " "), "\r\n")
	if strings.HasPrefix(s, `"`) {
		var b strings.Builder
		for i := 1; i < len(s); i++ {
			switch s[i] {
			case '\\':
				if i+1 < len(s) {
					i++
					b.WriteByte(s[i])
				}
			case '"':
				return b.String()
			default:
				b.WriteByte(s[i])
			}
		}
		return b.String()
	}
	if i := strings.IndexByte(s, ' '); i >= 0 {
		return s[:i]
	}
	return s
}

var (
	fetchRespRe  = regexp.MustCompile(`^\* (\d+) FETCH \(`)
	fetchFlagsRe = regexp.MustCompile(`\bFLAGS \(`)
	enabledRe    = regexp.MustCompile(`(?i)^\* ENABLED\b`)
	searchRespRe = regexp.MustCompile(`(?i)^\* SEARCH\b`)
	fetchUIDRe   = regexp.MustCompile(`\bUID (\d+)`)
	statusRespRe = regexp.MustCompile(`^\* STATUS (.*) \(`)
	taggedRe     = regexp.MustCompile(`^(\S+) (OK|NO|BAD) ?`)
)

// response changes a response line, before it reaches the client.
func (o *objectState) response(line []byte) []byte {
	if m := capListRe.FindIndex(line); m != nil && !bytes.Contains(line, []byte("OBJECTID")) && o.session() != nil {
		// go-imap lists only what it does itself.
		return append(append(append([]byte{}, line[:m[1]]...), "OBJECTID "+capNotify+" "+capCondStore+" "...), line[m[1]:]...)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.tags) == 0 && o.fetch == nil && !o.condstore {
		return line
	}
	ids := o.ids
	switch {
	case fetchRespRe.Match(line):
		if ids == nil {
			return line
		}
		c := o.fetchCmd()
		head := line
		if n := bytes.LastIndexByte(head, '{'); n >= 0 && literalSize(line) > 0 {
			head = head[:n]
		}
		var add string
		if c != nil && (c.email || c.thread) {
			if um := fetchUIDRe.FindSubmatch(head); um != nil {
				uid, _ := strconv.ParseUint(string(um[1]), 10, 32)
				if email, thread, ok := ids.emailIDs(imap.UID(uid)); ok {
					if c.email {
						add += "EMAILID (" + email + ") "
					}
					if c.thread {
						add += "THREADID (" + thread + ") "
					}
				}
			}
		}
		// MODSEQ: asked for, or with FLAGS once CONDSTORE is on.
		if (c != nil && c.modseq || o.condstore && fetchFlagsRe.Match(head)) && !bytes.Contains(head, []byte("MODSEQ (")) {
			sm := fetchRespRe.FindSubmatch(line)
			seq, _ := strconv.ParseUint(string(sm[1]), 10, 32)
			if ms, ok := ids.modSeqAt(uint32(seq)); ok {
				if c != nil && c.changedSince > 0 && ms <= c.changedSince && literalSize(line) == 0 {
					return nil // not changed since: left out
				}
				add += "MODSEQ (" + strconv.FormatUint(ms, 10) + ") "
			}
		}
		if add == "" {
			return line
		}
		at := fetchRespRe.FindIndex(line)[1]
		return append(append(append([]byte{}, line[:at]...), add...), line[at:]...)
	case enabledRe.Match(line):
		if !o.hasKind("enable") {
			return line
		}
		o.condstore = true
		return append(bytes.TrimRight(line, "\r\n"), " CONDSTORE\r\n"...)
	case searchRespRe.Match(line):
		c := o.kindCmd("search")
		if c == nil || ids == nil {
			return line
		}
		var nums []uint32
		for _, f := range strings.Fields(strings.TrimSpace(string(line[len("* SEARCH"):]))) {
			if n, err := strconv.ParseUint(f, 10, 32); err == nil {
				nums = append(nums, uint32(n))
			}
		}
		if ms := ids.maxModSeq(nums, c.uid); ms > 0 {
			return append(bytes.TrimRight(line, "\r\n"), " (MODSEQ "+strconv.FormatUint(ms, 10)+")\r\n"...)
		}
		return line
	case statusRespRe.Match(line):
		c := o.kindCmd("status")
		if c == nil || ids == nil {
			return line
		}
		sm := statusRespRe.FindSubmatchIndex(line)
		name := firstArg(line[sm[2]:sm[3]])
		var add string
		if id, ok := ids.mailboxID(name); ok && c.mailboxID {
			add += "MAILBOXID (" + id + ") "
		}
		if h, ok := ids.highestModSeq(name); ok && c.highest {
			add += "HIGHESTMODSEQ " + strconv.FormatUint(h, 10) + " "
		}
		at := sm[1]
		return append(append(append([]byte{}, line[:at]...), add...), line[at:]...)
	}
	tm := taggedRe.FindSubmatch(line)
	if tm == nil {
		return line
	}
	tag := string(tm[1])
	c := o.tags[tag]
	if c == nil {
		return line
	}
	delete(o.tags, tag)
	if o.fetch == c {
		o.fetch = nil
	}
	if !strings.EqualFold(string(tm[2]), "OK") || ids == nil {
		return line
	}
	switch c.kind {
	case "select":
		// The folder now selected.
		var pre []byte
		if id, ok := ids.mailboxID(""); ok {
			pre = append(pre, "* OK [MAILBOXID ("+id+")] Ok\r\n"...)
		}
		if h, ok := ids.highestModSeq(""); ok && o.condstore {
			pre = append(pre, "* OK [HIGHESTMODSEQ "+strconv.FormatUint(h, 10)+"] Highest\r\n"...)
		}
		return append(pre, line...)
	case "store":
		if c.modified != "" {
			at := len(tm[0])
			return append(append(append([]byte{}, line[:at]...), "[MODIFIED "+c.modified+"] "...), line[at:]...)
		}
	case "create":
		if id, ok := ids.mailboxID(c.name); ok && !bytes.Contains(line, []byte("[")) {
			at := len(tm[0])
			return append(append(append([]byte{}, line[:at]...), "[MAILBOXID ("+id+")] "...), line[at:]...)
		}
	}
	return line
}

// fetchCmd returns the FETCH in progress that asked for IDs (o.mu held).
// Commands run one at a time, so it is the only one.
func (o *objectState) fetchCmd() *objectCmd {
	if o.fetch == nil {
		for _, c := range o.tags {
			if c.kind == "fetch" {
				o.fetch = c
			}
		}
	}
	return o.fetch
}

func (o *objectState) hasKind(kind string) bool { return o.kindCmd(kind) != nil }

// kindCmd returns a command of kind in progress (o.mu held).
func (o *objectState) kindCmd(kind string) *objectCmd {
	for _, c := range o.tags {
		if c.kind == kind {
			return c
		}
	}
	return nil
}

// --- The session's side ----------------------------------------------------

func (s *Session) emailIDs(uid imap.UID) (string, string, bool) {
	a, m := s.acct, s.mbox
	if a == nil || m == nil {
		return "", "", false
	}
	a.Lock()
	defer a.Unlock()
	i, ok := m.Index(uid)
	if !ok {
		return "", "", false
	}
	id := engine.EmailID(m.Msgs()[i].Key())
	return id, "t" + id[1:], true
}

// mailboxID returns a folder's MAILBOXID; "" names the selected folder.
func (s *Session) mailboxID(name string) (string, bool) {
	a := s.acct
	if a == nil {
		return "", false
	}
	a.Lock()
	defer a.Unlock()
	m := s.mbox
	if name != "" {
		m = a.Mailbox(name)
	}
	if m == nil {
		return "", false
	}
	return m.ID(), true
}

func (s *Session) uidsOf(id string, thread bool) []imap.UID {
	a, m := s.acct, s.mbox
	if a == nil || m == nil {
		return nil
	}
	if thread && strings.HasPrefix(id, "t") {
		id = "e" + id[1:] // one email a thread
	}
	a.Lock()
	defer a.Unlock()
	var out []imap.UID
	for _, msg := range m.Msgs() {
		if engine.EmailID(msg.Key()) == id {
			out = append(out, msg.UID())
		}
	}
	return out
}
