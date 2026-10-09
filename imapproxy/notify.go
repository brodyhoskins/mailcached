package imapproxy

// NOTIFY (RFC 5465) toward mail clients: changes to folders other than
// the selected one, and changes to the folder list, as they happen, and
// changes to the selected folder between commands. go-imap's server knows
// none of it, so the connection wrapper (compress.go) does it, as it does
// OBJECTID:
//
//   - It answers NOTIFY itself. A NOTIFY SET then reaches go-imap as a
//     NOOP with the same tag, which returns what changed in the selected
//     folder, as the RFC asks, and gives the tagged OK.
//   - For other folders it watches the account and sends STATUS
//     responses, and LIST responses for created, deleted, renamed and
//     (un)subscribed folders, between responses of go-imap's.
//   - For the selected folder (SELECTED) it slips a NOOP of its own in
//     between the client's commands, whose responses are go-imap's usual
//     EXISTS, EXPUNGE and FETCH, and whose tagged OK it drops. MessageNew
//     with fetch attributes adds a UID FETCH of the new messages the same
//     way. With SELECTED-DELAYED only that FETCH is slipped in, and the
//     rest waits for the client's next command, as without NOTIFY.
//
// FlagChange in other folders is a STATUS with HIGHESTMODSEQ once the
// client enabled CONDSTORE (condstore.go); before that, a STATUS with
// UNSEEN when the number of unseen messages changes. The events the
// client caused itself are reported too (the RFC says it SHOULD NOT), as
// the proxy cannot tell them apart.

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/engine"
)

// capNotify is the capability.
const capNotify = "NOTIFY"

// injectTag starts the tags of the commands the wrapper slips in. Tags
// cannot hold "+", so no client tag starts this way.
const injectTag = "+mcn"

var notifyCmdRe = regexp.MustCompile(`(?i)^(\S+) NOTIFY( |\r?\n)`)

// notifyDebounce gathers a burst of changes into one round of
// notifications.
var notifyDebounce = 50 * time.Millisecond

// boxSnap is what a client was last told about a folder.
type boxSnap struct {
	name             string
	delim            rune
	attrs            []imap.MailboxAttr
	subscribed       bool
	selectable       bool
	messages, unseen int
	uidNext          imap.UID
	uidValidity      uint32
	highestModSeq    uint64
}

// notifier is a connection's NOTIFY state.
type notifier struct {
	c *compressConn

	mu      sync.Mutex
	spec    *notifySpec
	stop    chan struct{} // closed to end the watch
	boxes   map[string]boxSnap
	selID   string   // the selected folder at the last round
	selNext imap.UID // its UIDNEXT then, for MessageNew's FETCH
}

// handleNotify answers a NOTIFY command. It returns the line to hand to
// go-imap: a NOOP with the command's tag, or nil when the wrapper
// answered the command itself.
func (c *compressConn) handleNotify(tag, args string) ([]byte, error) {
	s, _ := c.obj.session().(*Session)
	var acct *engine.Account
	if s != nil {
		acct, _ = s.current()
	}
	if acct == nil {
		return nil, c.reply(tag + " BAD Log in before NOTIFY")
	}
	spec, err := parseNotify(strings.TrimRight(args, "\r\n"))
	var ne *notifyError
	if errors.As(err, &ne) {
		return nil, c.reply(tag + " " + ne.status + " " + ne.text)
	}
	if err := c.ntf.set(spec, s, acct); err != nil {
		return nil, err
	}
	return []byte(tag + " NOOP\r\n"), nil
}

// reply writes a response line of the wrapper's own.
func (c *compressConn) reply(line string) error {
	return c.writeUnsolicited([]string{line})
}

// writeUnsolicited writes response lines of the wrapper's own, between
// two of go-imap's responses: never inside one, nor inside a literal.
func (c *compressConn) writeUnsolicited(lines []string) error {
	if len(lines) == 0 {
		return nil
	}
	for {
		c.wmu.Lock()
		if c.closed {
			c.wmu.Unlock()
			return errors.New("connection closed")
		}
		clean := len(c.ow.line) == 0 && c.ow.literal == 0 &&
			(c.inject == nil || len(c.inject.line) == 0 && c.inject.literal == 0)
		if clean {
			var b bytes.Buffer
			for _, l := range lines {
				b.WriteString(l)
				b.WriteString("\r\n")
			}
			_, err := c.out.Write(b.Bytes())
			c.wmu.Unlock()
			return err
		}
		c.wmu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
}

// injectCommand queues a command to slip in between the client's. A
// command that does not fit is dropped: the next round sends another.
func (c *compressConn) injectCommand(cmd string) {
	line := fmt.Sprintf("%s%d %s\r\n", injectTag, c.injN.Add(1), cmd)
	select {
	case c.injQ <- c.obj.command([]byte(line)):
	default:
	}
}

// condstore reports whether the client enabled CONDSTORE.
func (c *compressConn) condstore() bool {
	c.obj.mu.Lock()
	defer c.obj.mu.Unlock()
	return c.obj.condstore
}

// injected reports whether a response line ends a command the wrapper
// slipped in.
func injected(line []byte) bool { return bytes.HasPrefix(line, []byte(injectTag)) }

// set replaces the connection's NOTIFY; nil is NOTIFY NONE. With the
// STATUS indicator it writes the STATUS of every folder it watches for
// messages, before the tagged OK.
func (n *notifier) set(spec *notifySpec, s *Session, a *engine.Account) error {
	n.mu.Lock()
	if n.stop != nil {
		close(n.stop)
		n.stop = nil
	}
	n.spec = spec
	if spec == nil {
		n.mu.Unlock()
		return nil
	}
	for i := range spec.groups {
		for j, name := range spec.groups[i].names {
			spec.groups[i].names[j] = engine.CanonicalName(name)
		}
	}
	a.Lock()
	n.boxes = snapshot(a)
	wake := a.Changed()
	_, sel := s.current()
	n.selID, n.selNext = "", 0
	if sel != nil {
		n.selID, n.selNext = sel.ID(), sel.UIDNext()
	}
	a.Unlock()
	var lines []string
	if spec.status {
		for id, b := range n.boxes {
			ev := spec.eventsFor(b)
			if id == n.selID || !b.selectable || !ev.messages && !ev.flags {
				continue
			}
			lines = append(lines, statusLine(b, ev, true, n.c.condstore()))
		}
		slices.Sort(lines)
	}
	stop := make(chan struct{})
	n.stop = stop
	n.mu.Unlock()
	go n.watch(s, a, wake, stop)
	return n.c.writeUnsolicited(lines)
}

// close ends the watch, with the connection.
func (n *notifier) close() {
	n.mu.Lock()
	if n.stop != nil {
		close(n.stop)
		n.stop = nil
	}
	n.mu.Unlock()
}

func (n *notifier) watch(s *Session, a *engine.Account, wake <-chan struct{}, stop chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case <-wake:
		}
		// Changes come in bursts: one round for the burst.
		select {
		case <-stop:
			return
		case <-time.After(notifyDebounce):
		}
		a.Lock()
		wake = a.Changed()
		a.Unlock()
		if err := n.round(s, a, stop); err != nil {
			return
		}
	}
}

// round tells the client what changed since the last round.
func (n *notifier) round(s *Session, a *engine.Account, stop chan struct{}) error {
	n.mu.Lock()
	if n.stop != stop {
		n.mu.Unlock()
		return nil
	}
	spec := n.spec
	a.Lock()
	cur := snapshot(a)
	_, sel := s.current()
	var fetch []imap.UID
	selID := ""
	if sel != nil {
		selID = sel.ID()
		if selID == n.selID && spec.sel.fetch != "" {
			for _, msg := range sel.Msgs() {
				if msg.UID() >= n.selNext {
					fetch = append(fetch, msg.UID())
				}
			}
		}
		n.selNext = sel.UIDNext()
	}
	a.Unlock()
	lines := spec.diff(n.boxes, cur, selID, n.c.condstore())
	n.boxes = cur
	selChanged := selID != n.selID
	n.selID = selID
	n.mu.Unlock()

	if err := n.c.writeUnsolicited(lines); err != nil {
		return err
	}
	if sel == nil || selChanged {
		return nil
	}
	if spec.selected == "selected" {
		n.c.injectCommand("NOOP")
	}
	if len(fetch) > 0 {
		n.c.injectCommand("UID FETCH " + imap.UIDSetNum(fetch...).String() + " " + spec.sel.fetch)
	}
	return nil
}

// snapshot takes every folder's state (a.mu held).
func snapshot(a *engine.Account) map[string]boxSnap {
	out := map[string]boxSnap{}
	for _, m := range a.Mailboxes() {
		b := boxSnap{name: m.Name(), delim: m.Delim(), attrs: slices.Clone(m.Attrs()), subscribed: m.Subscribed(),
			selectable: m.Selectable(), uidNext: m.UIDNext(), uidValidity: m.UIDValidity(), highestModSeq: a.HighestModSeq(m)}
		msgs := m.Msgs()
		b.messages = len(msgs)
		for _, msg := range msgs {
			if !engine.HasFlag(msg.Flags(), imap.FlagSeen) {
				b.unseen++
			}
		}
		out[m.ID()] = b
	}
	return out
}

// eventsFor returns the events the client asked for about a folder other
// than the selected one.
func (spec *notifySpec) eventsFor(b boxSnap) events {
	var ev events
	for _, g := range spec.groups {
		if !g.matches(b) {
			continue
		}
		ev.messages = ev.messages || g.ev.messages
		ev.flags = ev.flags || g.ev.flags
		ev.names = ev.names || g.ev.names
		ev.subscriptions = ev.subscriptions || g.ev.subscriptions
	}
	return ev
}

func (g *notifyGroup) matches(b boxSnap) bool {
	switch g.filter {
	case "personal":
		return true
	case "inboxes":
		return b.name == "INBOX"
	case "subscribed":
		return b.subscribed
	case "mailboxes":
		return slices.Contains(g.names, b.name)
	case "subtree":
		for _, n := range g.names {
			if b.name == n || b.delim != 0 && strings.HasPrefix(b.name, n+string(b.delim)) {
				return true
			}
		}
	}
	return false
}

// diff returns the responses that tell a client what changed from old to
// cur. selID is the selected folder, whose message events are not sent
// as STATUS.
func (spec *notifySpec) diff(old, cur map[string]boxSnap, selID string, condstore bool) []string {
	var lines []string
	type rename struct{ old, new string }
	renames := map[string]rename{}
	for id, b := range cur {
		if o, ok := old[id]; ok && o.name != b.name {
			renames[id] = rename{o.name, b.name}
		}
	}
	// A folder renamed with its parent: the parent's LIST says it.
	underRenamed := func(id string) bool {
		r := renames[id]
		for pid, p := range renames {
			if pid == id {
				continue
			}
			d := string(cur[pid].delim)
			if strings.HasPrefix(r.old, p.old+d) && r.new == p.new+strings.TrimPrefix(r.old, p.old) {
				return true
			}
		}
		return false
	}
	for id, b := range cur {
		o, existed := old[id]
		ev := spec.eventsFor(b)
		switch {
		case !existed:
			if ev.names {
				lines = append(lines, listLine(b, ""))
			}
			continue
		case o.name != b.name:
			if (ev.names || spec.eventsFor(o).names) && !underRenamed(id) {
				lines = append(lines, listLine(b, o.name))
			}
		case o.subscribed != b.subscribed:
			if ev.subscriptions || spec.eventsFor(o).subscriptions {
				lines = append(lines, listLine(b, ""))
			}
		}
		if id == selID || !b.selectable {
			continue
		}
		switch {
		case ev.messages && (o.messages != b.messages || o.uidNext != b.uidNext || o.uidValidity != b.uidValidity):
			lines = append(lines, statusLine(b, ev, o.uidValidity != b.uidValidity, condstore))
		case ev.flags && condstore && (o.highestModSeq != b.highestModSeq || o.uidValidity != b.uidValidity):
			lines = append(lines, "* STATUS "+quoteMailbox(b.name)+" (UIDVALIDITY "+strconv.FormatUint(uint64(b.uidValidity), 10)+
				" HIGHESTMODSEQ "+strconv.FormatUint(b.highestModSeq, 10)+")")
		case ev.flags && o.uidValidity != b.uidValidity:
			lines = append(lines, "* STATUS "+quoteMailbox(b.name)+" (UIDVALIDITY "+strconv.FormatUint(uint64(b.uidValidity), 10)+
				" UNSEEN "+strconv.Itoa(b.unseen)+")")
		case ev.flags && o.unseen != b.unseen:
			lines = append(lines, "* STATUS "+quoteMailbox(b.name)+" (UNSEEN "+strconv.Itoa(b.unseen)+")")
		}
	}
	for id, o := range old {
		if _, ok := cur[id]; !ok && spec.eventsFor(o).names {
			o.attrs, o.subscribed = []imap.MailboxAttr{imap.MailboxAttrNonExistent}, false
			lines = append(lines, listLine(o, ""))
		}
	}
	slices.Sort(lines)
	return lines
}

// statusLine is a folder's STATUS for message events.
func statusLine(b boxSnap, ev events, validity, condstore bool) string {
	s := "* STATUS " + quoteMailbox(b.name) + " (MESSAGES " + strconv.Itoa(b.messages) +
		" UIDNEXT " + strconv.FormatUint(uint64(b.uidNext), 10)
	if validity || ev.messages {
		s += " UIDVALIDITY " + strconv.FormatUint(uint64(b.uidValidity), 10)
	}
	if ev.flags {
		s += " UNSEEN " + strconv.Itoa(b.unseen)
	}
	if condstore {
		s += " HIGHESTMODSEQ " + strconv.FormatUint(b.highestModSeq, 10)
	}
	return s + ")"
}

// listLine is a folder's LIST, with OLDNAME after a rename.
func listLine(b boxSnap, oldName string) string {
	attrs := make([]string, 0, len(b.attrs)+1)
	for _, a := range b.attrs {
		attrs = append(attrs, string(a))
	}
	if b.subscribed {
		attrs = append(attrs, string(imap.MailboxAttrSubscribed))
	}
	delim := "NIL"
	if b.delim != 0 {
		delim = `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(string(b.delim)) + `"`
	}
	s := "* LIST (" + strings.Join(attrs, " ") + ") " + delim + " " + quoteMailbox(b.name)
	if oldName != "" {
		s += ` ("OLDNAME" (` + quoteMailbox(oldName) + `))`
	}
	return s
}
