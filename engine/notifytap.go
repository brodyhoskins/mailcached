package engine

// NOTIFY (RFC 5465) toward the provider. On the engine's own connection,
// a provider that offers it is asked for changes in every folder, not only
// the selected one:
//
//	NOTIFY SET (selected (MessageNew MessageExpunge FlagChange))
//	  (personal (MessageNew MessageExpunge FlagChange MailboxName SubscriptionChange))
//
// The provider then reports a change in another folder with a STATUS
// response, and a change to the folder list with a LIST response, at any
// time. go-imap's client drops responses no command asked for, so the
// connection's stream is tapped: a STATUS or LIST that answers none of the
// engine's own STATUS or LIST commands names a folder to sync, or asks for
// the list. With CONDSTORE enabled as well, a flag change anywhere comes as
// a STATUS with HIGHESTMODSEQ, and the engine need not check every folder
// every minute.

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/brodyhoskins/mailcached/internal/utf7"
)

// The NOTIFY the engine asks for, and the one without FlagChange for
// providers that refuse it.
const (
	notifyAll = "NOTIFY SET (selected (MessageNew MessageExpunge FlagChange)) " +
		"(personal (MessageNew MessageExpunge FlagChange MailboxName SubscriptionChange))"
	notifyNoFlags = "NOTIFY SET (selected (MessageNew MessageExpunge FlagChange)) " +
		"(personal (MessageNew MessageExpunge MailboxName SubscriptionChange))"
)

// notifyTap watches a connection's stream for what NOTIFY reports.
type notifyTap struct {
	notify func()

	mu      sync.Mutex
	pending map[string]string // the engine's STATUS and LIST commands: tag -> "LIST" or "STATUS <name>"
	names   map[string]bool   // folders reported; "" for one the tap could not name
	list    bool              // the folder list changed

	r, w tapStream
}

// tapStream is the place in one direction of the stream.
type tapStream struct {
	head, tail []byte
	skip       int64 // literal bytes to pass over
}

func newNotifyTap(notify func()) *notifyTap {
	return &notifyTap{notify: notify, pending: map[string]string{}, names: map[string]bool{}}
}

// The start and end of a line kept: enough for a command or response and
// its folder name, and for the literal it announces.
const (
	tapHead = 1024
	tapTail = 32
)

// feed passes bytes of one direction through, calling line with each
// line's start.
func (s *tapStream) feed(p []byte, line func(head []byte)) {
	for len(p) > 0 {
		if s.skip > 0 {
			n := min(int64(len(p)), s.skip)
			p = p[n:]
			s.skip -= n
			continue
		}
		i := bytes.IndexByte(p, '\n')
		part := p
		if i >= 0 {
			part = p[:i+1]
		}
		p = p[len(part):]
		s.head = append(s.head, part[:min(len(part), tapHead-len(s.head))]...)
		s.tail = append(s.tail, part...)
		if len(s.tail) > tapTail {
			s.tail = append(s.tail[:0], s.tail[len(s.tail)-tapTail:]...)
		}
		if i < 0 {
			return
		}
		line(s.head)
		s.skip = literalAt(s.tail)
		s.head, s.tail = s.head[:0], s.tail[:0]
	}
}

var tapLiteralRe = regexp.MustCompile(`\{([0-9]+)\+?\}\r?\n$`)

func literalAt(tail []byte) int64 {
	m := tapLiteralRe.FindSubmatch(tail)
	if m == nil {
		return 0
	}
	n, _ := strconv.ParseInt(string(m[1]), 10, 64)
	return n
}

var (
	tapCmdRe    = regexp.MustCompile(`(?i)^(\S+) (STATUS|LIST|LSUB) ?(.*)`)
	tapTaggedRe = regexp.MustCompile(`(?i)^(\S+) (OK|NO|BAD)\b`)
	tapStatusRe = regexp.MustCompile(`(?i)^\* STATUS (.*)`)
	tapListRe   = regexp.MustCompile(`(?i)^\* (LIST|LSUB) `)
)

// wrote notes what the engine sends.
func (t *notifyTap) wrote(p []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.w.feed(p, func(head []byte) {
		m := tapCmdRe.FindSubmatch(head)
		if m == nil {
			return
		}
		kind := strings.ToUpper(string(m[2]))
		if kind == "STATUS" {
			name, _ := tapMailbox(m[3])
			kind += " " + name
		}
		t.pending[string(m[1])] = kind
	})
}

// read notes what the provider sends.
func (t *notifyTap) read(p []byte) {
	t.mu.Lock()
	woke := false
	t.r.feed(p, func(head []byte) {
		if m := tapTaggedRe.FindSubmatch(head); m != nil {
			delete(t.pending, string(m[1]))
			return
		}
		if tapListRe.Match(head) {
			if !t.asked("LIST", "") {
				t.list, woke = true, true
			}
			return
		}
		if m := tapStatusRe.FindSubmatch(head); m != nil {
			name, ok := tapMailbox(m[1])
			if !ok {
				name = ""
			}
			if !t.asked("STATUS", name) {
				t.names[name], woke = true, true
			}
		}
	})
	t.mu.Unlock()
	if woke {
		t.notify()
	}
}

// asked reports whether a response answers one of the engine's commands:
// a LIST, or a STATUS of the folder (any STATUS when the name is not
// known). A LIST may return STATUS responses too (t.mu held).
func (t *notifyTap) asked(kind, name string) bool {
	for _, c := range t.pending {
		switch {
		case c == "LIST" || c == "LSUB":
			return true
		case kind == "STATUS" && strings.HasPrefix(c, "STATUS ") && (name == "" || c == "STATUS "+name):
			return true
		}
	}
	return false
}

// take returns what was reported since the last take.
func (t *notifyTap) take() (names []string, all, list bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for n := range t.names {
		if n == "" {
			all = true
		} else {
			names = append(names, n)
		}
	}
	clear(t.names)
	list, t.list = t.list, false
	return names, all, list
}

// tapMailbox reads the folder name at the start of s: an atom or a quoted
// string. A literal is not read: ok is false.
func tapMailbox(s []byte) (string, bool) {
	var raw string
	switch {
	case len(s) == 0 || s[0] == '{':
		return "", false
	case s[0] == '"':
		var b strings.Builder
		i := 1
		for ; i < len(s) && s[i] != '"'; i++ {
			if s[i] == '\\' && i+1 < len(s) {
				i++
			}
			b.WriteByte(s[i])
		}
		if i >= len(s) {
			return "", false
		}
		raw = b.String()
	default:
		end := bytes.IndexAny(s, " ()\r\n")
		if end < 0 {
			end = len(s)
		}
		raw = string(s[:end])
	}
	name, err := utf7.Decode(raw)
	if err != nil {
		return "", false
	}
	return CanonicalName(name), true
}
