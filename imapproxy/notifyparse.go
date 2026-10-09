package imapproxy

// Parsing of the NOTIFY command (RFC 5465 section 8).

import (
	"errors"
	"strconv"
	"strings"
)

// node is one item of a command: an atom, a string, or a parenthesized
// list. raw is the item as the client wrote it.
type node struct {
	atom   string
	str    string
	isStr  bool
	list   []node
	isList bool
	raw    string
}

// text returns an atom or a string.
func (n node) text() (string, bool) {
	switch {
	case n.isStr:
		return n.str, true
	case n.atom != "" && !n.isList:
		return n.atom, true
	}
	return "", false
}

var errSyntax = errors.New("syntax error")

// parseItems reads the items of s, a command's arguments with any
// literals inline ("{n}\r\n" and n bytes).
func parseItems(s string) ([]node, error) {
	p := &itemParser{s: s}
	items, err := p.items(false)
	if err != nil {
		return nil, err
	}
	if p.i < len(p.s) {
		return nil, errSyntax
	}
	return items, nil
}

type itemParser struct {
	s string
	i int
}

func (p *itemParser) items(inList bool) ([]node, error) {
	var out []node
	for {
		for p.i < len(p.s) && p.s[p.i] == ' ' {
			p.i++
		}
		if p.i >= len(p.s) {
			if inList {
				return nil, errSyntax
			}
			return out, nil
		}
		if p.s[p.i] == ')' {
			if !inList {
				return nil, errSyntax
			}
			p.i++
			return out, nil
		}
		n, err := p.item()
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
}

func (p *itemParser) item() (node, error) {
	start := p.i
	switch c := p.s[p.i]; c {
	case '(':
		p.i++
		l, err := p.items(true)
		if err != nil {
			return node{}, err
		}
		return node{list: l, isList: true, raw: p.s[start:p.i]}, nil
	case '"':
		var b strings.Builder
		for p.i++; p.i < len(p.s); p.i++ {
			switch p.s[p.i] {
			case '\\':
				p.i++
				if p.i < len(p.s) {
					b.WriteByte(p.s[p.i])
				}
			case '"':
				p.i++
				return node{str: b.String(), isStr: true, raw: p.s[start:p.i]}, nil
			default:
				b.WriteByte(p.s[p.i])
			}
		}
		return node{}, errSyntax
	case '{':
		end := strings.Index(p.s[p.i:], "}\r\n")
		if end < 0 {
			return node{}, errSyntax
		}
		n, err := strconv.Atoi(strings.TrimSuffix(p.s[p.i+1:p.i+end], "+"))
		p.i += end + 3
		if err != nil || n < 0 || p.i+n > len(p.s) {
			return node{}, errSyntax
		}
		v := p.s[p.i : p.i+n]
		p.i += n
		return node{str: v, isStr: true, raw: p.s[start:p.i]}, nil
	}
	// An atom; brackets, as in BODY.PEEK[HEADER.FIELDS (FROM)], hold
	// spaces and parentheses.
	depth := 0
	for ; p.i < len(p.s); p.i++ {
		c := p.s[p.i]
		if c == '[' {
			depth++
		} else if c == ']' && depth > 0 {
			depth--
		} else if depth == 0 && (c == ' ' || c == '(' || c == ')' || c == '"' || c == '{') {
			break
		}
	}
	if p.i == start {
		return node{}, errSyntax
	}
	return node{atom: p.s[start:p.i], raw: p.s[start:p.i]}, nil
}

// The events the proxy reports.
const (
	evMessageNew         = "MessageNew"
	evMessageExpunge     = "MessageExpunge"
	evFlagChange         = "FlagChange"
	evMailboxName        = "MailboxName"
	evSubscriptionChange = "SubscriptionChange"
)

var supportedEvents = []string{evMessageNew, evMessageExpunge, evFlagChange, evMailboxName, evSubscriptionChange}

// events is what a group asks for.
type events struct {
	messages, flags, names, subscriptions bool
	fetch                                 string // MessageNew's fetch-atts, "(...)", selected only
}

// notifyGroup is an event group for folders other than the selected one.
type notifyGroup struct {
	filter string   // inboxes, personal, subscribed, subtree, mailboxes
	names  []string // subtree and mailboxes
	ev     events
}

// notifySpec is a NOTIFY SET.
type notifySpec struct {
	status bool
	// selected is "", "selected" or "selected-delayed"; sel its events.
	selected string
	sel      events
	groups   []notifyGroup
}

// notifyError is a NOTIFY refusal: its status and text.
type notifyError struct{ status, text string }

func (e *notifyError) Error() string { return e.status + " " + e.text }

func bad(text string) error { return &notifyError{"BAD", text} }

// parseNotify parses a NOTIFY command's arguments. A nil spec is NOTIFY
// NONE.
func parseNotify(args string) (*notifySpec, error) {
	items, err := parseItems(args)
	if err != nil || len(items) == 0 {
		return nil, bad("Syntax error in NOTIFY")
	}
	first := strings.ToUpper(items[0].atom)
	if first == "NONE" && len(items) == 1 {
		return nil, nil
	}
	if first != "SET" {
		return nil, bad("NOTIFY needs SET or NONE")
	}
	spec := &notifySpec{}
	items = items[1:]
	if len(items) > 0 && strings.EqualFold(items[0].atom, "STATUS") {
		spec.status = true
		items = items[1:]
	}
	if len(items) == 0 {
		return nil, bad("NOTIFY SET needs an event group")
	}
	var unsupported bool
	for _, g := range items {
		if !g.isList || len(g.list) < 2 {
			return nil, bad("Bad event group")
		}
		filter := strings.ToLower(g.list[0].atom)
		rest := g.list[1:]
		var names []string
		switch filter {
		case "selected", "selected-delayed":
			if spec.selected != "" {
				return nil, bad("Only one of SELECTED and SELECTED-DELAYED")
			}
			spec.selected = filter
		case "inboxes", "personal", "subscribed":
		case "subtree", "mailboxes":
			if len(rest) < 2 {
				return nil, bad("Bad event group")
			}
			mb := rest[0]
			rest = rest[1:]
			list := []node{mb}
			if mb.isList {
				list = mb.list
			}
			for _, n := range list {
				s, ok := n.text()
				if !ok {
					return nil, bad("Bad mailbox name")
				}
				d, err := decodeUTF7(s)
				if err != nil {
					return nil, bad("Bad mailbox name")
				}
				names = append(names, d)
			}
		default:
			return nil, bad("Unknown mailbox filter")
		}
		if len(rest) != 1 {
			return nil, bad("Bad event group")
		}
		ev, unsup, err := parseEvents(rest[0], filter == "selected" || filter == "selected-delayed")
		if err != nil {
			return nil, err
		}
		unsupported = unsupported || unsup
		if filter == "selected" || filter == "selected-delayed" {
			spec.sel = ev
		} else {
			spec.groups = append(spec.groups, notifyGroup{filter: filter, names: names, ev: ev})
		}
	}
	if unsupported {
		return nil, &notifyError{"NO", "[BADEVENT (" + strings.Join(supportedEvents, " ") + ")] Unsupported event"}
	}
	return spec, nil
}

// parseEvents reads a group's events: a list, or NONE.
func parseEvents(n node, selected bool) (ev events, unsupported bool, err error) {
	if !n.isList {
		if strings.EqualFold(n.atom, "NONE") {
			return ev, false, nil
		}
		return ev, false, bad("Bad event list")
	}
	var isNew, isExpunge bool
	l := n.list
	for i := 0; i < len(l); i++ {
		if l[i].isList || l[i].isStr {
			return ev, false, bad("Bad event list")
		}
		switch strings.ToLower(l[i].atom) {
		case "messagenew":
			isNew = true
			if i+1 < len(l) && l[i+1].isList {
				if !selected {
					return ev, false, bad("Fetch attributes are for the selected mailbox only")
				}
				ev.fetch = l[i+1].raw
				i++
			}
		case "messageexpunge":
			isExpunge = true
		case "flagchange":
			ev.flags = true
		case "mailboxname", "subscriptionchange":
			if selected {
				return ev, false, bad("Only message events for the selected mailbox")
			}
			if strings.EqualFold(l[i].atom, evMailboxName) {
				ev.names = true
			} else {
				ev.subscriptions = true
			}
		default:
			// AnnotationChange, MailboxMetadataChange,
			// ServerMetadataChange, and any other.
			unsupported = true
		}
	}
	if isNew != isExpunge {
		return ev, false, bad("MessageNew and MessageExpunge go together")
	}
	if ev.flags && !isNew {
		return ev, false, bad("FlagChange needs MessageNew and MessageExpunge")
	}
	ev.messages = isNew
	return ev, unsupported, nil
}
