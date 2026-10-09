package imapproxy

// CONDSTORE (RFC 7162 section 3) toward mail clients: a mod-sequence for
// every message, which rises whenever its flags change, so a client asks
// only for what changed since it last looked. The numbers come from the
// engine's change log (engine.Account.ModSeq, HighestModSeq). go-imap's
// server knows none of it, so the connection wrapper does it on the wire,
// with OBJECTID (objectid.go):
//
//   - SELECT and EXAMINE with (CONDSTORE), and ENABLE CONDSTORE, turn it
//     on; then SELECT reports HIGHESTMODSEQ, and every FETCH response with
//     FLAGS carries MODSEQ.
//   - FETCH MODSEQ, and the CHANGEDSINCE modifier, which leaves out the
//     messages not changed since.
//   - STATUS HIGHESTMODSEQ.
//   - STORE with UNCHANGEDSINCE: the messages changed since are left out
//     of the STORE and named in the OK's MODIFIED code.
//   - SEARCH MODSEQ, which becomes a UID set, and the (MODSEQ n) its
//     answer then ends with.
//
// QRESYNC is not offered: it needs the UIDs expunged since a
// mod-sequence, which the log does not keep.

import (
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/engine"
)

// capCondStore is the capability.
const capCondStore = "CONDSTORE"

var (
	changedSinceRe    = regexp.MustCompile(`(?i) *\(CHANGEDSINCE ([0-9]+)\)`)
	selectCondStoreRe = regexp.MustCompile(`(?i) *\(CONDSTORE\) *\r?\n$`)
	searchModSeqRe    = regexp.MustCompile(`(?i)\bMODSEQ (?:"[^"]*" (?:all|shared|priv) )?([0-9]+)`)
	unchangedSinceRe  = regexp.MustCompile(`(?i)^ (\S+) \(UNCHANGEDSINCE ([0-9]+)\)`)
)

// condStore is what the wrapper asks the session for CONDSTORE.
type condStore interface {
	// modSeqAt returns the MODSEQ of the message with sequence number seq
	// in the client's view of the selected folder.
	modSeqAt(seq uint32) (uint64, bool)
	// highestModSeq returns a folder's HIGHESTMODSEQ; "" names the
	// selected folder.
	highestModSeq(name string) (uint64, bool)
	// modSeqAtLeast returns the UIDs in the selected folder of the
	// messages with a MODSEQ of n or more.
	modSeqAtLeast(n uint64) []imap.UID
	// maxModSeq returns the highest MODSEQ of messages, by sequence
	// number or (with uid) UID; 0 for none.
	maxModSeq(nums []uint32, uid bool) uint64
	// unchangedSince splits a STORE's set (sequence numbers or, with uid,
	// UIDs) into the messages not changed since n, to store, and those
	// changed, for MODIFIED. Either is "" when it is empty.
	unchangedSince(set string, uid bool, n uint64) (keep, modified string)
}

// store handles a STORE with UNCHANGEDSINCE (o.mu held).
func (o *objectState) store(tag string, uid bool, cmd, rest []byte) []byte {
	m := unchangedSinceRe.FindSubmatchIndex(rest)
	if m == nil || o.ids == nil {
		return append(append([]byte{}, cmd...), rest...)
	}
	o.condstore = true
	set := string(rest[m[2]:m[3]])
	n, _ := strconv.ParseUint(string(rest[m[4]:m[5]]), 10, 64)
	keep, modified := o.ids.unchangedSince(set, uid, n)
	o.tags[tag] = &objectCmd{kind: "store", modified: modified}
	if keep == "" {
		// Nothing to store: an OK with MODIFIED.
		return []byte(tag + " NOOP\r\n")
	}
	return append(append(append([]byte{}, cmd...), " "+keep...), rest[m[1]:]...)
}

// --- The session's side ----------------------------------------------------

func (s *Session) modSeqAt(seq uint32) (uint64, bool) {
	a, m := s.acct, s.mbox
	if a == nil || m == nil || s.view == nil {
		return 0, false
	}
	a.Lock()
	defer a.Unlock()
	i := s.view.DecodeSeqNum(seq)
	msgs := m.Msgs()
	if i == 0 || int(i) > len(msgs) {
		return 0, false
	}
	return a.ModSeq(msgs[i-1]), true
}

func (s *Session) highestModSeq(name string) (uint64, bool) {
	a := s.acct
	if a == nil {
		return 0, false
	}
	a.Lock()
	defer a.Unlock()
	m := s.mbox
	if name != "" {
		m = a.Mailbox(name)
	}
	if m == nil {
		return 0, false
	}
	return a.HighestModSeq(m), true
}

func (s *Session) modSeqAtLeast(n uint64) []imap.UID {
	a, m := s.acct, s.mbox
	if a == nil || m == nil {
		return nil
	}
	a.Lock()
	defer a.Unlock()
	var out []imap.UID
	for _, msg := range m.Msgs() {
		if a.ModSeq(msg) >= n {
			out = append(out, msg.UID())
		}
	}
	return out
}

func (s *Session) maxModSeq(nums []uint32, uid bool) uint64 {
	a, m := s.acct, s.mbox
	if a == nil || m == nil || s.view == nil || len(nums) == 0 {
		return 0
	}
	a.Lock()
	defer a.Unlock()
	msgs := m.Msgs()
	var h uint64
	for _, n := range nums {
		var msg *engine.Message
		if uid {
			if i, ok := m.Index(imap.UID(n)); ok {
				msg = msgs[i]
			}
		} else if i := s.view.DecodeSeqNum(n); i > 0 && int(i) <= len(msgs) {
			msg = msgs[i-1]
		}
		if msg != nil {
			h = max(h, a.ModSeq(msg))
		}
	}
	return h
}

func (s *Session) unchangedSince(set string, uid bool, n uint64) (keep, modified string) {
	a, m := s.acct, s.mbox
	if a == nil || m == nil || s.view == nil {
		return set, ""
	}
	a.Lock()
	defer a.Unlock()
	msgs := m.Msgs()
	// The numbers the client knows, and '*': the highest of them.
	type num struct {
		n   uint32
		msg *engine.Message
	}
	var all []num
	for i, msg := range msgs {
		if uid {
			all = append(all, num{uint32(msg.UID()), msg})
		} else if c := s.view.EncodeSeqNum(uint32(i) + 1); c != 0 {
			all = append(all, num{c, msg})
		}
	}
	var star uint32
	for _, x := range all {
		star = max(star, x.n)
	}
	ranges, ok := parseNumSet(set, star)
	if !ok {
		return set, ""
	}
	var kept, changed []uint32
	for _, x := range all {
		if !slices.ContainsFunc(ranges, func(r [2]uint32) bool { return x.n >= r[0] && x.n <= r[1] }) {
			continue
		}
		if a.ModSeq(x.msg) > n {
			changed = append(changed, x.n)
		} else {
			kept = append(kept, x.n)
		}
	}
	return numSetString(kept, uid), numSetString(changed, uid)
}

// parseNumSet reads a sequence set ("1:4,7,9:*"), with star for '*'.
func parseNumSet(set string, star uint32) ([][2]uint32, bool) {
	var out [][2]uint32
	num := func(s string) (uint32, bool) {
		if s == "*" {
			return star, true
		}
		n, err := strconv.ParseUint(s, 10, 32)
		return uint32(n), err == nil
	}
	for _, part := range strings.Split(set, ",") {
		lo, hi, isRange := strings.Cut(part, ":")
		a, ok := num(lo)
		if !ok {
			return nil, false
		}
		b := a
		if isRange {
			if b, ok = num(hi); !ok {
				return nil, false
			}
		}
		out = append(out, [2]uint32{min(a, b), max(a, b)})
	}
	return out, true
}

func numSetString(nums []uint32, uid bool) string {
	if len(nums) == 0 {
		return ""
	}
	if uid {
		uids := make([]imap.UID, len(nums))
		for i, n := range nums {
			uids[i] = imap.UID(n)
		}
		return imap.UIDSetNum(uids...).String()
	}
	return imap.SeqSetNum(nums...).String()
}
