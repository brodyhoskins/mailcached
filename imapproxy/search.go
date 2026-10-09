package imapproxy

import (
	"errors"
	"slices"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"

	"github.com/brodyhoskins/mailcached/engine"
)

// Search runs in the proxy: flags, dates and numbers come from its copy.
// Criteria that look at content (text, headers, sizes) are asked of the
// provider for messages the proxy does not change, which the provider
// has as clients see them, when they stand at the top level of the
// search (not inside OR or NOT). For the others, the provider has the
// messages before the Transform (ciphertext, for one that decrypts), so
// the proxy downloads them once and searches them itself; later searches
// hit the cache.
func (s *Session) Search(kind imapserver.NumKind, criteria *imap.SearchCriteria, options *imap.SearchOptions) (*imap.SearchData, error) {
	if s.mbox == nil {
		return nil, errNotSelected
	}
	s.acct.Lock()
	all := s.resolve(imap.SeqSet{{Start: 1, Stop: 0}})
	staticCriteria(criteria, uint32(len(s.mbox.Msgs())), maxUID(s.mbox.Msgs()))
	s.acct.Unlock()

	var contents map[*engine.Message][]byte
	var atProvider map[*engine.Message]bool // the direct messages the provider matched
	local := criteria
	if engine.NeedsBody(criteria) {
		read := messagesOf(all)
		if l, remote := splitContent(criteria); !engine.NeedsBody(l) {
			var direct, others []*engine.Message
			for _, msg := range read {
				if msg.Direct() {
					direct = append(direct, msg)
				} else {
					others = append(others, msg)
				}
			}
			if len(direct) > 0 {
				m, err := s.acct.SearchAtProvider(direct, remote)
				switch {
				case err == nil:
					atProvider, local, read = m, l, others
				case !errors.Is(err, engine.ErrNoSearch):
					return nil, passError(err)
				}
			}
		}
		var err error
		if contents, err = s.contents(read); err != nil {
			return nil, err
		}
	}

	var (
		data   imap.SearchData
		seqSet imap.SeqSet
		uidSet imap.UIDSet
	)
	for _, t := range all {
		s.acct.Lock()
		seq := s.view.EncodeSeqNum(t.seq)
		m := engine.MatchMessage{Seq: seq, UID: t.msg.UID(), Flags: slices.Clone(t.msg.Flags()), Date: t.msg.Date()}
		s.acct.Unlock()
		if seq == 0 {
			continue
		}
		if atProvider != nil && t.msg.Direct() {
			if !atProvider[t.msg] || !engine.Match(m, nil, local) {
				continue
			}
		} else {
			raw, ok := contents[t.msg]
			if contents != nil && !ok {
				continue
			}
			if !engine.Match(m, raw, criteria) {
				continue
			}
		}
		var num uint32
		switch kind {
		case imapserver.NumKindSeq:
			seqSet.AddNum(seq)
			num = seq
		case imapserver.NumKindUID:
			uidSet.AddNum(m.UID)
			num = uint32(m.UID)
		}
		if data.Min == 0 || num < data.Min {
			data.Min = num
		}
		if num > data.Max {
			data.Max = num
		}
		data.Count++
	}
	if kind == imapserver.NumKindSeq {
		data.All = seqSet
	} else {
		data.All = uidSet
	}
	return &data, nil
}

func staticCriteria(c *imap.SearchCriteria, maxSeq uint32, maxUID imap.UID) {
	for i := range c.SeqNum {
		c.SeqNum[i] = staticSeqSet(c.SeqNum[i], maxSeq)
	}
	for i := range c.UID {
		c.UID[i] = staticUIDSet(c.UID[i], maxUID)
	}
	for i := range c.Not {
		staticCriteria(&c.Not[i], maxSeq, maxUID)
	}
	for i := range c.Or {
		staticCriteria(&c.Or[i][0], maxSeq, maxUID)
		staticCriteria(&c.Or[i][1], maxSeq, maxUID)
	}
}

// splitContent splits the top level of c into what the proxy matches
// itself (local) and the content criteria for the provider (remote).
func splitContent(c *imap.SearchCriteria) (local, remote *imap.SearchCriteria) {
	l, r := *c, imap.SearchCriteria{}
	r.Header, r.Body, r.Text = c.Header, c.Body, c.Text
	r.Larger, r.Smaller, r.SentSince, r.SentBefore = c.Larger, c.Smaller, c.SentSince, c.SentBefore
	l.Header, l.Body, l.Text = nil, nil, nil
	l.Larger, l.Smaller = 0, 0
	l.SentSince, l.SentBefore = time.Time{}, time.Time{}
	return &l, &r
}
