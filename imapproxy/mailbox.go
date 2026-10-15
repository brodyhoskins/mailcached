package imapproxy

import (
	"errors"
	"slices"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"

	"github.com/brodyhoskins/mailcached/engine"
)

// target is one message addressed by a command, with its sequence number in
// the proxy's (server) numbering.
type target struct {
	seq uint32
	msg *engine.Message
}

// resolve turns a client's sequence or UID set into messages (lock held).
// Sequence numbers are the client's view, which can lag behind the
// mailbox by the updates still queued for this client.
func (s *Session) resolve(numSet imap.NumSet) []target {
	msgs := s.mbox.Msgs()
	var out []target
	switch set := numSet.(type) {
	case imap.SeqSet:
		set = staticSeqSet(set, uint32(len(msgs)))
		for i, msg := range msgs {
			seq := uint32(i) + 1
			if c := s.view.EncodeSeqNum(seq); c != 0 && set.Contains(c) {
				out = append(out, target{seq, msg})
			}
		}
	case imap.UIDSet:
		set = staticUIDSet(set, maxUID(msgs))
		for i, msg := range msgs {
			if set.Contains(msg.UID()) {
				out = append(out, target{uint32(i) + 1, msg})
			}
		}
	}
	return out
}

func maxUID(msgs []*engine.Message) imap.UID {
	if len(msgs) == 0 {
		return 0
	}
	return msgs[len(msgs)-1].UID()
}

// staticSeqSet replaces "*" (0) with the largest number, so ranges like
// "5:*" compare correctly.
func staticSeqSet(set imap.SeqSet, max uint32) imap.SeqSet {
	set = slices.Clone(set)
	for i := range set {
		staticRange(&set[i].Start, &set[i].Stop, max)
	}
	return set
}

func staticUIDSet(set imap.UIDSet, max imap.UID) imap.UIDSet {
	set = slices.Clone(set)
	for i := range set {
		staticRange((*uint32)(&set[i].Start), (*uint32)(&set[i].Stop), uint32(max))
	}
	return set
}

func staticRange(start, stop *uint32, max uint32) {
	dyn := *start == 0 || *stop == 0
	if *start == 0 {
		*start = max
	}
	if *stop == 0 {
		*stop = max
	}
	if dyn && *start > *stop {
		*start, *stop = *stop, *start
	}
}

// targets resolves numSet under the account lock.
func (s *Session) targets(numSet imap.NumSet) []target {
	s.acct.Lock()
	defer s.acct.Unlock()
	return s.resolve(numSet)
}

func messagesOf(targets []target) []*engine.Message {
	out := make([]*engine.Message, len(targets))
	for i, t := range targets {
		out[i] = t.msg
	}
	return out
}

var errReadOnly = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeCannot, Text: "Mailbox is read-only"}

// destinationError turns the engine's error for a copy or move.
func destinationError(err error) error {
	if errors.Is(err, engine.ErrNoMailbox) {
		return &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeTryCreate, Text: "No such mailbox"}
	}
	return passError(err)
}

// The commands below change the engine's copy at once; the engine queues
// the change for the provider, so clients never wait on it.

func (s *Session) Store(w *imapserver.FetchWriter, numSet imap.NumSet, flags *imap.StoreFlags, options *imap.StoreOptions) error {
	defer busy()()
	if s.mbox == nil {
		return errNotSelected
	}
	if s.readOnly {
		return errReadOnly
	}
	targets := s.targets(numSet)
	if len(targets) == 0 {
		return nil
	}
	s.changeFlags(targets, flags.Op, flags.Flags, s.view)
	if flags.Silent {
		return nil
	}
	return s.writeFlags(w, targets)
}

// changeFlags changes the flags of targets. Every client but source hears
// of it through the mailbox tracker; source, if not nil, reports it
// itself.
func (s *Session) changeFlags(targets []target, flagOp imap.StoreFlagsOp, flags []imap.Flag, source *imapserver.SessionTracker) {
	s.acct.Lock()
	in := s.mbox.Name()
	s.acct.Unlock()
	s.acct.SetFlags(messagesOf(targets), in, flagOp, flags, source)
}

func (s *Session) writeFlags(w *imapserver.FetchWriter, targets []target) error {
	for _, t := range targets {
		s.acct.Lock()
		c := uint32(0)
		uid := t.msg.UID()
		if i, ok := s.mbox.Index(uid); ok && t.msg.Box() == s.mbox.Name() {
			c = s.view.EncodeSeqNum(uint32(i) + 1)
		}
		flags := slices.Clone(t.msg.Flags())
		s.acct.Unlock()
		if c == 0 {
			continue
		}
		rw := w.CreateMessage(c)
		rw.WriteUID(uid)
		rw.WriteFlags(flags)
		if err := rw.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Expunge removes the messages with \Deleted (of uids, if not nil). The
// EXPUNGE responses go out through the mailbox tracker when the command
// completes.
func (s *Session) Expunge(w *imapserver.ExpungeWriter, uids *imap.UIDSet) error {
	defer busy()()
	if s.mbox == nil {
		return errNotSelected
	}
	if s.readOnly {
		return errReadOnly
	}
	var set imap.UIDSet
	if uids != nil {
		s.acct.Lock()
		set = staticUIDSet(*uids, maxUID(s.mbox.Msgs()))
		s.acct.Unlock()
	}
	s.acct.Expunge(s.mbox, func(msg *engine.Message) bool {
		return engine.HasFlag(msg.Flags(), imap.FlagDeleted) && (uids == nil || set.Contains(msg.UID()))
	})
	return nil
}

// copyData is COPYUID data for messages copied or moved.
func copyData(done []engine.Copied, validity uint32) *imap.CopyData {
	data := &imap.CopyData{UIDValidity: validity}
	for _, c := range done {
		data.SourceUIDs.AddNum(c.FromUID)
		data.DestUIDs.AddNum(c.ToUID)
	}
	return data
}

func (s *Session) Copy(numSet imap.NumSet, dest string) (*imap.CopyData, error) {
	defer busy()()
	if s.mbox == nil {
		return nil, errNotSelected
	}
	targets := s.targets(numSet)
	if len(targets) == 0 {
		return nil, nil
	}
	s.acct.Lock()
	in := s.mbox.Name()
	s.acct.Unlock()
	done, validity, err := s.acct.Copy(messagesOf(targets), in, dest)
	if err != nil {
		return nil, destinationError(err)
	}
	if len(done) == 0 {
		return nil, nil
	}
	return copyData(done, validity), nil
}

func (s *Session) Move(w *imapserver.MoveWriter, numSet imap.NumSet, dest string) error {
	defer busy()()
	if s.mbox == nil {
		return errNotSelected
	}
	if s.readOnly {
		return errReadOnly
	}
	targets := s.targets(numSet)
	if len(targets) == 0 {
		return w.WriteCopyData(nil)
	}
	in := make(map[*engine.Message]bool, len(targets))
	for _, t := range targets {
		in[t.msg] = true
	}
	done, validity, err := s.acct.Move(s.mbox, func(msg *engine.Message) bool { return in[msg] }, dest)
	if err != nil {
		return destinationError(err)
	}
	if len(done) == 0 {
		return w.WriteCopyData(nil)
	}
	return w.WriteCopyData(copyData(done, validity))
}
