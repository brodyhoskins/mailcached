package imapproxy

import (
	"errors"
	"io"
	"slices"
	"sort"
	"sync"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"

	"github.com/brodyhoskins/mailcached/engine"
)

// Session is one client connection. It reads the engine's copy of the
// account and holds no provider connection of its own.
type Session struct {
	b    *Server
	conn *imapserver.Conn

	// mu guards acct and mbox for other goroutines (NOTIFY's watch);
	// the session's own goroutine changes them under it.
	mu   sync.Mutex
	user string
	acct *engine.Account

	// The selected mailbox, and this client's view of its numbering.
	mbox     *engine.Mailbox
	view     *imapserver.SessionTracker
	readOnly bool

	// stats counts the running FETCH's sources, for the fetch trace; nil
	// when tracing is off.
	stats *engine.FetchStats
}

var (
	_ imapserver.SessionIMAP4rev2 = (*Session)(nil)

	errNotSelected = &imap.Error{Type: imap.StatusResponseTypeBad, Text: "No mailbox selected"}
	errNoMailbox   = &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeNonExistent, Text: "No such mailbox"}
)

func (s *Session) Close() error {
	s.b.mu.Lock()
	delete(s.b.conns, s)
	s.b.mu.Unlock()
	s.closeMailbox()
	return nil
}

// Login checks the credentials (engine.Account.Login).
func (s *Session) Login(username, password string) error {
	if s.acct != nil {
		return &imap.Error{Type: imap.StatusResponseTypeBad, Text: "Already logged in"}
	}
	remote := s.conn.NetConn().RemoteAddr()
	eng := s.b.Engine
	if _, ok := eng.Route(username); !ok {
		s.b.Log.Info("imap: login rejected: no account matches", "user", username, "remote", remote)
		return imapserver.ErrAuthFailed
	}
	a := eng.Account(username)
	if err := a.Login(password); err != nil {
		if errors.Is(err, engine.ErrLoginRejected) || errors.Is(err, engine.ErrNoAccount) {
			s.b.Log.Info("imap: login rejected", "user", username, "remote", remote)
			return imapserver.ErrAuthFailed
		}
		s.b.Log.Error("imap: upstream login failed", "user", username, "err", err)
		return passError(err)
	}
	s.mu.Lock()
	s.user, s.acct = username, a
	s.mu.Unlock()
	s.b.Log.Info("imap: login", "user", username, "remote", remote)
	return nil
}

// mailboxFor returns the folder (engine.Account.MailboxFor).
func (s *Session) mailboxFor(name string) (*engine.Mailbox, error) {
	m, err := s.acct.MailboxFor(name)
	if errors.Is(err, engine.ErrNoMailbox) {
		return nil, errNoMailbox
	}
	return m, passError(err)
}

func (s *Session) Select(name string, options *imap.SelectOptions) (*imap.SelectData, error) {
	s.closeMailbox()
	m, err := s.mailboxFor(name)
	if err != nil {
		return nil, err
	}
	a := s.acct
	a.Lock()
	defer a.Unlock()
	s.mu.Lock()
	s.mbox, s.view = m, m.Tracker().NewSession()
	s.mu.Unlock()
	s.readOnly = options != nil && options.ReadOnly
	perm := m.PermanentFlags()
	if s.readOnly {
		perm = nil
	}
	return &imap.SelectData{
		Flags:             m.Flags(),
		PermanentFlags:    perm,
		NumMessages:       uint32(len(m.Msgs())),
		FirstUnseenSeqNum: firstUnseen(m.Msgs()),
		UIDNext:           m.UIDNext(),
		UIDValidity:       m.UIDValidity(),
	}, nil
}

func firstUnseen(msgs []*engine.Message) uint32 {
	for i, m := range msgs {
		if !engine.HasFlag(m.Flags(), imap.FlagSeen) {
			return uint32(i) + 1
		}
	}
	return 0
}

func (s *Session) Unselect() error {
	if s.mbox == nil {
		return errNotSelected
	}
	s.closeMailbox()
	return nil
}

func (s *Session) closeMailbox() {
	if s.view != nil {
		s.view.Close()
	}
	s.mu.Lock()
	s.mbox, s.view = nil, nil
	s.mu.Unlock()
}

// current returns the account and the selected folder, from any
// goroutine.
func (s *Session) current() (*engine.Account, *engine.Mailbox) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.acct, s.mbox
}

// --- Folders: done at the provider, then the list is read again ----------

func (s *Session) Create(name string, options *imap.CreateOptions) error {
	return passError(s.acct.CreateFolder(name, options))
}

func (s *Session) Delete(name string) error {
	return passError(s.acct.DeleteFolder(name))
}

func (s *Session) Rename(name, newName string, options *imap.RenameOptions) error {
	return passError(s.acct.RenameFolder(name, newName, options))
}

func (s *Session) Subscribe(name string) error {
	return passError(s.acct.Subscribe(name, true))
}

func (s *Session) Unsubscribe(name string) error {
	return passError(s.acct.Subscribe(name, false))
}

// List answers from the engine's copy of the folder list.
func (s *Session) List(w *imapserver.ListWriter, ref string, patterns []string, options *imap.ListOptions) error {
	a := s.acct
	a.Lock()
	delim := a.Delim()
	if len(patterns) == 0 {
		a.Unlock()
		// LIST "" "" asks for the hierarchy delimiter.
		return w.WriteList(&imap.ListData{Attrs: []imap.MailboxAttr{imap.MailboxAttrNoSelect}, Delim: delim})
	}
	var out []imap.ListData
	for _, m := range a.Mailboxes() {
		name := m.Name()
		if !slices.ContainsFunc(patterns, func(p string) bool { return imapserver.MatchList(name, delim, ref, p) }) {
			continue
		}
		if options != nil && options.SelectSubscribed && !m.Subscribed() {
			continue
		}
		if options != nil && options.SelectSpecialUse && !hasSpecialUse(m.Attrs()) {
			continue
		}
		d := imap.ListData{Mailbox: name, Delim: m.Delim(), Attrs: slices.Clone(m.Attrs())}
		if m.Subscribed() && options != nil && (options.ReturnSubscribed || options.SelectSubscribed) {
			d.Attrs = append(d.Attrs, imap.MailboxAttrSubscribed)
		}
		if options != nil && options.ReturnStatus != nil && m.Selectable() {
			d.Status = statusOf(m, options.ReturnStatus)
		}
		out = append(out, d)
	}
	a.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Mailbox < out[j].Mailbox })
	for i := range out {
		if err := w.WriteList(&out[i]); err != nil {
			return err
		}
	}
	return nil
}

var specialUse = []imap.MailboxAttr{
	imap.MailboxAttrAll, imap.MailboxAttrArchive, imap.MailboxAttrDrafts, imap.MailboxAttrFlagged,
	imap.MailboxAttrJunk, imap.MailboxAttrSent, imap.MailboxAttrTrash,
}

func hasSpecialUse(attrs []imap.MailboxAttr) bool {
	return slices.ContainsFunc(specialUse, func(a imap.MailboxAttr) bool { return engine.HasAttr(attrs, a) })
}

// Status answers from the engine's copy, which the engine keeps current.
// Clients send it for every folder, often, so it does not ask the
// provider, except for a folder never synced.
func (s *Session) Status(name string, options *imap.StatusOptions) (*imap.StatusData, error) {
	a := s.acct
	a.Lock()
	m := a.Mailbox(name)
	if m != nil && m.Selectable() && !m.Synced().IsZero() {
		defer a.Unlock()
		return statusOf(m, options), nil
	}
	a.Unlock()
	m, err := s.mailboxFor(name)
	if err != nil {
		return nil, err
	}
	a.Lock()
	defer a.Unlock()
	return statusOf(m, options), nil
}

// statusOf computes STATUS data (lock held).
func statusOf(m *engine.Mailbox, options *imap.StatusOptions) *imap.StatusData {
	d := &imap.StatusData{Mailbox: m.Name()}
	msgs := m.Msgs()
	if options.NumMessages {
		n := uint32(len(msgs))
		d.NumMessages = &n
	}
	if options.UIDNext {
		d.UIDNext = m.UIDNext()
	}
	if options.UIDValidity {
		d.UIDValidity = m.UIDValidity()
	}
	if options.NumUnseen {
		var n uint32
		for _, msg := range msgs {
			if !engine.HasFlag(msg.Flags(), imap.FlagSeen) {
				n++
			}
		}
		d.NumUnseen = &n
	}
	if options.NumDeleted {
		var n uint32
		for _, msg := range msgs {
			if engine.HasFlag(msg.Flags(), imap.FlagDeleted) {
				n++
			}
		}
		d.NumDeleted = &n
	}
	if options.NumRecent {
		var n uint32
		d.NumRecent = &n
	}
	return d
}

func (s *Session) Namespace() (*imap.NamespaceData, error) {
	s.acct.Lock()
	delim := s.acct.Delim()
	s.acct.Unlock()
	return &imap.NamespaceData{Personal: []imap.NamespaceDescriptor{{Prefix: "", Delim: delim}}}, nil
}

// Append stores a message (engine.Account.Append).
func (s *Session) Append(name string, r imap.LiteralReader, options *imap.AppendOptions) (*imap.AppendData, error) {
	if r.Size() > s.b.MaxMessageBytes {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeTooBig, Text: "Message too big"}
	}
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	msg, err := s.acct.Append(name, data, options)
	if errors.Is(err, engine.ErrTransform) {
		return nil, &imap.Error{Type: imap.StatusResponseTypeNo, Code: imap.ResponseCodeServerBug, Text: "Message could not be stored"}
	}
	if err != nil || msg == nil {
		return nil, passError(err)
	}
	a := s.acct
	a.Lock()
	defer a.Unlock()
	m := a.Mailbox(msg.Box())
	if m == nil {
		return nil, nil
	}
	return &imap.AppendData{UID: msg.UID(), UIDValidity: m.UIDValidity()}, nil
}

func (s *Session) Poll(w *imapserver.UpdateWriter, allowExpunge bool) error {
	if s.view == nil {
		return nil
	}
	return s.view.Poll(w, allowExpunge)
}

// Idle reports changes as the engine records them; no provider connection
// is needed per client.
func (s *Session) Idle(w *imapserver.UpdateWriter, stop <-chan struct{}) error {
	// Under s.mu: when the connection breaks, go-imap closes the session
	// without waiting for Idle to return.
	s.mu.Lock()
	view := s.view
	s.mu.Unlock()
	if view == nil {
		<-stop
		return nil
	}
	return view.Idle(w, stop)
}
