package engine

import (
	"context"
	"time"

	"github.com/emersion/go-imap/v2"
)

// A provider is how an account's engine reaches the mail provider: IMAP
// (imapprov.go) or JMAP. The engine names messages the way it stores
// them: a folder, and the provider's UID there. A provider without UIDs
// gives its messages UIDs of its own.
//
// A refusal (the provider says no: a folder that is gone, a quota) comes
// back as an *imap.Error, whatever the protocol. The queue undoes a
// refused change, and the backfill skips a folder that refuses. Any other
// error means the provider could not be reached, and the work is tried
// again later.
type provider interface {
	// Login checks password with the provider. A rejection wraps
	// errLoginRejected.
	Login(password string) error
	// Conn returns a connection for one request. Call its Release. hint
	// names the folder the request is about, "" for none: a connection
	// that has it open already is preferred.
	Conn(p priority, hint string) (conn, error)
	// Watch opens the engine's own connection, which also waits for
	// changes. notify is called when the provider reports one.
	Watch(notify func()) (watchConn, error)
	// Close closes the idle connections.
	Close()
}

// conn is a connection to the provider. The folder names are the
// provider's.
type conn interface {
	// List reads the folder list.
	List() ([]folderInfo, error)
	// Sync says what changed in a folder since the state st describes.
	Sync(name string, st syncState) (*delta, error)
	// FetchFull downloads whole messages and calls each with every one.
	// A message the provider no longer has is left out.
	FetchFull(name string, uids []imap.UID, each func(uid imap.UID, raw []byte)) error
	// FetchSections downloads sections of messages (piece.go) and calls
	// each with every one: the message, the section's index in secs, and
	// its bytes. errNoPieces means the provider cannot.
	FetchSections(name string, uids []imap.UID, secs []Section, each func(uid imap.UID, i int, data []byte)) error
	// Search returns the UIDs in a folder of the messages that match c
	// at the provider. errNoSearch means the provider cannot.
	Search(name string, c *imap.SearchCriteria) ([]imap.UID, error)
	// FetchHeaders returns the header entries of messages, without their
	// bodies.
	FetchHeaders(name string, uids []imap.UID) (map[imap.UID]*HeaderEntry, error)
	// Store changes flags. It returns the flags the messages have after
	// the change, if the provider says; nil otherwise.
	Store(name string, uids []imap.UID, op imap.StoreFlagsOp, flags []imap.Flag) (map[imap.UID][]imap.Flag, error)
	// Copy and Move return the UIDs the messages got in dest, by their
	// UIDs in name; nil if the provider does not say.
	Copy(name string, uids []imap.UID, dest string) (map[imap.UID]imap.UID, error)
	Move(name string, uids []imap.UID, dest string) (map[imap.UID]imap.UID, error)
	// Expunge deletes messages from a folder.
	Expunge(name string, uids []imap.UID) error
	// Append stores a message. uid is 0 if the provider does not say.
	Append(name string, data []byte, opts *imap.AppendOptions) (uid imap.UID, validity uint32, err error)
	Create(name string, opts *imap.CreateOptions) error
	Delete(name string) error
	Rename(name, newName string, opts *imap.RenameOptions) error
	Subscribe(name string, on bool) error
	// Release gives the connection back. err is the last error from
	// using it, so a broken connection is not used again.
	Release(err error)
}

// watchConn is the engine's own connection.
type watchConn interface {
	conn
	// Wait returns when the provider may have changed, or after d, with
	// what to sync. changed ends it with errCredentialsChanged, and wake
	// (the provider's notify) ends it early.
	Wait(ctx context.Context, d time.Duration, changed, wake <-chan struct{}) (wakeup, error)
	// Notifies reports whether the provider reports every change, in
	// every folder, so the folders need not all be checked often.
	Notifies() bool
	// Describe returns attributes for the log line once the engine is up
	// to date.
	Describe() []any
}

// wakeup is what to sync after a Wait.
type wakeup struct {
	names []string // folders, by the provider's names
	all   bool     // every folder
	list  bool     // the folder list
}

// folderInfo is one folder of the provider's list.
type folderInfo struct {
	name       string
	delim      rune
	attrs      []imap.MailboxAttr // without \Subscribed
	subscribed bool
	selectable bool
}

// syncState is what the proxy knows of a folder at the provider, for
// conn.Sync.
type syncState struct {
	validity uint32
	next     imap.UID
	modSeq   uint64
	// count is how many messages the proxy knows the provider has there.
	count int
	// synced is false before the first sync. stale is set when the proxy
	// may show a message the provider has nowhere; force skips the check
	// that nothing changed.
	synced, stale, force bool
	// refetchFlags asks for every flag; flagsFull is when they were last
	// all compared.
	refetchFlags bool
	flagsFull    time.Time
	// known reports whether the proxy knows the message with the
	// provider's UID u. It takes the account lock.
	known func(u imap.UID) bool
}

// delta is what changed in a folder at the provider.
type delta struct {
	// unchanged says nothing changed; the other fields are empty.
	unchanged bool
	// reset says the provider renumbered the folder: every message the
	// proxy knows there is gone, and fresh lists them all again.
	reset bool
	// present, if not nil, is every UID the provider has in the folder.
	present map[imap.UID]bool
	// gone lists UIDs the provider no longer has.
	gone []imap.UID
	// flags are changed flags of known messages.
	flags []flagUpdate
	// fresh are messages the proxy may not know, in any order.
	fresh []freshMessage
	// The folder's state after the delta.
	validity uint32
	next     imap.UID
	modSeq   uint64
	// folderFlags and permanentFlags are the flags the folder supports.
	folderFlags, permanentFlags []imap.Flag
	// fullFlags says every flag was compared.
	fullFlags bool
}

type flagUpdate struct {
	uid   imap.UID
	flags []imap.Flag
}

// freshMessage is a message as the sync first sees it.
type freshMessage struct {
	uid   imap.UID
	flags []imap.Flag
	date  time.Time
	size  int64
	// header holds the syncSection fields: Message-ID and those the
	// Transform needs.
	header []byte
}
