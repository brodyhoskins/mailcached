package engine

import (
	"context"
	"time"

	"github.com/emersion/go-imap/v2"
)

// A Provider is how an account's engine reaches the mail provider: IMAP,
// JMAP, ActiveSync, or one that Engine.NewProvider makes. The engine names
// messages by folder and the provider's UID there. A provider without UIDs
// gives its messages UIDs of its own: ascending as messages arrive, never
// reused in a folder, and the same after a restart. If it cannot keep
// them, it changes the folder's Validity.
//
// A refusal (the provider says no: a folder that is gone, a quota) comes
// back as an *imap.Error, whatever the protocol. The queue undoes a
// refused change, and the backfill skips a folder that refuses. Any other
// error means the provider could not be reached, and the work is tried
// again later.
type Provider interface {
	// Login checks password with the provider. A rejection wraps
	// ErrLoginRejected.
	Login(password string) error
	// Conn returns a connection for one request. Call its Release. hint
	// names the folder the request is about, "" for none: a connection
	// that has it open already is preferred.
	Conn(p Priority, hint string) (Conn, error)
	// Watch opens the engine's own connection, which also waits for
	// changes. notify is called when the provider reports one.
	Watch(notify func()) (WatchConn, error)
	// Close closes the idle connections.
	Close()
	// Capacity returns the requests the provider takes at once now, 0 for
	// no known limit. It falls when the provider pushes back, and rises
	// again when the pushback ends.
	Capacity() int
}

// Conn is a connection to the provider. The folder names are the
// provider's.
type Conn interface {
	// List reads the folder list.
	List() ([]FolderInfo, error)
	// Sync says what changed in a folder since the state st describes.
	Sync(name string, st SyncState) (*Delta, error)
	// FetchFull downloads whole messages and calls each with every one.
	// A message the provider no longer has is left out.
	FetchFull(name string, uids []imap.UID, each func(uid imap.UID, raw []byte)) error
	// FetchSections downloads sections of messages (piece.go) and calls
	// each with every one: the message, the section's index in secs, and
	// its bytes. ErrNoPieces means the provider cannot.
	FetchSections(name string, uids []imap.UID, secs []Section, each func(uid imap.UID, i int, data []byte)) error
	// Search returns the UIDs in a folder of the messages that match c
	// at the provider. ErrNoSearch means the provider cannot.
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

// WatchConn is the engine's own connection.
type WatchConn interface {
	Conn
	// Wait returns when the provider may have changed, or after d, with
	// what to sync. changed ends it with ErrCredentialsChanged, and wake
	// (the provider's notify) ends it early.
	Wait(ctx context.Context, d time.Duration, changed, wake <-chan struct{}) (Wakeup, error)
	// Notifies reports whether the provider reports every change, in
	// every folder, so the folders need not all be checked often.
	Notifies() bool
	// Describe returns attributes for the log line once the engine is up
	// to date.
	Describe() []any
}

// Wakeup is what to sync after a Wait.
type Wakeup struct {
	Names []string // folders, by the provider's names
	All   bool     // every folder
	List  bool     // the folder list
}

// FolderInfo is one folder of the provider's list.
type FolderInfo struct {
	Name       string
	Delim      rune
	Attrs      []imap.MailboxAttr // without \Subscribed
	Subscribed bool
	Selectable bool
}

// SyncState is what the proxy knows of a folder at the provider, for
// Conn.Sync.
type SyncState struct {
	Validity uint32
	Next     imap.UID
	ModSeq   uint64
	// Count is how many messages the proxy knows the provider has there.
	Count int
	// Synced is false before the first sync. Stale is set when the proxy
	// may show a message the provider has nowhere; Force skips the check
	// that nothing changed.
	Synced, Stale, Force bool
	// RefetchFlags asks for every flag; FlagsFull is when they were last
	// all compared.
	RefetchFlags bool
	FlagsFull    time.Time
	// Known reports whether the proxy knows the message with the
	// provider's UID u. It takes the account lock.
	Known func(u imap.UID) bool
}

// Delta is what changed in a folder at the provider.
type Delta struct {
	// Unchanged says nothing changed; the other fields are empty.
	Unchanged bool
	// Reset says the provider renumbered the folder: every message the
	// proxy knows there is gone, and Fresh lists them all again.
	Reset bool
	// Present, if not nil, is every UID the provider has in the folder.
	Present map[imap.UID]bool
	// Gone lists UIDs the provider no longer has.
	Gone []imap.UID
	// Flags are changed flags of known messages.
	Flags []FlagUpdate
	// Fresh are messages the proxy may not know, in any order.
	Fresh []FreshMessage
	// The folder's state after the delta.
	Validity uint32
	Next     imap.UID
	ModSeq   uint64
	// FolderFlags and PermanentFlags are the flags the folder supports.
	FolderFlags, PermanentFlags []imap.Flag
	// FullFlags says every flag was compared.
	FullFlags bool
}

// FlagUpdate is the flags a known message has now.
type FlagUpdate struct {
	UID   imap.UID
	Flags []imap.Flag
}

// FreshMessage is a message as the sync first sees it.
type FreshMessage struct {
	UID   imap.UID
	Flags []imap.Flag
	Date  time.Time
	Size  int64
	// Header is the message's header, or at least the fields NewProvider
	// was given (Message-ID and those the Transform needs).
	Header []byte
}
