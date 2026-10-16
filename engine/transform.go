package engine

import (
	"context"
	"net/textproto"
)

// Transform changes messages between the provider and clients, for example
// to decrypt mail on its way to clients and encrypt what they store. Without
// one, the proxy serves every message as the provider has it.
type Transform interface {
	// Fields lists the header fields Changes needs. The sync fetches them
	// for every message, with Message-ID.
	Fields() []string
	// Changes reports, from a message's Fields, whether Read changes it.
	// A message it does not change is served as the provider has it,
	// without downloading it whole.
	Changes(h textproto.MIMEHeader) bool
	// Read turns a message from the provider into the one clients see,
	// and says how sure the result is (ReadStatus).
	Read(ctx context.Context, raw []byte) (out []byte, status ReadStatus)
	// Write turns a message a client stores with APPEND (a Sent copy, a
	// draft) into the one the provider stores. An error refuses the
	// APPEND.
	Write(ctx context.Context, raw []byte) ([]byte, error)
}

// ReadStatus says what to do with the result of Transform.Read.
type ReadStatus int

const (
	// ReadFinal: the result is what clients see from now on. It is
	// cached on disk.
	ReadFinal ReadStatus = iota
	// ReadRetry: clients see the result, but a later Read may give
	// another (a key that is missing now). It is kept in memory only,
	// until Engine.Recheck.
	ReadRetry
	// ReadHold: clients must not see the message yet. A new message (one
	// that arrived at or after Account.Since) is held: clients do not see
	// it at all until a later Read gives ReadFinal or ReadRetry. It is
	// tried again with every sweep and on Engine.Recheck. For an older
	// message, ReadHold is ReadRetry.
	ReadHold
	// ReadJunk, ReadTrash and ReadDelete move new mail away; for older
	// mail they act as ReadRetry.
	ReadJunk
	ReadTrash
	ReadDelete
	// ReadDefer is ReadJunk, released once the stamp is known.
	ReadDefer
)

func (s ReadStatus) moveAway() (how moveAway, ok bool) {
	switch s {
	case ReadJunk:
		return moveAway{act: AuthJunk, strict: true}, true
	case ReadTrash:
		return moveAway{act: AuthTrash, strict: true}, true
	case ReadDelete:
		return moveAway{act: AuthDelete, strict: true}, true
	case ReadDefer:
		return moveAway{act: AuthJunk, deferred: true, strict: true}, true
	}
	return moveAway{}, false
}
