package imapproxy

import (
	"io"
	"log/slog"

	"github.com/brodyhoskins/mailcached/internal/enginetest"
	"github.com/brodyhoskins/mailcached/internal/sealtest"
)

const (
	alice = enginetest.User // the proxy's user
	bob   = enginetest.Bob  // an outside correspondent
)

var testLog = slog.New(slog.NewTextHandler(io.Discard, nil))

// The tests' Transform (sealtest.Sealer).
type sealer = sealtest.Sealer

const sealedType = sealtest.SealedType

var (
	seal     = sealtest.Seal
	isSealed = sealtest.IsSealed
)
