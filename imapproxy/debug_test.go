package imapproxy

import (
	"log/slog"
	"os"
)

func init() {
	if os.Getenv("MAILCACHED_DEBUG") != "" {
		debugLog = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
}
