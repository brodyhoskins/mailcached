package imapproxy

import (
	"strings"

	"github.com/brodyhoskins/mailcached/internal/utf7"
)

func encodeUTF7(s string) string          { return utf7.Encode(s) }
func decodeUTF7(s string) (string, error) { return utf7.Decode(s) }

// quoteMailbox writes a folder name as an IMAP quoted string.
func quoteMailbox(name string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(encodeUTF7(name)) + `"`
}
