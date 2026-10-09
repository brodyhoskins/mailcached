package engine

import (
	"github.com/emersion/go-imap/v2"
	"slices"
	"strings"
)

// NonNil returns flags, or an empty list for nil.
func NonNil(flags []imap.Flag) []imap.Flag {
	if flags == nil {
		return []imap.Flag{}
	}
	return flags
}

func HasFlag(flags []imap.Flag, f imap.Flag) bool {
	return slices.ContainsFunc(flags, func(x imap.Flag) bool { return strings.EqualFold(string(x), string(f)) })
}

// ApplyFlags returns flags after a STORE. \Recent is the server's.
func ApplyFlags(flags []imap.Flag, flagOp imap.StoreFlagsOp, change []imap.Flag) []imap.Flag {
	change = slices.DeleteFunc(slices.Clone(change), func(f imap.Flag) bool { return strings.EqualFold(string(f), `\Recent`) })
	out := []imap.Flag{}
	switch flagOp {
	case imap.StoreFlagsSet:
		out = append(out, change...)
	case imap.StoreFlagsAdd:
		out = append(out, flags...)
		for _, f := range change {
			if !HasFlag(out, f) {
				out = append(out, f)
			}
		}
	case imap.StoreFlagsDel:
		for _, f := range flags {
			if !HasFlag(change, f) {
				out = append(out, f)
			}
		}
	}
	return out
}
