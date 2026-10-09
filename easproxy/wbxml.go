package easproxy

import "github.com/brodyhoskins/mailcached/internal/wbxml"

// The WBXML codec, by the short names the commands use.
type node = wbxml.Node

var (
	el     = wbxml.El
	tx     = wbxml.Tx
	op     = wbxml.Op
	encode = wbxml.Encode
	decode = wbxml.Decode
)
