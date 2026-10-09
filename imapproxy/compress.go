package imapproxy

// COMPRESS=DEFLATE (RFC 4978) toward mail clients. go-imap's server doesn't
// support it, so each connection is wrapped: the wrapper answers the
// COMPRESS command itself, and adds COMPRESS=DEFLATE to the capabilities
// the server lists. Both directions track literals so message contents
// are never mistaken for commands or responses.
//
// The wrapper must see the IMAP protocol in the clear, so it sits inside
// implicit TLS and isn't used with STARTTLS.

import (
	"bufio"
	"bytes"
	"compress/flate"
	"errors"
	"io"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/brodyhoskins/mailcached/internal/inflate"
)

// This file and handshake.go come from rclone-imap (Brody Hoskins), which
// solved COMPRESS for go-imap v2 in both directions.

const capCompress = "COMPRESS=DEFLATE"

// compressListener wraps the connections it accepts in compressConn.
type compressListener struct {
	net.Listener
	// offer advertises and answers COMPRESS=DEFLATE. Without it the
	// wrapper only traces, and a COMPRESS command reaches go-imap, which
	// rejects it.
	offer bool
	trace *slog.Logger // logs commands and status replies; nil for none
}

func (l compressListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	cc := newCompressConn(c, l.offer)
	if l.trace != nil {
		cc.trace = l.trace.With("remote", c.RemoteAddr().String())
	}
	return cc, nil
}

// compressConn is a connection that can switch to compression.
type compressConn struct {
	net.Conn

	// Client to server, only used by the server's reading goroutine
	br      *bufio.Reader // the raw connection
	in      io.Reader     // br, or a decompressor reading from it
	pending []byte        // input for the server not yet read
	literal int64         // literal bytes still to pass on
	authed  bool          // a LOGIN or AUTHENTICATE has been seen
	offer   bool          // see compressListener

	// Server to client
	wmu      sync.Mutex
	out      io.Writer       // capability injection, then a compressor
	inject   *capInjector    // nil once compression is on
	fw       *flate.Writer   // the compressor
	inflater *inflate.Reader // the decompressor, once compression is on

	trace *slog.Logger // see compressListener
	obj   *objectState // OBJECTID (objectid.go)
	ow    *lineWriter  // responses through obj, then out
	ntf   *notifier    // NOTIFY (notify.go)
	// The client's input is read by a goroutine of its own (readLoop),
	// so that Read can hand go-imap a command of the wrapper's own
	// (injQ) while it waits for the client's next one.
	rd       chan inChunk
	rdOnce   sync.Once
	done     chan struct{} // closed by Close
	closed   bool          // wmu held
	boundary bool          // the last chunk ended a command
	rerr     error         // the input's end
	injQ     chan []byte
	injN     atomic.Int64
	idling   bool // readLoop: an IDLE awaits its DONE
	// The reply trace's place in what the proxy sends (wmu held): the
	// start and end of the line so far, and the literal bytes to skip.
	tHead, tTail []byte
	tSkip        int64
}

func newCompressConn(c net.Conn, offer bool) *compressConn {
	cc := &compressConn{Conn: c, br: bufio.NewReader(c), offer: offer, obj: &objectState{},
		rd: make(chan inChunk), done: make(chan struct{}), injQ: make(chan []byte, 8)}
	cc.ntf = &notifier{c: cc}
	cc.in = cc.br
	cc.out = c
	cc.ow = &lineWriter{to: func() io.Writer { return cc.out }, rewrite: func(line []byte) []byte {
		line = cc.obj.response(line)
		if injected(line) {
			return nil // the end of a command the wrapper slipped in
		}
		return line
	}}
	if offer {
		cc.inject = &capInjector{w: c}
		cc.out = cc.inject
	}
	return cc
}

var (
	compressCmdRe = regexp.MustCompile(`(?i)^(\S+) COMPRESS (\S+)\r?\n$`)
	authCmdRe     = regexp.MustCompile(`(?i)^\S+ (LOGIN|AUTHENTICATE) `)
	literalRe     = regexp.MustCompile(`\{([0-9]+)\+?\}\r?\n$`)
)

// literalSize returns the size of the literal a line announces, or 0.
func literalSize(line []byte) int64 {
	m := literalRe.FindSubmatch(line)
	if m == nil {
		return 0
	}
	n, _ := strconv.ParseInt(string(m[1]), 10, 64)
	return n
}

// inChunk is a piece of the client's input: a line, or part of a
// literal. end says it ends a command.
type inChunk struct {
	b   []byte
	err error
	end bool
}

func (c *compressConn) Read(p []byte) (int, error) {
	c.rdOnce.Do(func() { go c.readLoop() })
	for len(c.pending) == 0 {
		if c.rerr != nil {
			return 0, c.rerr
		}
		var ch inChunk
		if c.boundary {
			// Between commands: one of the wrapper's may go first.
			select {
			case ch = <-c.rd:
			case cmd := <-c.injQ:
				c.pending = cmd
				continue
			}
		} else {
			ch = <-c.rd
		}
		c.pending, c.rerr, c.boundary = ch.b, ch.err, ch.end
	}
	n := copy(p, c.pending)
	c.pending = c.pending[n:]
	return n, nil
}

var (
	idleCmdRe = regexp.MustCompile(`(?i)^\S+ IDLE\r?\n$`)
	authStart = regexp.MustCompile(`(?i)^\S+ AUTHENTICATE `)
)

// readLoop reads the client's input, answers what the wrapper answers
// itself (COMPRESS, NOTIFY), and hands the rest to Read.
func (c *compressConn) readLoop() {
	send := func(ch inChunk) bool {
		select {
		case c.rd <- ch:
			return ch.err == nil
		case <-c.done:
			return false
		}
	}
	for {
		if c.literal > 0 {
			buf := make([]byte, min(c.literal, 32<<10))
			n, err := c.in.Read(buf)
			c.literal -= int64(n)
			if !send(inChunk{b: buf[:n], err: err}) {
				return
			}
			continue
		}
		line, err := readLine(c.in)
		if len(line) == 0 {
			if err == nil {
				continue
			}
			send(inChunk{err: err})
			return
		}
		if err != nil && err != io.EOF {
			send(inChunk{err: err})
			return
		}
		if m := compressCmdRe.FindSubmatch(line); m != nil && c.offer {
			if c.trace != nil {
				c.trace.Info("imap trace: client COMPRESS", "algorithm", string(m[2]))
			}
			if werr := c.compress(string(m[1]), string(m[2])); werr != nil {
				send(inChunk{err: werr})
				return
			}
			continue
		}
		if authCmdRe.Match(line) {
			c.authed = true
		}
		if m := notifyCmdRe.FindSubmatch(line); m != nil && c.offer {
			c.traceCommand(line)
			full, rerr := c.readCommand(line)
			if rerr != nil {
				send(inChunk{err: rerr})
				return
			}
			fwd, werr := c.handleNotify(string(m[1]), full[len(m[0]):])
			if werr != nil {
				send(inChunk{err: werr})
				return
			}
			if fwd != nil && !send(inChunk{b: fwd, end: true}) {
				return
			}
			continue
		}
		end := false
		switch {
		case c.idling:
			c.idling = false // DONE
			end = true
		case idleCmdRe.Match(line):
			c.idling = true
		case authStart.Match(line):
			// The exchange that follows is not commands.
		default:
			line = c.obj.command(fixUIDZero(line))
			c.literal = literalSize(line)
			end = c.literal == 0
		}
		c.traceCommand(line)
		if !send(inChunk{b: line, err: err, end: end}) {
			return
		}
	}
}

// readCommand reads the rest of a command whose first line is line: the
// literals it announces, and the lines after them. A synchronizing
// literal is given the go-ahead.
func (c *compressConn) readCommand(line []byte) (string, error) {
	var b bytes.Buffer
	for {
		b.Write(line)
		n := literalSize(line)
		if n == 0 {
			return b.String(), nil
		}
		if n > maxLine {
			return "", errors.New("literal too long")
		}
		if !bytes.HasSuffix(bytes.TrimRight(line, "\r\n"), []byte("+}")) {
			if err := c.reply("+ Ready"); err != nil {
				return "", err
			}
		}
		if _, err := io.CopyN(&b, c.in, n); err != nil {
			return "", err
		}
		var err error
		if line, err = readLine(c.in); err != nil {
			return "", err
		}
	}
}

// readLine reads a line from r, which may be a decompressor without
// buffering of its own.
func readLine(r io.Reader) ([]byte, error) {
	if br, ok := r.(*bufio.Reader); ok {
		return br.ReadBytes('\n')
	}
	var line []byte
	var b [1]byte
	for {
		n, err := r.Read(b[:])
		if n > 0 {
			line = append(line, b[0])
			if b[0] == '\n' {
				return line, nil
			}
		}
		if err != nil {
			return line, err
		}
	}
}

// compress answers a COMPRESS command, turning compression on.
func (c *compressConn) compress(tag, algorithm string) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	reply := func(s string) error {
		_, err := io.WriteString(c.out, tag+" "+s+"\r\n")
		return err
	}
	switch {
	case c.inject == nil:
		return reply("NO [COMPRESSIONACTIVE] DEFLATE is already active")
	case !c.authed:
		return reply("BAD Log in before COMPRESS")
	case !bytes.EqualFold([]byte(algorithm), []byte("DEFLATE")):
		return reply("NO Only DEFLATE is supported")
	}
	if err := reply("OK DEFLATE active"); err != nil {
		return err
	}
	// Anything the client sent after COMPRESS is already compressed
	// Not compress/flate: it stalls on Apple's partial flushes (see the
	// inflate package).
	c.inflater = inflate.NewReader(c.br)
	c.in = bufio.NewReader(c.inflater)
	fw, err := flate.NewWriter(c.Conn, flate.DefaultCompression)
	if err != nil {
		return err
	}
	c.fw = fw
	c.out = inflate.NewFlushWriter(fw)
	c.inject = nil
	return nil
}

func (c *compressConn) Write(p []byte) (int, error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	c.traceReplies(p)
	return c.ow.Write(p)
}

func (c *compressConn) Close() error {
	c.ntf.close()
	c.wmu.Lock()
	if !c.closed {
		c.closed = true
		close(c.done)
	}
	if c.fw != nil {
		_ = c.fw.Close()
	}
	inf := c.inflater
	c.wmu.Unlock()
	err := c.Conn.Close()
	if inf != nil {
		inf.Close()
	}
	return err
}

// capInjector adds COMPRESS=DEFLATE to the capabilities in the server's
// responses.
type capInjector struct {
	w       io.Writer
	line    []byte // the start of a response line
	literal int64  // literal bytes still to pass on
}

// maxLine is how much of a line is held to look for capabilities.
const maxLine = 64 * 1024

func (c *capInjector) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		if c.literal > 0 {
			k := min(int64(len(p)), c.literal)
			if _, err := c.w.Write(p[:k]); err != nil {
				return 0, err
			}
			c.literal -= k
			p = p[k:]
			continue
		}
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			c.line = append(c.line, p...)
			if len(c.line) > maxLine {
				if _, err := c.w.Write(c.line); err != nil {
					return 0, err
				}
				c.line = c.line[:0]
			}
			break
		}
		c.line = append(c.line, p[:i+1]...)
		p = p[i+1:]
		c.literal = literalSize(c.line)
		if _, err := c.w.Write(addCompressCap(c.line)); err != nil {
			return 0, err
		}
		c.line = c.line[:0]
	}
	return n, nil
}

// lineWriter hands each response line to rewrite before writing it to
// to(), and passes literals through unchanged.
type lineWriter struct {
	to      func() io.Writer
	rewrite func([]byte) []byte
	line    []byte
	literal int64
}

func (l *lineWriter) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		if l.literal > 0 {
			k := min(int64(len(p)), l.literal)
			if _, err := l.to().Write(p[:k]); err != nil {
				return 0, err
			}
			l.literal -= k
			p = p[k:]
			continue
		}
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			l.line = append(l.line, p...)
			if len(l.line) > maxLine {
				if _, err := l.to().Write(l.line); err != nil {
					return 0, err
				}
				l.line = l.line[:0]
			}
			break
		}
		l.line = append(l.line, p[:i+1]...)
		p = p[i+1:]
		out := l.rewrite(l.line)
		l.literal = literalSize(out)
		if _, err := l.to().Write(out); err != nil {
			return 0, err
		}
		l.line = l.line[:0]
	}
	return n, nil
}

var capListRe = regexp.MustCompile(`^(\* CAPABILITY |.*\[CAPABILITY )`)

// addCompressCap adds COMPRESS=DEFLATE to a capability response.
func addCompressCap(line []byte) []byte {
	m := capListRe.FindIndex(line)
	if m == nil || bytes.Contains(line, []byte(capCompress)) {
		return line
	}
	out := make([]byte, 0, len(line)+len(capCompress)+1)
	out = append(out, line[:m[1]]...)
	out = append(out, capCompress+" "...)
	return append(out, line[m[1]:]...)
}

var (
	traceCmdRe    = regexp.MustCompile(`^(\S+) ([A-Za-z]+)(?: ([A-Za-z]+))?`)
	traceStatusRe = regexp.MustCompile(`^(\S+ (?:OK|NO|BAD)\b.{0,100}|\* (?:LIST|LSUB|BYE|NO|BAD)\b.{0,100}|\* \d+ (?:EXISTS|EXPUNGE)\b)`)
)

// traceCommand logs a client command line without credentials: LOGIN and
// AUTHENTICATE lose their arguments, and lines that are not commands (an
// AUTHENTICATE response) are not logged at all.
func (c *compressConn) traceCommand(line []byte) {
	if c.trace == nil {
		return
	}
	m := traceCmdRe.FindSubmatch(line)
	if m == nil {
		return
	}
	cmd := strings.ToUpper(string(m[2]))
	if cmd == "UID" && len(m[3]) > 0 {
		cmd += " " + strings.ToUpper(string(m[3]))
	}
	text := strings.TrimRight(string(line), "\r\n")
	if cmd == "LOGIN" || cmd == "AUTHENTICATE" {
		text = string(m[1]) + " " + cmd + " <redacted>"
	}
	if len(text) > 160 {
		text = text[:160] + "..."
	}
	c.trace.Info("imap trace: client", "line", text)
}

// traceReplies logs status replies, folder listings and EXISTS/EXPUNGE
// counts in what the proxy sends, never message contents: the literals
// that carry messages are skipped, so a header line such as
// "X-Spam-Flag: NO" is not taken for a reply (c.wmu held).
func (c *compressConn) traceReplies(p []byte) {
	if c.trace == nil {
		return
	}
	for len(p) > 0 {
		if c.tSkip > 0 {
			n := min(int64(len(p)), c.tSkip)
			p = p[n:]
			c.tSkip -= n
			continue
		}
		i := bytes.IndexByte(p, '\n')
		part := p
		if i >= 0 {
			part = p[:i+1]
		}
		p = p[len(part):]
		// A reply is matched on its start and announces a literal at its
		// end; the middle of a long line is not kept.
		c.tHead = append(c.tHead, part[:min(len(part), traceHead-len(c.tHead))]...)
		c.tTail = append(c.tTail, part...)
		if len(c.tTail) > traceTail {
			c.tTail = append(c.tTail[:0], c.tTail[len(c.tTail)-traceTail:]...)
		}
		if i < 0 {
			return
		}
		if m := traceStatusRe.Find(c.tHead); m != nil {
			c.trace.Info("imap trace: proxy", "line", strings.TrimRight(string(m), "\r\n"))
		}
		c.tSkip = literalSize(c.tTail)
		c.tHead, c.tTail = c.tHead[:0], c.tTail[:0]
	}
}

// The start and end of a reply line kept for the trace.
const (
	traceHead = 160
	traceTail = 32
)

// uidCmdRe matches a UID command and its UID set.
var uidCmdRe = regexp.MustCompile(`(?i)^(\S+ UID (?:FETCH|STORE|COPY|MOVE|EXPUNGE) )([0-9:*,]+)`)

// fixUIDZero turns UID 0 at either end of a UID range into 1. UIDs start
// at 1, so "0:961" means the same as "1:961". Apple Mail sends such
// ranges, which servers accept and go-imap rejects as a bad number set,
// failing the command. A 0 on its own is left: it names no message, and
// as 1 it would name message 1. The length does not change.
func fixUIDZero(line []byte) []byte {
	m := uidCmdRe.FindSubmatchIndex(line)
	if m == nil {
		return line
	}
	set := line[m[4]:m[5]]
	for i := range set {
		if set[i] != '0' {
			continue
		}
		before := i > 0 && set[i-1] != ','
		after := i < len(set)-1 && set[i+1] != ','
		if before && set[i-1] != ':' || after && set[i+1] != ':' {
			continue // a digit of a larger number, such as 10
		}
		if (before && set[i-1] == ':') || (after && set[i+1] == ':') {
			set[i] = '1'
		}
	}
	return line
}
