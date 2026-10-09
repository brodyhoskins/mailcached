// Package inflate decodes a raw DEFLATE stream (RFC 1951) for interactive
// protocols such as IMAP COMPRESS=DEFLATE (RFC 4978).
//
// Go's decoders (compress/flate and github.com/klauspost/compress/flate)
// read a few bits past the symbol they decode. A peer that ends each write
// with zlib's Z_PARTIAL_FLUSH, as RFC 4978 suggests and Apple's clients do,
// leaves the stream a few bits into an empty block, so those decoders wait
// for the peer's next write before returning the data they already have.
// With a request/response protocol that write never comes.
//
// This decoder decodes symbols one bit at a time, after Mark Adler's
// puff.c, so it never reads past a code, and it runs in its own goroutine:
// just before it would wait for input, it hands over everything decoded so
// far. One bit at a time is slower than a table decoder but fast enough
// for what a mail client sends.
package inflate

import (
	"bufio"
	"errors"
	"io"
	"sync"
)

const (
	maxBits    = 15    // longest code
	windowSize = 32768 // farthest back-reference
	maxLitLen  = 288
	maxDist    = 30
)

var (
	errCorrupt = errors.New("inflate: corrupt input")

	lengthBase  = [29]uint16{3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258}
	lengthExtra = [29]uint8{0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0}
	distBase    = [30]uint16{1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577}
	distExtra   = [30]uint8{0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13}
	// Order of the code length code lengths in a dynamic block header.
	clOrder = [19]uint8{16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15}

	fixedLit, fixedDist = fixedTables()
)

// huffman is a canonical Huffman code: how many codes have each length,
// and the symbols in code order.
type huffman struct {
	count  [maxBits + 1]uint16
	symbol []uint16
}

// build makes the code for the given code lengths. Incomplete codes are
// allowed, as in zlib, but oversubscribed ones are not.
func (h *huffman) build(lengths []uint8) error {
	h.count = [maxBits + 1]uint16{}
	for _, l := range lengths {
		h.count[l]++
	}
	left := 1
	for l := 1; l <= maxBits; l++ {
		left = left<<1 - int(h.count[l])
		if left < 0 {
			return errCorrupt
		}
	}
	var offs [maxBits + 1]uint16
	for l := 1; l < maxBits; l++ {
		offs[l+1] = offs[l] + h.count[l]
	}
	h.symbol = make([]uint16, len(lengths))
	for sym, l := range lengths {
		if l != 0 {
			h.symbol[offs[l]] = uint16(sym)
			offs[l]++
		}
	}
	return nil
}

func fixedTables() (*huffman, *huffman) {
	var lens [maxLitLen]uint8
	for i := range lens {
		switch {
		case i < 144:
			lens[i] = 8
		case i < 256:
			lens[i] = 9
		case i < 280:
			lens[i] = 7
		default:
			lens[i] = 8
		}
	}
	lit := &huffman{}
	_ = lit.build(lens[:])
	var dl [maxDist]uint8
	for i := range dl {
		dl[i] = 5
	}
	dist := &huffman{}
	_ = dist.build(dl[:])
	return lit, dist
}

// Reader decodes a raw DEFLATE stream.
type Reader struct {
	ch   chan []byte   // decoded chunks
	done chan struct{} // closed by Close
	buf  []byte        // rest of the current chunk
	err  error         // why ch was closed; read after it is

	closeOnce sync.Once
}

// NewReader decodes src in a new goroutine, which ends at the end of the
// stream, on an error from src, or after Close.
func NewReader(src io.Reader) *Reader {
	br, ok := src.(*bufio.Reader)
	if !ok {
		br = bufio.NewReader(src)
	}
	r := &Reader{ch: make(chan []byte, 4), done: make(chan struct{})}
	d := &decoder{src: br, r: r}
	go d.run()
	return r
}

// Read returns decoded data as soon as there is some.
func (r *Reader) Read(p []byte) (int, error) {
	if len(r.buf) == 0 {
		chunk, ok := <-r.ch
		if !ok {
			return 0, r.err
		}
		r.buf = chunk
	}
	n := copy(p, r.buf)
	r.buf = r.buf[n:]
	return n, nil
}

// Close stops the decoder. It does not close the source. It is safe to
// call more than once, from any goroutine.
func (r *Reader) Close() error {
	r.closeOnce.Do(func() { close(r.done) })
	return nil
}

// decoder is the state of the decoding goroutine.
type decoder struct {
	src *bufio.Reader
	r   *Reader

	bits  uint32 // bit buffer, least significant first
	nbits uint

	final           bool // the current block is the last one
	dynLit, dynDist huffman

	hist []byte // output, at least the last windowSize bytes
	mark int    // hist[mark:] is not yet handed over
}

func (d *decoder) run() {
	err := d.blocks()
	if err == nil {
		err = io.EOF
	}
	if d.flush() {
		d.r.err = err
	}
	close(d.r.ch)
}

// flush hands over the output not yet sent. It reports false if the
// Reader was closed.
func (d *decoder) flush() bool {
	if d.mark == len(d.hist) {
		return true
	}
	chunk := append([]byte(nil), d.hist[d.mark:]...)
	select {
	case d.r.ch <- chunk:
	case <-d.r.done:
		return false
	}
	d.mark = len(d.hist)
	if len(d.hist) > 2*windowSize {
		keep := d.hist[len(d.hist)-windowSize:]
		d.hist = append(d.hist[:0], keep...)
		d.mark = len(d.hist)
	}
	return true
}

var errClosed = errors.New("inflate: closed")

// need ensures n bits are buffered. Before it would wait for input, it
// hands over what has been decoded.
func (d *decoder) need(n uint) error {
	for d.nbits < n {
		if d.src.Buffered() == 0 && !d.flush() {
			return errClosed
		}
		b, err := d.src.ReadByte()
		if err != nil {
			// A peer that hangs up mid-stream is a normal end for a
			// network protocol: everything decoded has been handed over.
			return err
		}
		d.bits |= uint32(b) << d.nbits
		d.nbits += 8
	}
	return nil
}

func (d *decoder) take(n uint) (uint32, error) {
	if n == 0 {
		return 0, nil
	}
	if err := d.need(n); err != nil {
		return 0, err
	}
	v := d.bits & (1<<n - 1)
	d.bits >>= n
	d.nbits -= n
	return v, nil
}

// decode reads one symbol a bit at a time, so it never reads past the end
// of the symbol's code.
func (d *decoder) decode(h *huffman) (int, error) {
	code, first, index := 0, 0, 0
	for l := 1; l <= maxBits; l++ {
		b, err := d.take(1)
		if err != nil {
			return 0, err
		}
		code |= int(b)
		count := int(h.count[l])
		if code-count < first {
			return int(h.symbol[index+code-first]), nil
		}
		index += count
		first = (first + count) << 1
		code <<= 1
	}
	return 0, errCorrupt
}

// blocks decodes blocks until the last one.
func (d *decoder) blocks() error {
	for {
		v, err := d.take(3)
		if err != nil {
			return err
		}
		d.final = v&1 == 1
		switch v >> 1 {
		case 0:
			err = d.stored()
		case 1:
			err = d.codes(fixedLit, fixedDist)
		case 2:
			if err = d.dynamic(); err == nil {
				err = d.codes(&d.dynLit, &d.dynDist)
			}
		default:
			err = errCorrupt
		}
		if err != nil {
			return err
		}
		if d.final {
			return nil
		}
		// Keep memory bounded on long runs without waits.
		if len(d.hist)-d.mark > windowSize && !d.flush() {
			return errClosed
		}
	}
}

func (d *decoder) stored() error {
	d.bits, d.nbits = 0, 0 // skip to a byte boundary
	lens, err := d.take(32)
	if err != nil {
		return err
	}
	if uint16(lens) != ^uint16(lens>>16) {
		return errCorrupt
	}
	for n := int(uint16(lens)); n > 0; {
		if d.src.Buffered() == 0 && !d.flush() {
			return errClosed
		}
		k := min(n, max(d.src.Buffered(), 1))
		start := len(d.hist)
		d.hist = append(d.hist, make([]byte, k)...)
		if _, err := io.ReadFull(d.src, d.hist[start:]); err != nil {
			if err == io.ErrUnexpectedEOF {
				err = io.EOF // see need
			}
			return err
		}
		n -= k
	}
	return nil
}

func (d *decoder) dynamic() error {
	v, err := d.take(14)
	if err != nil {
		return err
	}
	nlen, ndist, ncode := int(v&31)+257, int(v>>5&31)+1, int(v>>10)+4
	if nlen > 286 || ndist > maxDist {
		return errCorrupt
	}
	var cl [19]uint8
	for i := 0; i < ncode; i++ {
		b, err := d.take(3)
		if err != nil {
			return err
		}
		cl[clOrder[i]] = uint8(b)
	}
	var clCode huffman
	if err := clCode.build(cl[:]); err != nil {
		return err
	}
	lengths := make([]uint8, nlen+ndist)
	for i := 0; i < len(lengths); {
		sym, err := d.decode(&clCode)
		if err != nil {
			return err
		}
		if sym < 16 {
			lengths[i] = uint8(sym)
			i++
			continue
		}
		var val uint8
		var rep uint32
		switch sym {
		case 16:
			if i == 0 {
				return errCorrupt
			}
			val = lengths[i-1]
			rep, err = d.take(2)
			rep += 3
		case 17:
			rep, err = d.take(3)
			rep += 3
		default:
			rep, err = d.take(7)
			rep += 11
		}
		if err != nil {
			return err
		}
		if i+int(rep) > len(lengths) {
			return errCorrupt
		}
		for ; rep > 0; rep-- {
			lengths[i] = val
			i++
		}
	}
	if lengths[256] == 0 {
		return errCorrupt // no end-of-block code
	}
	if err := d.dynLit.build(lengths[:nlen]); err != nil {
		return err
	}
	return d.dynDist.build(lengths[nlen:])
}

// codes decodes literals and back-references up to the end of the block.
func (d *decoder) codes(lit, dist *huffman) error {
	for {
		sym, err := d.decode(lit)
		if err != nil {
			return err
		}
		switch {
		case sym < 256:
			d.hist = append(d.hist, byte(sym))
			continue
		case sym == 256:
			return nil
		}
		sym -= 257
		if sym >= len(lengthBase) {
			return errCorrupt
		}
		extra, err := d.take(uint(lengthExtra[sym]))
		if err != nil {
			return err
		}
		length := int(lengthBase[sym]) + int(extra)
		dsym, err := d.decode(dist)
		if err != nil {
			return err
		}
		if dsym >= len(distBase) {
			return errCorrupt
		}
		extra, err = d.take(uint(distExtra[dsym]))
		if err != nil {
			return err
		}
		back := int(distBase[dsym]) + int(extra)
		if back > len(d.hist) {
			return errCorrupt
		}
		start := len(d.hist) - back
		for i := 0; i < length; i++ { // overlapping copies repeat bytes
			d.hist = append(d.hist, d.hist[start+i])
		}
	}
}
