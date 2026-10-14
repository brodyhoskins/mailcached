package engine

// Chunks: how a message is cut up for the disk store (chunkstore.go), so
// that what messages share is stored once. A message up to chunkWhole is
// one chunk. A larger one is cut into segments: its base64 parts, decoded,
// and the bytes between them. Each segment is cut into chunks where its
// content says (content-defined chunking, FastCDC), so the same
// attachment gives the same chunks in every message that has it, however
// its client wrapped the base64.
//
// A segment rebuilds its bytes exactly: a base64 part is decoded only if
// encoding it again, with its line length and line ending, gives the same
// bytes. Clients have seen the message's size and its parts' sizes, so
// the stored message must be the same to the byte.
//
// The sizes come from a measurement of real caches: dedup saves the same
// at a 16 KiB average as at 64 KiB, and larger chunks compress better and
// make fewer rows. Quoted-printable parts are not decoded: that saved
// under 1%.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"math/rand/v2"
	"mime"
	"net/textproto"
	"strings"
)

const (
	// chunkWhole is the size up to which a message is one chunk.
	chunkWhole = 64 << 10
	// chunkAvg is the average chunk size; chunks are at least a quarter
	// of it and at most four times it.
	chunkAvg = 64 << 10
	chunkMin = chunkAvg / 4
	chunkMax = chunkAvg * 4
	// b64Min is the size from which a base64 part is decoded.
	b64Min = 1 << 10
	// mimeDepth bounds how deep parts nest.
	mimeDepth = 20
)

// Segment kinds, as stored.
const (
	segRaw    = 0
	segBase64 = 1
)

// segment is a range of a message: raw bytes, or a decoded base64 part
// with what encodes it back.
type segment struct {
	kind    int
	lineLen int  // segBase64: characters per line
	crlf    bool // segBase64: lines end with CRLF, not LF
	data    []byte
}

// encoded returns the segment's bytes in the message.
func (s segment) encoded() []byte {
	if s.kind == segRaw {
		return s.data
	}
	enc := base64.StdEncoding.EncodeToString(s.data)
	eol := "\n"
	if s.crlf {
		eol = "\r\n"
	}
	var b bytes.Buffer
	b.Grow(len(enc) + len(enc)/max(s.lineLen, 1)*len(eol))
	for i := 0; i < len(enc); i += s.lineLen {
		if i > 0 {
			b.WriteString(eol)
		}
		b.WriteString(enc[i:min(i+s.lineLen, len(enc))])
	}
	return b.Bytes()
}

// segments cuts a message into segments that rebuild it.
func segments(msg []byte) []segment {
	if len(msg) <= chunkWhole {
		return []segment{{kind: segRaw, data: msg}}
	}
	var parts []b64Part
	findBase64(msg, 0, &parts, 0)
	var out []segment
	pos := 0
	for _, p := range parts { // in message order
		if p.start > pos {
			out = append(out, segment{kind: segRaw, data: msg[pos:p.start]})
		}
		out = append(out, p.seg)
		pos = p.end
	}
	if pos < len(msg) {
		out = append(out, segment{kind: segRaw, data: msg[pos:]})
	}
	return out
}

// chunks cuts a segment's data at content-defined boundaries. A message
// up to chunkWhole is one segment and one chunk.
func (s segment) chunks() [][]byte {
	data := s.data
	if len(data) <= chunkWhole && s.kind == segRaw {
		return [][]byte{data}
	}
	var out [][]byte
	for len(data) > 0 {
		n := fastCDC(data)
		out = append(out, data[:n])
		data = data[n:]
	}
	return out
}

// chunkHash names a chunk by its content (meta chunk_hash).
func chunkHash(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// gear is FastCDC's table of random values, one per byte. It must never
// change: other values cut the same data elsewhere, and no new chunk
// would match a stored one.
var gear = func() (g [256]uint64) {
	r := rand.New(rand.NewPCG(0x6d61696c, 0x63616368))
	for i := range g {
		g[i] = r.Uint64()
	}
	return
}()

// Normalized chunking: a boundary is harder to find before chunkAvg and
// easier after, so sizes gather near it.
const (
	cdcBits  = 16 // log2(chunkAvg)
	cdcMaskS = (1<<(cdcBits+2) - 1) << (64 - cdcBits - 2)
	cdcMaskL = (1<<(cdcBits-2) - 1) << (64 - cdcBits + 2)
)

// fastCDC returns the length of the first chunk of b.
func fastCDC(b []byte) int {
	if len(b) <= chunkMin {
		return len(b)
	}
	b = b[:min(len(b), chunkMax)]
	var h uint64
	i := chunkMin
	for ; i < len(b) && i < chunkAvg; i++ {
		h = h<<1 + gear[b[i]]
		if h&cdcMaskS == 0 {
			return i + 1
		}
	}
	for ; i < len(b); i++ {
		h = h<<1 + gear[b[i]]
		if h&cdcMaskL == 0 {
			return i + 1
		}
	}
	return len(b)
}

// b64Part is a base64 part that rebuilds exactly, at [start, end) of the
// message.
type b64Part struct {
	start, end int
	seg        segment
}

// findBase64 adds the base64 parts of the entity ent, at off in the
// message, in message order.
func findBase64(ent []byte, off int, out *[]b64Part, depth int) {
	if depth > mimeDepth {
		return
	}
	hdrEnd, bodyStart := headerEnd(ent)
	if hdrEnd < 0 {
		return
	}
	h, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(append(ent[:hdrEnd:hdrEnd], "\r\n\r\n"...)))).ReadMIMEHeader()
	if err != nil {
		return
	}
	body := ent[bodyStart:]
	off += bodyStart
	mt, params, _ := mime.ParseMediaType(h.Get("Content-Type"))
	switch {
	case strings.HasPrefix(mt, "multipart/") && params["boundary"] != "":
		for _, p := range bodyParts(body, params["boundary"]) {
			findBase64(body[p[0]:p[1]], off+p[0], out, depth+1)
		}
	case mt == "message/rfc822":
		findBase64(body, off, out, depth+1)
	case strings.EqualFold(strings.TrimSpace(h.Get("Content-Transfer-Encoding")), "base64"):
		enc := bytes.TrimRight(body, " \t\r\n")
		if len(enc) < b64Min {
			return
		}
		if seg, ok := decodeBase64(enc); ok {
			*out = append(*out, b64Part{off, off + len(enc), seg})
		}
	}
}

// decodeBase64 decodes base64 that encodes back to exactly enc.
func decodeBase64(enc []byte) (segment, bool) {
	seg := segment{kind: segBase64, crlf: bytes.Contains(enc, []byte("\r\n"))}
	eol := []byte("\n")
	if seg.crlf {
		eol = []byte("\r\n")
	}
	if seg.lineLen = bytes.Index(enc, eol); seg.lineLen < 0 {
		seg.lineLen = len(enc)
	}
	if seg.lineLen == 0 {
		return segment{}, false
	}
	flat := bytes.ReplaceAll(enc, eol, nil)
	seg.data = make([]byte, base64.StdEncoding.DecodedLen(len(flat)))
	n, err := base64.StdEncoding.Strict().Decode(seg.data, flat)
	if err != nil {
		return segment{}, false
	}
	seg.data = seg.data[:n]
	return seg, bytes.Equal(seg.encoded(), enc)
}

// headerEnd returns where an entity's header ends and its body starts,
// or -1 without a body.
func headerEnd(b []byte) (int, int) {
	if bytes.HasPrefix(b, []byte("\r\n")) {
		return 0, 2
	}
	if bytes.HasPrefix(b, []byte("\n")) {
		return 0, 1
	}
	i, j := bytes.Index(b, []byte("\r\n\r\n")), bytes.Index(b, []byte("\n\n"))
	switch {
	case i >= 0 && (j < 0 || i <= j):
		return i, i + 4
	case j >= 0:
		return j, j + 2
	}
	return -1, -1
}

// bodyParts returns [start, end) of each part of a multipart body. The
// line break before a delimiter line belongs to the delimiter.
func bodyParts(body []byte, boundary string) [][2]int {
	delim := []byte("--" + boundary)
	var lines []int // where each delimiter line starts
	if bytes.HasPrefix(body, delim) {
		lines = append(lines, 0)
	}
	nl := append([]byte("\n"), delim...)
	for i := 0; ; {
		j := bytes.Index(body[i:], nl)
		if j < 0 {
			break
		}
		lines = append(lines, i+j+1)
		i += j + 1
	}
	var out [][2]int
	for k := 0; k+1 < len(lines); k++ {
		ln := lines[k]
		if bytes.HasPrefix(body[ln+len(delim):], []byte("--")) {
			break // the close delimiter
		}
		eol := bytes.IndexByte(body[ln:], '\n')
		if eol < 0 {
			break
		}
		start, end := ln+eol+1, lines[k+1]-1
		if end > start && body[end-1] == '\r' {
			end--
		}
		if end >= start {
			out = append(out, [2]int{start, end})
		}
	}
	return out
}
