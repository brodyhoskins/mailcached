// Package httpenc handles HTTP Content-Encoding: Zstandard (preferred) and
// gzip, both ways. Clients decode responses with Decode; servers wrap
// their responses with Wrap, which picks an encoding from the request's
// Accept-Encoding, and decode request bodies with Decode as well.
package httpenc

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
)

// Accept is the Accept-Encoding a client sends.
const Accept = "zstd, gzip"

// MaxWindow bounds the memory a zstd stream may ask the decoder for.
const MaxWindow = 64 << 20

// Decode returns the decoded body of a message with Content-Encoding enc
// ("" or "identity" for none).
func Decode(enc string, body io.Reader) (io.ReadCloser, error) {
	switch enc = strings.ToLower(strings.TrimSpace(enc)); enc {
	case "", "identity":
		return io.NopCloser(body), nil
	case "zstd":
		d, err := zstd.NewReader(body, zstd.WithDecoderMaxMemory(MaxWindow), zstd.WithDecoderConcurrency(1))
		if err != nil {
			return nil, err
		}
		return d.IOReadCloser(), nil
	case "gzip":
		return gzip.NewReader(body)
	default:
		return nil, fmt.Errorf("unsupported Content-Encoding %q", enc)
	}
}

// ErrTooLarge means a decoded body went past the limit.
var ErrTooLarge = errors.New("body too large")

// ReadAll reads a body with Content-Encoding enc, decoded, up to max
// bytes after decoding, so a small compressed body cannot expand without
// bound.
func ReadAll(enc string, body io.Reader, max int64) ([]byte, error) {
	r, err := Decode(enc, body)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, ErrTooLarge
	}
	return b, nil
}

// Negotiate picks the encoding for a response from Accept-Encoding: "zstd",
// "gzip" or "" for none. A coding with q=0 is refused.
func Negotiate(accept string) string {
	var zstdQ, gzipQ float64 = -1, -1
	for _, part := range strings.Split(accept, ",") {
		name, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		q := 1.0
		for _, p := range strings.Split(params, ";") {
			k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
			if strings.EqualFold(k, "q") {
				if f, err := strconv.ParseFloat(v, 64); err == nil {
					q = f
				}
			}
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "zstd":
			zstdQ = q
		case "gzip", "x-gzip":
			gzipQ = q
		case "*":
			if zstdQ < 0 {
				zstdQ = q
			}
			if gzipQ < 0 {
				gzipQ = q
			}
		}
	}
	switch {
	case zstdQ > 0 && zstdQ >= gzipQ:
		return "zstd"
	case gzipQ > 0:
		return "gzip"
	}
	return ""
}

// MinSize is the smallest body Wrap compresses: below it, the encoding
// costs more than it saves.
const MinSize = 1024

var (
	zstdPool = sync.Pool{New: func() any {
		e, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1),
			zstd.WithWindowSize(1<<20))
		return e
	}}
	gzipPool = sync.Pool{New: func() any { return gzip.NewWriter(nil) }}
)

// encoder is a pooled zstd or gzip writer.
type encoder interface {
	io.WriteCloser
	Flush() error
	Reset(io.Writer)
}

// Wrap returns a ResponseWriter that compresses what the handler writes
// with the encoding Negotiate picks for r, and a function to call when the
// handler is done. A body that ends below MinSize before any Flush goes
// out as it is. Flush compresses what was written so far and sends it,
// for streams such as EventSource.
func Wrap(w http.ResponseWriter, r *http.Request) (http.ResponseWriter, func() error) {
	w.Header().Add("Vary", "Accept-Encoding")
	enc := Negotiate(r.Header.Get("Accept-Encoding"))
	if enc == "" || r.Method == http.MethodHead {
		return w, func() error { return nil }
	}
	cw := &compressWriter{ResponseWriter: w, enc: enc}
	return cw, cw.finish
}

// compressWriter buffers the first MinSize bytes to decide whether to
// compress, then streams through the encoder.
type compressWriter struct {
	http.ResponseWriter
	enc     string
	status  int
	buf     []byte
	started bool // headers sent
	e       encoder
}

func (c *compressWriter) WriteHeader(status int) {
	if c.status == 0 {
		c.status = status
	}
}

func (c *compressWriter) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if c.e != nil {
		return c.e.Write(p)
	}
	if c.started {
		return c.ResponseWriter.Write(p)
	}
	c.buf = append(c.buf, p...)
	if len(c.buf) >= MinSize {
		if err := c.start(true); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

// start sends the headers and the buffered bytes, through an encoder if
// compress.
func (c *compressWriter) start(compress bool) error {
	c.started = true
	h := c.Header()
	compress = compress && h.Get("Content-Encoding") == "" && c.status != http.StatusNoContent &&
		c.status != http.StatusNotModified
	if compress {
		h.Set("Content-Encoding", c.enc)
		h.Del("Content-Length")
		switch c.enc {
		case "zstd":
			c.e = zstdPool.Get().(*zstd.Encoder)
		default:
			c.e = gzipPool.Get().(*gzip.Writer)
		}
		c.e.Reset(c.ResponseWriter)
	}
	c.ResponseWriter.WriteHeader(c.status)
	buf := c.buf
	c.buf = nil
	if len(buf) == 0 {
		return nil
	}
	var err error
	if c.e != nil {
		_, err = c.e.Write(buf)
	} else {
		_, err = c.ResponseWriter.Write(buf)
	}
	return err
}

// Flush sends what was written so far. A stream is compressed from its
// first Flush on, whatever its size.
func (c *compressWriter) Flush() {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if !c.started {
		if err := c.start(true); err != nil {
			return
		}
	}
	if c.e != nil {
		if err := c.e.Flush(); err != nil {
			return
		}
	}
	http.NewResponseController(c.ResponseWriter).Flush()
}

func (c *compressWriter) finish() error {
	if !c.started {
		if c.status == 0 {
			c.status = http.StatusOK
		}
		if err := c.start(len(c.buf) >= MinSize); err != nil {
			return err
		}
	}
	if c.e == nil {
		return nil
	}
	err := c.e.Close()
	switch e := c.e.(type) {
	case *zstd.Encoder:
		e.Reset(nil)
		zstdPool.Put(e)
	case *gzip.Writer:
		e.Reset(io.Discard)
		gzipPool.Put(e)
	}
	c.e = nil
	return err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (c *compressWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// Hijack is not supported through compression.
func (c *compressWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, http.ErrNotSupported
}
