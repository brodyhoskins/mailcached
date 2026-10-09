package httpenc

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNegotiate(t *testing.T) {
	for accept, want := range map[string]string{
		"":                     "",
		"identity":             "",
		"gzip":                 "gzip",
		"zstd":                 "zstd",
		"gzip, zstd":           "zstd",
		"zstd;q=0.5, gzip":     "gzip",
		"zstd;q=0, gzip;q=0":   "",
		"*":                    "zstd",
		"gzip;q=0.8, *;q=0.1":  "gzip",
		"br, deflate":          "",
		" GZIP ; q=1 , x-gzip": "gzip",
	} {
		if got := Negotiate(accept); got != want {
			t.Errorf("Negotiate(%q) = %q, want %q", accept, got, want)
		}
	}
}

func serve(t *testing.T, accept string, write func(w http.ResponseWriter)) *http.Response {
	t.Helper()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cw, done := Wrap(w, r)
		write(cw)
		if err := done(); err != nil {
			t.Error(err)
		}
	})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	if accept != "" {
		r.Header.Set("Accept-Encoding", accept)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec.Result()
}

func TestRoundTrip(t *testing.T) {
	body := []byte(strings.Repeat("The quick brown fox jumps over the lazy dog. ", 200))
	for _, accept := range []string{"zstd", "gzip", ""} {
		resp := serve(t, accept, func(w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/plain")
			w.Write(body[:100])
			w.Write(body[100:])
		})
		enc := resp.Header.Get("Content-Encoding")
		if enc != accept {
			t.Errorf("Accept-Encoding %q: Content-Encoding %q", accept, enc)
		}
		if resp.Header.Get("Vary") != "Accept-Encoding" {
			t.Errorf("Vary %q", resp.Header.Get("Vary"))
		}
		raw, _ := io.ReadAll(resp.Body)
		if accept != "" && len(raw) >= len(body) {
			t.Errorf("%s: %d bytes, not compressed", accept, len(raw))
		}
		got, err := ReadAll(enc, bytes.NewReader(raw), 1<<20)
		if err != nil || !bytes.Equal(got, body) {
			t.Errorf("%s: decoded %d bytes, err %v", accept, len(got), err)
		}
	}
}

func TestSmallBodyNotCompressed(t *testing.T) {
	resp := serve(t, "zstd", func(w http.ResponseWriter) {
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"ok":true}`))
	})
	if resp.Header.Get("Content-Encoding") != "" || resp.StatusCode != http.StatusCreated {
		t.Fatalf("status %d, Content-Encoding %q", resp.StatusCode, resp.Header.Get("Content-Encoding"))
	}
	if b, _ := io.ReadAll(resp.Body); string(b) != `{"ok":true}` {
		t.Fatalf("body %q", b)
	}
}

// A flushed stream is compressed, and each flush can be decoded before
// the stream ends.
func TestFlushStreams(t *testing.T) {
	for _, enc := range []string{"zstd", "gzip"} {
		pr, pw := io.Pipe()
		rw := &pipeWriter{h: http.Header{}, w: pw}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Accept-Encoding", enc)
		cw, done := Wrap(rw, r)
		wrote := make(chan struct{})
		go func() {
			defer close(wrote)
			cw.Write([]byte("event: state\ndata: 1\n\n"))
			cw.(http.Flusher).Flush()
		}()
		d, err := Decode(enc, pr)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 64)
		n, err := io.ReadAtLeast(d, buf, len("event: state\ndata: 1\n\n"))
		if err != nil || string(buf[:n]) != "event: state\ndata: 1\n\n" {
			t.Fatalf("%s: read %q, %v", enc, buf[:n], err)
		}
		if rw.h.Get("Content-Encoding") != enc {
			t.Fatalf("%s: Content-Encoding %q", enc, rw.h.Get("Content-Encoding"))
		}
		<-wrote
		go io.Copy(io.Discard, pr)
		done()
		pw.Close()
	}
}

func TestReadAllLimit(t *testing.T) {
	var buf bytes.Buffer
	cw, done := Wrap(&recorder{h: http.Header{}, w: &buf}, gzipRequest())
	cw.Write(make([]byte, 10000))
	done()
	if _, err := ReadAll("gzip", &buf, 100); err != ErrTooLarge {
		t.Fatalf("err %v", err)
	}
}

func gzipRequest() *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Accept-Encoding", "gzip")
	return r
}

// pipeWriter is a ResponseWriter that streams to a pipe.
type pipeWriter struct {
	h http.Header
	w io.Writer
}

func (p *pipeWriter) Header() http.Header         { return p.h }
func (p *pipeWriter) Write(b []byte) (int, error) { return p.w.Write(b) }
func (p *pipeWriter) WriteHeader(int)             {}
func (p *pipeWriter) Flush()                      {}

type recorder = pipeWriter
