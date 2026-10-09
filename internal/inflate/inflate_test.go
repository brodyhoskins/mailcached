package inflate

import (
	"bytes"
	"compress/flate"
	"encoding/hex"
	"io"
	"math/rand"
	"testing"
	"time"
)

// TestRoundTrip decodes what compress/flate encodes, at every level.
func TestRoundTrip(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	random := make([]byte, 200_000)
	rng.Read(random)
	text := bytes.Repeat([]byte("Subject: Quarterly numbers\r\nThe secret number is 42.\r\n"), 4000)
	mixed := append(append([]byte(nil), text[:50_000]...), random[:50_000]...)

	for _, data := range [][]byte{nil, []byte("x"), text, random, mixed} {
		for level := flate.HuffmanOnly; level <= flate.BestCompression; level++ {
			var buf bytes.Buffer
			w, _ := flate.NewWriter(&buf, level)
			// Flush now and then, as an IMAP peer does.
			for chunk := range chunks(data, 7_777) {
				w.Write(chunk)
				w.Flush()
			}
			w.Close()
			got, err := io.ReadAll(NewReader(&buf))
			if err != nil {
				t.Fatalf("level %d, %d bytes: %v", level, len(data), err)
			}
			if !bytes.Equal(got, data) {
				t.Fatalf("level %d, %d bytes: output differs", level, len(data))
			}
		}
	}
}

func chunks(b []byte, n int) func(func([]byte) bool) {
	return func(yield func([]byte) bool) {
		for len(b) > 0 {
			k := min(n, len(b))
			if !yield(b[:k]) {
				return
			}
			b = b[k:]
		}
	}
}

// readWithin reads exactly n bytes from r or fails after a timeout.
func readWithin(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	type res struct {
		b   []byte
		err error
	}
	c := make(chan res, 1)
	go func() {
		b := make([]byte, n)
		_, err := io.ReadFull(r, b)
		c <- res{b, err}
	}()
	select {
	case got := <-c:
		if got.err != nil {
			t.Fatal(got.err)
		}
		return got.b
	case <-time.After(2 * time.Second):
		t.Fatal("decoder stalled waiting for input it does not need")
		return nil
	}
}

// TestPartialFlush feeds zlib output written with Z_PARTIAL_FLUSH, as
// Apple's mail clients send it, one write at a time. Each command must
// come out before the next write arrives. The data was made with:
//
//	c = zlib.compressobj(6, zlib.DEFLATED, -15)
//	c.compress(cmd) + c.flush(zlib.Z_PARTIAL_FLUSH)
func TestPartialFlush(t *testing.T) {
	writes := []struct{ hex, want string }{
		{"723256f0f10c0e5150525250d252e2e50208", "B3 LIST \"\" \"*\"\r\n"},
		{"2027138560571f57e710054f3f27ff085e2e8000", "B4 SELECT INBOX\r\n"},
		{"723255f074f1711d650c590640", string(bytes.Repeat([]byte("B5 IDLE\r\n"), 50))},
	}
	pr, pw := io.Pipe()
	defer pw.Close()
	r := NewReader(pr)
	defer r.Close()
	for _, w := range writes {
		b, _ := hex.DecodeString(w.hex)
		go pw.Write(b)
		if got := readWithin(t, r, len(w.want)); string(got) != w.want {
			t.Fatalf("got %q, want %q", got, w.want)
		}
	}
}

// TestSyncFlushNoLookahead checks the same for compress/flate's Flush.
func TestSyncFlushNoLookahead(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	w, _ := flate.NewWriter(pw, flate.DefaultCompression)
	r := NewReader(pr)
	defer r.Close()
	// One goroutine writes, a message at a time, each after the last was read.
	msgs := make(chan []byte)
	defer close(msgs)
	go func() {
		for m := range msgs {
			w.Write(m)
			w.Flush()
		}
	}()
	for i := 0; i < 20; i++ {
		msg := bytes.Repeat([]byte{byte('a' + i)}, 1+i*97)
		msgs <- msg
		if got := readWithin(t, r, len(msg)); !bytes.Equal(got, msg) {
			t.Fatalf("command %d differs", i)
		}
	}
}

func TestCorrupt(t *testing.T) {
	for _, in := range [][]byte{
		{0x07},                         // reserved block type
		{0x01, 0x05, 0x00, 0x00, 0x00}, // stored length check fails
	} {
		if _, err := io.ReadAll(NewReader(bytes.NewReader(in))); err == nil {
			t.Errorf("%x: no error", in)
		}
	}
}

func BenchmarkDecode(b *testing.B) {
	text := bytes.Repeat([]byte("Subject: Quarterly numbers\r\nThe secret number is 42.\r\n"), 20000)
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write(text)
	w.Close()
	b.SetBytes(int64(len(text)))
	for b.Loop() {
		io.Copy(io.Discard, NewReader(bytes.NewReader(buf.Bytes())))
	}
}

// TestHangUp checks that a stream cut off mid-block, as when a client
// disconnects, ends with io.EOF after the data decoded so far.
func TestHangUp(t *testing.T) {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.DefaultCompression)
	w.Write([]byte("A1 NOOP\r\n"))
	w.Flush()
	w.Write([]byte("A2 IDLE\r\n")) // never flushed: the client hangs up
	r := NewReader(bytes.NewReader(buf.Bytes()))
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("err = %v, want a clean end", err)
	}
	if string(got) != "A1 NOOP\r\n" {
		t.Fatalf("got %q", got)
	}
}
