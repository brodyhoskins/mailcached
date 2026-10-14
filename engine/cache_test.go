package engine

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const alice = "alice@example.com"

// testCache returns a cache on dir, closed with the test.
func testCache(t *testing.T, dir string, plain bool) *Cache {
	t.Helper()
	c := &Cache{Dir: dir, MaxBytes: 1 << 20, Plain: plain}
	t.Cleanup(func() { c.Close() })
	return c
}

// count returns a number from the account's chunk database.
func count(t *testing.T, c *Cache, query string) int64 {
	t.Helper()
	db, err := c.chunkDB(alice)
	if err != nil {
		t.Fatal(err)
	}
	var n int64
	if err := db.w.QueryRow(query).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// random returns n bytes that do not compress.
func random(seed uint64, n int) []byte {
	r := rand.New(rand.NewPCG(seed, seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

// wrap encodes data as base64 lines of width ending in eol.
func wrap(data []byte, width int, eol string) string {
	enc := base64.StdEncoding.EncodeToString(data)
	var lines []string
	for i := 0; i < len(enc); i += width {
		lines = append(lines, enc[i:min(i+width, len(enc))])
	}
	return strings.Join(lines, eol)
}

// mailWith returns a message with a text part and an attachment, encoded
// with width and eol.
func mailWith(text string, att []byte, width int, eol string) []byte {
	return []byte(strings.Join([]string{
		"Message-ID: <" + text + "@example.com>",
		`Content-Type: multipart/mixed; boundary="b1"`,
		"",
		"--b1",
		"Content-Type: text/plain",
		"",
		strings.Repeat(text+" ", 100),
		"--b1",
		"Content-Type: application/octet-stream",
		"Content-Transfer-Encoding: base64",
		"",
		wrap(att, width, eol),
		"--b1--",
		"",
	}, eol))
}

func TestCacheCompressesOnDisk(t *testing.T) {
	dir := t.TempDir()
	msg := bytes.Repeat([]byte("Subject: hello\r\n\r\nThe same line, again and again.\r\n"), 200)
	key := hashKey("test", "compress")
	c := testCache(t, dir, false)
	if err := c.Put(alice, key, msg, true); err != nil {
		t.Fatal(err)
	}
	if n := count(t, c, `SELECT sum(length(data)) FROM chunks`); n >= int64(len(msg))/4 {
		t.Errorf("stored %d bytes for a %d-byte message", n, len(msg))
	}
	// A fresh cache has nothing in memory, so this reads the disk copy.
	if got := testCache(t, dir, false).Get(alice, key); !bytes.Equal(got, msg) {
		t.Fatal("disk copy does not round-trip")
	}
}

// TestCacheRoundTrip reads back, to the byte, messages whose base64
// parts are decoded, and ones whose parts cannot be.
func TestCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	att := random(1, 300<<10)
	irregular := []byte(strings.Replace(string(mailWith("odd", att, 76, "\r\n")), "\r\n", "\r\n\r\n", 1))
	nested := []byte("Content-Type: multipart/mixed; boundary=outer\n\n--outer\nContent-Type: message/rfc822\n\n" +
		string(mailWith("inner", random(2, 100<<10), 64, "\n")) + "\n--outer--\n")
	msgs := map[string][]byte{
		"small":     []byte("Subject: small\r\n\r\nHello.\r\n"),
		"crlf76":    mailWith("crlf", att, 76, "\r\n"),
		"lf72":      mailWith("lf", att, 72, "\n"),
		"irregular": irregular,
		"nested":    nested,
		// The last base64 line longer than the rest: kept as it is.
		"ragged":  append(mailWith("ragged", random(3, 100<<10), 76, "\r\n"), []byte("QUFB\r\n")...),
		"no mime": bytes.Repeat([]byte("plain text without a header\n"), 5000),
	}
	c := testCache(t, dir, false)
	for name, m := range msgs {
		if err := c.Put(alice, hashKey("test", name), m, true); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	fresh := testCache(t, dir, false)
	for name, m := range msgs {
		if got := fresh.Get(alice, hashKey("test", name)); !bytes.Equal(got, m) {
			t.Errorf("%s: read back %d bytes, want %d", name, len(got), len(m))
		}
	}
	if n := count(t, c, `SELECT count(*) FROM segments WHERE kind = 1`); n < 3 {
		t.Errorf("%d base64 segments, want the attachments decoded", n)
	}
}

// TestCacheDedup stores an attachment once, however its messages wrap
// it, and deletes its chunks with the last message that has them.
func TestCacheDedup(t *testing.T) {
	c := testCache(t, t.TempDir(), true)
	att := random(4, 500<<10)
	a, b := hashKey("test", "a"), hashKey("test", "b")
	if err := c.Put(alice, a, mailWith("a", att, 76, "\r\n"), true); err != nil {
		t.Fatal(err)
	}
	one := count(t, c, `SELECT sum(length(data)) FROM chunks`)
	if err := c.Put(alice, b, mailWith("b", att, 72, "\n"), true); err != nil {
		t.Fatal(err)
	}
	if two := count(t, c, `SELECT sum(length(data)) FROM chunks`); two-one > 20<<10 {
		t.Errorf("the second copy added %d bytes", two-one)
	}
	if err := c.Delete(alice, a); err != nil {
		t.Fatal(err)
	}
	c.forget(b)
	if got := c.Get(alice, b); !bytes.Equal(got, mailWith("b", att, 72, "\n")) {
		t.Fatal("the other message lost its chunks")
	}
	if err := c.Delete(alice, b); err != nil {
		t.Fatal(err)
	}
	if n := count(t, c, `SELECT count(*) FROM chunks`); n != 0 {
		t.Errorf("%d chunks left", n)
	}
	// Trim needs the space back on the file system.
	if n := count(t, c, `PRAGMA auto_vacuum`); n != 2 {
		t.Errorf("auto_vacuum = %d, want 2 (incremental)", n)
	}
	db, _ := c.chunkDB(alice)
	if err := db.vacuum(); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(filepath.Join(accountDir(c.Dir, alice), chunkFile))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() > 100<<10 {
		t.Errorf("the database is %d bytes after its chunks were deleted", fi.Size())
	}
}

// TestCacheReplace stores a message again in place of its old copy.
func TestCacheReplace(t *testing.T) {
	c := testCache(t, t.TempDir(), true)
	key := hashKey("test", "replace")
	for i, m := range [][]byte{mailWith("old", random(5, 200<<10), 76, "\r\n"), []byte("new")} {
		if err := c.Put(alice, key, m, true); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	c.forget(key)
	if got := c.Get(alice, key); string(got) != "new" {
		t.Fatalf("Get = %.20q", got)
	}
	if n := count(t, c, `SELECT count(*) FROM chunks`); n != 1 {
		t.Errorf("%d chunks, want the new message's one", n)
	}
	if n := count(t, c, `SELECT sum(refs) FROM chunks`); n != 1 {
		t.Errorf("%d references, want 1", n)
	}
}

func TestCacheDelete(t *testing.T) {
	c := testCache(t, t.TempDir(), false)
	key := hashKey("test", "delete")
	if err := c.Put(alice, key, []byte("x"), true); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete(alice, key); err != nil {
		t.Fatal(err)
	}
	if c.Has(alice, key) || c.Get(alice, key) != nil {
		t.Fatal("deleted entry still cached")
	}
}

// setReadAt sets when a message was last read.
func setReadAt(t *testing.T, c *Cache, key string, at time.Time) {
	t.Helper()
	db, err := c.chunkDB(alice)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.touch(key, at); err != nil {
		t.Fatal(err)
	}
}

func TestCachePrune(t *testing.T) {
	dir := t.TempDir()
	c := testCache(t, dir, false)
	old, fresh := hashKey("test", "old"), hashKey("test", "fresh")
	for _, k := range []string{old, fresh} {
		if err := c.Put(alice, k, []byte(k), true); err != nil {
			t.Fatal(err)
		}
		setReadAt(t, c, k, time.Now().Add(-100*24*time.Hour))
	}
	// Reading fresh from disk counts as use.
	c2 := testCache(t, dir, false)
	if c2.Get(alice, fresh) == nil {
		t.Fatal("fresh not cached")
	}
	eventually(t, "the read time", func() bool {
		db, _ := c2.chunkDB(alice)
		_, at, _ := db.read(fresh)
		return time.Since(at) < time.Hour
	})
	n, err := c2.Prune(90 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || c2.Has(alice, old) || !c2.Has(alice, fresh) {
		t.Fatalf("pruned %d; old cached %v, fresh cached %v", n, c2.Has(alice, old), c2.Has(alice, fresh))
	}
}

// TestCacheRemoveRead keeps a message read after its key was chosen.
func TestCacheRemoveRead(t *testing.T) {
	c := testCache(t, t.TempDir(), false)
	key := hashKey("test", "read")
	if err := c.Put(alice, key, []byte(key), true); err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().Add(-time.Hour)
	setReadAt(t, c, key, cutoff.Add(-time.Hour))
	db, err := c.chunkDB(alice)
	if err != nil {
		t.Fatal(err)
	}
	keys, _, err := db.readBefore(cutoff)
	if err != nil || len(keys) != 1 {
		t.Fatalf("read before: %v, %v", keys, err)
	}
	setReadAt(t, c, key, time.Now()) // read since
	if n, _, err := db.removeRead(cutoff, keys...); err != nil || n != 0 {
		t.Fatalf("removed %d, %v", n, err)
	}
	if !c.Has(alice, key) {
		t.Fatal("removed a message read since")
	}
}

// TestCachePlain stores chunks uncompressed in a new database, and keeps
// a database's compression when the setting changes.
func TestCachePlain(t *testing.T) {
	msg := bytes.Repeat([]byte("Subject: plain\r\n\r\nNot compressed.\r\n"), 100)
	key := hashKey("test", "plain")

	plainDir := t.TempDir()
	c := testCache(t, plainDir, true)
	if err := c.Put(alice, key, msg, true); err != nil {
		t.Fatal(err)
	}
	if n := count(t, c, `SELECT sum(length(data)) FROM chunks`); n != int64(len(msg)) {
		t.Errorf("stored %d bytes of a %d-byte message", n, len(msg))
	}

	zDir := t.TempDir()
	if err := testCache(t, zDir, false).Put(alice, key, msg, true); err != nil {
		t.Fatal(err)
	}
	c = testCache(t, zDir, true)
	if got := c.Get(alice, key); !bytes.Equal(got, msg) {
		t.Fatal("zstd copy unreadable with Plain")
	}
	if err := c.Put(alice, hashKey("test", "plain2"), append(msg, 'x'), true); err != nil {
		t.Fatal(err)
	}
	if n := count(t, c, `SELECT max(length(data)) FROM chunks`); n >= int64(len(msg))/4 {
		t.Errorf("a zstd database stored %d bytes uncompressed", n)
	}
}

// TestCacheRefusesUnknown refuses a chunk database whose meta it does not
// know, and leaves it as it is.
func TestCacheRefusesUnknown(t *testing.T) {
	dir := t.TempDir()
	c := testCache(t, dir, false)
	key := hashKey("test", "meta")
	if err := c.Put(alice, key, []byte("x"), true); err != nil {
		t.Fatal(err)
	}
	db, _ := c.chunkDB(alice)
	if _, err := db.w.Exec(`UPDATE meta SET value = 'brotli' WHERE name = 'chunk_compression'`); err != nil {
		t.Fatal(err)
	}
	c.Close()
	c2 := testCache(t, dir, false)
	if c2.Has(alice, key) {
		t.Error("a database with unknown compression was read")
	}
	if err := c2.Put(alice, key, []byte("y"), true); err == nil {
		t.Error("a database with unknown compression was written")
	}
}

// TestCacheTrim deletes the least recently read messages until the free
// space is above the minimum, with a tenth to spare.
func TestCacheTrim(t *testing.T) {
	dir := t.TempDir()
	var avail atomic.Int64
	avail.Store(10000) // room for the writes, and their checks
	c := &Cache{Dir: dir, MaxBytes: 1 << 20, Plain: true, MinFreePercent: 5,
		statfs: func(string) (uint64, uint64, error) { return uint64(avail.Load()), 10000, nil }}
	t.Cleanup(func() { c.Close() })
	keys := make([]string, 4)
	for i := range keys {
		keys[i] = hashKey("test", "trim", fmt.Sprint(i))
		if err := c.Put(alice, keys[i], bytes.Repeat([]byte{byte('a' + i)}, 200), true); err != nil {
			t.Fatal(err)
		}
		// Read in the order 0, 1, 2, 3: 0 is the least recent.
		setReadAt(t, c, keys[i], time.Now().Add(time.Duration(i-10)*time.Hour))
	}

	avail.Store(600) // above 5% of 10000
	if n, err := c.Trim(); n != 0 || err != nil {
		t.Fatalf("Trim with room = %d, %v", n, err)
	}
	avail.Store(300) // 200 short, plus 50 to spare: two messages
	if n, err := c.Trim(); n != 2 || err != nil {
		t.Fatalf("Trim = %d, %v; want 2", n, err)
	}
	fresh := testCache(t, dir, true)
	for i, key := range keys {
		if got, want := fresh.Has(alice, key), i >= 2; got != want {
			t.Errorf("message %d kept = %v, want %v", i, got, want)
		}
	}
	if c.Get(alice, keys[0]) != nil {
		t.Error("a deleted message is still served from memory")
	}
}

// TestFastCDCShift cuts the same data at the same places after bytes are
// put in front of it.
func TestFastCDCShift(t *testing.T) {
	data := random(6, 2<<20)
	cut := func(b []byte) map[string]bool {
		out := map[string]bool{}
		for _, ch := range (segment{kind: segBase64, data: b}).chunks() {
			if len(ch) > chunkMax || len(ch) == 0 {
				t.Fatalf("a %d-byte chunk", len(ch))
			}
			out[string(chunkHash(ch))] = true
		}
		return out
	}
	a, b := cut(data), cut(append(random(7, 1000), data...))
	shared := 0
	for h := range a {
		if b[h] {
			shared++
		}
	}
	if shared < len(a)-2 {
		t.Errorf("%d of %d chunks shared after a shift", shared, len(a))
	}
}
