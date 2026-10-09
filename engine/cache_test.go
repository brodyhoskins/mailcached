package engine

import (
	"bytes"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCacheCompressesOnDisk(t *testing.T) {
	dir := t.TempDir()
	msg := bytes.Repeat([]byte("Subject: hello\r\n\r\nThe same line, again and again.\r\n"), 200)
	key := hashKey("test", "compress")

	c := &Cache{Dir: dir, MaxBytes: 1 << 20}
	if err := c.Put("alice@example.com", key, msg, true); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(c.path("alice@example.com", key))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Size() >= int64(len(msg))/4 {
		t.Errorf("disk copy is %d bytes for a %d-byte message", fi.Size(), len(msg))
	}
	// A fresh cache has nothing in memory, so this reads the disk copy.
	if got := (&Cache{Dir: dir, MaxBytes: 1 << 20}).Get("alice@example.com", key); !bytes.Equal(got, msg) {
		t.Fatal("disk copy does not round-trip")
	}
}

func TestCacheDelete(t *testing.T) {
	c := &Cache{Dir: t.TempDir(), MaxBytes: 1 << 20}
	key := hashKey("test", "delete")
	if err := c.Put("alice@example.com", key, []byte("x"), true); err != nil {
		t.Fatal(err)
	}
	if err := c.Delete("alice@example.com", key); err != nil {
		t.Fatal(err)
	}
	if c.Has("alice@example.com", key) || c.Get("alice@example.com", key) != nil {
		t.Fatal("deleted entry still cached")
	}
}

func TestCachePrune(t *testing.T) {
	c := &Cache{Dir: t.TempDir(), MaxBytes: 1 << 20}
	old, fresh := hashKey("test", "old"), hashKey("test", "fresh")
	for _, k := range []string{old, fresh} {
		if err := c.Put("alice@example.com", k, []byte(k), true); err != nil {
			t.Fatal(err)
		}
	}
	long := time.Now().Add(-100 * 24 * time.Hour)
	for _, k := range []string{old, fresh} {
		if err := os.Chtimes(c.path("alice@example.com", k), long, long); err != nil {
			t.Fatal(err)
		}
	}
	// Reading fresh counts as use.
	if c.Get("alice@example.com", fresh) == nil {
		t.Fatal("fresh not cached")
	}
	n, err := c.Prune(90 * 24 * time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || c.Has("alice@example.com", old) || !c.Has("alice@example.com", fresh) {
		t.Fatalf("pruned %d; old cached %v, fresh cached %v", n, c.Has("alice@example.com", old), c.Has("alice@example.com", fresh))
	}
}

// TestCachePlain writes uncompressed copies as .eml, and reads copies of
// both kinds, so a change of setting or file system needs no conversion.
func TestCachePlain(t *testing.T) {
	dir := t.TempDir()
	msg := []byte("Subject: plain\r\n\r\nNot compressed.\r\n")
	zkey, pkey := hashKey("test", "z"), hashKey("test", "p")
	if err := (&Cache{Dir: dir, MaxBytes: 1 << 20}).Put("alice@example.com", zkey, msg, true); err != nil {
		t.Fatal(err)
	}
	c := &Cache{Dir: dir, MaxBytes: 1 << 20, Plain: true}
	if err := c.Put("alice@example.com", pkey, msg, true); err != nil {
		t.Fatal(err)
	}
	if p := c.path("alice@example.com", pkey); !strings.HasSuffix(p, ".eml") {
		t.Errorf("plain copy is %s", p)
	}
	if p := (&Cache{Dir: dir}).path("alice@example.com", zkey); !strings.HasSuffix(p, ".eml.zst") {
		t.Errorf("compressed copy is %s", p)
	}
	if b, err := os.ReadFile(c.path("alice@example.com", pkey)); err != nil || !bytes.Equal(b, msg) {
		t.Fatalf("plain disk copy = %q, %v", b, err)
	}
	fresh := &Cache{Dir: dir, MaxBytes: 1 << 20}
	for _, key := range []string{zkey, pkey} {
		if got := fresh.Get("alice@example.com", key); !bytes.Equal(got, msg) {
			t.Errorf("Get = %q", got)
		}
	}
	// Reading the plain copy converts it in the background; the test
	// directory goes only after that.
	eventually(t, "the conversion", func() bool {
		return strings.HasSuffix(fresh.find("alice@example.com", pkey), ".eml.zst")
	})
}

// TestCacheConverts rewrites a copy read in the other format, in the
// background, and removes the old one.
func TestCacheConverts(t *testing.T) {
	dir := t.TempDir()
	msg := []byte("Subject: convert\r\n\r\nOnce.\r\n")
	key := hashKey("test", "convert")
	if err := (&Cache{Dir: dir, MaxBytes: 1 << 20, Plain: true}).Put("alice@example.com", key, msg, true); err != nil {
		t.Fatal(err)
	}
	c := &Cache{Dir: dir, MaxBytes: 1 << 20}
	if got := c.Get("alice@example.com", key); !bytes.Equal(got, msg) {
		t.Fatalf("Get = %q", got)
	}
	eventually(t, "conversion", func() bool {
		_, zerr := os.Stat(c.path("alice@example.com", key))
		_, perr := os.Stat(c.altPath("alice@example.com", key))
		return zerr == nil && os.IsNotExist(perr)
	})
	if got := (&Cache{Dir: dir, MaxBytes: 1 << 20}).Get("alice@example.com", key); !bytes.Equal(got, msg) {
		t.Fatalf("converted copy = %q", got)
	}
}

// TestCacheTrim deletes the least recently read copies until the free
// space is above the minimum, with a tenth to spare.
func TestCacheTrim(t *testing.T) {
	dir := t.TempDir()
	var avail atomic.Int64
	avail.Store(10000) // room for the writes, and their checks
	c := &Cache{Dir: dir, MaxBytes: 1 << 20, Plain: true, MinFreePercent: 5,
		statfs: func(string) (uint64, uint64, error) { return uint64(avail.Load()), 10000, nil }}
	keys := make([]string, 4)
	for i := range keys {
		keys[i] = hashKey("test", "trim", string(rune('a'+i)))
		if err := c.Put("alice@example.com", keys[i], bytes.Repeat([]byte("x"), 200), true); err != nil {
			t.Fatal(err)
		}
		// Read in the order 0, 1, 2, 3: 0 is the least recent.
		when := time.Now().Add(time.Duration(i-10) * time.Hour)
		if err := os.Chtimes(c.path("alice@example.com", keys[i]), when, when); err != nil {
			t.Fatal(err)
		}
	}

	avail.Store(600) // above 5% of 10000
	if n, err := c.Trim(); n != 0 || err != nil {
		t.Fatalf("Trim with room = %d, %v", n, err)
	}
	avail.Store(300) // 200 short, plus 50 to spare: two copies
	if n, err := c.Trim(); n != 2 || err != nil {
		t.Fatalf("Trim = %d, %v; want 2", n, err)
	}
	fresh := &Cache{Dir: dir, MaxBytes: 1 << 20}
	for i, key := range keys {
		if got, want := fresh.Has("alice@example.com", key), i >= 2; got != want {
			t.Errorf("copy %d kept = %v, want %v", i, got, want)
		}
	}
	if c.Get("alice@example.com", keys[0]) != nil {
		t.Error("a deleted copy is still served from memory")
	}
}
