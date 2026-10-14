package engine

import (
	"bytes"
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/brodyhoskins/mailcached/config"
	"github.com/brodyhoskins/mailcached/internal/enginetest"
)

// TestBackfillRefill downloads again what a client read and the cache
// lost, and not what Trim deleted or no client read.
func TestBackfillRefill(t *testing.T) {
	addr, _ := enginetest.IMAP(t, testLog, nil)
	dir := t.TempDir()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	c := &Cache{Dir: dir, MaxBytes: 1 << 20}
	t.Cleanup(func() { c.Close() })
	b := &Engine{Store: st, Timeout: 5 * time.Second, Cache: c, Log: testLog,
		Route: func(string) (Upstream, bool) {
			return Upstream{Addr: addr, TLS: config.TLSNone, Timeout: 5 * time.Second}, true
		}}
	t.Cleanup(b.Close)
	a := b.Account(enginetest.User)
	if err := a.Login(enginetest.Password); err != nil {
		t.Fatal(err)
	}
	// Larger than PieceWhole: the sync does not download them ahead.
	body := bytes.Repeat([]byte("Hello.\r\n"), int(PieceWhole)/8)
	appendTo(t, addr, "INBOX", append([]byte("Message-ID: <refill-read@test>\r\nSubject: Read\r\n\r\n"), body...))
	appendTo(t, addr, "INBOX", append([]byte("Message-ID: <refill-unread@test>\r\nSubject: Unread\r\n\r\n"), body...))
	if err := a.SyncNow("INBOX"); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	msgs := append([]*Message(nil), a.boxes["INBOX"].msgs...)
	a.mu.Unlock()
	if len(msgs) != 2 {
		t.Fatalf("%d messages, want 2", len(msgs))
	}
	read, unread := msgs[0], msgs[1]

	if _, err := a.Download([]*Message{read}, nil); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the read time", func() bool {
		keys, _ := st.readsSince(a.login, time.Time{})
		return keys[read.key]
	})
	// Lost before any header entry, as after a read through ActiveSync:
	// the first backfill downloads it whole, and the other's header.
	if err := c.Delete(a.login, read.key); err != nil {
		t.Fatal(err)
	}
	if err := a.backfill(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !c.Has(a.login, read.key) || c.Has(a.login, unread.key) {
		t.Fatalf("before: read cached %v, unread cached %v", c.Has(a.login, read.key), c.Has(a.login, unread.key))
	}

	// A lost cache gets back what a client read.
	if err := c.Delete(a.login, read.key); err != nil {
		t.Fatal(err)
	}
	if err := a.backfill(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !c.Has(a.login, read.key) || c.Has(a.login, unread.key) {
		t.Fatalf("after loss: read cached %v, unread cached %v", c.Has(a.login, read.key), c.Has(a.login, unread.key))
	}

	// Not what Trim deleted: it would fill the disk again.
	c.MinFreePercent = 5
	c.statfs = func(string) (uint64, uint64, error) { return 0, 10000, nil }
	c.Reads = st
	// Listed before Trim, as when Trim runs while lost holds the reads.
	listed, err := st.readsSince(a.login, time.Time{})
	if err != nil || !listed[read.key] {
		t.Fatalf("reads = %v, %v; want %s", listed, err, read.key)
	}
	if n, err := c.Trim(); n != 1 || err != nil {
		t.Fatalf("Trim = %d, %v; want 1", n, err)
	}
	if got := c.uncached(a.login, []string{read.key}); got[read.key] {
		t.Fatal("a read listed before Trim deleted it was returned for refill")
	}
	if err := a.backfill(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.Has(a.login, read.key) {
		t.Fatal("a message read before the latest Trim was downloaded again")
	}
}

// TestRecordReadsCoalesce records many reads with one writer.
func TestRecordReadsCoalesce(t *testing.T) {
	st, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	b := &Engine{Store: st, Cache: &Cache{MaxBytes: 1 << 20}, Log: testLog}
	t.Cleanup(b.Close)
	a := b.Account(enginetest.User)
	msgs := make([]*Message, 50)
	for i := range msgs {
		msgs[i] = &Message{key: fmt.Sprint("key-", i)}
	}
	for _, msg := range msgs {
		a.RecordReads([]*Message{msg, msgs[0]})
	}
	b.Close() // waits for the writer
	keys, err := st.readsSince(a.login, time.Time{})
	if err != nil || len(keys) != len(msgs) {
		t.Errorf("%d reads recorded, %v; want %d", len(keys), err, len(msgs))
	}
}

// TestStorePrunesReadsOnOpen prunes the records of reads of a database
// opened after Prune, and readsSince returns none older than its age.
func TestStorePrunesReadsOnOpen(t *testing.T) {
	dir := t.TempDir()
	st, err := OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := st.db(alice)
	if err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour).Unix()
	if _, err := db.Exec(`INSERT INTO reads (key, read_at) VALUES ('old', ?), ('new', ?)`, old, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	st.Close()

	st, err = OpenStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if _, err := st.Prune(24 * time.Hour); err != nil { // before alice's database opens
		t.Fatal(err)
	}
	keys, err := st.readsSince(alice, time.Time{})
	if err != nil || keys["old"] || !keys["new"] {
		t.Errorf("readsSince = %v, %v; want only new", keys, err)
	}
	var n int
	r, err := st.reader(alice)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.QueryRow(`SELECT count(*) FROM reads`).Scan(&n); err != nil || n != 1 {
		t.Errorf("%d reads kept, %v; want 1", n, err)
	}
}
