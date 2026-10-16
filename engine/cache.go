package engine

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"
	"uuid"

	"github.com/klauspost/compress/zstd"
)

// Chunks on disk are Zstandard-compressed, unless the file system
// compresses them already (Cache.Plain). Level 3 (zstd's default) gets
// within a few percent of the slowest levels on mail, at a fraction of the
// CPU time; Brotli saved 5% more on a real cache, and reads took five
// times as long. Encoder and decoder are safe for concurrent
// EncodeAll/DecodeAll.
var (
	zenc, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1))
	zdec, _ = zstd.NewReader(nil, zstd.WithDecoderConcurrency(0), zstd.WithDecoderMaxMemory(1<<30))
)

// TrimReads is where Trim forgets the clients' reads of the messages it
// deletes, by account folder (the Store).
type TrimReads interface {
	ForgetReads(dir string, keys []string) error
	NoteReadsIn(dir string, keys []string) error
}

// Cache holds messages as clients see them, so each is fetched and
// transformed once.
// Entries are keyed by message fingerprint (fingerprintKey), not by folder
// and UID, so a message keeps its entry when it moves, and a copy in two
// folders shares one.
//
// Entries live in memory (least recently used out first) and, if Dir is
// set, on disk in the account's chunk database (chunkstore.go), where what
// messages share is stored once. The disk store is not encrypted: with a
// Transform that decrypts, protect Dir like the private keys.
type Cache struct {
	Dir      string // cache_dir
	MaxBytes int64  // memory bound
	// Plain stores chunks uncompressed, for a file system that compresses
	// them. It applies to new chunk databases: one keeps what it was made
	// with.
	Plain bool
	// The free space to leave on Dir's file system (see Trim): a
	// percentage of it, or bytes, whichever is more. Zero for neither.
	MinFreePercent float64
	MinFreeBytes   int64
	Log            *slog.Logger // for Trim; nil for none
	// Reads, if not nil, keeps the clients' reads (the Store): Trim forgets
	// those of the messages it deletes, so the backfill does not download
	// them again.
	Reads TrimReads

	trim trimState
	// readsMu orders Trim with the writer of reads (noteReads): trimmed
	// holds the keys Trim removed since they were last put, whose reads
	// are not recorded.
	readsMu sync.Mutex
	trimmed map[string]bool
	statfs  func(dir string) (avail, total uint64, err error) // tests; nil for the system's

	dbMu    sync.Mutex
	dbs     map[string]*chunkDB // by account folder
	closed  bool
	touches sync.WaitGroup // the background writes of touch, which Close waits for

	mu    sync.Mutex
	size  int64
	lru   *list.List // of *cacheEntry, front is newest
	index map[string]*list.Element
	// pieces are the cached pieces of each message (piece.go), by the
	// message's key. They are not saved: after a restart, the pieces of a
	// message cached whole stay on disk until Prune or Trim takes them.
	pieces map[string][]string
}

type cacheEntry struct {
	key    string
	data   []byte
	final  bool      // false: a ReadRetry result, which Recheck drops
	readAt time.Time // of the disk copy, see touch
}

// fingerprintKey names a message by account, Message-ID, size on the
// server and arrival date (INTERNALDATE), which IMAP keeps when a message
// is moved or copied. The size tells apart messages that share a
// Message-ID but differ, such as a copy encrypted to the recipients and
// the Sent copy encrypted to the sender; the date makes a fingerprint hard
// to forge, so a crafted message cannot take over another's cached copy.
func fingerprintKey(account, messageID string, size int64, date time.Time) string {
	return hashKey("fp", strings.ToLower(account), messageID, fmt.Sprint(size), fmt.Sprint(date.Unix()))
}

// idKey names a message without a Message-ID by the proxy's ID for it,
// which it keeps when it moves; its copies share the key.
func idKey(account string, id uuid.UUID) string {
	return hashKey("id", strings.ToLower(account), id.String())
}

func hashKey(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:])
}

// Has reports whether a message is cached, without reading it.
func (c *Cache) Has(account, key string) bool {
	c.mu.Lock()
	_, ok := c.index[key]
	c.mu.Unlock()
	if ok || c.Dir == "" {
		return ok
	}
	db, err := c.chunkDB(account)
	return err == nil && db.has(key)
}

// Get returns a cached message, or nil. A read counts as use for Prune.
func (c *Cache) Get(account, key string) []byte {
	data, _ := c.get(account, key)
	return data
}

// Where a cached message came from, for the fetch trace.
const (
	fromMemory = "memory"
	fromDisk   = "disk"
)

// get is Get, and says where the message came from.
func (c *Cache) get(account, key string) ([]byte, string) {
	c.mu.Lock()
	if el, ok := c.index[key]; ok {
		c.lru.MoveToFront(el)
		e := el.Value.(*cacheEntry)
		data, readAt := e.data, e.readAt
		touch := e.final && time.Since(readAt) >= touchEvery
		if touch {
			e.readAt = time.Now()
		}
		c.mu.Unlock()
		if touch {
			c.touch(account, key)
		}
		return data, fromMemory
	}
	c.mu.Unlock()
	data, readAt := c.readDisk(account, key)
	if data == nil {
		return nil, ""
	}
	c.remember(key, data, true, readAt) // read from disk: final
	if time.Since(readAt) >= touchEvery {
		c.touch(account, key)
	}
	return data, fromDisk
}

// readDisk returns a message's disk copy, or nil, without keeping it in
// memory or counting the read as use: for the backfill, which reads every
// copy once and must not push out what clients are reading.
func (c *Cache) readDisk(account, key string) ([]byte, time.Time) {
	if c.Dir == "" {
		return nil, time.Time{}
	}
	db, err := c.chunkDB(account)
	if err != nil {
		c.logWarn("cache: chunk database", err)
		return nil, time.Time{}
	}
	data, readAt, err := db.read(key)
	if err != nil {
		c.logWarn("cache: read", err)
		return nil, time.Time{}
	}
	return data, readAt
}

func (c *Cache) logWarn(msg string, err error) {
	if c.Log != nil {
		c.Log.Warn(msg, "err", err)
	}
}

// touchEvery limits how often a read updates a message's read time.
const touchEvery = 24 * time.Hour

// touch records a read in the disk store, which Prune and Trim go by, in
// the background: a read does not wait on writes.
func (c *Cache) touch(account, key string) {
	if c.Dir == "" {
		return
	}
	db, err := c.chunkDB(account)
	if err != nil {
		return
	}
	c.dbMu.Lock()
	defer c.dbMu.Unlock()
	if c.closed {
		return
	}
	c.touches.Go(func() { _ = db.touch(key, time.Now()) })
}

// Prune deletes the messages on disk not read for maxAge, and returns how
// many.
func (c *Cache) Prune(maxAge time.Duration) (int, error) {
	if c.Dir == "" || maxAge <= 0 {
		return 0, nil
	}
	dbs, err := c.chunkDBs()
	n := 0
	for _, db := range dbs {
		cutoff := time.Now().Add(-maxAge)
		keys, _, rerr := db.readBefore(cutoff)
		if rerr != nil {
			err = errors.Join(err, rerr)
			continue
		}
		for _, k := range keys {
			c.forget(k)
		}
		// Again by cutoff: a message read since stays.
		removed, _, rerr := db.removeRead(cutoff, keys...)
		if rerr != nil {
			err = errors.Join(err, rerr)
			continue
		}
		n += removed
		if removed > 0 {
			err = errors.Join(err, db.vacuum())
		}
	}
	return n, err
}

// Put stores a message. persist is false for results that may change later,
// such as a Transform result that is not final: those stay in memory only.
func (c *Cache) Put(account, key string, data []byte, persist bool) error {
	if persist {
		c.dropPieces(account, key)
	}
	return c.put(account, key, data, persist)
}

// putPiece stores a piece of the message with key msgKey.
func (c *Cache) putPiece(account, msgKey, key string, data []byte) error {
	c.mu.Lock()
	if c.pieces == nil {
		c.pieces = map[string][]string{}
	}
	if !slices.Contains(c.pieces[msgKey], key) {
		c.pieces[msgKey] = append(c.pieces[msgKey], key)
	}
	c.mu.Unlock()
	return c.put(account, key, data, true)
}

// dropPieces forgets the pieces of a message: it is cached whole, or
// gone.
func (c *Cache) dropPieces(account, msgKey string) {
	c.mu.Lock()
	keys := c.pieces[msgKey]
	delete(c.pieces, msgKey)
	c.mu.Unlock()
	for _, k := range keys {
		_ = c.Delete(account, k)
	}
}

func (c *Cache) put(account, key string, data []byte, persist bool) error {
	now := time.Now()
	c.readsMu.Lock()
	delete(c.trimmed, key)
	c.readsMu.Unlock()
	c.remember(key, data, persist, now)
	if !persist || c.Dir == "" {
		return nil
	}
	db, err := c.chunkDB(account)
	if err != nil {
		return err
	}
	if err := db.write(key, data, now); err != nil {
		return err
	}
	c.trimSoon()
	return nil
}

// Delete removes a message, and its pieces, from memory and disk.
func (c *Cache) Delete(account, key string) error {
	c.dropPieces(account, key)
	c.forget(key)
	if c.Dir == "" {
		return nil
	}
	db, err := c.chunkDB(account)
	if err != nil {
		return err
	}
	err = db.remove(key)
	return err
}

// noteReads records reads of keys with note, except of those Trim
// removed: a read queued before the removal must not make the backfill
// download the message again.
func (c *Cache) noteReads(keys []string, note func(keys []string) error) error {
	if c == nil {
		return note(keys)
	}
	c.readsMu.Lock()
	defer c.readsMu.Unlock()
	keys = slices.DeleteFunc(keys, func(k string) bool { return c.trimmed[k] })
	return note(keys)
}

// uncached returns those of keys not cached and not removed by Trim,
// holding off Trim meanwhile: a read of a message Trim removes must not
// make the backfill download it again.
func (c *Cache) uncached(account string, keys []string) map[string]bool {
	c.readsMu.Lock()
	defer c.readsMu.Unlock()
	out := map[string]bool{}
	for _, k := range keys {
		if !c.trimmed[k] && !c.Has(account, k) {
			out[k] = true
		}
	}
	return out
}

// Close closes the chunk databases.
func (c *Cache) Close() error {
	c.dbMu.Lock()
	c.closed = true
	c.dbMu.Unlock()
	c.touches.Wait()
	c.dbMu.Lock()
	defer c.dbMu.Unlock()
	var errs []error
	for _, db := range c.dbs {
		errs = append(errs, db.close())
	}
	c.dbs = nil
	return errors.Join(errs...)
}

// forget drops a message from memory. Keys include the account, so the
// memory cache needs no account.
func (c *Cache) forget(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.index[key]; ok {
		c.size -= int64(len(el.Value.(*cacheEntry).data))
		c.lru.Remove(el)
		delete(c.index, key)
	}
}

// remember keeps a message in memory; readAt is when the disk copy was
// last read.
func (c *Cache) remember(key string, data []byte, final bool, readAt time.Time) {
	if int64(len(data)) > c.MaxBytes/4 {
		return // one huge message would flush everything else
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.index == nil {
		c.index = map[string]*list.Element{}
		c.lru = list.New()
	}
	if el, ok := c.index[key]; ok {
		e := el.Value.(*cacheEntry)
		c.size += int64(len(data) - len(e.data))
		e.data, e.final, e.readAt = data, final, readAt
		c.lru.MoveToFront(el)
	} else {
		c.index[key] = c.lru.PushFront(&cacheEntry{key: key, data: data, final: final, readAt: readAt})
		c.size += int64(len(data))
	}
	for c.size > c.MaxBytes && c.lru.Len() > 0 {
		el := c.lru.Back()
		e := el.Value.(*cacheEntry)
		c.lru.Remove(el)
		delete(c.index, e.key)
		c.size -= int64(len(e.data))
	}
}

// DropNonFinal forgets the results Read gave as ReadRetry, so they are
// read again.
func (c *Cache) DropNonFinal() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, el := range c.index {
		if e := el.Value.(*cacheEntry); !e.final {
			c.lru.Remove(el)
			delete(c.index, key)
			c.size -= int64(len(e.data))
		}
	}
}
