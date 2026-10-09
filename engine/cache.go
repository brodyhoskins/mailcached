package engine

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"
	"uuid"

	"github.com/klauspost/compress/zstd"
)

// Disk copies are Zstandard-compressed, unless the file system compresses
// them already (Cache.Plain). Level 3 (zstd's default) gets within a few
// percent of the slowest levels on mail, at a fraction of the CPU time.
// Encoder and decoder are safe for concurrent EncodeAll/DecodeAll.
var (
	zenc, _ = zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault), zstd.WithEncoderConcurrency(1))
	zdec, _ = zstd.NewReader(nil, zstd.WithDecoderConcurrency(0), zstd.WithDecoderMaxMemory(1<<30))
)

// Disk copies are named <key>.eml, or <key>.eml.zst when compressed. A
// copy of either kind is read, so a change of Plain needs no conversion.
const (
	extPlain = ".eml"
	extZstd  = ".eml.zst"
)

// Cache holds messages as clients see them, so each is fetched and
// transformed once.
// Entries are keyed by message fingerprint (fingerprintKey), not by folder
// and UID, so a message keeps its entry when it moves, and a copy in two
// folders shares one.
//
// Entries live in memory (least recently used out first) and, if Dir is
// set, on disk in the account's folder (accountDir). The disk copies are
// not encrypted: with a Transform that decrypts, protect Dir like the
// private keys.
type Cache struct {
	Dir      string // cache_dir
	MaxBytes int64  // memory bound
	// Plain writes disk copies uncompressed, for a file system that
	// compresses them (see FSCompresses).
	Plain bool
	// The free space to leave on Dir's file system (see Trim): a
	// percentage of it, or bytes, whichever is more. Zero for neither.
	MinFreePercent float64
	MinFreeBytes   int64
	Log            *slog.Logger // for Trim; nil for none

	trim   trimState
	statfs func(dir string) (avail, total uint64, err error) // tests; nil for the system's

	mu         sync.Mutex
	converting chan struct{} // see convert
	size       int64
	lru        *list.List // of *cacheEntry, front is newest
	index      map[string]*list.Element
	// pieces are the cached pieces of each message (piece.go), by the
	// message's key. They are not saved: after a restart, the pieces of a
	// message cached whole stay on disk until Trim takes them.
	pieces map[string][]string
}

type cacheEntry struct {
	key   string
	data  []byte
	final bool // false: a ReadRetry result, which Recheck drops
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
	return c.find(account, key) != ""
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
		data := el.Value.(*cacheEntry).data
		c.mu.Unlock()
		c.touch(account, key)
		return data, fromMemory
	}
	c.mu.Unlock()
	if c.Dir == "" {
		return nil, ""
	}
	p := c.find(account, key)
	if p == "" {
		return nil, ""
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, ""
	}
	if strings.HasSuffix(p, extZstd) {
		if data, err = zdec.DecodeAll(data, nil); err != nil {
			return nil, ""
		}
	}
	c.remember(key, data, true) // read from disk: final
	c.touchPath(p)
	if p != c.path(account, key) {
		c.convert(account, key, p, data)
	}
	return data, fromDisk
}

// readDisk returns a message's disk copy, or nil, without keeping it in
// memory or counting the read as use: for the backfill, which reads every
// copy once and must not push out what clients are reading.
func (c *Cache) readDisk(account, key string) []byte {
	if c.Dir == "" {
		return nil
	}
	p := c.find(account, key)
	if p == "" {
		return nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	if strings.HasSuffix(p, extZstd) {
		if data, err = zdec.DecodeAll(data, nil); err != nil {
			return nil
		}
	}
	return data
}

// convertMax bounds the disk copies being converted at once.
const convertMax = 2

// convert rewrites a disk copy read in the other format (written under
// the other setting, or on another file system) in the format Put writes,
// in the background, and removes the old copy. A copy that finds no free
// worker is converted on a later read.
func (c *Cache) convert(account, key, old string, data []byte) {
	c.mu.Lock()
	if c.converting == nil {
		c.converting = make(chan struct{}, convertMax)
	}
	sem := c.converting
	c.mu.Unlock()
	select {
	case sem <- struct{}{}:
	default:
		return
	}
	go func() {
		defer func() { <-sem }()
		if err := c.write(account, key, data); err != nil {
			return
		}
		// Gone already: the message was deleted meanwhile, and so is the
		// new copy.
		if err := os.Remove(old); os.IsNotExist(err) {
			_ = os.Remove(c.path(account, key))
		}
	}()
}

// touchEvery limits how often a read updates a file's time.
const touchEvery = 24 * time.Hour

// touch records a read in the disk copy's modification time, which Prune
// goes by. File access times are not used: many systems do not keep them.
func (c *Cache) touch(account, key string) {
	if c.Dir == "" {
		return
	}
	if p := c.find(account, key); p != "" {
		c.touchPath(p)
	}
}

func (c *Cache) touchPath(p string) {
	fi, err := os.Stat(p)
	if err != nil || time.Since(fi.ModTime()) < touchEvery {
		return
	}
	now := time.Now()
	_ = os.Chtimes(p, now, now)
}

// Prune deletes disk copies not read for maxAge, and returns how many.
func (c *Cache) Prune(maxAge time.Duration) (int, error) {
	if c.Dir == "" || maxAge <= 0 {
		return 0, nil
	}
	cutoff := time.Now().Add(-maxAge)
	n := 0
	err := filepath.WalkDir(c.Dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		key, ok := copyKey(filepath.Base(p))
		if !ok {
			return nil
		}
		fi, err := d.Info()
		if err != nil || !fi.ModTime().Before(cutoff) {
			return nil
		}
		c.forget(key)
		if err := os.Remove(p); err == nil {
			n++
		}
		return nil
	})
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
	c.remember(key, data, persist)
	if !persist || c.Dir == "" {
		return nil
	}
	if err := c.write(account, key, data); err != nil {
		return err
	}
	// A copy written under the other setting is stale now.
	_ = os.Remove(c.altPath(account, key))
	c.trimSoon()
	return nil
}

// write saves a disk copy in the format Put writes.
func (c *Cache) write(account, key string, data []byte) error {
	p := c.path(account, key)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return err
	}
	out := data
	if !c.Plain {
		out = zenc.EncodeAll(data, nil)
	}
	if _, err := tmp.Write(out); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return nil
}

// Delete removes a message, and its pieces, from memory and disk.
func (c *Cache) Delete(account, key string) error {
	c.dropPieces(account, key)
	c.forget(key)
	if c.Dir == "" {
		return nil
	}
	for _, p := range []string{c.path(account, key), c.altPath(account, key)} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
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

// path is where Put writes a disk copy, altPath where the other setting
// would have.
func (c *Cache) path(account, key string) string {
	return c.pathExt(account, key, c.Plain)
}

func (c *Cache) altPath(account, key string) string {
	return c.pathExt(account, key, !c.Plain)
}

func (c *Cache) pathExt(account, key string, plain bool) string {
	ext := extZstd
	if plain {
		ext = extPlain
	}
	return filepath.Join(accountDir(c.Dir, account), "messages", key[:2], key+ext)
}

// find returns the disk copy of key, "" if there is none. The plain copy
// comes first: it is cheaper to read.
func (c *Cache) find(account, key string) string {
	for _, p := range []string{c.pathExt(account, key, true), c.pathExt(account, key, false)} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

func (c *Cache) remember(key string, data []byte, final bool) {
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
		e.data, e.final = data, final
		c.lru.MoveToFront(el)
	} else {
		c.index[key] = c.lru.PushFront(&cacheEntry{key: key, data: data, final: final})
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
