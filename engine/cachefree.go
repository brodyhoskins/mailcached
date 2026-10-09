package engine

import (
	"cmp"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"time"
)

// The cache leaves free space on its file system: MinFreePercent of it,
// or MinFreeBytes, whichever is more. Below that, Trim deletes disk copies
// least recently read first (a read updates a copy's modification time,
// see touch), until a little more than the minimum is free, so it does not
// run again for every new message. Only message copies are deleted; they
// can be downloaded again. The mailbox state stays.

// trimEvery is how often a write checks the free space.
const trimEvery = time.Minute

// trimState is the part of Cache that Trim uses.
type trimState struct {
	checked atomic.Int64 // unix nanoseconds of the last check after a write
	running atomic.Bool
}

// errNoStatfs is returned where the free space cannot be read.
var errNoStatfs = errors.New("free space unknown on this system")

// toFree returns how many bytes to delete: 0 when there is room enough.
func (c *Cache) toFree() (int64, error) {
	if c.Dir == "" || (c.MinFreePercent <= 0 && c.MinFreeBytes <= 0) {
		return 0, nil
	}
	stat := c.statfs
	if stat == nil {
		stat = statfs
	}
	a, t, err := stat(c.Dir)
	if err != nil {
		return 0, err
	}
	avail, total := int64(min(a, 1<<62)), int64(min(t, 1<<62))
	minFree := max(int64(c.MinFreePercent/100*float64(total)), c.MinFreeBytes)
	if avail >= minFree {
		return 0, nil
	}
	// A tenth more than the minimum, so the next messages fit.
	return minFree - avail + minFree/10, nil
}

// Trim deletes the least recently read disk copies until the free space is
// back above the minimum, and returns how many it deleted.
func (c *Cache) Trim() (int, error) {
	if !c.trim.running.CompareAndSwap(false, true) {
		return 0, nil
	}
	defer c.trim.running.Store(false)
	need, err := c.toFree()
	if err != nil || need <= 0 {
		return 0, err
	}
	type copy struct {
		path, key string
		size      int64
		used      time.Time
	}
	var all []copy
	err = filepath.WalkDir(c.Dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		key, ok := copyKey(filepath.Base(p))
		if !ok {
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		all = append(all, copy{p, key, fi.Size(), fi.ModTime()})
		return nil
	})
	if err != nil {
		return 0, err
	}
	slices.SortFunc(all, func(x, y copy) int { return cmp.Compare(x.used.UnixNano(), y.used.UnixNano()) })
	n := 0
	for _, f := range all {
		if need <= 0 {
			break
		}
		c.forget(f.key)
		if err := os.Remove(f.path); err == nil {
			need -= f.size
			n++
		}
	}
	return n, nil
}

// trimSoon checks the free space after a write, at most every trimEvery,
// in the background.
func (c *Cache) trimSoon() {
	now := time.Now().UnixNano()
	last := c.trim.checked.Load()
	if now-last < int64(trimEvery) || !c.trim.checked.CompareAndSwap(last, now) {
		return
	}
	go func() {
		if n, err := c.Trim(); err == nil && n > 0 && c.Log != nil {
			c.Log.Info("cache: disk nearly full, least recently read messages deleted", "deleted", n)
		}
	}()
}

// copyKey returns the cache key a disk copy's file name holds.
func copyKey(name string) (string, bool) {
	if key, ok := strings.CutSuffix(name, extZstd); ok {
		return key, true
	}
	return strings.CutSuffix(name, extPlain)
}
