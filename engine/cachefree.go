package engine

import (
	"errors"
	"slices"
	"sync/atomic"
	"time"
)

// The cache leaves free space on its file system: MinFreePercent of it,
// or MinFreeBytes, whichever is more. Below that, Trim deletes messages
// least recently read first (see touch), until a little more than the
// minimum is free, so it does not run again for every new message. Only
// cached messages are deleted; they can be downloaded again. The mailbox
// state stays.

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

// Trim deletes the least recently read messages on disk until the free
// space is back above the minimum, and returns how many it deleted. A
// message frees only the chunks no other message has.
func (c *Cache) Trim() (int, error) {
	if !c.trim.running.CompareAndSwap(false, true) {
		return 0, nil
	}
	defer c.trim.running.Store(false)
	need, err := c.toFree()
	if err != nil || need <= 0 {
		return 0, err
	}
	dbs, err := c.chunkDBs()
	type stored struct {
		db   *chunkDB
		key  string
		used time.Time
	}
	var all []stored
	for _, db := range dbs {
		keys, times, rerr := db.readBefore(time.Now().Add(time.Hour))
		if rerr != nil {
			err = errors.Join(err, rerr)
			continue
		}
		for i, k := range keys {
			all = append(all, stored{db, k, times[i]})
		}
	}
	slices.SortFunc(all, func(x, y stored) int { return x.used.Compare(y.used) })
	n := 0
	touched := map[*chunkDB]bool{}
	for _, m := range all {
		if need <= 0 {
			break
		}
		c.forget(m.key)
		// Only if not read since it was listed.
		removed, freed, rerr := m.db.removeRead(m.used.Add(time.Second), m.key)
		if rerr != nil {
			err = errors.Join(err, rerr)
			continue
		}
		if removed == 0 {
			continue
		}
		touched[m.db] = true
		need -= freed
		n++
	}
	for db := range touched {
		err = errors.Join(err, db.vacuum())
	}
	return n, err
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
