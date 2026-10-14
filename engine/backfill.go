package engine

import (
	"cmp"
	"context"
	"errors"
	"log/slog"
	"slices"
	"time"

	"github.com/emersion/go-imap/v2"
)

// The backfill fills the message list of every folder ahead of clients,
// so a client that syncs an account for the first time gets its lists
// from the proxy's header entries (headerEntry), without whole messages.
// It runs in the background with the sync engine, whether or not a client
// is connected, newest messages first. A cached message's entry comes from
// its cached copy. For a message the proxy does not change, the provider
// is asked for the entry alone, not the body. A message the Transform
// changes is downloaded and transformed, because its list entry is that of
// the changed message. All of it is bulk work, so client requests and new
// mail go first.
//
// It runs when the engine connects, and again after a sweep that found
// new messages. Messages with an entry are skipped, except those a client
// read lately that the cache lost (refillable): they are downloaded again,
// so a new or emptied cache gets back what clients read.

// backfillWindow is how many messages, newest first across all folders,
// the backfill handles at a time.
const backfillWindow = 500

// backfillLogEvery is how often a running backfill logs its progress.
const backfillLogEvery = 30 * time.Second

// startBackfill starts a backfill if one is needed and none is running.
// It ends with ctx.
func (a *Account) startBackfill(ctx context.Context) {
	if !a.b.Backfill || a.b.Store == nil || !a.backfillStale.Load() {
		return
	}
	if !a.backfillRunning.CompareAndSwap(false, true) {
		return
	}
	a.backfillStale.Store(false)
	go func() {
		defer a.backfillRunning.Store(false)
		err := a.backfill(ctx)
		if err != nil {
			// Tried again on the next sweep.
			a.backfillStale.Store(true)
			if ctx.Err() == nil && !errors.Is(err, ErrNoCredentials) {
				a.b.Log.Warn("backfill: stopped", "user", a.login, "err", err)
			}
		}
	}()
}

// lost returns the keys of the messages of todo to download again: those
// a client read (RecordReads) since the last Prune of the Store that the
// cache lost. Trim forgets the reads of what it deletes (Cache.Reads), and
// Cache.uncached leaves out what it deleted since the reads were listed.
// None without a disk cache, whose memory holds few.
func (a *Account) lost(todo []backfillItem) (map[string]bool, error) {
	if a.b.Cache.Dir == "" {
		return nil, nil
	}
	reads, err := a.b.Store.reads(a.login)
	if err != nil || len(reads) == 0 {
		return nil, err
	}
	var read []string
	for _, it := range todo {
		if _, ok := reads[it.msg.key]; ok {
			read = append(read, it.msg.key)
		}
	}
	return a.b.Cache.uncached(a.login, read), nil
}

// backfillItem is a message to backfill, in folder name.
type backfillItem struct {
	name string
	msg  *Message
}

func (a *Account) backfill(ctx context.Context) error {
	have, err := a.b.Store.headerKeys(a.login)
	if err != nil {
		return err
	}
	a.mu.Lock()
	var todo []backfillItem
	for name, m := range a.boxes {
		if !m.selectable {
			continue
		}
		for _, msg := range m.msgs {
			todo = append(todo, backfillItem{name, msg})
		}
	}
	a.mu.Unlock()
	// The checks on disk come after the lock.
	lost, err := a.lost(todo)
	if err != nil {
		return err
	}
	todo = slices.DeleteFunc(todo, func(it backfillItem) bool { return have[it.msg.key] && !lost[it.msg.key] })
	if len(todo) == 0 {
		return nil
	}
	slices.SortFunc(todo, func(x, y backfillItem) int {
		return cmp.Or(y.msg.date.Compare(x.msg.date), cmp.Compare(x.name, y.name), cmp.Compare(y.msg.uid, x.msg.uid))
	})
	var lists, whole, cached []backfillItem
	for _, it := range todo {
		switch {
		case lost[it.msg.key]:
			// Read lately, with or without a header entry.
			whole = append(whole, it)
		case a.b.Cache.Has(a.login, it.msg.key):
			cached = append(cached, it)
		case !it.msg.direct:
			whole = append(whole, it)
		default:
			lists = append(lists, it)
		}
	}

	log := a.b.Log.With("user", a.login)
	start := time.Now()
	log.Info("backfill: started", "lists", len(lists), "whole", len(whole), "cached", len(cached))
	// Entries of cached messages first: no provider needed.
	fromCache, err := a.backfillPass(ctx, log, "cached", cached, map[string]bool{}, func(msgs []*Message) (int, error) {
		save := map[string]*HeaderEntry{}
		for _, m := range msgs {
			if data, _ := a.b.Cache.readDisk(a.login, m.key); data != nil {
				save[m.key] = EntryOf(data)
			}
		}
		return len(save), a.b.Store.putHeaders(a.login, save)
	})
	if err != nil {
		return err
	}
	skipped := map[string]bool{} // folders the provider refused
	headers, err := a.backfillPass(ctx, log, "lists", lists, skipped, func(msgs []*Message) (int, error) {
		got, err := a.fetchHeaders(msgs, bulk)
		return len(got), err
	})
	if err != nil {
		return err
	}
	downloads, err := a.backfillPass(ctx, log, "whole", whole, skipped, func(msgs []*Message) (int, error) {
		return len(msgs), a.download(msgs, nil, true, nil)
	})
	if err != nil {
		return err
	}
	log.Info("backfill: done", "headers", headers, "downloaded", downloads, "from_cache", fromCache, "took", time.Since(start).Round(time.Second))
	return nil
}

// backfillPass runs fetch on todo, a window at a time, each window by
// folder. It returns the sum of what fetch returned.
func (a *Account) backfillPass(ctx context.Context, log *slog.Logger, pass string, todo []backfillItem, skipped map[string]bool,
	fetch func(msgs []*Message) (int, error)) (int, error) {
	total := 0
	lastLog := time.Now()
	for i := 0; i < len(todo); i += backfillWindow {
		window := todo[i:min(i+backfillWindow, len(todo))]
		if time.Since(lastLog) >= backfillLogEvery {
			log.Info("backfill: progress", "pass", pass, "done", i, "of", len(todo))
			lastLog = time.Now()
		}
		byFolder := map[string][]*Message{}
		var names []string
		for _, it := range window {
			if skipped[it.name] {
				continue
			}
			if byFolder[it.name] == nil {
				names = append(names, it.name)
			}
			byFolder[it.name] = append(byFolder[it.name], it.msg)
		}
		for _, name := range names {
			if err := ctx.Err(); err != nil {
				return total, err
			}
			n, err := fetch(byFolder[name])
			total += n
			var ie *imap.Error
			if errors.As(err, &ie) {
				// A folder deleted since the sync, for example.
				log.Info("backfill: folder skipped", "mailbox", name, "err", err)
				skipped[name] = true
				continue
			}
			if err != nil {
				return total, err
			}
		}
	}
	return total, nil
}
