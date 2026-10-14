package engine

// The disk store of the Cache: one SQLite database per account,
// chunks.sqlite3 in the account's folder. A message is a manifest (its
// key, size and when it was last read) and its segments in order (chunk.go),
// each a list of chunk hashes. A chunk is stored once, however many
// messages have it, and counts its references: it is deleted with the last
// message that has it. A message and its references are written in one
// transaction, so a crash never leaves a manifest without its chunks.
//
// The meta table says how the database was made: chunk_hash (sha256) and
// chunk_compression (zstd, or none for a file system that compresses). A
// database with values this program does not know is refused. A change of
// either is a new database, not a conversion: the cache can be downloaded
// again.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// chunkSchemaVersion is the version of chunkSchema. Until the first
// release there is one schema, version 1, as with storeSchema.
const chunkSchemaVersion = 1

const chunkSchema = `
CREATE TABLE meta (
	name   TEXT PRIMARY KEY,
	value  TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE manifests (
	key      TEXT PRIMARY KEY,
	size     INTEGER NOT NULL,
	read_at  INTEGER NOT NULL  -- unix seconds; Prune and Trim go by it
) WITHOUT ROWID;
CREATE INDEX manifests_read_at ON manifests (read_at);
CREATE TABLE segments (
	key       TEXT NOT NULL,
	seq       INTEGER NOT NULL,
	kind      INTEGER NOT NULL,  -- segRaw, segBase64
	line_len  INTEGER NOT NULL,  -- segBase64
	crlf      INTEGER NOT NULL,  -- segBase64
	chunks    BLOB NOT NULL,     -- the chunks' hashes, one after another
	PRIMARY KEY (key, seq)
) WITHOUT ROWID;
-- A rowid table: chunks are too large for WITHOUT ROWID.
CREATE TABLE chunks (
	hash  BLOB PRIMARY KEY,  -- of the uncompressed bytes, per chunk_hash
	refs  INTEGER NOT NULL,
	data  BLOB NOT NULL      -- per chunk_compression
);
`

// The values of meta this program knows.
const (
	hashSHA256        = "sha256"
	compressZstd      = "zstd"
	compressNone      = "none"
	chunkFile         = "chunks.sqlite3"
	chunkHashLen      = 32
	chunkMetaHash     = "chunk_hash"
	chunkMetaCompress = "chunk_compression"
)

// chunkDB is an account's chunk database, opened as the Store opens its
// databases: one connection for writes, a pool for reads.
type chunkDB struct {
	w, r     *sql.DB
	compress bool   // chunk_compression is zstd
	dir      string // the account folder
}

// chunkDB opens an account's chunk database, creating it.
func (c *Cache) chunkDB(account string) (*chunkDB, error) {
	return c.openChunkDB(accountDir(c.Dir, account), true)
}

// openChunkDB opens the chunk database in an account's folder; without
// create, only one that exists.
func (c *Cache) openChunkDB(dir string, create bool) (*chunkDB, error) {
	c.dbMu.Lock()
	defer c.dbMu.Unlock()
	if db := c.dbs[dir]; db != nil {
		return db, nil
	}
	if c.closed {
		return nil, errors.New("cache closed")
	}
	path := filepath.Join(dir, chunkFile)
	if !create {
		if _, err := os.Stat(path); err != nil {
			return nil, err
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	file := "file:" + path + "?_pragma=busy_timeout(5000)"
	// auto_vacuum before WAL, which fixes the page size, after which
	// auto_vacuum cannot change. Incremental: deleted chunks give their
	// space back to the file system (vacuum), which Trim needs. It takes
	// effect in a new database only.
	w, err := sql.Open("sqlite", file+"&_pragma=auto_vacuum(INCREMENTAL)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	db := &chunkDB{w: w, dir: dir}
	if err := db.init(c.Plain); err != nil {
		w.Close()
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if db.r, err = sql.Open("sqlite", file+"&_pragma=query_only(1)"); err != nil {
		w.Close()
		return nil, err
	}
	db.r.SetMaxOpenConns(readConns)
	db.r.SetMaxIdleConns(readConns)
	if c.dbs == nil {
		c.dbs = map[string]*chunkDB{}
	}
	c.dbs[dir] = db
	return db, nil
}

// init creates the tables of a new database, with chunks compressed
// unless plain, and reads meta. A database of another version, or with
// values of meta this program does not know, is refused.
func (d *chunkDB) init(plain bool) error {
	var v int
	if err := d.w.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	switch v {
	case 0:
		compress := compressZstd
		if plain {
			compress = compressNone
		}
		tx, err := d.w.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err := tx.Exec(chunkSchema); err != nil {
			return err
		}
		if _, err := tx.Exec(`INSERT INTO meta (name, value) VALUES (?, ?), (?, ?)`,
			chunkMetaHash, hashSHA256, chunkMetaCompress, compress); err != nil {
			return err
		}
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, chunkSchemaVersion)); err != nil {
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	case chunkSchemaVersion:
	default:
		return fmt.Errorf("chunk database version %d, this program knows %d", v, chunkSchemaVersion)
	}
	meta := map[string]string{}
	rows, err := d.w.Query(`SELECT name, value FROM meta`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var n, v string
		if err := rows.Scan(&n, &v); err != nil {
			rows.Close()
			return err
		}
		meta[n] = v
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if h := meta[chunkMetaHash]; h != hashSHA256 {
		return fmt.Errorf("unknown %s %q", chunkMetaHash, h)
	}
	switch comp := meta[chunkMetaCompress]; comp {
	case compressZstd:
		d.compress = true
	case compressNone:
	default:
		return fmt.Errorf("unknown %s %q", chunkMetaCompress, comp)
	}
	return nil
}

func (d *chunkDB) close() error { return errors.Join(d.r.Close(), d.w.Close()) }

// has reports whether a message is stored.
func (d *chunkDB) has(key string) bool {
	var one int
	return d.r.QueryRow(`SELECT 1 FROM manifests WHERE key = ?`, key).Scan(&one) == nil
}

// read returns a stored message and when it was last read, or nil.
func (d *chunkDB) read(key string) ([]byte, time.Time, error) {
	// One transaction: one snapshot of the manifest and its chunks.
	tx, err := d.r.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, time.Time{}, err
	}
	defer tx.Rollback()
	var size, readAt int64
	err = tx.QueryRow(`SELECT size, read_at FROM manifests WHERE key = ?`, key).Scan(&size, &readAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, nil
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	rows, err := tx.Query(`SELECT kind, line_len, crlf, chunks FROM segments WHERE key = ? ORDER BY seq`, key)
	if err != nil {
		return nil, time.Time{}, err
	}
	var segs []segment
	var lists [][]byte
	for rows.Next() {
		var s segment
		var list []byte
		if err := rows.Scan(&s.kind, &s.lineLen, &s.crlf, &list); err != nil {
			rows.Close()
			return nil, time.Time{}, err
		}
		segs = append(segs, s)
		lists = append(lists, list)
	}
	if err := rows.Close(); err != nil {
		return nil, time.Time{}, err
	}
	out := make([]byte, 0, size)
	get, err := tx.Prepare(`SELECT data FROM chunks WHERE hash = ?`)
	if err != nil {
		return nil, time.Time{}, err
	}
	defer get.Close()
	for i, s := range segs {
		if len(lists[i])%chunkHashLen != 0 {
			return nil, time.Time{}, fmt.Errorf("message %s: bad chunk list", key)
		}
		var data []byte
		for h := lists[i]; len(h) > 0; h = h[chunkHashLen:] {
			var stored []byte
			if err := get.QueryRow(h[:chunkHashLen]).Scan(&stored); err != nil {
				return nil, time.Time{}, fmt.Errorf("message %s: chunk: %w", key, err)
			}
			if d.compress {
				if stored, err = zdec.DecodeAll(stored, nil); err != nil {
					return nil, time.Time{}, fmt.Errorf("message %s: %w", key, err)
				}
			}
			data = append(data, stored...)
		}
		if s.kind == segRaw {
			out = append(out, data...)
			continue
		}
		s.data = data
		out = append(out, s.encoded()...)
	}
	if int64(len(out)) != size {
		return nil, time.Time{}, fmt.Errorf("message %s: %d bytes, the manifest says %d", key, len(out), size)
	}
	return out, time.Unix(readAt, 0), nil
}

// write stores a message, in place of any stored under its key.
func (d *chunkDB) write(key string, msg []byte, readAt time.Time) error {
	segs := segments(msg)
	type chunk struct {
		hash, data, stored []byte
	}
	var all []*chunk
	lists := make([][]byte, len(segs))
	for i, s := range segs {
		for _, data := range s.chunks() {
			ch := &chunk{hash: chunkHash(data), data: data}
			all = append(all, ch)
			lists[i] = append(lists[i], ch.hash...)
		}
	}
	// Compress the chunks not stored yet before the transaction, which
	// holds up every other write. One stored meanwhile is not used; one
	// deleted meanwhile is compressed in the transaction.
	have, err := d.r.Prepare(`SELECT 1 FROM chunks WHERE hash = ?`)
	if err != nil {
		return err
	}
	for _, ch := range all {
		var one int
		if have.QueryRow(ch.hash).Scan(&one) != nil {
			ch.stored = d.encode(ch.data)
		}
	}
	have.Close()

	tx, err := d.w.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	dropped, err := dropManifest(tx, key)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`INSERT INTO manifests (key, size, read_at) VALUES (?, ?, ?)`,
		key, len(msg), readAt.Unix()); err != nil {
		return err
	}
	for i, s := range segs {
		if _, err := tx.Exec(`INSERT INTO segments (key, seq, kind, line_len, crlf, chunks) VALUES (?, ?, ?, ?, ?, ?)`,
			key, i, s.kind, s.lineLen, s.crlf, lists[i]); err != nil {
			return err
		}
	}
	for _, ch := range all {
		res, err := tx.Exec(`UPDATE chunks SET refs = refs + 1 WHERE hash = ?`, ch.hash)
		if err != nil {
			return err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			continue
		}
		if ch.stored == nil {
			ch.stored = d.encode(ch.data)
		}
		if _, err := tx.Exec(`INSERT INTO chunks (hash, refs, data) VALUES (?, 1, ?)`, ch.hash, ch.stored); err != nil {
			return err
		}
	}
	// The old message's chunks this one does not have.
	if _, err := deleteUnused(tx, dropped); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *chunkDB) encode(data []byte) []byte {
	if d.compress {
		return zenc.EncodeAll(data, nil)
	}
	return data
}

// remove deletes messages.
func (d *chunkDB) remove(keys ...string) error {
	_, _, err := d.removeRead(time.Time{}, keys...)
	return err
}

// removeRead deletes the messages of keys last read before cutoff, or
// all of them if cutoff is zero, and returns how many and the bytes of
// the chunks deleted with them: the space Trim gets back. A message read
// since its key was chosen stays.
func (d *chunkDB) removeRead(cutoff time.Time, keys ...string) (int, int64, error) {
	tx, err := d.w.Begin()
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	n := 0
	var dropped [][]byte
	for _, key := range keys {
		if !cutoff.IsZero() {
			var at int64
			err := tx.QueryRow(`SELECT read_at FROM manifests WHERE key = ?`, key).Scan(&at)
			if errors.Is(err, sql.ErrNoRows) || err == nil && at >= cutoff.Unix() {
				continue
			}
			if err != nil {
				return 0, 0, err
			}
		}
		h, err := dropManifest(tx, key)
		if err != nil {
			return 0, 0, err
		}
		dropped = append(dropped, h...)
		n++
	}
	freed, err := deleteUnused(tx, dropped)
	if err != nil {
		return 0, 0, err
	}
	return n, freed, tx.Commit()
}

// dropManifest deletes a message's manifest and segments, takes its
// references from its chunks, and returns their hashes. The chunks are
// deleted by deleteUnused, after any new references.
func dropManifest(tx *sql.Tx, key string) ([][]byte, error) {
	rows, err := tx.Query(`SELECT chunks FROM segments WHERE key = ?`, key)
	if err != nil {
		return nil, err
	}
	var hashes [][]byte
	for rows.Next() {
		var list []byte
		if err := rows.Scan(&list); err != nil {
			rows.Close()
			return nil, err
		}
		for ; len(list) >= chunkHashLen; list = list[chunkHashLen:] {
			hashes = append(hashes, list[:chunkHashLen])
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for _, h := range hashes {
		if _, err := tx.Exec(`UPDATE chunks SET refs = refs - 1 WHERE hash = ?`, h); err != nil {
			return nil, err
		}
	}
	if _, err := tx.Exec(`DELETE FROM segments WHERE key = ?`, key); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(`DELETE FROM manifests WHERE key = ?`, key); err != nil {
		return nil, err
	}
	return hashes, nil
}

// deleteUnused deletes the chunks of hashes that no message has, and
// returns their stored bytes.
func deleteUnused(tx *sql.Tx, hashes [][]byte) (int64, error) {
	var freed int64
	for _, h := range hashes {
		var n sql.NullInt64
		err := tx.QueryRow(`DELETE FROM chunks WHERE hash = ? AND refs <= 0 RETURNING length(data)`, h).Scan(&n)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return 0, err
		}
		freed += n.Int64
	}
	return freed, nil
}

// touch records a read.
func (d *chunkDB) touch(key string, at time.Time) error {
	_, err := d.w.Exec(`UPDATE manifests SET read_at = ? WHERE key = ?`, at.Unix(), key)
	return err
}

// readBefore returns the keys of the messages last read before cutoff,
// least recently read first, with when.
func (d *chunkDB) readBefore(cutoff time.Time) ([]string, []time.Time, error) {
	rows, err := d.r.Query(`SELECT key, read_at FROM manifests WHERE read_at < ? ORDER BY read_at`, cutoff.Unix())
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var keys []string
	var times []time.Time
	for rows.Next() {
		var k string
		var t int64
		if err := rows.Scan(&k, &t); err != nil {
			return nil, nil, err
		}
		keys = append(keys, k)
		times = append(times, time.Unix(t, 0))
	}
	return keys, times, rows.Err()
}

// vacuum gives the space of deleted chunks back to the file system.
func (d *chunkDB) vacuum() error {
	// The pragma frees a page each step: read it to the end.
	rows, err := d.w.Query(`PRAGMA incremental_vacuum`)
	if err != nil {
		return err
	}
	for rows.Next() {
	}
	if err := rows.Close(); err != nil {
		return err
	}
	_, err = d.w.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// chunkDBs opens the chunk database of every account that has one.
func (c *Cache) chunkDBs() ([]*chunkDB, error) {
	ents, err := os.ReadDir(filepath.Join(c.Dir, "accounts"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*chunkDB
	var errs []error
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		db, err := c.openChunkDB(filepath.Join(c.Dir, "accounts", e.Name()), false)
		switch {
		case err == nil:
			out = append(out, db)
		case !errors.Is(err, os.ErrNotExist):
			errs = append(errs, err)
		}
	}
	return out, errors.Join(errs...)
}
