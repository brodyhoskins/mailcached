package engine

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"uuid"

	"github.com/emersion/go-imap/v2"
	_ "modernc.org/sqlite"
)

// Store keeps each account's mailbox state on disk, in one SQLite
// database per account: folders, messages with the proxy's IDs and UIDs
// and where the provider has them, the queue of changes not yet made at
// the provider, the header entries clients fill message lists with
// (headerEntry), and when clients last read each message, so a lost cache
// can be filled again. Never whole messages: those are in the Cache. It
// lets the proxy answer clients right after a restart, before the sync has
// caught up with the provider, and finish the queue after a shutdown.
//
// Each account has its own database, so accounts never wait on each
// other's writes, and an account is removed by deleting its folder
// (accountDir).
type Store struct {
	Dir string // cache_dir

	mu  sync.Mutex
	dbs map[string]*accountDB
	// maxAge is the age of the last Prune: a database opened later is
	// pruned with it, and readsSince returns nothing older.
	maxAge atomic.Int64
}

// readConns is the size of an account's pool for reads.
const readConns = 4

// accountDB is an account's database, opened twice: one connection for
// writes (SQLite takes one writer at a time), and a pool for reads, which
// WAL lets run beside a write, so a client's message list never waits on
// the sync or the backfill.
type accountDB struct {
	w, r *sql.DB
}

// A message's row keeps its place twice: where clients see it (box, uid)
// and where the provider has it (p_box, p_uid). They differ while a queued
// change has not reached the provider.
const storeSchema = `
CREATE TABLE IF NOT EXISTS meta (
	name   TEXT PRIMARY KEY,
	value  TEXT NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS mailboxes (
	name            TEXT PRIMARY KEY,
	jmap_id         TEXT NOT NULL,
	delim           TEXT NOT NULL,
	attrs           TEXT NOT NULL,
	subscribed      INTEGER NOT NULL,
	uid_validity    INTEGER NOT NULL,
	uid_next        INTEGER NOT NULL,
	p_uid_validity  INTEGER NOT NULL,
	p_uid_next      INTEGER NOT NULL,
	highest_modseq  INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS messages (
	id      BLOB PRIMARY KEY,
	box     TEXT NOT NULL,
	uid     INTEGER NOT NULL,
	p_box   TEXT NOT NULL,
	p_uid   INTEGER NOT NULL,
	origin  BLOB,
	flags   TEXT NOT NULL,
	date    INTEGER NOT NULL,
	key     TEXT NOT NULL,
	direct  INTEGER NOT NULL,
	held    INTEGER NOT NULL
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS messages_key ON messages (key);
CREATE TABLE IF NOT EXISTS ops (
	seq      INTEGER PRIMARY KEY,
	kind     TEXT NOT NULL,
	ids      BLOB NOT NULL,
	dest     TEXT NOT NULL,
	flag_op  INTEGER NOT NULL,
	flags    TEXT NOT NULL,
	at       INTEGER NOT NULL,
	started  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS headers (
	key        TEXT PRIMARY KEY,
	header     BLOB NOT NULL,
	size       INTEGER NOT NULL,
	structure  TEXT NOT NULL,
	preview    TEXT,
	used       INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS reads (
	key      TEXT PRIMARY KEY,
	read_at  INTEGER NOT NULL  -- unix seconds
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS jmap_boxes (
	id         TEXT PRIMARY KEY,
	validity   INTEGER NOT NULL,
	next       INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS jmap_uids (
	box        TEXT NOT NULL,
	email      TEXT NOT NULL,
	uid        INTEGER NOT NULL,
	PRIMARY KEY (box, email)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS eas_folders (
	id         TEXT PRIMARY KEY,
	parent     TEXT NOT NULL,
	display    TEXT NOT NULL,
	type       INTEGER NOT NULL,
	sync_key   TEXT NOT NULL,
	validity   INTEGER NOT NULL,
	next       INTEGER NOT NULL
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS eas_items (
	folder     TEXT NOT NULL,
	sid        TEXT NOT NULL,
	uid        INTEGER NOT NULL,
	flags      TEXT NOT NULL,
	PRIMARY KEY (folder, sid)
) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS changes (
	kind       TEXT NOT NULL,
	id         TEXT NOT NULL,
	created    INTEGER NOT NULL,
	changed    INTEGER NOT NULL,
	counts     INTEGER NOT NULL,
	destroyed  INTEGER NOT NULL,
	PRIMARY KEY (kind, id)
) WITHOUT ROWID;
`

// safeName matches logins usable as a folder name as they are.
var safeName = regexp.MustCompile(`^[a-z0-9][a-z0-9._+@-]*$`)

// accountDir is the folder of an account's state and cached messages.
// A login that is not a safe file name is named by its hash.
func accountDir(root, login string) string {
	login = strings.ToLower(login)
	name := login
	if !safeName.MatchString(login) || len(login) > 200 {
		name = hashKey("account", login)[:32]
	}
	return filepath.Join(root, "accounts", name)
}

// OpenStore returns the store for the databases under dir.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(filepath.Join(dir, "accounts"), 0o700); err != nil {
		return nil, err
	}
	return &Store{Dir: dir, dbs: map[string]*accountDB{}}, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for _, db := range s.dbs {
		errs = append(errs, db.r.Close(), db.w.Close())
	}
	s.dbs = nil
	return errors.Join(errs...)
}

// db opens an account's database for writes, creating it.
func (s *Store) db(account string) (*sql.DB, error) {
	db, err := s.open(account)
	if err != nil {
		return nil, err
	}
	return db.w, nil
}

// reader opens an account's database for reads.
func (s *Store) reader(account string) (*sql.DB, error) {
	db, err := s.open(account)
	if err != nil {
		return nil, err
	}
	return db.r, nil
}

func (s *Store) open(account string) (*accountDB, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if db := s.dbs[account]; db != nil {
		return db, nil
	}
	if s.dbs == nil {
		return nil, errors.New("store closed")
	}
	dir := accountDir(s.Dir, account)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	file := "file:" + filepath.Join(dir, "state.sqlite3") + "?_pragma=busy_timeout(5000)"
	w, err := sql.Open("sqlite", file+"&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	w.SetMaxOpenConns(1)
	if err := initSchema(w); err != nil {
		w.Close()
		return nil, err
	}
	if age := time.Duration(s.maxAge.Load()); age > 0 {
		// A failure waits for the next Prune.
		_, _ = prune(w, time.Now().Add(-age).Unix())
	}
	// The journal mode is the writer's to set: setting it, even to what
	// it is, can wait on a write.
	r, err := sql.Open("sqlite", file+"&_pragma=query_only(1)")
	if err != nil {
		w.Close()
		return nil, err
	}
	// Kept open: a new connection reads the schema again.
	r.SetMaxOpenConns(readConns)
	r.SetMaxIdleConns(readConns)
	db := &accountDB{w: w, r: r}
	s.dbs[account] = db
	go warm(filepath.Join(dir, "state.sqlite3"))
	return db, nil
}

// warm reads a database file through once, so the system caches it. A
// lookup in a file that is not cached reads pages from all over the disk,
// which takes seconds for a client's message list on a slow disk; one
// read from start to end takes a moment.
func warm(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = io.Copy(io.Discard, f)
}

// schemaVersion is the version of storeSchema. Until the first release
// there is one schema, version 1: a change to it is made in storeSchema.
// A new table is created in an old database when it opens (IF NOT
// EXISTS); any other change needs the old database deleted by hand.
const schemaVersion = 1

// initSchema creates the tables of a new database. A database of another
// version is refused: it is never changed or emptied.
func initSchema(db *sql.DB) error {
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	switch v {
	case 0:
		if _, err := db.Exec(storeSchema); err != nil {
			return err
		}
		_, err := db.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, schemaVersion))
		return err
	case schemaVersion:
		_, err := db.Exec(storeSchema)
		return err
	}
	return fmt.Errorf("cache database has schema version %d, this build uses %d: delete the account's cache folder", v, schemaVersion)
}

// storedMailbox is a mailbox as loaded from the store.
type storedMailbox struct {
	name          string
	jmapID        string
	delim         rune
	attrs         []imap.MailboxAttr
	subscribed    bool
	uidValidity   uint32
	uidNext       imap.UID
	pUIDValidity  uint32
	pUIDNext      imap.UID
	highestModSeq uint64
}

// savedState is an account's state as loaded from the store.
type savedState struct {
	boxes []*storedMailbox
	msgs  []*Message // every message, ordered by box and UID
	ops   []*op      // the queue, oldest first
	log   *changeLog
	// rebind says the state was saved for another provider: what clients
	// see is kept, and where the provider has each message is not.
	rebind bool
}

// load returns an account's saved state. provider is the server the
// account goes to now. If the state was saved for another one (the account
// moved, or its provider now speaks JMAP), where that provider had each
// message is forgotten, since UIDs from one provider mean nothing at
// another (and two may report the same UIDVALIDITY). What clients see is
// kept: the sync matches the messages at the new provider to it by their
// cache keys, as it does for a queued copy, so clients keep their UIDs and
// IDs. Header entries of messages no folder has any more are dropped.
func (s *Store) load(account, provider string) (*savedState, error) {
	db, err := s.db(account)
	if err != nil {
		return nil, err
	}
	var saved string
	err = db.QueryRow(`SELECT value FROM meta WHERE name = 'provider'`).Scan(&saved)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	out := &savedState{}
	if provider != "" && saved != provider {
		if _, err := db.Exec(`UPDATE messages SET p_box = '', p_uid = 0;
			UPDATE mailboxes SET p_uid_validity = 0, p_uid_next = 0, highest_modseq = 0;
			DELETE FROM jmap_boxes; DELETE FROM jmap_uids; DELETE FROM meta WHERE name LIKE 'jmap_%';
			DELETE FROM eas_folders; DELETE FROM eas_items;
			DELETE FROM meta WHERE name IN ('eas_folder_key', 'eas_modseq', 'eas_policy_key');
			INSERT INTO meta (name, value) VALUES ('provider', ?)
			ON CONFLICT (name) DO UPDATE SET value = excluded.value`, provider); err != nil {
			return nil, err
		}
		out.rebind = saved != ""
	}
	if _, err := db.Exec(`DELETE FROM headers WHERE key NOT IN (SELECT key FROM messages)`); err != nil {
		return nil, err
	}

	rows, err := db.Query(`SELECT name, jmap_id, delim, attrs, subscribed, uid_validity, uid_next, p_uid_validity, p_uid_next, highest_modseq FROM mailboxes`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		m := &storedMailbox{}
		var delim, attrs string
		var sub int
		if err := rows.Scan(&m.name, &m.jmapID, &delim, &attrs, &sub, &m.uidValidity, &m.uidNext, &m.pUIDValidity, &m.pUIDNext, &m.highestModSeq); err != nil {
			rows.Close()
			return nil, err
		}
		if delim != "" {
			m.delim = []rune(delim)[0]
		}
		for _, a := range strings.Fields(attrs) {
			m.attrs = append(m.attrs, imap.MailboxAttr(a))
		}
		m.subscribed = sub != 0
		out.boxes = append(out.boxes, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	rows, err = db.Query(`SELECT id, box, uid, p_box, p_uid, origin, flags, date, key, direct, held FROM messages ORDER BY box, uid`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		m := &Message{}
		var id, origin []byte
		var uid, pUID uint32
		var flags string
		var date int64
		if err := rows.Scan(&id, &m.box, &uid, &m.pBox, &pUID, &origin, &flags, &date, &m.key, &m.direct, &m.held); err != nil {
			rows.Close()
			return nil, err
		}
		copy(m.id[:], id)
		copy(m.origin[:], origin)
		m.uid, m.pUID = imap.UID(uid), imap.UID(pUID)
		m.flags, m.date = splitFlags(flags), time.Unix(date, 0).UTC()
		out.msgs = append(out.msgs, m)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	if out.log, err = loadLog(db); err != nil {
		return nil, err
	}

	rows, err = db.Query(`SELECT seq, kind, ids, dest, flag_op, flags, at, started FROM ops ORDER BY seq`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		o := &op{}
		var ids []byte
		var flags string
		var at int64
		if err := rows.Scan(&o.seq, &o.kind, &ids, &o.dest, &o.flagOp, &flags, &at, &o.started); err != nil {
			return nil, err
		}
		for i := 0; i+16 <= len(ids); i += 16 {
			o.ids = append(o.ids, uuid.UUID(ids[i:i+16]))
		}
		o.flags, o.at = splitFlags(flags), time.Unix(at, 0)
		out.ops = append(out.ops, o)
	}
	return out, rows.Err()
}

// Headers returns the header entries saved for keys. A read counts as use
// for prune.
func (s *Store) Headers(account string, keys []string) map[string]*HeaderEntry {
	if s == nil || len(keys) == 0 {
		return nil
	}
	r, err := s.reader(account)
	if err != nil {
		return nil
	}
	out := map[string]*HeaderEntry{}
	var stale []string
	cutoff := time.Now().Add(-touchEvery).Unix()
	for chunk := range slices.Chunk(keys, headersBatch) {
		args := make([]any, len(chunk))
		for i, k := range chunk {
			args[i] = k
		}
		rows, err := r.Query(`SELECT key, header, size, structure, preview, used FROM headers WHERE key IN (?`+strings.Repeat(", ?", len(chunk)-1)+`)`, args...)
		if err != nil {
			continue
		}
		for rows.Next() {
			var key, structure string
			var preview sql.NullString
			var h HeaderEntry
			var used int64
			if rows.Scan(&key, &h.Header, &h.Size, &structure, &preview, &used) != nil {
				continue
			}
			if preview.Valid {
				h.Preview = &preview.String
			}
			if h.Structure, err = decodeStructure(structure); err != nil {
				continue
			}
			out[key] = &h
			if used < cutoff {
				stale = append(stale, key)
			}
		}
		rows.Close()
	}
	if len(stale) > 0 {
		if db, err := s.db(account); err == nil {
			if tx, err := db.Begin(); err == nil {
				now := time.Now().Unix()
				for _, key := range stale {
					_, _ = tx.Exec(`UPDATE headers SET used = ? WHERE key = ?`, now, key)
				}
				_ = tx.Commit()
			}
		}
	}
	return out
}

// headersBatch bounds the keys of one query, below SQLite's limit on
// parameters.
const headersBatch = 500

// putHeaders saves header entries.
func (s *Store) putHeaders(account string, entries map[string]*HeaderEntry) error {
	if s == nil || len(entries) == 0 {
		return nil
	}
	db, err := s.db(account)
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	now := time.Now().Unix()
	for key, h := range entries {
		structure, err := encodeStructure(h.Structure)
		if err != nil {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO headers (key, header, size, structure, preview, used) VALUES (?, ?, ?, ?, ?, ?)
			ON CONFLICT (key) DO UPDATE SET header = excluded.header, size = excluded.size,
			structure = excluded.structure, preview = coalesce(excluded.preview, headers.preview), used = excluded.used`,
			key, h.Header, h.Size, structure, h.Preview, now); err != nil {
			return errors.Join(err, tx.Rollback())
		}
	}
	return tx.Commit()
}

// headerKeys returns the keys that have a header entry. Unlike headers, it
// does not count as use.
func (s *Store) headerKeys(account string) (map[string]bool, error) {
	if s == nil {
		return nil, nil
	}
	db, err := s.reader(account)
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT key FROM headers`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		out[key] = true
	}
	return out, rows.Err()
}

// noteReads records that a client read the messages of keys now, unless
// a later read is recorded (a clock set back). The backfill downloads them
// again if the cache loses them (readsSince).
func (s *Store) noteReads(account string, keys []string) error {
	if s == nil || len(keys) == 0 {
		return nil
	}
	db, err := s.db(account)
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	now := time.Now()
	for _, key := range keys {
		if _, err := tx.Exec(`INSERT INTO reads (key, read_at) VALUES (?, ?)
			ON CONFLICT (key) DO UPDATE SET read_at = excluded.read_at WHERE read_at < excluded.read_at`,
			key, now.Unix()); err != nil {
			return errors.Join(err, tx.Rollback())
		}
	}
	return tx.Commit()
}

// reads returns when a client last read each message, by key, within the
// age of the last Prune. Times are in seconds.
func (s *Store) reads(account string) (map[string]time.Time, error) {
	if s == nil {
		return nil, nil
	}
	var t time.Time
	if age := time.Duration(s.maxAge.Load()); age > 0 {
		t = time.Now().Add(-age)
	}
	db, err := s.reader(account)
	if err != nil {
		return nil, err
	}
	rows, err := db.Query(`SELECT key, read_at FROM reads WHERE read_at >= ?`, t.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]time.Time{}
	for rows.Next() {
		var key string
		var at int64
		if err := rows.Scan(&key, &at); err != nil {
			return nil, err
		}
		out[key] = time.Unix(at, 0)
	}
	return out, rows.Err()
}

// readsSince returns the keys of the messages a client read after t, and
// within the age of the last Prune. A read in the second of t counts, as
// it may be after t.
func (s *Store) readsSince(account string, t time.Time) (map[string]bool, error) {
	all, err := s.reads(account)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for key, at := range all {
		if readAfter(at, t) {
			out[key] = true
		}
	}
	return out, nil
}

// ForgetReads deletes the records of reads of keys in the account folder
// dir: Trim deleted their messages (Cache.Reads), and the backfill must
// not download them again.
func (s *Store) ForgetReads(dir string, keys []string) error {
	return s.inDir(dir, keys, `DELETE FROM reads WHERE key = ?`)
}

// NoteReadsIn records that a client read keys now, in the account folder
// dir: Trim kept their messages, which a client read meanwhile, after
// ForgetReads.
func (s *Store) NoteReadsIn(dir string, keys []string) error {
	now := strconv.FormatInt(time.Now().Unix(), 10)
	return s.inDir(dir, keys, `INSERT INTO reads (key, read_at) VALUES (?, `+now+`)
		ON CONFLICT (key) DO UPDATE SET read_at = excluded.read_at WHERE read_at < excluded.read_at`)
}

// inDir runs query with each of keys in one transaction, in the database
// of the account folder dir, open or not. None if it has no database.
func (s *Store) inDir(dir string, keys []string, query string) error {
	if s == nil || len(keys) == 0 {
		return nil
	}
	var db *sql.DB
	s.mu.Lock()
	for login, d := range s.dbs {
		if accountDir(s.Dir, login) == dir {
			db = d.w
		}
	}
	s.mu.Unlock()
	if db == nil {
		// An account not open now: its file, if it has one.
		path := filepath.Join(dir, "state.sqlite3")
		if _, err := os.Stat(path); err != nil {
			return nil
		}
		var err error
		if db, err = sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)"); err != nil {
			return err
		}
		defer db.Close()
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, key := range keys {
		if _, err := tx.Exec(query, key); err != nil {
			return errors.Join(err, tx.Rollback())
		}
	}
	return tx.Commit()
}

// readAfter reports whether a read recorded at at may be after t: both are
// in seconds.
func readAfter(at, t time.Time) bool { return at.Unix() >= t.Unix() }

// deleteHeaders drops the header entries of messages that are gone.
func (s *Store) deleteHeaders(account string, keys []string) error {
	if s == nil || len(keys) == 0 {
		return nil
	}
	db, err := s.db(account)
	if err != nil {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	for _, key := range keys {
		if _, err := tx.Exec(`DELETE FROM headers WHERE key = ?`, key); err != nil {
			return errors.Join(err, tx.Rollback())
		}
	}
	return tx.Commit()
}

// Prune deletes header entries not read for maxAge, and records of reads
// older than that, in the databases open now. It returns how many header
// entries it deleted. Others are pruned when they are opened.
func (s *Store) Prune(maxAge time.Duration) (int, error) {
	if s == nil || maxAge <= 0 {
		return 0, nil
	}
	s.maxAge.Store(int64(maxAge))
	s.mu.Lock()
	dbs := make([]*sql.DB, 0, len(s.dbs))
	for _, db := range s.dbs {
		dbs = append(dbs, db.w)
	}
	s.mu.Unlock()
	cutoff := time.Now().Add(-maxAge).Unix()
	n := 0
	var errs []error
	for _, db := range dbs {
		k, err := prune(db, cutoff)
		n += k
		if err != nil {
			errs = append(errs, err)
		}
	}
	return n, errors.Join(errs...)
}

// prune deletes from db the header entries and the records of reads older
// than cutoff (unix seconds), and returns how many header entries.
func prune(db *sql.DB, cutoff int64) (int, error) {
	res, err := db.Exec(`DELETE FROM headers WHERE used < ?`, cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	_, err = db.Exec(`DELETE FROM reads WHERE read_at < ?`, cutoff)
	return int(n), err
}

func joinFlags(flags []imap.Flag) string {
	s := make([]string, len(flags))
	for i, f := range flags {
		s[i] = string(f)
	}
	return strings.Join(s, " ")
}

func splitFlags(s string) []imap.Flag {
	var out []imap.Flag
	for _, f := range strings.Fields(s) {
		out = append(out, imap.Flag(f))
	}
	return out
}

func joinAttrs(attrs []imap.MailboxAttr) string {
	s := make([]string, len(attrs))
	for i, a := range attrs {
		s[i] = string(a)
	}
	return strings.Join(s, " ")
}

// storeTx batches the writes of one sync step. It saves the changes the
// account's change log recorded meanwhile when it commits.
type storeTx struct {
	tx  *sql.Tx
	err error
	log *changeLog
}

// begin starts a batch (a.mu held). Without a Store the batch does
// nothing.
func (a *Account) begin() *storeTx {
	s := a.b.Store
	if s == nil {
		return &storeTx{log: a.log}
	}
	db, err := s.db(a.login)
	if err != nil {
		return &storeTx{err: err, log: a.log}
	}
	tx, err := db.Begin()
	return &storeTx{tx: tx, err: err, log: a.log}
}

func (t *storeTx) exec(q string, args ...any) {
	if t.tx == nil || t.err != nil {
		return
	}
	_, t.err = t.tx.Exec(q, args...)
}

func (t *storeTx) putMailbox(m *Mailbox) {
	t.exec(`INSERT INTO mailboxes (name, jmap_id, delim, attrs, subscribed, uid_validity, uid_next, p_uid_validity, p_uid_next, highest_modseq)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (name) DO UPDATE SET jmap_id = excluded.jmap_id, delim = excluded.delim, attrs = excluded.attrs,
		subscribed = excluded.subscribed, uid_validity = excluded.uid_validity, uid_next = excluded.uid_next,
		p_uid_validity = excluded.p_uid_validity, p_uid_next = excluded.p_uid_next, highest_modseq = excluded.highest_modseq`,
		m.name, m.jmapID, string(m.delim), joinAttrs(m.attrs), m.subscribed, m.uidValidity, uint32(m.uidNext),
		m.pUIDValidity, uint32(m.pUIDNext), m.highestModSeq)
}

func (t *storeTx) deleteMailbox(name string) {
	t.exec(`DELETE FROM mailboxes WHERE name = ?`, name)
}

// renameMailbox renames a folder and every message's place in it.
func (t *storeTx) renameMailbox(name, newName string) {
	t.exec(`UPDATE mailboxes SET name = ? WHERE name = ?`, newName, name)
	t.exec(`UPDATE messages SET box = ? WHERE box = ?`, newName, name)
	t.exec(`UPDATE messages SET p_box = ? WHERE p_box = ?`, newName, name)
}

func (t *storeTx) putMessage(m *Message) {
	var origin []byte
	if m.origin != uuid.Nil() {
		origin = m.origin[:]
	}
	t.exec(`INSERT INTO messages (id, box, uid, p_box, p_uid, origin, flags, date, key, direct, held) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET box = excluded.box, uid = excluded.uid, p_box = excluded.p_box,
		p_uid = excluded.p_uid, origin = excluded.origin, flags = excluded.flags, date = excluded.date,
		key = excluded.key, direct = excluded.direct, held = excluded.held`,
		m.id[:], m.box, uint32(m.uid), m.pBox, uint32(m.pUID), origin, joinFlags(m.flags), m.date.Unix(), m.key, m.direct, m.held)
}

func (t *storeTx) deleteMessage(m *Message) {
	t.exec(`DELETE FROM messages WHERE id = ?`, m.id[:])
}

func (t *storeTx) putOp(o *op) {
	ids := make([]byte, 0, 16*len(o.ids))
	for _, id := range o.ids {
		ids = append(ids, id[:]...)
	}
	t.exec(`INSERT INTO ops (seq, kind, ids, dest, flag_op, flags, at, started) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (seq) DO UPDATE SET started = excluded.started`,
		o.seq, o.kind, ids, o.dest, o.flagOp, joinFlags(o.flags), o.at.Unix(), o.started)
}

func (t *storeTx) deleteOp(o *op) {
	t.exec(`DELETE FROM ops WHERE seq = ?`, o.seq)
}

// commit ends the batch, reporting the first error.
func (t *storeTx) commit() error {
	t.saveLog()
	if t.tx == nil {
		return t.err
	}
	if t.err != nil {
		return errors.Join(t.err, t.tx.Rollback())
	}
	return t.tx.Commit()
}
