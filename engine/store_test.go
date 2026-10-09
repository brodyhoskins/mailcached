package engine

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// TestSchemaVersion checks that a new database gets schemaVersion, and
// that a database of another version is refused and left as it is.
func TestSchemaVersion(t *testing.T) {
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "state.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	version := func() int {
		var v int
		if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	if v := version(); v != schemaVersion {
		t.Fatalf("new database has version %d, want %d", v, schemaVersion)
	}
	if err := initSchema(db); err != nil {
		t.Fatalf("second open: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO meta (name, value) VALUES ('x', 'y'); PRAGMA user_version = 99`); err != nil {
		t.Fatal(err)
	}
	if err := initSchema(db); err == nil {
		t.Fatal("database of another version was not refused")
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM meta`).Scan(&n); err != nil || n != 1 || version() != 99 {
		t.Fatalf("refused database changed: rows=%d version=%d err=%v", n, version(), err)
	}
}
