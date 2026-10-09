package easproxy

// Device state. ActiveSync servers remember, for each device, what it
// has: its folders, and in each folder its messages with their read and
// flag state, as of a sync key. A Sync sends the difference between that
// and the folder now, and the device's next request names the new key.
// The state before the last answer is kept too, so a device that never
// got an answer (a lost connection) can ask again with the key it has.
//
// The state lives in files of their own in the Store's folder, one per
// device, not in the account's database.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
)

// folderRec is a folder as a device knows it.
type folderRec struct {
	Name   string `json:"name"`
	Parent string `json:"parent"`
	Type   int    `json:"type"`
}

// itemRec is a message as a device knows it.
type itemRec struct {
	Read      bool `json:"r,omitempty"`
	Flagged   bool `json:"f,omitempty"`
	Answered  bool `json:"a,omitempty"`
	Forwarded bool `json:"w,omitempty"`
}

// collState is a folder's sync state on a device.
type collState struct {
	Key      int                  `json:"key"`
	Items    map[imap.UID]itemRec `json:"items"`
	PrevKey  int                  `json:"prevKey"`
	Prev     map[imap.UID]itemRec `json:"prev"`
	Validity uint32               `json:"validity"`
	// HMS is the folder's HIGHESTMODSEQ when the device last had all of
	// it: a Ping reports the folder when it differs.
	HMS uint64 `json:"hms"`
	// Options are the device's last options for the folder, used when a
	// Sync leaves them out.
	Options *syncOptions `json:"options,omitempty"`
}

// syncOptions are a folder's Sync options.
type syncOptions struct {
	FilterType  int        `json:"filter"`
	Prefs       []bodyPref `json:"prefs"`
	MIMESupport int        `json:"mime"`
}

type bodyPref struct {
	Type       int   `json:"type"`
	Truncation int64 `json:"trunc"`
	AllOrNone  bool  `json:"allOrNone,omitempty"`
	Preview    int   `json:"preview,omitempty"`
}

// deviceState is all a device's state.
type deviceState struct {
	FolderKey   int                   `json:"folderKey"`
	Folders     map[string]folderRec  `json:"folders"`
	PrevKey     int                   `json:"prevFolderKey"`
	PrevFolders map[string]folderRec  `json:"prevFolders"`
	Collections map[string]*collState `json:"collections"`
	// The last Ping's folders and heartbeat, for a Ping without them.
	PingFolders   []string `json:"pingFolders"`
	PingHeartbeat int      `json:"pingHeartbeat"`
	// The last Sync's folders, for a Sync without a body.
	SyncFolders []string  `json:"syncFolders"`
	PolicyKey   string    `json:"policyKey"`
	Seen        time.Time `json:"seen"`
}

// device is a device's state in memory, and where it is saved.
type device struct {
	mu   sync.Mutex
	file string
	st   deviceState
	// ping ends a waiting Ping when another request of the device
	// replaces it.
	pingMu sync.Mutex
	ping   chan struct{}
}

// devices are the devices the server has seen, by login and device ID.
type devices struct {
	mu  sync.Mutex
	dir string // "" keeps state in memory only
	m   map[string]*device
}

func hashName(parts ...string) string {
	h := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(h[:12])
}

// get returns a device's state, loading it.
func (d *devices) get(login, id string) *device {
	key := hashName(strings.ToLower(login), id)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.m == nil {
		d.m = map[string]*device{}
	}
	if dv := d.m[key]; dv != nil {
		return dv
	}
	dv := &device{}
	if d.dir != "" {
		dv.file = filepath.Join(d.dir, hashName(strings.ToLower(login)), key+".json")
		if b, err := os.ReadFile(dv.file); err == nil {
			_ = json.Unmarshal(b, &dv.st)
		}
	}
	if dv.st.Collections == nil {
		dv.st.Collections = map[string]*collState{}
	}
	d.m[key] = dv
	return dv
}

// save writes the state (dv.mu held).
func (dv *device) save() error {
	dv.st.Seen = time.Now().UTC()
	if dv.file == "" {
		return nil
	}
	b, err := json.Marshal(&dv.st)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dv.file), 0o700); err != nil {
		return err
	}
	tmp := dv.file + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, dv.file)
}

// coll returns a folder's state, or nil (dv.mu held).
func (dv *device) coll(id string) *collState { return dv.st.Collections[id] }

// itemID is a message's ServerId: its folder and UID.
func itemID(folder string, uid imap.UID) string {
	return folder + ":" + strconv.FormatUint(uint64(uid), 10)
}

// parseItemID splits a ServerId.
func parseItemID(id string) (folder string, uid imap.UID, ok bool) {
	f, u, found := strings.Cut(id, ":")
	if !found {
		return "", 0, false
	}
	n, err := strconv.ParseUint(u, 10, 32)
	if err != nil || n == 0 {
		return "", 0, false
	}
	return f, imap.UID(n), true
}

func cloneItems(m map[imap.UID]itemRec) map[imap.UID]itemRec {
	out := make(map[imap.UID]itemRec, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func cloneFolders(m map[string]folderRec) map[string]folderRec {
	out := make(map[string]folderRec, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
