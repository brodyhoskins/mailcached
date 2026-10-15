package jmapproxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapserver"

	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/internal/httpenc"
	"github.com/brodyhoskins/mailcached/internal/jmap"
)

// Uploads are kept in memory for uploadTTL, at most uploadMax in all; the
// oldest go first. A client uploads a message to import it, or an
// attachment for a draft, and uses it right away.
const (
	uploadTTL = time.Hour
	uploadMax = 256 << 20
)

type upload struct {
	login string
	data  []byte
	typ   string
	at    time.Time
}

type uploads struct {
	mu    sync.Mutex
	blobs map[string]*upload // by blob ID
	size  int64
}

// put keeps data and returns its blob ID.
func (u *uploads) put(login string, data []byte, typ string) string {
	h := sha256.Sum256(append([]byte(login+"\x00"), data...))
	id := "u" + hex.EncodeToString(h[:12])
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.blobs == nil {
		u.blobs = map[string]*upload{}
	}
	u.prune()
	if old := u.blobs[id]; old != nil {
		old.at = time.Now()
		return id
	}
	for u.size+int64(len(data)) > uploadMax && len(u.blobs) > 0 {
		var oldest string
		for k, b := range u.blobs {
			if oldest == "" || b.at.Before(u.blobs[oldest].at) {
				oldest = k
			}
		}
		u.size -= int64(len(u.blobs[oldest].data))
		delete(u.blobs, oldest)
	}
	u.blobs[id] = &upload{login: login, data: data, typ: typ, at: time.Now()}
	u.size += int64(len(data))
	return id
}

func (u *uploads) get(login, id string) *upload {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.prune()
	if b := u.blobs[id]; b != nil && b.login == login {
		return b
	}
	return nil
}

func (u *uploads) prune() {
	for k, b := range u.blobs {
		if time.Since(b.at) > uploadTTL {
			u.size -= int64(len(b.data))
			delete(u.blobs, k)
		}
	}
}

var errNoBlob = errors.New("no such blob")

// blob returns the contents of a blob, and its media type if known: an
// upload, a whole message as clients see it, or a part of one, decoded.
func (s *Server) blob(c *client, id string) ([]byte, string, error) {
	if strings.HasPrefix(id, "u") {
		if b := s.uploads.get(c.login, id); b != nil {
			return b.data, b.typ, nil
		}
		return nil, "", errNoBlob
	}
	email, partID, ok := emailOfBlob(id)
	if !ok {
		return nil, "", errNoBlob
	}
	a := c.acct
	a.Lock()
	msgs := a.Email(email)
	var rep *engine.Message
	if len(msgs) > 0 {
		rep = msgs[0]
	}
	a.Unlock()
	if rep == nil {
		return nil, "", errNoBlob
	}
	got, err := a.Download([]*engine.Message{rep}, nil)
	if err != nil {
		return nil, "", err
	}
	raw := got[rep]
	if raw == nil {
		return nil, "", errNoBlob
	}
	if partID == "" {
		return raw, "message/rfc822", nil
	}
	var path []int
	for _, n := range strings.Split(partID, ".") {
		i, err := strconv.Atoi(n)
		if err != nil || i <= 0 {
			return nil, "", errNoBlob
		}
		path = append(path, i)
	}
	p := partsOfRaw(raw).find(partID)
	if p == nil {
		return nil, "", errNoBlob
	}
	data := imapserver.ExtractBinarySection(bytes.NewReader(raw), &imap.FetchItemBinarySection{Part: path, Peek: true})
	return data, p.typ, nil
}

func (s *Server) serveDownload(w http.ResponseWriter, r *http.Request) {
	c := clientOf(r)
	if jmap.ID(r.PathValue("account")) != c.id {
		http.Error(w, "No such account", http.StatusNotFound)
		return
	}
	leave, err := s.hold(w, r, c)
	if err != nil {
		return
	}
	defer leave() // until the blob is written
	data, typ, err := s.blob(c, r.PathValue("blob"))
	if errors.Is(err, errNoBlob) {
		http.Error(w, "No such blob", http.StatusNotFound)
		return
	}
	if err != nil {
		s.Log.Warn("jmap: download failed", "user", c.login, "err", err)
		http.Error(w, "Upstream server unavailable", http.StatusServiceUnavailable)
		return
	}
	if t := r.URL.Query().Get("type"); t != "" {
		if _, _, err := mime.ParseMediaType(t); err == nil {
			typ = t
		}
	}
	if typ == "" {
		typ = "application/octet-stream"
	}
	w.Header().Set("Content-Type", typ)
	name := r.PathValue("name")
	w.Header().Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": name}))
	// A blob never changes.
	w.Header().Set("Cache-Control", "private, immutable, max-age=31536000")
	_, _ = w.Write(data)
}

func (s *Server) serveUpload(w http.ResponseWriter, r *http.Request) {
	c := clientOf(r)
	if jmap.ID(r.PathValue("account")) != c.id {
		http.Error(w, "No such account", http.StatusNotFound)
		return
	}
	leave, err := s.hold(w, r, c)
	if err != nil {
		return
	}
	defer leave()
	data, err := httpenc.ReadAll(r.Header.Get("Content-Encoding"), r.Body, s.maxMessage())
	if errors.Is(err, httpenc.ErrTooLarge) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		fmt.Fprintf(w, `{"type":%q,"status":413,"limit":"maxSizeUpload"}`, jmap.ProblemLimit)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	typ := r.Header.Get("Content-Type")
	if typ == "" {
		typ = "application/octet-stream"
	}
	id := s.uploads.put(c.login, data, typ)
	writeJSON(w, http.StatusCreated, jmap.UploadResponse{AccountID: c.id, BlobID: jmap.ID(id), Type: typ, Size: int64(len(data))})
}
