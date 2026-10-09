package autodetect

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestActiveSyncGuess finds an ActiveSync server on mail.<domain>.
func TestActiveSyncGuess(t *testing.T) {
	f := &fake{}
	d := f.detector()
	d.ActiveSync = true
	var asked []string
	d.UsableActiveSync = func(_ context.Context, u string) bool {
		asked = append(asked, u)
		return u == "https://mail.x.example/Microsoft-Server-ActiveSync"
	}
	r, err := d.Lookup("a@x.example")
	if err != nil {
		t.Fatal(err)
	}
	if r.ActiveSync.Upstream.Upstream != "https://mail.x.example/Microsoft-Server-ActiveSync" || len(asked) != 1 {
		t.Fatalf("%+v (asked %v)", r.ActiveSync, asked)
	}

	d = f.detector()
	d.UsableActiveSync = func(context.Context, string) bool { return true }
	if _, err := d.Lookup("a@x.example"); err == nil {
		t.Fatal("found something with ActiveSync off")
	}
}

// TestUsableActiveSync accepts a 401 that asks for Basic credentials at
// the endpoint alone, or the protocol versions; not a login wall.
func TestUsableActiveSync(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/wall/"):
			w.Header().Set("WWW-Authenticate", `Basic realm="x"`)
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/eas/Microsoft-Server-ActiveSync":
			w.Header().Set("WWW-Authenticate", `Basic realm="ActiveSync"`)
			w.WriteHeader(http.StatusUnauthorized)
		case r.URL.Path == "/open/Microsoft-Server-ActiveSync":
			w.Header().Set("MS-ASProtocolVersions", "14.1")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	usable := usableActiveSync(srv.Client())
	for path, want := range map[string]bool{
		"/eas/Microsoft-Server-ActiveSync":  true,
		"/open/Microsoft-Server-ActiveSync": true,
		"/wall/Microsoft-Server-ActiveSync": false,
		"/none/Microsoft-Server-ActiveSync": false,
	} {
		if got := usable(context.Background(), srv.URL+path); got != want {
			t.Errorf("%s: %v, want %v", path, got, want)
		}
	}
}
