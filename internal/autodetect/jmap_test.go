package autodetect

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestJMAPFromSRV finds a JMAP server from an SRV record, through the MX
// domain, and prefers it to the well-known URL.
func TestJMAPFromSRV(t *testing.T) {
	f := &fake{
		mx:  map[string][]*net.MX{"custom.example": {{Host: "in1.mailhost.example."}}},
		srv: map[string][]*net.SRV{"_jmap._tcp.mailhost.example": {{Target: "api.mailhost.example.", Port: 443}}},
	}
	d := f.detector()
	d.JMAP = true
	var asked []string
	d.UsableJMAP = func(_ context.Context, u string) bool {
		asked = append(asked, u)
		return u == "https://api.mailhost.example/.well-known/jmap" || u == "https://mailhost.example/.well-known/jmap"
	}
	r, err := d.Lookup("alice@custom.example")
	if err != nil {
		t.Fatal(err)
	}
	if r.JMAP.Upstream.Upstream != "https://api.mailhost.example/.well-known/jmap" || r.JMAP.From != "srv mailhost.example" {
		t.Fatalf("JMAP %+v (asked %v)", r.JMAP, asked)
	}
	if r.IMAP.Upstream.Upstream != "" {
		t.Fatalf("IMAP %+v", r.IMAP)
	}
}

// TestJMAPOff skips JMAP unless asked.
func TestJMAPOff(t *testing.T) {
	f := &fake{srv: map[string][]*net.SRV{"_jmap._tcp.x.example": {{Target: "jmap.x.example.", Port: 8443}}}}
	d := f.detector()
	d.UsableJMAP = func(context.Context, string) bool { return true }
	if _, err := d.Lookup("a@x.example"); err == nil {
		t.Fatal("found something with JMAP off")
	}
	d = f.detector()
	d.JMAP = true
	d.UsableJMAP = func(_ context.Context, u string) bool { return strings.Contains(u, ":8443") }
	r, err := d.Lookup("a@x.example")
	if err != nil || r.JMAP.Upstream.Upstream != "https://jmap.x.example:8443/.well-known/jmap" {
		t.Fatalf("%+v, %v", r.JMAP, err)
	}
}

// TestUsableJMAP accepts a 401 that asks for credentials and a session
// with mail, and nothing else.
func TestUsableJMAP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/auth":
			w.Header().Set("WWW-Authenticate", `Basic realm="JMAP"`)
			w.WriteHeader(http.StatusUnauthorized)
		case "/bare401":
			w.WriteHeader(http.StatusUnauthorized)
		case "/session":
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"capabilities":{"urn:ietf:params:jmap:core":{},"urn:ietf:params:jmap:mail":{}}}`))
		case "/html":
			w.Write([]byte("<html>urn:ietf:params:jmap:mail</html>"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	ok := usableJMAP(srv.Client())
	for path, want := range map[string]bool{"/auth": true, "/bare401": false, "/session": true, "/html": false, "/none": false} {
		if got := ok(context.Background(), srv.URL+path); got != want {
			t.Errorf("%s: %v, want %v", path, got, want)
		}
	}
}
