package eas

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/brodyhoskins/mailcached/internal/wbxml"
)

// TestProvision: a server that wants a policy key answers 449 until the
// client provisions, in two steps, and the key is saved.
func TestProvision(t *testing.T) {
	var steps []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u, p, _ := r.BasicAuth(); u != "a@x" || p != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.Method == http.MethodOptions {
			w.Header().Set("MS-ASProtocolVersions", "2.5,12.0,12.1,14.0,14.1,16.0")
			return
		}
		write := func(n *wbxml.Node) {
			b, _ := wbxml.Encode(n)
			w.Header().Set("Content-Type", "application/vnd.ms-sync.wbxml")
			w.Write(b)
		}
		switch r.URL.Query().Get("Cmd") {
		case "Provision":
			b, _ := io.ReadAll(r.Body)
			doc, err := wbxml.Decode(b)
			if err != nil {
				t.Error(err)
				return
			}
			key := doc.Child("Policies").Child("Policy").Value("PolicyKey")
			steps = append(steps, "provision:"+key)
			pol := []*wbxml.Node{wbxml.Tx("Provision:PolicyType", policyType), wbxml.Tx("Provision:Status", "1")}
			if key == "" {
				pol = append(pol, wbxml.Tx("Provision:PolicyKey", "111"),
					wbxml.El("Provision:Data", wbxml.El("Provision:EASProvisionDoc", wbxml.Tx("Provision:DevicePasswordEnabled", "1"))))
			} else {
				pol = append(pol, wbxml.Tx("Provision:PolicyKey", "222"))
			}
			write(wbxml.El("Provision:Provision", wbxml.Tx("Provision:Status", "1"),
				wbxml.El("Provision:Policies", wbxml.El("Provision:Policy", pol...))))
		case "FolderSync":
			if r.Header.Get("MS-ASProtocolVersion") != "14.1" {
				t.Errorf("version %q", r.Header.Get("MS-ASProtocolVersion"))
			}
			if r.Header.Get("X-MS-PolicyKey") != "222" {
				steps = append(steps, "449")
				w.WriteHeader(449)
				return
			}
			steps = append(steps, "foldersync")
			write(wbxml.El("FolderHierarchy:FolderSync", wbxml.Tx("FolderHierarchy:Status", "1"),
				wbxml.Tx("FolderHierarchy:SyncKey", "1")))
		}
	}))
	defer srv.Close()

	var saved string
	c := &Client{URL: srv.URL, User: "a@x", Password: "pw", DeviceID: "D1", DeviceType: "mailcached",
		PolicyKeySaved: func(k string) { saved = k }}
	n, err := c.Do(context.Background(), "FolderSync", nil, wbxml.El("FolderHierarchy:FolderSync", wbxml.Tx("FolderHierarchy:SyncKey", "0")))
	if err != nil {
		t.Fatal(err)
	}
	if n.Value("SyncKey") != "1" || saved != "222" || c.Version() != "14.1" {
		t.Fatalf("key %q saved %q version %q", n.Value("SyncKey"), saved, c.Version())
	}
	want := []string{"449", "provision:", "provision:111", "foldersync"}
	if len(steps) != len(want) {
		t.Fatalf("steps %v", steps)
	}
	for i := range want {
		if steps[i] != want[i] {
			t.Fatalf("steps %v", steps)
		}
	}

	bad := &Client{URL: srv.URL, User: "a@x", Password: "no", DeviceID: "D1", DeviceType: "mailcached"}
	if err := bad.Options(context.Background()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong password: %v", err)
	}
}
