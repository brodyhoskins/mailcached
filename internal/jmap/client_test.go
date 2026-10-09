package jmap

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/brodyhoskins/mailcached/internal/httpenc"
)

// fakeServer is a JMAP server just big enough to test the client.
func fakeServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	auth := func(h http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if u, p, ok := r.BasicAuth(); !ok || u != "alice" || p != "secret" {
				if r.Header.Get("Authorization") != "Bearer tok" {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
			}
			cw, done := httpenc.Wrap(w, r)
			h(cw, r)
			done()
		}
	}
	mux.HandleFunc("/.well-known/jmap", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/jmap/session", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/jmap/session", auth(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"capabilities":{%q:{"maxObjectsInGet":7}},"accounts":{"A1":{"name":"alice"}},
			"primaryAccounts":{%q:"A1"},"username":"alice","apiUrl":"/jmap/api",
			"downloadUrl":"/jmap/download/{accountId}/{blobId}/{name}?type={type}",
			"uploadUrl":"/jmap/upload/{accountId}/","eventSourceUrl":"/jmap/events?types={types}&closeafter={closeafter}&ping={ping}",
			"state":"s1","padding":%q}`, CapCore, CapMail, strings.Repeat("x", 2000))
	}))
	mux.HandleFunc("/jmap/api", auth(func(w http.ResponseWriter, r *http.Request) {
		var req Request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(ProblemDetails{Type: ProblemNotJSON, Status: 400})
			return
		}
		var resp Response
		resp.SessionState = "s1"
		for _, call := range req.MethodCalls {
			switch call.Name {
			case "Core/echo":
				resp.MethodResponses = append(resp.MethodResponses, call)
			default:
				inv, _ := NewInvocation("error", MethodError{Type: ErrUnknownMethod}, call.CallID)
				resp.MethodResponses = append(resp.MethodResponses, inv)
			}
		}
		json.NewEncoder(w).Encode(resp)
	}))
	mux.HandleFunc("/jmap/upload/A1/", auth(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(UploadResponse{AccountID: "A1", BlobID: ID("b-" + string(b)), Type: r.Header.Get("Content-Type"), Size: int64(len(b))})
	}))
	mux.HandleFunc("/jmap/download/A1/", auth(func(w http.ResponseWriter, r *http.Request) {
		blob := strings.Split(strings.TrimPrefix(r.URL.Path, "/jmap/download/A1/"), "/")[0]
		if blob != "big" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, strings.Repeat("Subject: hi\r\n", 500))
	}))
	mux.HandleFunc("/jmap/events", auth(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("types") != "Email,Mailbox" || r.URL.Query().Get("closeafter") != "no" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, ": ping\n\nevent: state\ndata: {\"@type\":\"StateChange\",\n")
		io.WriteString(w, "data: \"changed\":{\"A1\":{\"Email\":\"e2\"}}}\n\n")
		w.(http.Flusher).Flush()
	}))
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestClient(t *testing.T) {
	srv := fakeServer(t)
	c := &Client{SessionURL: srv.URL + "/.well-known/jmap", User: "alice", Secret: "secret"}
	ctx := context.Background()

	s, err := c.Session(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if s.APIURL != srv.URL+"/jmap/api" || s.MailAccount() != "A1" || s.Core().MaxObjectsInGet != 7 {
		t.Fatalf("session %+v, core %+v", s, s.Core())
	}
	if !strings.Contains(s.DownloadURL, "{blobId}") {
		t.Fatalf("download template lost: %s", s.DownloadURL)
	}

	b := c.NewBatch(CapMail)
	echo := b.Add("Core/echo", map[string]any{"hello": true})
	bad := b.Add("Nope/get", GetArgs{AccountID: "A1"})
	res, err := b.Do(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]bool
	if err := res.Get(echo, "Core/echo", &got); err != nil || !got["hello"] {
		t.Fatalf("echo %v, %v", got, err)
	}
	var me *MethodError
	if err := res.Get(bad, "Nope/get", &got); !errors.As(err, &me) || me.Type != ErrUnknownMethod {
		t.Fatalf("unknown method: %v", err)
	}

	up, err := c.Upload(ctx, "A1", "message/rfc822", []byte("raw"))
	if err != nil || up.BlobID != "b-raw" || up.Type != "message/rfc822" || up.Size != 3 {
		t.Fatalf("upload %+v, %v", up, err)
	}
	data, err := c.Download(ctx, "A1", "big")
	if err != nil || len(data) != 500*len("Subject: hi\r\n") {
		t.Fatalf("download %d bytes, %v", len(data), err)
	}
	if _, err := c.Download(ctx, "A1", "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing blob: %v", err)
	}

	ctx2, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var changes []StateChange
	err = c.Events(ctx2, []string{"Email", "Mailbox"}, 30, func(sc StateChange) { changes = append(changes, sc) })
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("events ended with %v", err)
	}
	if len(changes) != 1 || changes[0].Changed["A1"]["Email"] != "e2" {
		t.Fatalf("changes %+v", changes)
	}
}

func TestClientRejected(t *testing.T) {
	srv := fakeServer(t)
	c := &Client{SessionURL: srv.URL + "/jmap/session", User: "alice", Secret: "wrong"}
	if _, err := c.Session(context.Background()); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err %v", err)
	}
	c = &Client{SessionURL: srv.URL + "/jmap/session", Secret: "tok", Bearer: true}
	if _, err := c.Session(context.Background()); err != nil {
		t.Fatalf("bearer: %v", err)
	}
}

func TestExpand(t *testing.T) {
	got := expand("/d/{accountId}/{blobId}/{name}?type={type}", map[string]string{
		"accountId": "A1", "blobId": "b/1", "name": "a file.eml", "type": "message/rfc822"})
	if want := "/d/A1/b%2F1/a%20file.eml?type=message%2Frfc822"; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}
}

func TestReadEvents(t *testing.T) {
	stream := "event: ping\ndata: {}\n\n" + // not a state change
		"data: {\"@type\":\"StateChange\",\"changed\":{\"A\":{\"Mailbox\":\"m1\"}}}\r\n\r\n"
	var got []StateChange
	err := readEvents(bufio.NewReader(strings.NewReader(stream)), func() {}, func(sc StateChange) { got = append(got, sc) })
	if err != io.EOF || len(got) != 1 || got[0].Changed["A"]["Mailbox"] != "m1" {
		t.Fatalf("got %+v, %v", got, err)
	}
}

func TestSameDomain(t *testing.T) {
	if !sameDomain("example.com", "api.example.com") || sameDomain("example.com", "example.org") {
		t.Fatal("sameDomain")
	}
}
