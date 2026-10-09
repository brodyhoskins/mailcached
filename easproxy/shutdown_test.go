package easproxy

import (
	"net"
	"net/http/httptest"
	"testing"
	"time"
)

// TestCloseEndsPing checks that a Ping waiting at shutdown is answered,
// as if its heartbeat expired, not cut off.
func TestCloseEndsPing(t *testing.T) {
	e := newEnv(t)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go e.srv.Serve(l)
	// Talk to the server's own listener, not the test server.
	e.http = &httptest.Server{URL: "http://" + l.Addr().String()}
	ids, _ := e.folders(t)
	// Synced, so the Ping has nothing to report.
	key := e.syncOnce(t, ids["INBOX"], "0").Value("SyncKey")
	e.syncOnce(t, ids["INBOX"], key)

	done := make(chan *node, 1)
	go func() {
		done <- e.post(t, "Ping", el("Ping:Ping", tx("Ping:HeartbeatInterval", "600"),
			el("Ping:Folders", el("Ping:Folder", tx("Ping:Id", ids["INBOX"]), tx("Ping:Class", "Email")))))
	}()
	time.Sleep(300 * time.Millisecond)
	if err := e.srv.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-done:
		if p.Value("Status") != "1" {
			t.Fatalf("ping: status %s", p.Value("Status"))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Ping did not return")
	}
}
