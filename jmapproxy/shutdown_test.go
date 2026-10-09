package jmapproxy

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/brodyhoskins/mailcached/internal/enginetest"
)

// TestCloseEndsPush checks that push streams end cleanly at shutdown: the
// EventSource stream ends, and the WebSocket closes with "going away".
func TestCloseEndsPush(t *testing.T) {
	e := newEnv(t)
	ws := dialWS(t, e)

	req, _ := http.NewRequest(http.MethodGet, e.http.URL+"/jmap/eventsource?types=*&closeafter=no&ping=0", nil)
	req.SetBasicAuth(enginetest.User, enginetest.Password)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	r := bufio.NewReader(res.Body)
	if _, err := r.ReadString('\n'); err != nil {
		t.Fatal(err)
	}

	if err := e.srv.Close(); err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, r)
		ended <- err
	}()
	select {
	case err := <-ended:
		if err != nil {
			t.Fatalf("the event stream: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the event stream did not end")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err = ws.Read(ctx)
	if websocket.CloseStatus(err) != websocket.StatusGoingAway {
		t.Fatalf("the WebSocket: %v", err)
	}
}
