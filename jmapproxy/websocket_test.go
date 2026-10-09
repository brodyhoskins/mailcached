package jmapproxy

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/brodyhoskins/mailcached/internal/enginetest"
	"github.com/brodyhoskins/mailcached/internal/jmap"
)

func dialWS(t *testing.T, e *env) *websocket.Conn {
	t.Helper()
	s, err := e.c.Session(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	wc := s.WebSocketCap()
	if wc == nil || !wc.SupportsPush || !strings.HasPrefix(wc.URL, "ws://") {
		t.Fatalf("websocket capability %+v", wc)
	}
	h := http.Header{"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte(enginetest.User+":"+enginetest.Password))}}
	ws, _, err := websocket.Dial(context.Background(), wc.URL, &websocket.DialOptions{HTTPHeader: h, Subprotocols: []string{"jmap"},
		CompressionMode: websocket.CompressionContextTakeover})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.CloseNow() })
	return ws
}

func wsSend(t *testing.T, ws *websocket.Conn, msg string) {
	t.Helper()
	if err := ws.Write(context.Background(), websocket.MessageText, []byte(msg)); err != nil {
		t.Fatal(err)
	}
}

func wsRead(t *testing.T, ws *websocket.Conn) map[string]json.RawMessage {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, b, err := ws.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s: %v", b, err)
	}
	return m
}

func TestWebSocket(t *testing.T) {
	e := newEnv(t)
	ws := dialWS(t, e)

	wsSend(t, ws, `{"@type":"Request","id":"R1","using":["urn:ietf:params:jmap:core"],"methodCalls":[["Core/echo",{"hello":true},"c1"]]}`)
	m := wsRead(t, ws)
	if string(m["@type"]) != `"Response"` || string(m["requestId"]) != `"R1"` || !strings.Contains(string(m["methodResponses"]), `"hello":true`) {
		t.Fatalf("response %s", m)
	}
	wsSend(t, ws, `The quick brown fox`)
	if m := wsRead(t, ws); string(m["@type"]) != `"RequestError"` || string(m["type"]) != `"`+jmap.ProblemNotJSON+`"` {
		t.Fatalf("request error %s", m)
	}

	// Push: an old pushState gets the current state at once, and a change
	// gets another.
	wsSend(t, ws, `{"@type":"WebSocketPushEnable","dataTypes":["Email"],"pushState":"old"}`)
	first := wsRead(t, ws)
	if string(first["@type"]) != `"StateChange"` || len(first["pushState"]) < 3 || strings.Contains(string(first["changed"]), "Mailbox") {
		t.Fatalf("state change %s", first)
	}
	appendMsg(t, e.upstream(t), "INBOX", plain("ws-1@test", "Pushed", "Over the WebSocket."))
	next := wsRead(t, ws)
	if string(next["@type"]) != `"StateChange"` || string(next["pushState"]) == string(first["pushState"]) {
		t.Fatalf("second state change %s, first %s", next, first)
	}
}

// TestWebSocketClient checks the client side, against this server.
func TestWebSocketClient(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	got := make(chan jmap.StateChange, 4)
	go e.c.WebSocketPush(ctx, []string{"Email"}, func(sc jmap.StateChange) {
		select {
		case got <- sc:
		default:
		}
	})
	// New mail until one is pushed: the client connects meanwhile.
	up := e.upstream(t)
	for i := 0; ; i++ {
		appendMsg(t, up, "INBOX", plain(fmt.Sprintf("ws-%d@test", i+2), "Pushed", "To the client."))
		select {
		case sc := <-got:
			if sc.Changed[e.acct]["Email"] == "" {
				t.Fatalf("state change %+v", sc)
			}
			return
		case <-time.After(500 * time.Millisecond):
		}
		if i == 10 {
			t.Fatal("no state change")
		}
	}
}
