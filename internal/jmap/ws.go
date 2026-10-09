package jmap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/coder/websocket"
)

// ErrNoWebSocketPush means the server has no push over a WebSocket.
var ErrNoWebSocketPush = errors.New("jmap: the server has no WebSocket push")

// WebSocketCap returns the server's WebSocket capability, or nil.
func (s *Session) WebSocketCap() *WebSocketCapability {
	raw, ok := s.Capabilities[CapWebSocket]
	if !ok {
		return nil
	}
	var c WebSocketCapability
	if json.Unmarshal(raw, &c) != nil || c.URL == "" {
		return nil
	}
	return &c
}

// wsPing is how often a quiet WebSocket is checked.
var wsPing = time.Minute

// WebSocketPush listens for state changes of types over a WebSocket (RFC
// 8887), and calls f with each, until ctx ends or the connection fails.
func (c *Client) WebSocketPush(ctx context.Context, types []string, f func(StateChange)) error {
	s, err := c.Session(ctx)
	if err != nil {
		return err
	}
	wc := s.WebSocketCap()
	if wc == nil || !wc.SupportsPush {
		return ErrNoWebSocketPush
	}
	h := http.Header{}
	req := &http.Request{Header: h}
	c.authorize(req)
	ws, resp, err := websocket.Dial(ctx, wc.URL, &websocket.DialOptions{
		HTTPClient: c.httpClient(), HTTPHeader: h, Subprotocols: []string{"jmap"},
		CompressionMode: websocket.CompressionContextTakeover,
	})
	if err != nil {
		if resp != nil && resp.StatusCode != http.StatusSwitchingProtocols {
			return &StatusError{resp.StatusCode, err.Error()}
		}
		return err
	}
	defer ws.CloseNow()
	if ws.Subprotocol() != "jmap" {
		return errors.New("jmap: the server did not take the jmap subprotocol")
	}
	ws.SetReadLimit(c.maxBody())
	en, _ := json.Marshal(WSPushEnable{Type: "WebSocketPushEnable", DataTypes: types})
	if err := ws.Write(ctx, websocket.MessageText, en); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		t := time.NewTicker(wsPing)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				pctx, pcancel := context.WithTimeout(ctx, 30*time.Second)
				err := ws.Ping(pctx)
				pcancel()
				if err != nil {
					ws.CloseNow()
					return
				}
			}
		}
	}()
	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			return err
		}
		if typ != websocket.MessageText {
			continue
		}
		var sc StateChange
		if json.Unmarshal(data, &sc) == nil && sc.Type == "StateChange" && sc.Changed != nil {
			f(sc)
		}
	}
}
