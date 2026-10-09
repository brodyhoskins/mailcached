package jmapproxy

// JMAP over WebSocket (RFC 8887): API requests and responses as text
// messages, answered in any order, and push (StateChange) once the client
// sends WebSocketPushEnable. The client logs in on the handshake, as for
// any other request. Messages are compressed with permessage-deflate when
// the client offers it.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/brodyhoskins/mailcached/internal/jmap"
)

// wsConcurrent is how many requests of one WebSocket run at once
// (maxConcurrentRequests).
const wsConcurrent = 8

func (s *Server) serveWebSocket(w http.ResponseWriter, r *http.Request) {
	c, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		Subprotocols:    []string{"jmap"},
		CompressionMode: websocket.CompressionContextTakeover,
	})
	if err != nil {
		s.Log.Info("jmap: websocket handshake failed", "user", c.login, "remote", r.RemoteAddr, "err", err)
		return
	}
	defer ws.CloseNow()
	if ws.Subprotocol() != "jmap" {
		ws.Close(websocket.StatusPolicyViolation, "the jmap subprotocol is required")
		return
	}
	ws.SetReadLimit(maxRequest)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	r = r.WithContext(context.WithValue(ctx, clientKey{}, c))
	conn := &wsConn{s: s, ws: ws, c: c, r: r}
	s.sockets.Add(1)
	defer s.sockets.Done()
	go func() {
		select {
		case <-s.quitting():
			ws.Close(websocket.StatusGoingAway, "server shutting down")
		case <-ctx.Done():
		}
	}()
	conn.serve(ctx)
}

// wsConn is one client's WebSocket.
type wsConn struct {
	s  *Server
	ws *websocket.Conn
	c  *client
	r  *http.Request

	mu       sync.Mutex
	stopPush context.CancelFunc // nil while push is off
}

func (w *wsConn) serve(ctx context.Context) {
	sem := make(chan struct{}, wsConcurrent)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer w.pushOff()
	for {
		typ, data, err := w.ws.Read(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageText {
			w.ws.Close(websocket.StatusUnsupportedData, "text messages only")
			return
		}
		var head struct {
			Type string  `json:"@type"`
			ID   *string `json:"id"`
		}
		if err := json.Unmarshal(data, &head); err != nil {
			w.problem(nil, &jmap.ProblemDetails{Type: jmap.ProblemNotJSON, Status: 400, Detail: err.Error()})
			continue
		}
		switch head.Type {
		case "Request":
			sem <- struct{}{}
			wg.Add(1)
			go func() {
				defer func() { <-sem; wg.Done() }()
				w.request(head.ID, data)
			}()
		case "WebSocketPushEnable":
			var en jmap.WSPushEnable
			if err := json.Unmarshal(data, &en); err != nil {
				w.problem(nil, &jmap.ProblemDetails{Type: jmap.ProblemNotRequest, Status: 400, Detail: err.Error()})
				continue
			}
			w.pushOn(ctx, en)
		case "WebSocketPushDisable":
			w.pushOff()
		default:
			w.problem(head.ID, &jmap.ProblemDetails{Type: jmap.ProblemNotRequest, Status: 400, Detail: "unknown @type"})
		}
	}
}

func (w *wsConn) request(id *string, data []byte) {
	var req jmap.WSRequest
	if p := parseRequest(data, &req); p != nil {
		w.problem(id, p)
		return
	}
	res, p := w.s.execute(w.r, w.c, &req.Request)
	if p != nil {
		w.problem(id, p)
		return
	}
	out := jmap.WSResponse{Type: "Response", Response: *res}
	if id != nil {
		out.RequestID = *id
	}
	w.send(out)
}

func (w *wsConn) problem(id *string, p *jmap.ProblemDetails) {
	w.send(jmap.WSRequestError{Type: "RequestError", RequestID: id, ProblemDetails: *p})
}

// send writes one message. Writes may run at once.
func (w *wsConn) send(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(w.r.Context(), time.Minute)
	defer cancel()
	if err := w.ws.Write(ctx, websocket.MessageText, b); err != nil && !errors.Is(err, context.Canceled) {
		w.s.Log.Debug("jmap: websocket write", "user", w.c.login, "err", err)
	}
}

// pushOn starts push, or changes its types. A client that gives a
// pushState other than the current one hears of the change at once.
func (w *wsConn) pushOn(ctx context.Context, en jmap.WSPushEnable) {
	w.pushOff()
	types := pushTypes
	if en.DataTypes != nil {
		types = slices.DeleteFunc(slices.Clone(en.DataTypes), func(t string) bool { return !slices.Contains(pushTypes, t) })
	}
	pctx, cancel := context.WithCancel(ctx)
	w.mu.Lock()
	w.stopPush = cancel
	w.mu.Unlock()
	a := w.c.acct
	a.Lock()
	state, wake := a.State(), a.Changed()
	a.Unlock()
	if en.PushState != "" && string(en.PushState) != state {
		w.sendState(types, state)
	}
	go func() {
		for {
			select {
			case <-pctx.Done():
				return
			case <-wake:
			}
			time.Sleep(50 * time.Millisecond) // one message for a burst
			a.Lock()
			now := a.State()
			wake = a.Changed()
			a.Unlock()
			if now != state && pctx.Err() == nil {
				state = now
				w.sendState(types, state)
			}
		}
	}()
}

func (w *wsConn) pushOff() {
	w.mu.Lock()
	if w.stopPush != nil {
		w.stopPush()
		w.stopPush = nil
	}
	w.mu.Unlock()
}

func (w *wsConn) sendState(types []string, state string) {
	if len(types) == 0 {
		return
	}
	changed := map[string]jmap.State{}
	for _, t := range types {
		changed[t] = jmap.State(state)
	}
	w.send(jmap.StateChange{Type: "StateChange", Changed: map[jmap.ID]map[string]jmap.State{w.c.id: changed},
		PushState: jmap.State(state)})
}
