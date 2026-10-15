package jmap

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/brodyhoskins/mailcached/internal/gate"
	"github.com/brodyhoskins/mailcached/internal/httpenc"
	"time"
)

// Client is a JMAP client for one user.
type Client struct {
	HTTP       *http.Client
	SessionURL string // e.g. https://example.com/.well-known/jmap
	User       string
	Secret     string // password, or token with Bearer
	Bearer     bool   // send Secret as a Bearer token, not Basic auth
	UserAgent  string
	// MaxBody limits a decoded response or download. Default 64 MiB.
	MaxBody int64
	// MaxConcurrent caps the API requests, uploads and downloads at a
	// time, together. The session's maxConcurrentRequests and
	// maxConcurrentUpload cap their kind as well. 0: no cap of its own.
	MaxConcurrent int

	mu      sync.Mutex
	session *Session
	// Requests running: by kind, and in all.
	api, upload, download, all gate.Gate
	backoff                    gate.Backoff // after a 503 or 429
}

// Capacity returns the API requests the client sends at once, 0 for no
// limit: MaxConcurrent, or the session's maxConcurrentRequests if lower.
func (c *Client) Capacity() int {
	c.mu.Lock()
	s := c.session
	c.mu.Unlock()
	n := c.MaxConcurrent
	if s != nil {
		if m := s.Core().MaxConcurrentRequests; m > 0 && (n <= 0 || m < n) {
			n = m
		}
	}
	return max(n, 0)
}

// enter waits for room for one more request: in g, up to the server's
// limit for its kind in the latest session (s while none is cached; 0
// for none), and up to MaxConcurrent in all.
func (c *Client) enter(ctx context.Context, g *gate.Gate, s *Session, kind func(CoreCapability) int) (leave func(), err error) {
	limit := func() int {
		c.mu.Lock()
		if c.session != nil {
			s = c.session
		}
		c.mu.Unlock()
		if n := kind(s.Core()); n > 0 {
			return n
		}
		return math.MaxInt
	}
	if err := g.EnterFunc(ctx, limit); err != nil {
		return nil, err
	}
	if c.MaxConcurrent > 0 {
		if err := c.all.Enter(ctx, c.MaxConcurrent); err != nil {
			g.Leave()
			return nil, err
		}
	}
	return func() {
		if c.MaxConcurrent > 0 {
			c.all.Leave()
		}
		g.Leave()
	}, nil
}

// ErrUnauthorized means the server rejected the credentials.
var ErrUnauthorized = errors.New("jmap: credentials rejected")

// StatusError is an HTTP status the client did not expect.
type StatusError struct {
	Status int
	Body   string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("jmap: http status %d: %s", e.Status, e.Body)
}

func (c *Client) maxBody() int64 {
	if c.MaxBody > 0 {
		return c.MaxBody
	}
	return 64 << 20
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func (c *Client) authorize(req *http.Request) {
	if c.Bearer {
		req.Header.Set("Authorization", "Bearer "+c.Secret)
		return
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.User+":"+c.Secret)))
}

// do sends req with the credentials and the client's headers. On a
// redirect the credentials go along to the same host, or over HTTPS to a
// host in the same domain (example.com/.well-known/jmap to
// api.example.com). It returns ErrUnauthorized for 401 and 403.
func (c *Client) do(req *http.Request) (*http.Response, error) {
	hc := *c.httpClient()
	origin := req.URL.Host
	hc.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return errors.New("jmap: too many redirects")
		}
		if r.URL.Host == origin || r.URL.Scheme == "https" && sameDomain(r.URL.Hostname(), via[0].URL.Hostname()) {
			c.authorize(r)
		} else {
			r.Header.Del("Authorization")
		}
		return nil
	}
	c.authorize(req)
	req.Header.Set("Accept-Encoding", httpenc.Accept)
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
	if err := c.backoff.Wait(req.Context()); err != nil {
		return nil, fmt.Errorf("jmap: %w", err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	c.backoff.Note(resp.StatusCode, resp.Header.Get("Retry-After"))
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		resp.Body.Close()
		return nil, ErrUnauthorized
	}
	return resp, nil
}

// sameDomain reports whether two host names end in the same two labels.
func sameDomain(a, b string) bool {
	last2 := func(h string) string {
		labels := strings.Split(strings.TrimSuffix(strings.ToLower(h), "."), ".")
		if len(labels) < 2 {
			return h
		}
		return strings.Join(labels[len(labels)-2:], ".")
	}
	return last2(a) == last2(b)
}

// readBody reads a decoded response body, and closes it.
func (c *Client) readBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	return httpenc.ReadAll(resp.Header.Get("Content-Encoding"), resp.Body, c.maxBody())
}

// Session returns the session resource, fetching it the first time.
func (c *Client) Session(ctx context.Context) (*Session, error) {
	c.mu.Lock()
	s := c.session
	c.mu.Unlock()
	if s != nil {
		return s, nil
	}
	return c.RefreshSession(ctx)
}

// RefreshSession fetches the session resource again.
func (c *Client) RefreshSession(ctx context.Context) (*Session, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.SessionURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := c.do(req)
	if err != nil {
		return nil, err
	}
	body, err := c.readBody(resp)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &StatusError{resp.StatusCode, snippet(body)}
	}
	var s Session
	if err := json.Unmarshal(body, &s); err != nil {
		return nil, fmt.Errorf("jmap: session: %w", err)
	}
	if s.APIURL == "" {
		return nil, errors.New("jmap: session has no apiUrl")
	}
	// The URLs may be relative to the session resource.
	base := resp.Request.URL
	for _, u := range []*string{&s.APIURL, &s.DownloadURL, &s.UploadURL, &s.EventSourceURL} {
		if *u != "" {
			*u = resolve(base, *u)
		}
	}
	c.mu.Lock()
	c.session = &s
	c.mu.Unlock()
	return &s, nil
}

// resolve makes ref absolute against base. Templates' braces survive.
func resolve(base *url.URL, ref string) string {
	if strings.Contains(ref, "://") {
		return ref
	}
	r, err := url.Parse(strings.NewReplacer("{", "%7B", "}", "%7D").Replace(ref))
	if err != nil {
		return ref
	}
	return strings.NewReplacer("%7B", "{", "%7D", "}").Replace(base.ResolveReference(r).String())
}

func snippet(b []byte) string {
	if len(b) > 200 {
		b = b[:200]
	}
	return strings.TrimSpace(string(b))
}

// Call sends one API request.
func (c *Client) Call(ctx context.Context, r *Request) (*Response, error) {
	s, err := c.Session(ctx)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(r)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.APIURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	leave, err := c.enter(ctx, &c.api, s, func(cc CoreCapability) int { return cc.MaxConcurrentRequests })
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		leave()
		return nil, err
	}
	out, err := c.readBody(resp)
	leave()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		var p ProblemDetails
		if json.Unmarshal(out, &p) == nil && p.Type != "" {
			return nil, &p
		}
		return nil, &StatusError{resp.StatusCode, snippet(out)}
	}
	var res Response
	if err := json.Unmarshal(out, &res); err != nil {
		return nil, fmt.Errorf("jmap: response: %w", err)
	}
	if res.SessionState != "" && res.SessionState != s.State {
		// The session changed (new URLs or accounts): read it again next
		// time.
		c.mu.Lock()
		if c.session == s {
			c.session = nil
		}
		c.mu.Unlock()
	}
	return &res, nil
}

// Batch builds a request of several method calls.
type Batch struct {
	c   *Client
	req Request
	err error
}

// NewBatch starts a request using the capabilities using (core is added).
func (c *Client) NewBatch(using ...string) *Batch {
	return &Batch{c: c, req: Request{Using: append([]string{CapCore}, using...)}}
}

// Add adds a call and returns its call id. args is encoded as JSON; a map
// can hold back-references ("#ids": ResultReference).
func (b *Batch) Add(name string, args any) string {
	id := "c" + strconv.Itoa(len(b.req.MethodCalls))
	inv, err := NewInvocation(name, args, id)
	if err != nil && b.err == nil {
		b.err = err
	}
	b.req.MethodCalls = append(b.req.MethodCalls, inv)
	return id
}

// Ref refers to the result of call id, of method name, at path.
func (b *Batch) Ref(id, name, path string) ResultReference {
	return ResultReference{ResultOf: id, Name: name, Path: path}
}

// Do sends the request.
func (b *Batch) Do(ctx context.Context) (*Results, error) {
	if b.err != nil {
		return nil, b.err
	}
	resp, err := b.c.Call(ctx, &b.req)
	if err != nil {
		return nil, err
	}
	return &Results{resp}, nil
}

// Results are the responses to a Batch.
type Results struct {
	Response *Response
}

// Get decodes the response to call id named name into out. A method
// error comes back as *MethodError.
func (r *Results) Get(id, name string, out any) error {
	for _, inv := range r.Response.MethodResponses {
		if inv.CallID != id {
			continue
		}
		if inv.Name == "error" {
			var me MethodError
			if err := json.Unmarshal(inv.Args, &me); err != nil {
				return err
			}
			return &me
		}
		if inv.Name == name {
			return json.Unmarshal(inv.Args, out)
		}
	}
	return fmt.Errorf("jmap: no %s response to call %s", name, id)
}

// expand fills a URL template's {name} variables (RFC 6570 level 1).
func expand(tmpl string, vars map[string]string) string {
	var b strings.Builder
	for {
		i := strings.IndexByte(tmpl, '{')
		if i < 0 {
			b.WriteString(tmpl)
			return b.String()
		}
		j := strings.IndexByte(tmpl[i:], '}')
		if j < 0 {
			b.WriteString(tmpl)
			return b.String()
		}
		b.WriteString(tmpl[:i])
		b.WriteString(escape(vars[tmpl[i+1:i+j]]))
		tmpl = tmpl[i+j+1:]
	}
}

// escape percent-encodes all but the unreserved characters.
func escape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || strings.IndexByte("-._~", c) >= 0 {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// Upload uploads a blob.
func (c *Client) Upload(ctx context.Context, account ID, contentType string, data []byte) (*UploadResponse, error) {
	s, err := c.Session(ctx)
	if err != nil {
		return nil, err
	}
	u := expand(s.UploadURL, map[string]string{"accountId": string(account)})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	leave, err := c.enter(ctx, &c.upload, s, func(cc CoreCapability) int { return cc.MaxConcurrentUpload })
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		leave()
		return nil, err
	}
	body, err := c.readBody(resp)
	leave()
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, &StatusError{resp.StatusCode, snippet(body)}
	}
	var out UploadResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("jmap: upload: %w", err)
	}
	return &out, nil
}

// ErrNotFound means the blob does not exist.
var ErrNotFound = errors.New("jmap: not found")

// Download downloads a blob.
func (c *Client) Download(ctx context.Context, account, blob ID) ([]byte, error) {
	s, err := c.Session(ctx)
	if err != nil {
		return nil, err
	}
	u := expand(s.DownloadURL, map[string]string{"accountId": string(account), "blobId": string(blob),
		"name": "message.eml", "type": "application/octet-stream"})
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	leave, err := c.enter(ctx, &c.download, s, func(CoreCapability) int { return 0 })
	if err != nil {
		return nil, err
	}
	resp, err := c.do(req)
	if err != nil {
		leave()
		return nil, err
	}
	body, err := c.readBody(resp)
	leave()
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusOK:
		return body, nil
	case http.StatusNotFound:
		return nil, ErrNotFound
	}
	return nil, &StatusError{resp.StatusCode, snippet(body)}
}

// Events follows the server's event source (RFC 8620 section 7.3) for
// types ("*" for all), and calls f with each state change, until ctx ends
// or the stream breaks. ping asks the server for a keep-alive every so
// many seconds (0 for none).
func (c *Client) Events(ctx context.Context, types []string, ping int, f func(StateChange)) error {
	s, err := c.Session(ctx)
	if err != nil {
		return err
	}
	if s.EventSourceURL == "" {
		return errors.New("jmap: the server has no event source")
	}
	u := expand(s.EventSourceURL, map[string]string{"types": strings.Join(types, ","), "closeafter": "no",
		"ping": strconv.Itoa(ping)})
	// The server sends something at least every ping seconds: a stream
	// silent for twice that, and half a minute more, is dead.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	silence := time.Duration(2*max(ping, 1))*time.Second + 30*time.Second
	dead := time.AfterFunc(silence, cancel)
	defer dead.Stop()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "text/event-stream")
	resp, err := c.do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 200))
		return &StatusError{resp.StatusCode, snippet(body)}
	}
	body, err := httpenc.Decode(resp.Header.Get("Content-Encoding"), resp.Body)
	if err != nil {
		return err
	}
	defer body.Close()
	return readEvents(bufio.NewReader(body), func() { dead.Reset(silence) }, f)
}

// readEvents parses a text/event-stream, and calls f with each "state"
// event. alive is called with every line.
func readEvents(r *bufio.Reader, alive func(), f func(StateChange)) error {
	var event string
	var data strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return err
		}
		alive()
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			if (event == "" || event == "state") && data.Len() > 0 {
				var sc StateChange
				if json.Unmarshal([]byte(data.String()), &sc) == nil && sc.Changed != nil {
					f(sc)
				}
			}
			event = ""
			data.Reset()
			continue
		}
		field, value, _ := strings.Cut(line, ":")
		value = strings.TrimPrefix(value, " ")
		switch field {
		case "event":
			event = value
		case "data":
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(value)
		}
	}
}
