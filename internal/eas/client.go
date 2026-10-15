// Package eas is an Exchange ActiveSync client (MS-ASHTTP, MS-ASCMD) for
// mail: the HTTP requests, the protocol version, and the device
// provisioning that servers ask for. The engine's ActiveSync provider
// builds the commands.
package eas

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/brodyhoskins/mailcached/internal/gate"
	"github.com/brodyhoskins/mailcached/internal/wbxml"
)

var (
	// ErrUnauthorized means the server refused the credentials.
	ErrUnauthorized = errors.New("activesync: credentials refused")
	// ErrForbidden means the server refuses this device or user (HTTP
	// 403): ActiveSync turned off for the account, or the device blocked.
	ErrForbidden = errors.New("activesync: access denied for this account or device")
	// ErrRemoteWipe means the server asked the device to wipe itself. The
	// client never does: a proxy holds no device to wipe. An
	// administrator asked for it, so it stops the account.
	ErrRemoteWipe = errors.New("activesync: the server asked for a remote wipe")
	// ErrNoVersion means the server speaks no version the client does.
	ErrNoVersion = errors.New("activesync: no common protocol version")
)

// Versions are the protocol versions the client speaks, best first.
var Versions = []string{"14.1", "14.0", "12.1"}

// StatusError is a command's failure, by its Status.
type StatusError struct {
	Cmd    string
	Status int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("activesync: %s: status %d", e.Cmd, e.Status)
}

// HTTPError is an HTTP failure other than 401 and 403.
type HTTPError struct {
	Cmd  string
	Code int
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("activesync: %s: HTTP %d %s", e.Cmd, e.Code, http.StatusText(e.Code))
}

// Client talks to one ActiveSync server as one device.
type Client struct {
	// URL is the server's endpoint, such as
	// https://mail.example.com/Microsoft-Server-ActiveSync.
	URL                  string
	User, Password       string
	DeviceID, DeviceType string
	UserAgent            string
	HTTP                 *http.Client
	// PolicyKeySaved, if not nil, is called with each new policy key, so
	// it is kept across restarts.
	PolicyKeySaved func(key string)
	// MaxConcurrent caps the commands at a time, Ping included. 0: no
	// cap.
	MaxConcurrent int

	mu        sync.Mutex
	version   string
	policyKey string
	running   gate.Gate
	backoff   gate.Backoff // after a 503 or 429
}

// SetPolicyKey sets the key saved from before.
func (c *Client) SetPolicyKey(key string) {
	c.mu.Lock()
	c.policyKey = key
	c.mu.Unlock()
}

// Version returns the protocol version in use, "" before Options.
func (c *Client) Version() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.version
}

// AtLeast reports whether the version in use is v or later.
func (c *Client) AtLeast(v string) bool { return versionNum(c.Version()) >= versionNum(v) }

func versionNum(v string) int {
	a, b, _ := strings.Cut(v, ".")
	x, _ := strconv.Atoi(a)
	y, _ := strconv.Atoi(b)
	return x*10 + y
}

func (c *Client) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

// Options checks the credentials and picks the protocol version.
func (c *Client) Options(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodOptions, c.URL, nil)
	if err != nil {
		return err
	}
	c.prepare(req)
	if err := c.backoff.Wait(ctx); err != nil {
		return fmt.Errorf("activesync: OPTIONS: %w", err)
	}
	res, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	c.backoff.Note(res.StatusCode, res.Header.Get("Retry-After"))
	_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
	res.Body.Close()
	if err := httpErr("OPTIONS", res.StatusCode); err != nil {
		return err
	}
	offered := strings.Split(strings.ReplaceAll(res.Header.Get("MS-ASProtocolVersions"), " ", ""), ",")
	for _, v := range Versions {
		if slices.Contains(offered, v) {
			c.mu.Lock()
			c.version = v
			c.mu.Unlock()
			return nil
		}
	}
	return fmt.Errorf("%w: the server offers %q", ErrNoVersion, res.Header.Get("MS-ASProtocolVersions"))
}

func httpErr(cmd string, code int) error {
	switch {
	case code == http.StatusUnauthorized:
		return ErrUnauthorized
	case code == http.StatusForbidden:
		return ErrForbidden
	case code < 200 || code > 299:
		return &HTTPError{Cmd: cmd, Code: code}
	}
	return nil
}

func (c *Client) prepare(req *http.Request) {
	req.SetBasicAuth(c.User, c.Password)
	if c.UserAgent != "" {
		req.Header.Set("User-Agent", c.UserAgent)
	}
}

// Do sends a command with a WBXML body (nil for none) and returns the
// answer, nil if empty. It provisions the device when the server asks,
// and tries once more. A Status other than 1 in the answer's root is left
// for the caller, except the ones about provisioning.
func (c *Client) Do(ctx context.Context, cmd string, params url.Values, doc *wbxml.Node) (*wbxml.Node, error) {
	var body []byte
	if doc != nil {
		var err error
		if body, err = wbxml.Encode(doc); err != nil {
			return nil, err
		}
	}
	return c.DoRaw(ctx, cmd, params, body, "application/vnd.ms-sync.wbxml")
}

// DoRaw is Do with a body of any type.
func (c *Client) DoRaw(ctx context.Context, cmd string, params url.Values, body []byte, contentType string) (*wbxml.Node, error) {
	if c.Version() == "" {
		if err := c.Options(ctx); err != nil {
			return nil, err
		}
	}
	for try := 0; ; try++ {
		n, err := c.do(ctx, cmd, params, body, contentType)
		if err == nil && cmd != "Provision" && n != nil {
			if st := atoi(n.Value("Status")); st == 140 || st == 141 {
				return nil, ErrRemoteWipe
			} else if st >= 142 && st <= 144 {
				err = errProvision
			}
		}
		if !errors.Is(err, errProvision) || try > 0 || cmd == "Provision" {
			return n, err
		}
		if err := c.provision(ctx); err != nil {
			return nil, err
		}
	}
}

var errProvision = errors.New("activesync: the device must be provisioned")

func (c *Client) do(ctx context.Context, cmd string, params url.Values, body []byte, contentType string) (*wbxml.Node, error) {
	q := url.Values{}
	for k, v := range params {
		q[k] = v
	}
	q.Set("Cmd", cmd)
	q.Set("User", c.User)
	q.Set("DeviceId", c.DeviceID)
	q.Set("DeviceType", c.DeviceType)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL+"?"+q.Encode(), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	c.prepare(req)
	c.mu.Lock()
	req.Header.Set("MS-ASProtocolVersion", c.version)
	if c.policyKey != "" {
		req.Header.Set("X-MS-PolicyKey", c.policyKey)
	}
	c.mu.Unlock()
	if len(body) > 0 {
		req.Header.Set("Content-Type", contentType)
	}
	// The backoff is checked with a slot held: a command that waited for
	// one sees a pause the command before it was told of.
	if c.MaxConcurrent > 0 {
		if err := c.running.Enter(ctx, c.MaxConcurrent); err != nil {
			return nil, err
		}
		defer c.running.Leave()
	}
	if err := c.backoff.Wait(ctx); err != nil {
		return nil, fmt.Errorf("activesync: %s: %w", cmd, err)
	}
	res, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	c.backoff.Note(res.StatusCode, res.Header.Get("Retry-After"))
	if res.StatusCode == 449 {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
		return nil, errProvision
	}
	if err := httpErr(cmd, res.StatusCode); err != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 64<<10))
		return nil, err
	}
	b, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, nil
	}
	if !strings.Contains(res.Header.Get("Content-Type"), "wbxml") {
		return nil, fmt.Errorf("activesync: %s: answer of type %q", cmd, res.Header.Get("Content-Type"))
	}
	return wbxml.Decode(b)
}

const policyType = "MS-EAS-Provisioning-WBXML"

// provision gets a policy key: the server sends its policy and a
// temporary key, and the client acknowledges the policy with that key
// for the final one. The proxy accepts the policy (it holds no device to
// lock); a remote wipe is never carried out.
func (c *Client) provision(ctx context.Context) error {
	c.SetPolicyKey("")
	ask := func(key, status string) (*wbxml.Node, error) {
		pol := []*wbxml.Node{wbxml.Tx("Provision:PolicyType", policyType)}
		if key != "" {
			pol = append(pol, wbxml.Tx("Provision:PolicyKey", key), wbxml.Tx("Provision:Status", status))
		}
		var kids []*wbxml.Node
		if c.AtLeast("14.1") {
			kids = append(kids, wbxml.El("Settings:DeviceInformation", wbxml.El("Settings:Set",
				wbxml.Tx("Settings:Model", "mailcached"), wbxml.Tx("Settings:FriendlyName", "mailcached"),
				wbxml.Tx("Settings:OS", "mailcached"), wbxml.Tx("Settings:UserAgent", c.UserAgent))))
		}
		kids = append(kids, wbxml.El("Provision:Policies", wbxml.El("Provision:Policy", pol...)))
		n, err := c.do(ctx, "Provision", nil, mustEncode(wbxml.El("Provision:Provision", kids...)), "application/vnd.ms-sync.wbxml")
		if err != nil {
			return nil, err
		}
		if n == nil {
			return nil, &StatusError{Cmd: "Provision", Status: 0}
		}
		if n.Child("RemoteWipe") != nil {
			return nil, ErrRemoteWipe
		}
		if st := n.Value("Status"); st != "1" {
			return nil, &StatusError{Cmd: "Provision", Status: atoi(st)}
		}
		return n.Child("Policies").Child("Policy"), nil
	}
	p, err := ask("", "")
	if err != nil {
		return err
	}
	if st := p.Value("Status"); st != "1" && st != "" {
		return &StatusError{Cmd: "Provision", Status: atoi(st)}
	}
	p, err = ask(p.Value("PolicyKey"), "1")
	if err != nil {
		return err
	}
	key := p.Value("PolicyKey")
	if key == "" {
		return &StatusError{Cmd: "Provision", Status: atoi(p.Value("Status"))}
	}
	c.SetPolicyKey(key)
	if c.PolicyKeySaved != nil {
		c.PolicyKeySaved(key)
	}
	return nil
}

func mustEncode(n *wbxml.Node) []byte {
	b, err := wbxml.Encode(n)
	if err != nil {
		panic(err)
	}
	return b
}

func atoi(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
