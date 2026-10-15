package jmapproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/brodyhoskins/mailcached/internal/httpenc"
	"github.com/brodyhoskins/mailcached/internal/jmap"
)

// method answers one method call. It returns the response's arguments,
// or a *jmap.MethodError. Extra responses (Email/set's implicit
// Email/copy, for example) go to call.extra.
type method func(c *call) (any, error)

// call is one method call being answered.
type call struct {
	s    *Server
	r    *http.Request
	c    *client
	args json.RawMessage
	// created maps the creation IDs of this request to the IDs created.
	created map[jmap.ID]jmap.ID
	extra   []jmap.Invocation
	id      string
}

// methods are the methods by name, and the capability each needs.
var methods = map[string]struct {
	capability string
	fn         method
}{
	"Core/echo":               {jmap.CapCore, func(c *call) (any, error) { return c.args, nil }},
	"Mailbox/get":             {jmap.CapMail, mailboxGet},
	"Mailbox/changes":         {jmap.CapMail, mailboxChanges},
	"Mailbox/query":           {jmap.CapMail, mailboxQuery},
	"Mailbox/queryChanges":    {jmap.CapMail, cannotQueryChanges},
	"Mailbox/set":             {jmap.CapMail, mailboxSet},
	"Email/get":               {jmap.CapMail, emailGet},
	"Email/changes":           {jmap.CapMail, emailChanges},
	"Email/query":             {jmap.CapMail, emailQuery},
	"Email/queryChanges":      {jmap.CapMail, cannotQueryChanges},
	"Email/set":               {jmap.CapMail, emailSet},
	"Email/import":            {jmap.CapMail, emailImport},
	"Thread/get":              {jmap.CapMail, threadGet},
	"Thread/changes":          {jmap.CapMail, threadChanges},
	"SearchSnippet/get":       {jmap.CapMail, snippetGet},
	"Identity/get":            {jmap.CapSubmission, identityGet},
	"Identity/changes":        {jmap.CapSubmission, identityChanges},
	"EmailSubmission/get":     {jmap.CapSubmission, submissionGet},
	"EmailSubmission/changes": {jmap.CapSubmission, submissionChanges},
	"EmailSubmission/query":   {jmap.CapSubmission, submissionQuery},
	"EmailSubmission/set":     {jmap.CapSubmission, submissionSet},
	"PushSubscription/get":    {jmap.CapCore, pushSubscriptionGet},
	"PushSubscription/set":    {jmap.CapCore, pushSubscriptionSet},
}

var known = []string{jmap.CapCore, jmap.CapMail, jmap.CapSubmission}

func (s *Server) serveAPI(w http.ResponseWriter, r *http.Request) {
	// The request holds its room from before its body is read until its
	// answer is written.
	c := clientOf(r)
	leave, err := s.hold(w, r, c)
	if err != nil {
		return
	}
	defer leave()
	body, err := httpenc.ReadAll(r.Header.Get("Content-Encoding"), r.Body, maxRequest)
	if errors.Is(err, httpenc.ErrTooLarge) {
		writeProblem(w, &jmap.ProblemDetails{Type: jmap.ProblemLimit, Status: 400, Limit: "maxSizeRequest"})
		return
	}
	if err != nil {
		problem(w, http.StatusBadRequest, jmap.ProblemNotJSON, err.Error())
		return
	}
	var req jmap.Request
	if p := parseRequest(body, &req); p != nil {
		writeProblem(w, p)
		return
	}
	res, p := s.execute(r, c, &req)
	if p != nil {
		writeProblem(w, p)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// parseRequest reads a Request, or says what is wrong with it.
func parseRequest(body []byte, req any) *jmap.ProblemDetails {
	if err := json.Unmarshal(body, req); err != nil {
		var se *json.SyntaxError
		if errors.As(err, &se) || !json.Valid(body) {
			return &jmap.ProblemDetails{Type: jmap.ProblemNotJSON, Status: 400, Detail: err.Error()}
		}
		return &jmap.ProblemDetails{Type: jmap.ProblemNotRequest, Status: 400, Detail: err.Error()}
	}
	return nil
}

// execute answers a Request, over HTTP or a WebSocket.
func (s *Server) execute(r *http.Request, c *client, req *jmap.Request) (*jmap.Response, *jmap.ProblemDetails) {
	for _, u := range req.Using {
		if !slices.Contains(known, u) {
			return nil, &jmap.ProblemDetails{Type: jmap.ProblemUnknownCapability, Status: 400, Detail: "Unknown capability " + u}
		}
	}
	if len(req.MethodCalls) > maxCalls {
		return nil, &jmap.ProblemDetails{Type: jmap.ProblemLimit, Status: 400, Limit: "maxCallsInRequest"}
	}
	created := map[jmap.ID]jmap.ID{}
	for k, v := range req.CreatedIDs {
		created[k] = v
	}
	var out []jmap.Invocation
	for _, inv := range req.MethodCalls {
		resp, extra := s.run(r, c, req.Using, inv, out, created)
		out = append(out, resp)
		out = append(out, extra...)
	}
	c.acct.Lock()
	state := sessionState(c.acct.State(), limit(c))
	c.acct.Unlock()
	res := &jmap.Response{MethodResponses: out, SessionState: jmap.State(state)}
	if req.CreatedIDs != nil {
		res.CreatedIDs = created
	}
	return res, nil
}

// run answers one method call.
func (s *Server) run(r *http.Request, c *client, using []string, inv jmap.Invocation, done []jmap.Invocation,
	created map[jmap.ID]jmap.ID) (jmap.Invocation, []jmap.Invocation) {
	fail := func(typ, desc string) (jmap.Invocation, []jmap.Invocation) {
		resp, _ := jmap.NewInvocation("error", jmap.MethodError{Type: typ, Description: desc}, inv.CallID)
		return resp, nil
	}
	m, ok := methods[inv.Name]
	if !ok {
		return fail(jmap.ErrUnknownMethod, "")
	}
	if !slices.Contains(using, m.capability) {
		return fail(jmap.ErrUnknownMethod, "The request does not use "+m.capability)
	}
	args, err := resolveRefs(inv.Args, done)
	if err != nil {
		return fail(jmap.ErrInvalidResultReference, err.Error())
	}
	// Every method but Core/echo and PushSubscription's names the
	// account.
	if inv.Name != "Core/echo" && !strings.HasPrefix(inv.Name, "PushSubscription/") {
		var a struct {
			AccountID jmap.ID `json:"accountId"`
		}
		if json.Unmarshal(args, &a) != nil || a.AccountID != c.id {
			return fail(jmap.ErrAccountNotFound, "")
		}
	}
	cl := &call{s: s, r: r, c: c, args: args, created: created, id: inv.CallID}
	resp, err := m.fn(cl)
	if err != nil {
		var me *jmap.MethodError
		if errors.As(err, &me) {
			return fail(me.Type, me.Description)
		}
		s.Log.Warn("jmap: method failed", "method", inv.Name, "user", c.login, "err", err)
		return fail(jmap.ErrServerFail, err.Error())
	}
	out, err := jmap.NewInvocation(inv.Name, resp, inv.CallID)
	if err != nil {
		return fail(jmap.ErrServerFail, err.Error())
	}
	return out, cl.extra
}

// decode reads the call's arguments into v.
func (c *call) decode(v any) error {
	if err := json.Unmarshal(c.args, v); err != nil {
		return invalid(err.Error())
	}
	return nil
}

func invalid(desc string) error {
	return &jmap.MethodError{Type: jmap.ErrInvalidArguments, Description: desc}
}

// resolve turns a creation reference ("#c1") into the ID it created.
func (c *call) resolve(id jmap.ID) jmap.ID {
	if strings.HasPrefix(string(id), "#") {
		if real, ok := c.created[id[1:]]; ok {
			return real
		}
	}
	return id
}

// resolveRefs replaces the "#name" arguments of a call with what their
// ResultReference points at (RFC 8620 section 3.7).
func resolveRefs(args json.RawMessage, done []jmap.Invocation) (json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(args, &m); err != nil {
		return args, nil // not an object: the method says so
	}
	changed := false
	for k, v := range m {
		if !strings.HasPrefix(k, "#") {
			continue
		}
		name := k[1:]
		if _, ok := m[name]; ok {
			return nil, fmt.Errorf("both %s and %s", name, k)
		}
		var ref jmap.ResultReference
		if err := json.Unmarshal(v, &ref); err != nil {
			return nil, err
		}
		var src *jmap.Invocation
		for i := range done {
			if done[i].CallID == ref.ResultOf {
				src = &done[i]
				break
			}
		}
		if src == nil || src.Name != ref.Name {
			return nil, fmt.Errorf("no %s result for %s", ref.Name, ref.ResultOf)
		}
		var doc any
		if err := json.Unmarshal(src.Args, &doc); err != nil {
			return nil, err
		}
		val, err := pointer(doc, ref.Path)
		if err != nil {
			return nil, err
		}
		raw, err := json.Marshal(val)
		if err != nil {
			return nil, err
		}
		delete(m, k)
		m[name] = raw
		changed = true
	}
	if !changed {
		return args, nil
	}
	return json.Marshal(m)
}

// pointer evaluates a JSON Pointer with JMAP's "*" for every item of an
// array, whose results are flattened (RFC 8620 section 3.7).
func pointer(doc any, path string) (any, error) {
	if path == "" {
		return doc, nil
	}
	if !strings.HasPrefix(path, "/") {
		return nil, fmt.Errorf("bad path %q", path)
	}
	tok, rest, more := strings.Cut(path[1:], "/")
	if more {
		rest = "/" + rest
	}
	tok = strings.NewReplacer("~1", "/", "~0", "~").Replace(tok)
	switch v := doc.(type) {
	case map[string]any:
		next, ok := v[tok]
		if !ok {
			return nil, fmt.Errorf("no %q in result", tok)
		}
		return pointer(next, rest)
	case []any:
		if tok == "*" {
			var out []any
			for _, item := range v {
				r, err := pointer(item, rest)
				if err != nil {
					return nil, err
				}
				if arr, ok := r.([]any); ok {
					out = append(out, arr...)
				} else {
					out = append(out, r)
				}
			}
			return out, nil
		}
		i, err := strconv.Atoi(tok)
		if err != nil || i < 0 || i >= len(v) {
			return nil, fmt.Errorf("no item %q in result", tok)
		}
		return pointer(v[i], rest)
	}
	return nil, fmt.Errorf("cannot follow %q", tok)
}

func cannotQueryChanges(*call) (any, error) {
	return nil, &jmap.MethodError{Type: jmap.ErrCannotCalculateChanges}
}
