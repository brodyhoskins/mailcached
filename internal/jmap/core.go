// Package jmap holds the parts of JMAP (RFC 8620, the core, and RFC 8621,
// mail) that mailcached speaks: the types, which its server and its
// client share, and a client.
package jmap

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Capabilities.
const (
	CapCore       = "urn:ietf:params:jmap:core"
	CapMail       = "urn:ietf:params:jmap:mail"
	CapSubmission = "urn:ietf:params:jmap:submission"
	CapWebSocket  = "urn:ietf:params:jmap:websocket"
)

// ID identifies an object. State is an opaque state string.
type (
	ID    string
	State string
)

// Session is the session resource (RFC 8620 section 2).
type Session struct {
	Capabilities    map[string]json.RawMessage `json:"capabilities"`
	Accounts        map[ID]Account             `json:"accounts"`
	PrimaryAccounts map[string]ID              `json:"primaryAccounts"`
	Username        string                     `json:"username"`
	APIURL          string                     `json:"apiUrl"`
	DownloadURL     string                     `json:"downloadUrl"`
	UploadURL       string                     `json:"uploadUrl"`
	EventSourceURL  string                     `json:"eventSourceUrl"`
	State           State                      `json:"state"`
}

// Account is an account of a session.
type Account struct {
	Name                string                     `json:"name"`
	IsPersonal          bool                       `json:"isPersonal"`
	IsReadOnly          bool                       `json:"isReadOnly"`
	AccountCapabilities map[string]json.RawMessage `json:"accountCapabilities"`
}

// CoreCapability is the value of CapCore in Session.Capabilities.
type CoreCapability struct {
	MaxSizeUpload         int64    `json:"maxSizeUpload"`
	MaxConcurrentUpload   int      `json:"maxConcurrentUpload"`
	MaxSizeRequest        int64    `json:"maxSizeRequest"`
	MaxConcurrentRequests int      `json:"maxConcurrentRequests"`
	MaxCallsInRequest     int      `json:"maxCallsInRequest"`
	MaxObjectsInGet       int      `json:"maxObjectsInGet"`
	MaxObjectsInSet       int      `json:"maxObjectsInSet"`
	CollationAlgorithms   []string `json:"collationAlgorithms"`
}

// Core returns the session's core capability, with RFC 8620's minimums
// where the server gave none.
func (s *Session) Core() CoreCapability {
	c := CoreCapability{MaxObjectsInGet: 500, MaxObjectsInSet: 500, MaxCallsInRequest: 16, MaxConcurrentRequests: 4}
	if raw, ok := s.Capabilities[CapCore]; ok {
		_ = json.Unmarshal(raw, &c)
	}
	c.MaxObjectsInGet = max(c.MaxObjectsInGet, 1)
	c.MaxObjectsInSet = max(c.MaxObjectsInSet, 1)
	c.MaxCallsInRequest = max(c.MaxCallsInRequest, 1)
	return c
}

// MailAccount returns the primary account for mail, or "".
func (s *Session) MailAccount() ID { return s.PrimaryAccounts[CapMail] }

// Request is an API request.
type Request struct {
	Using       []string     `json:"using"`
	MethodCalls []Invocation `json:"methodCalls"`
	CreatedIDs  map[ID]ID    `json:"createdIds,omitempty"`
}

// Response is an API response.
type Response struct {
	MethodResponses []Invocation `json:"methodResponses"`
	CreatedIDs      map[ID]ID    `json:"createdIds,omitempty"`
	SessionState    State        `json:"sessionState"`
}

// Invocation is a method call or response: [name, arguments, call id].
type Invocation struct {
	Name   string
	Args   json.RawMessage
	CallID string
}

func (inv Invocation) MarshalJSON() ([]byte, error) {
	args := inv.Args
	if args == nil {
		args = json.RawMessage("{}")
	}
	return json.Marshal([]any{inv.Name, args, inv.CallID})
}

func (inv *Invocation) UnmarshalJSON(b []byte) error {
	var parts []json.RawMessage
	if err := json.Unmarshal(b, &parts); err != nil {
		return err
	}
	if len(parts) != 3 {
		return errors.New("invocation is not [name, arguments, id]")
	}
	if err := json.Unmarshal(parts[0], &inv.Name); err != nil {
		return err
	}
	if len(parts[1]) == 0 || parts[1][0] != '{' {
		return errors.New("invocation arguments are not an object")
	}
	inv.Args = parts[1]
	return json.Unmarshal(parts[2], &inv.CallID)
}

// NewInvocation encodes args into an Invocation.
func NewInvocation(name string, args any, callID string) (Invocation, error) {
	raw, err := json.Marshal(args)
	if err != nil {
		return Invocation{}, err
	}
	return Invocation{Name: name, Args: raw, CallID: callID}, nil
}

// MethodError is a method-level error (RFC 8620 section 3.6.2), sent as
// an "error" response.
type MethodError struct {
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

func (e *MethodError) Error() string {
	if e.Description != "" {
		return "jmap: " + e.Type + ": " + e.Description
	}
	return "jmap: " + e.Type
}

// Method error types.
const (
	ErrServerUnavailable      = "serverUnavailable"
	ErrServerFail             = "serverFail"
	ErrUnknownMethod          = "unknownMethod"
	ErrInvalidArguments       = "invalidArguments"
	ErrInvalidResultReference = "invalidResultReference"
	ErrForbidden              = "forbidden"
	ErrAccountNotFound        = "accountNotFound"
	ErrAccountReadOnly        = "accountReadOnly"
	ErrRequestTooLarge        = "requestTooLarge"
	ErrCannotCalculateChanges = "cannotCalculateChanges"
	ErrStateMismatch          = "stateMismatch"
	ErrAnchorNotFound         = "anchorNotFound"
	ErrUnsupportedSort        = "unsupportedSort"
	ErrUnsupportedFilter      = "unsupportedFilter"
	ErrTooManyChanges         = "tooManyChanges"
	ErrUnknownCapability      = "unknownCapability" // in ProblemDetails
)

// ProblemDetails is a request-level error (RFC 7807, RFC 8620 section
// 3.6.1).
type ProblemDetails struct {
	Type   string `json:"type"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
	Limit  string `json:"limit,omitempty"`
}

func (p *ProblemDetails) Error() string {
	return fmt.Sprintf("jmap: request refused (%d): %s %s", p.Status, p.Type, p.Detail)
}

// Request-level problem types.
const (
	ProblemUnknownCapability = "urn:ietf:params:jmap:error:unknownCapability"
	ProblemNotJSON           = "urn:ietf:params:jmap:error:notJSON"
	ProblemNotRequest        = "urn:ietf:params:jmap:error:notRequest"
	ProblemLimit             = "urn:ietf:params:jmap:error:limit"
)

// ResultReference refers to an earlier result in the same request (RFC
// 8620 section 3.7). An argument "#name" holds one in place of "name".
type ResultReference struct {
	ResultOf string `json:"resultOf"`
	Name     string `json:"name"`
	Path     string `json:"path"`
}

// --- Standard methods (RFC 8620 section 5) --------------------------------

// GetArgs are the arguments of /get. IDs nil asks for all.
type GetArgs struct {
	AccountID  ID       `json:"accountId"`
	IDs        []ID     `json:"ids"`
	Properties []string `json:"properties,omitempty"`
	// Email/get only.
	BodyProperties      []string `json:"bodyProperties,omitempty"`
	FetchTextBodyValues bool     `json:"fetchTextBodyValues,omitempty"`
	FetchHTMLBodyValues bool     `json:"fetchHTMLBodyValues,omitempty"`
	FetchAllBodyValues  bool     `json:"fetchAllBodyValues,omitempty"`
	MaxBodyValueBytes   int      `json:"maxBodyValueBytes,omitempty"`
}

// GetResponse is the response of /get.
type GetResponse[T any] struct {
	AccountID ID    `json:"accountId"`
	State     State `json:"state"`
	List      []T   `json:"list"`
	NotFound  []ID  `json:"notFound"`
}

// ChangesArgs are the arguments of /changes.
type ChangesArgs struct {
	AccountID  ID    `json:"accountId"`
	SinceState State `json:"sinceState"`
	MaxChanges int   `json:"maxChanges,omitempty"`
}

// ChangesResponse is the response of /changes.
type ChangesResponse struct {
	AccountID      ID    `json:"accountId"`
	OldState       State `json:"oldState"`
	NewState       State `json:"newState"`
	HasMoreChanges bool  `json:"hasMoreChanges"`
	Created        []ID  `json:"created"`
	Updated        []ID  `json:"updated"`
	Destroyed      []ID  `json:"destroyed"`
	// Mailbox/changes only: Updated changed only the counts.
	UpdatedProperties []string `json:"updatedProperties,omitempty"`
}

// PatchObject is an /set update: property paths and their new values
// (null to reset).
type PatchObject map[string]json.RawMessage

// SetArgs are the arguments of /set.
type SetArgs[T any] struct {
	AccountID ID                 `json:"accountId"`
	IfInState State              `json:"ifInState,omitempty"`
	Create    map[ID]T           `json:"create,omitempty"`
	Update    map[ID]PatchObject `json:"update,omitempty"`
	Destroy   []ID               `json:"destroy,omitempty"`
	// Mailbox/set only.
	OnDestroyRemoveEmails bool `json:"onDestroyRemoveEmails,omitempty"`
	// EmailSubmission/set only.
	OnSuccessUpdateEmail  map[ID]PatchObject `json:"onSuccessUpdateEmail,omitempty"`
	OnSuccessDestroyEmail []ID               `json:"onSuccessDestroyEmail,omitempty"`
}

// SetResponse is the response of /set.
type SetResponse[T any] struct {
	AccountID    ID              `json:"accountId"`
	OldState     State           `json:"oldState,omitempty"`
	NewState     State           `json:"newState"`
	Created      map[ID]T        `json:"created,omitempty"`
	Updated      map[ID]*T       `json:"updated,omitempty"`
	Destroyed    []ID            `json:"destroyed,omitempty"`
	NotCreated   map[ID]SetError `json:"notCreated,omitempty"`
	NotUpdated   map[ID]SetError `json:"notUpdated,omitempty"`
	NotDestroyed map[ID]SetError `json:"notDestroyed,omitempty"`
}

// SetError is why one object of a /set was not changed.
type SetError struct {
	Type        string   `json:"type"`
	Description string   `json:"description,omitempty"`
	Properties  []string `json:"properties,omitempty"`
}

func (e SetError) Error() string {
	if e.Description != "" {
		return "jmap: " + e.Type + ": " + e.Description
	}
	return "jmap: " + e.Type
}

// SetError types.
const (
	SetForbidden         = "forbidden"
	SetOverQuota         = "overQuota"
	SetTooLarge          = "tooLarge"
	SetRateLimit         = "rateLimit"
	SetNotFound          = "notFound"
	SetInvalidPatch      = "invalidPatch"
	SetWillDestroy       = "willDestroy"
	SetInvalidProperties = "invalidProperties"
	SetSingleton         = "singleton"
	SetMailboxHasChild   = "mailboxHasChild"
	SetMailboxHasEmail   = "mailboxHasEmail"
	SetBlobNotFound      = "blobNotFound"
	SetTooManyKeywords   = "tooManyKeywords"
	SetTooManyMailboxes  = "tooManyMailboxes"
	SetInvalidEmail      = "invalidEmail"
	SetTooManyRecipients = "tooManyRecipients"
	SetNoRecipients      = "noRecipients"
	SetInvalidRecipients = "invalidRecipients"
	SetForbiddenMailFrom = "forbiddenMailFrom"
	SetForbiddenFrom     = "forbiddenFrom"
	SetForbiddenToSend   = "forbiddenToSend"
	SetCannotUnsend      = "cannotUnsend"
	SetAlreadyExists     = "alreadyExists"
)

// Comparator sorts a query.
type Comparator struct {
	Property    string `json:"property"`
	IsAscending *bool  `json:"isAscending,omitempty"` // default true
	Collation   string `json:"collation,omitempty"`
	Keyword     string `json:"keyword,omitempty"` // hasKeyword and friends
}

// Ascending reports the comparator's direction.
func (c Comparator) Ascending() bool { return c.IsAscending == nil || *c.IsAscending }

// QueryArgs are the arguments of /query. Filter is the type's filter,
// decoded by the method.
type QueryArgs struct {
	AccountID       ID              `json:"accountId"`
	Filter          json.RawMessage `json:"filter,omitempty"`
	Sort            []Comparator    `json:"sort,omitempty"`
	Position        int             `json:"position,omitempty"`
	Anchor          ID              `json:"anchor,omitempty"`
	AnchorOffset    int             `json:"anchorOffset,omitempty"`
	Limit           *int            `json:"limit,omitempty"`
	CalculateTotal  bool            `json:"calculateTotal,omitempty"`
	CollapseThreads bool            `json:"collapseThreads,omitempty"` // Email/query
	// Mailbox/query only.
	SortAsTree   bool `json:"sortAsTree,omitempty"`
	FilterAsTree bool `json:"filterAsTree,omitempty"`
}

// QueryResponse is the response of /query.
type QueryResponse struct {
	AccountID           ID    `json:"accountId"`
	QueryState          State `json:"queryState"`
	CanCalculateChanges bool  `json:"canCalculateChanges"`
	Position            int   `json:"position"`
	IDs                 []ID  `json:"ids"`
	Total               *int  `json:"total,omitempty"`
	Limit               *int  `json:"limit,omitempty"`
}

// UploadResponse is the response to an upload (RFC 8620 section 6.1).
type UploadResponse struct {
	AccountID ID     `json:"accountId"`
	BlobID    ID     `json:"blobId"`
	Type      string `json:"type"`
	Size      int64  `json:"size"`
}

// StateChange is a push notification (RFC 8620 section 7.1): the new
// state of each changed type, by account.
type StateChange struct {
	Type    string                  `json:"@type"` // "StateChange"
	Changed map[ID]map[string]State `json:"changed"`
	// PushState is the whole state, over a WebSocket (RFC 8887).
	PushState State `json:"pushState,omitempty"`
}

// WebSocketCapability is the session's urn:ietf:params:jmap:websocket
// (RFC 8887 section 3).
type WebSocketCapability struct {
	URL          string `json:"url"`
	SupportsPush bool   `json:"supportsPush"`
}

// The messages of JMAP over a WebSocket (RFC 8887 section 4.3).
type (
	// WSRequest is a Request with its type and ID.
	WSRequest struct {
		Type string `json:"@type"` // "Request"
		ID   string `json:"id,omitempty"`
		Request
	}
	// WSResponse is a Response with its type and the request's ID.
	WSResponse struct {
		Type      string `json:"@type"` // "Response"
		RequestID string `json:"requestId,omitempty"`
		Response
	}
	// WSRequestError is a ProblemDetails with its type and the request's
	// ID.
	WSRequestError struct {
		Type      string  `json:"@type"` // "RequestError"
		RequestID *string `json:"requestId"`
		ProblemDetails
	}
	// WSPushEnable turns push on (WebSocketPushEnable).
	WSPushEnable struct {
		Type      string   `json:"@type"`
		DataTypes []string `json:"dataTypes"`
		PushState State    `json:"pushState,omitempty"`
	}
)
