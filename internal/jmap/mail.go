package jmap

import (
	"encoding/json"
	"strings"
	"time"
)

// Mailbox roles (RFC 8621 section 2, from the IANA registry), which match
// the IMAP special-use attributes.
const (
	RoleInbox   = "inbox"
	RoleAll     = "all"
	RoleArchive = "archive"
	RoleDrafts  = "drafts"
	RoleFlagged = "flagged"
	RoleJunk    = "junk"
	RoleSent    = "sent"
	RoleTrash   = "trash"
)

// Mailbox is a folder.
type Mailbox struct {
	ID            ID            `json:"id"`
	Name          string        `json:"name"`
	ParentID      *ID           `json:"parentId"`
	Role          *string       `json:"role"`
	SortOrder     int           `json:"sortOrder"`
	TotalEmails   int           `json:"totalEmails"`
	UnreadEmails  int           `json:"unreadEmails"`
	TotalThreads  int           `json:"totalThreads"`
	UnreadThreads int           `json:"unreadThreads"`
	MyRights      MailboxRights `json:"myRights"`
	IsSubscribed  bool          `json:"isSubscribed"`
}

// MailboxRights are what the user may do with a mailbox.
type MailboxRights struct {
	MayReadItems   bool `json:"mayReadItems"`
	MayAddItems    bool `json:"mayAddItems"`
	MayRemoveItems bool `json:"mayRemoveItems"`
	MaySetSeen     bool `json:"maySetSeen"`
	MaySetKeywords bool `json:"maySetKeywords"`
	MayCreateChild bool `json:"mayCreateChild"`
	MayRename      bool `json:"mayRename"`
	MayDelete      bool `json:"mayDelete"`
	MaySubmit      bool `json:"maySubmit"`
}

// AllRights is every right.
var AllRights = MailboxRights{true, true, true, true, true, true, true, true, true}

// Keywords that match IMAP system flags (RFC 8621 section 4.1.1).
const (
	KeywordSeen      = "$seen"
	KeywordFlagged   = "$flagged"
	KeywordAnswered  = "$answered"
	KeywordDraft     = "$draft"
	KeywordForwarded = "$forwarded"
)

// EmailAddress is a name and an address.
type EmailAddress struct {
	Name  *string `json:"name"`
	Email string  `json:"email"`
}

// EmailHeader is one header field, raw.
type EmailHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// EmailBodyPart is a MIME part (RFC 8621 section 4.1.4).
type EmailBodyPart struct {
	PartID      *string         `json:"partId"`
	BlobID      *ID             `json:"blobId"`
	Size        int64           `json:"size"`
	Headers     []EmailHeader   `json:"headers,omitempty"`
	Name        *string         `json:"name"`
	Type        string          `json:"type"`
	Charset     *string         `json:"charset"`
	Disposition *string         `json:"disposition"`
	CID         *string         `json:"cid"`
	Language    []string        `json:"language"`
	Location    *string         `json:"location"`
	SubParts    []EmailBodyPart `json:"subParts,omitempty"`
}

// EmailBodyValue is the decoded text of a part.
type EmailBodyValue struct {
	Value             string `json:"value"`
	IsEncodingProblem bool   `json:"isEncodingProblem"`
	IsTruncated       bool   `json:"isTruncated"`
}

// Email is a message, as a client reads it. Header properties
// ("header:Name:asForm") are in Extra.
type Email struct {
	ID            ID                        `json:"id,omitempty"`
	BlobID        ID                        `json:"blobId,omitempty"`
	ThreadID      ID                        `json:"threadId,omitempty"`
	MailboxIDs    map[ID]bool               `json:"mailboxIds,omitempty"`
	Keywords      map[string]bool           `json:"keywords,omitempty"`
	Size          int64                     `json:"size,omitempty"`
	ReceivedAt    *time.Time                `json:"receivedAt,omitempty"`
	MessageID     []string                  `json:"messageId,omitempty"`
	InReplyTo     []string                  `json:"inReplyTo,omitempty"`
	References    []string                  `json:"references,omitempty"`
	Sender        []EmailAddress            `json:"sender,omitempty"`
	From          []EmailAddress            `json:"from,omitempty"`
	To            []EmailAddress            `json:"to,omitempty"`
	Cc            []EmailAddress            `json:"cc,omitempty"`
	Bcc           []EmailAddress            `json:"bcc,omitempty"`
	ReplyTo       []EmailAddress            `json:"replyTo,omitempty"`
	Subject       *string                   `json:"subject,omitempty"`
	SentAt        *time.Time                `json:"sentAt,omitempty"`
	BodyStructure *EmailBodyPart            `json:"bodyStructure,omitempty"`
	BodyValues    map[string]EmailBodyValue `json:"bodyValues,omitempty"`
	TextBody      []EmailBodyPart           `json:"textBody,omitempty"`
	HTMLBody      []EmailBodyPart           `json:"htmlBody,omitempty"`
	Attachments   []EmailBodyPart           `json:"attachments,omitempty"`
	HasAttachment bool                      `json:"hasAttachment,omitempty"`
	Preview       string                    `json:"preview,omitempty"`
	Headers       []EmailHeader             `json:"headers,omitempty"`

	Extra map[string]json.RawMessage `json:"-"`
}

func (e *Email) UnmarshalJSON(b []byte) error {
	type plain Email
	if err := json.Unmarshal(b, (*plain)(e)); err != nil {
		return err
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(b, &all); err != nil {
		return err
	}
	for k, v := range all {
		if strings.HasPrefix(k, "header:") {
			if e.Extra == nil {
				e.Extra = map[string]json.RawMessage{}
			}
			e.Extra[k] = v
		}
	}
	return nil
}

// HeaderRaw returns the raw value of a "header:Name" property, or "".
func (e *Email) HeaderRaw(name string) string {
	var v string
	if raw, ok := e.Extra["header:"+name]; ok {
		_ = json.Unmarshal(raw, &v)
	}
	return v
}

// EmailFilter is an Email/query filter: a condition, or an operator over
// filters.
type EmailFilter struct {
	// Operator: "AND", "OR" or "NOT"; "" for a condition.
	Operator   string        `json:"operator,omitempty"`
	Conditions []EmailFilter `json:"conditions,omitempty"`

	InMailbox               ID         `json:"inMailbox,omitempty"`
	InMailboxOtherThan      []ID       `json:"inMailboxOtherThan,omitempty"`
	Before                  *time.Time `json:"before,omitempty"`
	After                   *time.Time `json:"after,omitempty"`
	MinSize                 int64      `json:"minSize,omitempty"`
	MaxSize                 int64      `json:"maxSize,omitempty"`
	AllInThreadHaveKeyword  string     `json:"allInThreadHaveKeyword,omitempty"`
	SomeInThreadHaveKeyword string     `json:"someInThreadHaveKeyword,omitempty"`
	NoneInThreadHaveKeyword string     `json:"noneInThreadHaveKeyword,omitempty"`
	HasKeyword              string     `json:"hasKeyword,omitempty"`
	NotKeyword              string     `json:"notKeyword,omitempty"`
	HasAttachment           *bool      `json:"hasAttachment,omitempty"`
	Text                    string     `json:"text,omitempty"`
	From                    string     `json:"from,omitempty"`
	To                      string     `json:"to,omitempty"`
	Cc                      string     `json:"cc,omitempty"`
	Bcc                     string     `json:"bcc,omitempty"`
	Subject                 string     `json:"subject,omitempty"`
	Body                    string     `json:"body,omitempty"`
	Header                  []string   `json:"header,omitempty"`
}

// MailboxFilter is a Mailbox/query filter condition.
type MailboxFilter struct {
	Operator     string          `json:"operator,omitempty"`
	Conditions   []MailboxFilter `json:"conditions,omitempty"`
	ParentID     *ID             `json:"parentId,omitempty"`
	Name         string          `json:"name,omitempty"`
	Role         *string         `json:"role,omitempty"`
	HasAnyRole   *bool           `json:"hasAnyRole,omitempty"`
	IsSubscribed *bool           `json:"isSubscribed,omitempty"`
}

// EmailImport is one message of an Email/import.
type EmailImport struct {
	BlobID     ID              `json:"blobId"`
	MailboxIDs map[ID]bool     `json:"mailboxIds"`
	Keywords   map[string]bool `json:"keywords,omitempty"`
	ReceivedAt *time.Time      `json:"receivedAt,omitempty"`
}

// ImportArgs are the arguments of Email/import.
type ImportArgs struct {
	AccountID ID                 `json:"accountId"`
	IfInState State              `json:"ifInState,omitempty"`
	Emails    map[ID]EmailImport `json:"emails"`
}

// ImportResponse is the response of Email/import.
type ImportResponse struct {
	AccountID  ID              `json:"accountId"`
	OldState   State           `json:"oldState,omitempty"`
	NewState   State           `json:"newState"`
	Created    map[ID]Email    `json:"created,omitempty"`
	NotCreated map[ID]SetError `json:"notCreated,omitempty"`
}

// Thread is a conversation.
type Thread struct {
	ID       ID   `json:"id"`
	EmailIDs []ID `json:"emailIds"`
}

// Identity is an address the user sends as.
type Identity struct {
	ID            ID             `json:"id"`
	Name          string         `json:"name"`
	Email         string         `json:"email"`
	ReplyTo       []EmailAddress `json:"replyTo"`
	Bcc           []EmailAddress `json:"bcc"`
	TextSignature string         `json:"textSignature"`
	HTMLSignature string         `json:"htmlSignature"`
	MayDelete     bool           `json:"mayDelete"`
}

// Address is an SMTP envelope address.
type Address struct {
	Email      string             `json:"email"`
	Parameters map[string]*string `json:"parameters"`
}

// Envelope is an SMTP envelope.
type Envelope struct {
	MailFrom Address   `json:"mailFrom"`
	RcptTo   []Address `json:"rcptTo"`
}

// EmailSubmission is a message on its way out (RFC 8621 section 7).
type EmailSubmission struct {
	ID         ID         `json:"id,omitempty"`
	IdentityID ID         `json:"identityId,omitempty"`
	EmailID    ID         `json:"emailId,omitempty"`
	ThreadID   ID         `json:"threadId,omitempty"`
	Envelope   *Envelope  `json:"envelope,omitempty"`
	SendAt     *time.Time `json:"sendAt,omitempty"`
	UndoStatus string     `json:"undoStatus,omitempty"` // "pending", "final", "canceled"
	// DeliveryStatus, dsnBlobIds and mdnBlobIds are left out: the proxy
	// hands mail to the provider and learns no more.
}

// SearchSnippet highlights what matched a query in an email.
type SearchSnippet struct {
	EmailID ID      `json:"emailId"`
	Subject *string `json:"subject"`
	Preview *string `json:"preview"`
}
