// Package wbxml reads and writes WBXML, the binary XML that Exchange
// ActiveSync speaks (MS-ASWBXML), for both sides of mailcached: the
// ActiveSync server and the ActiveSync provider.
package wbxml

// WBXML, the binary XML that ActiveSync speaks (MS-ASWBXML): a tag is one
// byte in a code page, with a flag for content; strings are inline and
// NUL-terminated; binary data is opaque with its length. The tag names are
// those of MS-ASWBXML, as "Page:Tag".

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
)

// codePages are the code pages the server speaks, by number: the page's
// name, and its tags from token 0x05 on.
var codePages = map[byte]struct {
	name string
	tags map[byte]string
}{
	0: {"AirSync", tagsFrom(0x05, "Sync", "Responses", "Add", "Change", "Delete", "Fetch", "SyncKey", "ClientId",
		"ServerId", "Status", "Collection", "Class", "Version", "CollectionId", "GetChanges", "MoreAvailable",
		"WindowSize", "Commands", "Options", "FilterType", "Truncation", "RTFTruncation", "Conflict", "Collections",
		"ApplicationData", "DeletesAsMoves", "NotifyGUID", "Supported", "SoftDelete", "MIMESupport",
		"MIMETruncation", "Wait", "Limit", "Partial", "ConversationMode", "MaxItems", "HeartbeatInterval")},
	2: {"Email", tagsFrom(0x05, "Attachment", "Attachments", "AttName", "AttSize", "AttOid", "AttMethod",
		"AttRemoved", "Body", "BodySize", "BodyTruncated", "DateReceived", "DisplayName", "DisplayTo", "Importance",
		"MessageClass", "Subject", "Read", "To", "Cc", "From", "ReplyTo", "AllDayEvent", "Categories", "Category",
		"DTStamp", "EndTime", "InstanceType", "BusyStatus", "Location", "MeetingRequest", "Organizer",
		"RecurrenceId", "Reminder", "ResponseRequested", "Recurrences", "Recurrence", "Recurrence_Type",
		"Recurrence_Until", "Recurrence_Occurrences", "Recurrence_Interval", "Recurrence_DayOfWeek",
		"Recurrence_DayOfMonth", "Recurrence_WeekOfMonth", "Recurrence_MonthOfYear", "StartTime", "Sensitivity",
		"TimeZone", "GlobalObjId", "ThreadTopic", "MIMEData", "MIMETruncated", "MIMESize", "InternetCPID", "Flag",
		"FlagStatus", "ContentClass", "FlagType", "CompleteTime", "DisallowNewTimeProposal")},
	5: {"Move", tagsFrom(0x05, "MoveItems", "Move", "SrcMsgId", "SrcFldId", "DstFldId", "Response", "Status", "DstMsgId")},
	6: {"GetItemEstimate", tagsFrom(0x05, "GetItemEstimate", "Version", "Collections", "Collection", "Class",
		"CollectionId", "DateTime", "Estimate", "Response", "Status")},
	7: {"FolderHierarchy", tagsFrom(0x05, "Folders", "Folder", "DisplayName", "ServerId", "ParentId", "Type",
		"Response", "Status", "ContentClass", "Changes", "Add", "Delete", "Update", "SyncKey", "FolderCreate",
		"FolderDelete", "FolderUpdate", "FolderSync", "Count")},
	13: {"Ping", tagsFrom(0x05, "Ping", "AutdState", "Status", "HeartbeatInterval", "Folders", "Folder", "Id",
		"Class", "MaxFolders")},
	14: {"Provision", tagsFrom(0x05, "Provision", "Policies", "Policy", "PolicyType", "PolicyKey", "Data", "Status",
		"RemoteWipe", "EASProvisionDoc", "DevicePasswordEnabled", "AlphanumericDevicePasswordRequired",
		"RequireStorageCardEncryption", "PasswordRecoveryEnabled", "DocumentBrowseEnabled", "AttachmentsEnabled",
		"MinDevicePasswordLength", "MaxInactivityTimeDeviceLock", "MaxDevicePasswordFailedAttempts",
		"MaxAttachmentSize", "AllowSimpleDevicePassword", "DevicePasswordExpiration", "DevicePasswordHistory",
		"AllowStorageCard", "AllowCamera", "RequireDeviceEncryption", "AllowUnsignedApplications",
		"AllowUnsignedInstallationPackages", "MinDevicePasswordComplexCharacters", "AllowWiFi",
		"AllowTextMessaging", "AllowPOPIMAPEmail", "AllowBluetooth", "AllowIrDA", "RequireManualSyncWhenRoaming",
		"AllowDesktopSync", "MaxCalendarAgeFilter", "AllowHTMLEmail", "MaxEmailAgeFilter",
		"MaxEmailBodyTruncationSize", "MaxEmailHTMLBodyTruncationSize", "RequireSignedSMIMEMessages",
		"RequireEncryptedSMIMEMessages", "RequireSignedSMIMEAlgorithm", "RequireEncryptionSMIMEAlgorithm",
		"AllowSMIMEEncryptionAlgorithmNegotiation", "AllowSMIMESoftCerts", "AllowBrowser", "AllowConsumerEmail",
		"AllowRemoteDesktop", "AllowInternetSharing", "UnapprovedInROMApplicationList", "ApplicationName",
		"ApprovedApplicationList", "Hash")},
	15: {"Search", map[byte]string{0x05: "Search", 0x07: "Store", 0x08: "Name", 0x09: "Query", 0x0a: "Options",
		0x0b: "Range", 0x0c: "Status", 0x0d: "Response", 0x0e: "Result", 0x0f: "Properties", 0x10: "Total",
		0x11: "EqualTo", 0x12: "Value", 0x13: "And", 0x14: "Or", 0x15: "FreeText", 0x17: "DeepTraversal",
		0x18: "LongId", 0x19: "RebuildResults", 0x1a: "LessThan", 0x1b: "GreaterThan", 0x1e: "UserName",
		0x1f: "Password", 0x20: "ConversationId"}},
	17: {"AirSyncBase", map[byte]string{0x05: "BodyPreference", 0x06: "Type", 0x07: "TruncationSize",
		0x08: "AllOrNone", 0x0a: "Body", 0x0b: "Data", 0x0c: "EstimatedDataSize", 0x0d: "Truncated",
		0x0e: "Attachments", 0x0f: "Attachment", 0x10: "DisplayName", 0x11: "FileReference", 0x12: "Method",
		0x13: "ContentId", 0x14: "ContentLocation", 0x15: "IsInline", 0x16: "NativeBodyType", 0x17: "ContentType",
		0x18: "Preview", 0x19: "BodyPartPreference", 0x1a: "BodyPart", 0x1b: "Status"}},
	18: {"Settings", map[byte]string{0x05: "Settings", 0x06: "Status", 0x07: "Get", 0x08: "Set", 0x09: "Oof",
		0x0a: "OofState", 0x0b: "StartTime", 0x0c: "EndTime", 0x0d: "OofMessage", 0x0e: "AppliesToInternal",
		0x0f: "AppliesToExternalKnown", 0x10: "AppliesToExternalUnknown", 0x11: "Enabled", 0x12: "ReplyMessage",
		0x13: "BodyType", 0x14: "DevicePassword", 0x15: "Password", 0x16: "DeviceInformation", 0x17: "Model",
		0x18: "IMEI", 0x19: "FriendlyName", 0x1a: "OS", 0x1b: "OSLanguage", 0x1c: "PhoneNumber",
		0x1d: "UserInformation", 0x1e: "EmailAddresses", 0x1f: "SmtpAddress", 0x20: "UserAgent",
		0x21: "EnableOutboundSMS", 0x22: "MobileOperator", 0x23: "PrimarySmtpAddress", 0x24: "Accounts",
		0x25: "Account", 0x26: "AccountId", 0x27: "AccountName", 0x28: "UserDisplayName", 0x29: "SendDisabled",
		0x2b: "RightsManagementInformation"}},
	20: {"ItemOperations", tagsFrom(0x05, "ItemOperations", "Fetch", "Store", "Options", "Range", "Total",
		"Properties", "Data", "Status", "Response", "Version", "Schema", "Part", "EmptyFolderContents",
		"DeleteSubFolders", "UserName", "Password", "Move", "DstFldId", "ConversationId", "MoveAlways")},
	21: {"ComposeMail", map[byte]string{0x05: "SendMail", 0x06: "SmartForward", 0x07: "SmartReply",
		0x08: "SaveInSentItems", 0x09: "ReplaceMime", 0x0b: "Source", 0x0c: "FolderId", 0x0d: "ItemId",
		0x0e: "LongId", 0x0f: "InstanceId", 0x10: "Mime", 0x11: "ClientId", 0x12: "Status", 0x13: "AccountId"}},
	22: {"Email2", map[byte]string{0x05: "UmCallerID", 0x06: "UmUserNotes", 0x07: "UmAttDuration",
		0x08: "UmAttOrder", 0x09: "ConversationId", 0x0a: "ConversationIndex", 0x0b: "LastVerbExecuted",
		0x0c: "LastVerbExecutionTime", 0x0d: "ReceivedAsBcc", 0x0e: "Sender", 0x0f: "CalendarType",
		0x10: "IsLeapMonth", 0x11: "AccountId", 0x12: "FirstDayOfWeek", 0x13: "MeetingMessageType"}},
}

func tagsFrom(first byte, names ...string) map[byte]string {
	m := map[byte]string{}
	for i, n := range names {
		m[first+byte(i)] = n
	}
	return m
}

// tokens maps "Page:Tag" to its page and token.
var tokens = func() map[string][2]byte {
	out := map[string][2]byte{}
	for p, cp := range codePages {
		for t, name := range cp.tags {
			out[cp.name+":"+name] = [2]byte{p, t}
		}
	}
	return out
}()

// Node is an element: its children, or its text, or opaque data.
type Node struct {
	Name   string // "Page:Tag"
	Kids   []*Node
	Text   string
	Data   []byte
	Opaque bool
	Empty  bool // no content at all (<Tag/>)
}

// El makes an element with children; nil children are left out.
func El(name string, kids ...*Node) *Node {
	var ks []*Node
	for _, k := range kids {
		if k != nil {
			ks = append(ks, k)
		}
	}
	return &Node{Name: name, Kids: ks, Empty: len(ks) == 0}
}

// Tx makes an element with text.
func Tx(name, text string) *Node { return &Node{Name: name, Text: text} }

// Op makes an element with opaque data.
func Op(name string, data []byte) *Node { return &Node{Name: name, Data: data, Opaque: true} }

// Child returns the first child named name ("Tag" in the parent's page,
// or "Page:Tag"), or nil.
func (n *Node) Child(name string) *Node {
	if n == nil {
		return nil
	}
	for _, k := range n.Kids {
		if k.Is(name) {
			return k
		}
	}
	return nil
}

// All returns every child; nil for a nil element.
func (n *Node) All() []*Node {
	if n == nil {
		return nil
	}
	return n.Kids
}

// Children returns every child named name.
func (n *Node) Children(name string) []*Node {
	if n == nil {
		return nil
	}
	var out []*Node
	for _, k := range n.Kids {
		if k.Is(name) {
			out = append(out, k)
		}
	}
	return out
}

// Is reports whether the element is named name ("Tag" in any page, or
// "Page:Tag").
func (n *Node) Is(name string) bool {
	if strings.Contains(name, ":") {
		return n.Name == name
	}
	_, tag, _ := strings.Cut(n.Name, ":")
	return tag == name
}

// Value returns a child's text, or "".
func (n *Node) Value(name string) string {
	if c := n.Child(name); c != nil {
		if c.Opaque {
			return string(c.Data)
		}
		return c.Text
	}
	return ""
}

// Encode writes a document.
func Encode(root *Node) ([]byte, error) {
	var b bytes.Buffer
	b.Write([]byte{0x03, 0x01, 0x6a, 0x00}) // WBXML 1.3, unknown public ID, UTF-8, no string table
	page := byte(0)
	var walk func(n *Node) error
	walk = func(n *Node) error {
		t, ok := tokens[n.Name]
		if !ok {
			return fmt.Errorf("wbxml: unknown tag %s", n.Name)
		}
		if t[0] != page {
			b.WriteByte(0x00)
			b.WriteByte(t[0])
			page = t[0]
		}
		content := len(n.Kids) > 0 || n.Text != "" || n.Opaque
		if !content {
			b.WriteByte(t[1])
			return nil
		}
		b.WriteByte(t[1] | 0x40)
		switch {
		case n.Opaque:
			b.WriteByte(0xc3)
			writeMBUint(&b, uint32(len(n.Data)))
			b.Write(n.Data)
		case n.Text != "":
			b.WriteByte(0x03)
			b.WriteString(strings.ReplaceAll(n.Text, "\x00", ""))
			b.WriteByte(0x00)
		}
		for _, k := range n.Kids {
			if err := walk(k); err != nil {
				return err
			}
		}
		b.WriteByte(0x01)
		return nil
	}
	if err := walk(root); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func writeMBUint(b *bytes.Buffer, v uint32) {
	var tmp [5]byte
	i := len(tmp) - 1
	tmp[i] = byte(v & 0x7f)
	for v >>= 7; v > 0; v >>= 7 {
		i--
		tmp[i] = byte(v&0x7f) | 0x80
	}
	b.Write(tmp[i:])
}

var errWBXML = errors.New("wbxml: bad document")

// Decode reads a document.
func Decode(data []byte) (*Node, error) {
	r := bufio.NewReader(bytes.NewReader(data))
	readMB := func() (uint32, error) {
		var v uint32
		for i := 0; i < 5; i++ {
			c, err := r.ReadByte()
			if err != nil {
				return 0, err
			}
			v = v<<7 | uint32(c&0x7f)
			if c&0x80 == 0 {
				return v, nil
			}
		}
		return 0, errWBXML
	}
	if _, err := r.ReadByte(); err != nil { // version
		return nil, errWBXML
	}
	if _, err := readMB(); err != nil { // public ID
		return nil, errWBXML
	}
	if _, err := readMB(); err != nil { // charset
		return nil, errWBXML
	}
	n, err := readMB() // string table
	if err != nil {
		return nil, errWBXML
	}
	if _, err := io.CopyN(io.Discard, r, int64(n)); err != nil {
		return nil, errWBXML
	}
	page := byte(0)
	var parse func() (*Node, error)
	parse = func() (*Node, error) {
		for {
			c, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			switch c {
			case 0x00:
				if page, err = r.ReadByte(); err != nil {
					return nil, err
				}
				continue
			case 0x01:
				return nil, nil // END
			case 0x03:
				s, err := r.ReadString(0x00)
				if err != nil {
					return nil, err
				}
				return &Node{Text: strings.TrimSuffix(s, "\x00")}, nil
			case 0xc3:
				l, err := readMB()
				if err != nil {
					return nil, err
				}
				buf := make([]byte, l)
				if _, err := io.ReadFull(r, buf); err != nil {
					return nil, err
				}
				return &Node{Data: buf, Opaque: true}, nil
			}
			cp, ok := codePages[page]
			name := fmt.Sprintf("%d:%#x", page, c&0x3f)
			if ok {
				if t, ok := cp.tags[c&0x3f]; ok {
					name = cp.name + ":" + t
				}
			}
			el := &Node{Name: name}
			if c&0x80 != 0 {
				return nil, errWBXML // attributes: not used by ActiveSync
			}
			if c&0x40 == 0 {
				el.Empty = true
				return el, nil
			}
			for {
				k, err := parse()
				if err != nil {
					return nil, err
				}
				if k == nil {
					return el, nil
				}
				if k.Name == "" {
					el.Text += k.Text
					if k.Opaque {
						el.Data, el.Opaque = append(el.Data, k.Data...), true
					}
					continue
				}
				el.Kids = append(el.Kids, k)
			}
		}
	}
	root, err := parse()
	if err != nil || root == nil {
		return nil, errWBXML
	}
	return root, nil
}
