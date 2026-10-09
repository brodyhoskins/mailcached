package easproxy

// A message as a device sees it: the ApplicationData of a Sync Add or
// Fetch.

import (
	"errors"
	"net/mail"
	"strconv"
	"strings"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/engine"
)

// The body types of MS-ASAIRS.
const (
	bodyPlain = 1
	bodyHTML  = 2
	bodyRTF   = 3
	bodyMIME  = 4
)

// dateFormat is how ActiveSync writes dates.
const dateFormat = "2006-01-02T15:04:05.000Z"

// fileRef is an attachment's FileReference: its message and part.
func fileRef(folder string, uid imap.UID, path string) string {
	return itemID(folder, uid) + ":" + path
}

// parseFileRef splits a FileReference.
func parseFileRef(ref string) (folder string, uid imap.UID, path string, ok bool) {
	i := strings.LastIndexByte(ref, ':')
	if i < 0 {
		return "", 0, "", false
	}
	folder, uid, ok = parseItemID(ref[:i])
	return folder, uid, ref[i+1:], ok && ref[i+1:] != ""
}

var errGone = errors.New("message gone")

// appData downloads a message and makes its ApplicationData.
func (req *request) appData(msg *engine.Message, opts *syncOptions, folder string) (*node, error) {
	a := req.c.acct
	data, err := a.Download([]*engine.Message{msg}, nil)
	if err != nil {
		return nil, err
	}
	raw, ok := data[msg]
	if !ok {
		return nil, errGone
	}
	a.Lock()
	rec := recOf(msg)
	a.Unlock()
	return req.appDataOf(msg, raw, rec, opts, folder), nil
}

// flagNodes are the parts of ApplicationData a flag change touches.
func (req *request) flagNodes(r itemRec) []*node {
	read := "0"
	if r.Read {
		read = "1"
	}
	flag := el("Email:Flag")
	if r.Flagged {
		flag = el("Email:Flag", tx("Email:FlagStatus", "2"), tx("Email:FlagType", "Flag for follow up"))
	}
	out := []*node{tx("Email:Read", read), flag}
	if req.versionAtLeast("14.0") {
		switch {
		case r.Forwarded:
			out = append(out, tx("Email2:LastVerbExecuted", "3"))
		case r.Answered:
			out = append(out, tx("Email2:LastVerbExecuted", "1"))
		}
	}
	return out
}

// appDataOf makes a message's ApplicationData.
func (req *request) appDataOf(msg *engine.Message, raw []byte, rec itemRec, opts *syncOptions, folder string) *node {
	p := parse(raw)
	h := p.header
	get := func(name string) string { return strings.TrimSpace(engine.DecodeHeader(h.Get(name))) }
	var kids []*node
	add := func(name, v string) {
		if v != "" {
			kids = append(kids, tx(name, v))
		}
	}
	add("Email:To", get("To"))
	add("Email:Cc", get("Cc"))
	add("Email:From", get("From"))
	subject := get("Subject")
	add("Email:Subject", subject)
	add("Email:ReplyTo", get("Reply-To"))
	kids = append(kids, tx("Email:DateReceived", msg.Date().UTC().Format(dateFormat)))
	add("Email:DisplayTo", displayNames(get("To")))
	add("Email:ThreadTopic", subject)
	kids = append(kids, tx("Email:Importance", strconv.Itoa(importance(h.Get("Importance"), h.Get("X-Priority")))))
	flags := req.flagNodes(rec)
	kids = append(kids, flags[0]) // Read

	ct, _, _ := h.ContentType()
	smime := ct == "application/pkcs7-mime" || ct == "application/x-pkcs7-mime"
	signed := ct == "multipart/signed"
	if len(p.attachments) > 0 {
		var atts []*node
		for _, at := range p.attachments {
			n := el("AirSyncBase:Attachment", tx("AirSyncBase:DisplayName", at.name),
				tx("AirSyncBase:FileReference", fileRef(folder, msg.UID(), at.path)), tx("AirSyncBase:Method", "1"),
				tx("AirSyncBase:EstimatedDataSize", strconv.Itoa(at.size)))
			if at.contentID != "" {
				n.Kids = append(n.Kids, tx("AirSyncBase:ContentId", at.contentID))
			}
			if at.inline {
				n.Kids = append(n.Kids, tx("AirSyncBase:IsInline", "1"))
			}
			atts = append(atts, n)
		}
		kids = append(kids, el("AirSyncBase:Attachments", atts...))
	}
	kids = append(kids, req.bodyNode(raw, p, opts, smime || signed))
	class := "IPM.Note"
	switch {
	case smime:
		class = "IPM.Note.SMIME"
	case signed:
		class = "IPM.Note.SMIME.MultipartSigned"
	}
	kids = append(kids, tx("Email:MessageClass", class), tx("Email:InternetCPID", "65001"))
	kids = append(kids, flags[1:]...) // Flag, LastVerbExecuted
	kids = append(kids, tx("Email:ContentClass", "urn:content-classes:message"))
	native := bodyPlain
	if p.hasHTML {
		native = bodyHTML
	}
	kids = append(kids, tx("AirSyncBase:NativeBodyType", strconv.Itoa(native)))
	return el("AirSync:ApplicationData", kids...)
}

// bodyNode picks the body type the device prefers among those the message
// can give, and makes the Body.
func (req *request) bodyNode(raw []byte, p *parsed, opts *syncOptions, smime bool) *node {
	prefs := opts.Prefs
	if len(prefs) == 0 {
		prefs = []bodyPref{{Type: bodyPlain}}
	}
	mimeOK := opts.MIMESupport == 2 || (opts.MIMESupport == 1 && smime)
	pick := func(t int) *bodyPref {
		for i := range prefs {
			if prefs[i].Type == t {
				return &prefs[i]
			}
		}
		return nil
	}
	var pref *bodyPref
	switch {
	case mimeOK && pick(bodyMIME) != nil:
		pref = pick(bodyMIME)
	case pick(bodyHTML) != nil:
		pref = pick(bodyHTML)
	case pick(bodyPlain) != nil:
		pref = pick(bodyPlain)
	default:
		pref = &bodyPref{Type: bodyPlain}
	}
	var content string
	switch pref.Type {
	case bodyMIME:
		content = string(raw)
	case bodyHTML:
		content = p.htmlOf()
	default:
		content = p.plainOf()
	}
	cut, truncated := truncate(content, pref.Truncation)
	kids := []*node{tx("AirSyncBase:Type", strconv.Itoa(pref.Type)),
		tx("AirSyncBase:EstimatedDataSize", strconv.Itoa(len(content)))}
	if truncated {
		kids = append(kids, tx("AirSyncBase:Truncated", "1"))
	}
	if !(truncated && pref.AllOrNone) {
		kids = append(kids, tx("AirSyncBase:Data", cut))
	}
	if req.versionAtLeast("14.0") {
		for _, bp := range prefs {
			if bp.Preview > 0 {
				prev := strings.Join(strings.Fields(p.plainOf()), " ")
				if r := []rune(prev); len(r) > min(bp.Preview, 255) {
					prev = string(r[:min(bp.Preview, 255)])
				}
				kids = append(kids, tx("AirSyncBase:Preview", prev))
				break
			}
		}
	}
	return el("AirSyncBase:Body", kids...)
}

// displayNames returns the names of the addresses in a list, as
// DisplayTo shows them.
func displayNames(list string) string {
	addrs, err := mail.ParseAddressList(list)
	if err != nil {
		return ""
	}
	names := make([]string, len(addrs))
	for i, ad := range addrs {
		names[i] = ad.Name
		if names[i] == "" {
			names[i] = ad.Address
		}
	}
	return strings.Join(names, "; ")
}

// importance maps the Importance and X-Priority fields to 0 (low), 1
// (normal) or 2 (high).
func importance(imp, prio string) int {
	switch strings.ToLower(strings.TrimSpace(imp)) {
	case "high":
		return 2
	case "low":
		return 0
	}
	if p := strings.TrimSpace(prio); p != "" {
		switch p[0] {
		case '1', '2':
			return 2
		case '4', '5':
			return 0
		}
	}
	return 1
}
