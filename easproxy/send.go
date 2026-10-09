package easproxy

// SendMail, SmartReply and SmartForward. A device sends the whole MIME
// message; for SmartForward the server adds the original's attachments,
// unless the device says it replaced the MIME itself.

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"mime"
	"net/http"
	"net/mail"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/smtpproxy"
)

// The ComposeMail statuses of MS-ASCMD 2.2.2.
const (
	sendBadMIME      = 107
	sendServerError  = 110
	sendNoRecipients = 119
	sendFailed       = 120
	sendReplyFailed  = 121
	sendTooLarge     = 122
	sendItemNotFound = 150
)

// sendErr is a send's failure, as a ComposeMail status.
type sendErr int

func (e sendErr) Error() string { return "status " + strconv.Itoa(int(e)) }

func (req *request) send() (*node, error) {
	err := req.sendMessage()
	if err == nil {
		return nil, nil // an empty answer is success
	}
	var se sendErr
	if !errors.As(err, &se) {
		return nil, err
	}
	if !req.versionAtLeast("14.0") {
		// Before 14.0 a failure is an HTTP error.
		return nil, httpStatus(http.StatusInternalServerError)
	}
	return el("ComposeMail:"+req.cmd, tx("ComposeMail:Status", strconv.Itoa(int(se)))), nil
}

func (req *request) sendMessage() error {
	var msg []byte
	var saveInSent, replaceMIME bool
	var srcFolder, srcItem string
	if req.doc != nil {
		d := req.doc
		if n := d.Child("Mime"); n != nil {
			msg = n.Data
			if !n.Opaque {
				msg = []byte(n.Text)
			}
		}
		saveInSent = d.Child("SaveInSentItems") != nil
		replaceMIME = d.Child("ReplaceMime") != nil
		if src := d.Child("Source"); src != nil {
			srcFolder, srcItem = src.Value("FolderId"), src.Value("ItemId")
		}
	} else {
		// ActiveSync 12: the message is the body.
		msg = req.body
		saveInSent = req.params["SaveInSent"] == "T"
		srcFolder, srcItem = req.params["CollectionId"], req.params["ItemId"]
	}
	if len(msg) == 0 {
		return sendErr(sendBadMIME)
	}
	if int64(len(msg)) > req.s.maxMessage() {
		return sendErr(sendTooLarge)
	}
	if req.s.Submit == nil {
		return sendErr(sendFailed)
	}
	msg = crlf(msg)

	a := req.c.acct
	var src *engine.Message
	var srcBox string
	if req.cmd != "SendMail" && srcItem != "" {
		folder, uid, ok := parseItemID(srcItem)
		if srcFolder == "" {
			srcFolder = folder
		}
		a.Lock()
		m := folderByID(a, srcFolder)
		if m != nil {
			srcBox = m.Name()
		}
		a.Unlock()
		if ok && m != nil {
			src = messageAt(a, m, uid)
		}
		if src == nil {
			return sendErr(sendItemNotFound)
		}
	}
	if src != nil && !replaceMIME {
		data, err := a.Download([]*engine.Message{src}, nil)
		if err != nil {
			return sendErr(sendReplyFailed)
		}
		orig, ok := data[src]
		if !ok {
			return sendErr(sendItemNotFound)
		}
		if req.cmd == "SmartForward" {
			msg = withAttachments(msg, orig)
		} else {
			msg = withReplyHeaders(msg, orig)
		}
	}

	env, err := envelopeOf(msg, req.c.login)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(req.r.Context(), 2*time.Minute)
	defer cancel()
	if err := req.s.Submit(ctx, req.c.login, req.c.password, env); err != nil {
		req.s.Log.Info("activesync: submission refused", "user", req.c.login, "err", err)
		return sendErr(sendFailed)
	}
	if src != nil {
		f := imap.FlagAnswered
		if req.cmd == "SmartForward" {
			f = "$Forwarded"
		}
		a.SetFlags([]*engine.Message{src}, srcBox, imap.StoreFlagsAdd, []imap.Flag{f}, nil)
	}
	if saveInSent {
		req.saveSent(msg)
	}
	return nil
}

// saveSent stores a sent message in the Sent folder.
func (req *request) saveSent(data []byte) {
	a := req.c.acct
	a.Lock()
	sent := specialFolderName(a, typeSent)
	a.Unlock()
	if sent == "" {
		req.s.Log.Info("activesync: no Sent folder to save in", "user", req.c.login)
		return
	}
	if _, err := a.Append(sent, data, &imap.AppendOptions{Flags: []imap.Flag{imap.FlagSeen}}); err != nil {
		req.s.Log.Warn("activesync: could not save sent message", "user", req.c.login, "err", err)
	}
}

// envelopeOf finds a message's sender and recipients in its header, and
// removes its Bcc field.
func envelopeOf(data []byte, login string) (*smtpproxy.Envelope, error) {
	m, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, sendErr(sendBadMIME)
	}
	from := login
	for _, f := range []string{"Sender", "From"} {
		if l, err := m.Header.AddressList(f); err == nil && len(l) > 0 {
			from = l[0].Address
			break
		}
	}
	var to []string
	for _, f := range []string{"To", "Cc", "Bcc"} {
		l, _ := m.Header.AddressList(f)
		for _, ad := range l {
			if !slices.ContainsFunc(to, func(t string) bool { return strings.EqualFold(t, ad.Address) }) {
				to = append(to, ad.Address)
			}
		}
	}
	if len(to) == 0 {
		return nil, sendErr(sendNoRecipients)
	}
	return &smtpproxy.Envelope{From: from, To: to, Data: withoutBcc(data)}, nil
}

var bccField = regexp.MustCompile(`(?mi)^Bcc:.*\r?\n(?:[ \t].*\r?\n)*`)

// withoutBcc removes the Bcc field from a message's header.
func withoutBcc(data []byte) []byte {
	hdr, body := splitMessage(data)
	out := append(bccField.ReplaceAll(hdr, nil), "\r\n"...)
	return append(out, body...)
}

// splitMessage splits a message at the empty line that ends its header:
// the header with its last line's CRLF, and the body after the empty line.
func splitMessage(data []byte) (hdr, body []byte) {
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		return data[:i+2], data[i+4:]
	}
	return data, nil
}

// crlf makes every line end with CRLF.
func crlf(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n"))
}

// withReplyHeaders adds In-Reply-To and References for the original to a
// reply that has none.
func withReplyHeaders(data, orig []byte) []byte {
	om, err := mail.ReadMessage(bytes.NewReader(orig))
	if err != nil {
		return data
	}
	id := strings.TrimSpace(om.Header.Get("Message-Id"))
	if id == "" {
		return data
	}
	hdr, body := splitMessage(data)
	m, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return data
	}
	var add []byte
	if m.Header.Get("In-Reply-To") == "" {
		add = append(add, "In-Reply-To: "+id+"\r\n"...)
	}
	if m.Header.Get("References") == "" {
		refs := strings.TrimSpace(strings.Join(strings.Fields(om.Header.Get("References")), " ") + " " + id)
		add = append(add, "References: "+refs+"\r\n"...)
	}
	if len(add) == 0 {
		return data
	}
	out := append(slices.Clone(hdr), add...)
	out = append(out, "\r\n"...)
	return append(out, body...)
}

// contentFields are the header fields that describe a message's body.
var contentFields = regexp.MustCompile(`(?mi)^(?:Content-[A-Za-z-]+|MIME-Version):.*\r?\n(?:[ \t].*\r?\n)*`)

// withAttachments adds the attachments of orig to a forward: the forward
// becomes the first part of a multipart/mixed, the attachments the rest.
func withAttachments(data, orig []byte) []byte {
	p := parse(orig)
	if len(p.attachments) == 0 {
		return data
	}
	hdr, body := splitMessage(data)
	content := contentFields.FindAll(hdr, -1)
	rest := contentFields.ReplaceAll(hdr, nil)
	var rb [12]byte
	_, _ = rand.Read(rb[:])
	boundary := "=_mailcached_" + hex.EncodeToString(rb[:])

	var b bytes.Buffer
	b.Write(rest)
	b.WriteString("MIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"" + boundary + "\"\r\n\r\n")
	b.WriteString("--" + boundary + "\r\n")
	for _, f := range content {
		if !bytes.HasPrefix(bytes.ToLower(f), []byte("mime-version:")) {
			b.Write(f)
		}
	}
	b.WriteString("\r\n")
	b.Write(body)
	for _, at := range p.attachments {
		raw, t, ok := partData(orig, at.path)
		if !ok {
			continue
		}
		b.WriteString("\r\n--" + boundary + "\r\n")
		b.WriteString("Content-Type: " + t + "\r\n")
		disp := "attachment"
		if at.inline {
			disp = "inline"
		}
		b.WriteString("Content-Disposition: " + mime.FormatMediaType(disp, map[string]string{"filename": at.name}) + "\r\n")
		if at.contentID != "" {
			b.WriteString("Content-Id: <" + at.contentID + ">\r\n")
		}
		b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
		enc := base64.StdEncoding.EncodeToString(raw)
		for len(enc) > 76 {
			b.WriteString(enc[:76] + "\r\n")
			enc = enc[76:]
		}
		b.WriteString(enc + "\r\n")
	}
	b.WriteString("\r\n--" + boundary + "--\r\n")
	return b.Bytes()
}
