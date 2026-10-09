package imapproxy

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/emersion/go-imap/v2"

	"github.com/brodyhoskins/mailcached/engine"
)

// recorder keeps what the proxy sends the provider.
type recorder struct {
	net.Listener
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *recorder) Accept() (net.Conn, error) {
	c, err := r.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &recConn{Conn: c, r: r}, nil
}

func (r *recorder) sent() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}

func (r *recorder) reset() {
	r.mu.Lock()
	r.buf.Reset()
	r.mu.Unlock()
}

type recConn struct {
	net.Conn
	r *recorder
}

func (c *recConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.r.mu.Lock()
	c.r.buf.Write(p[:n])
	c.r.mu.Unlock()
	return n, err
}

// withAttachment is a message with a short text and a large attachment.
func withAttachment(subject string, attachment []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(attachment)
	var lines strings.Builder
	for len(enc) > 76 {
		lines.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	lines.WriteString(enc + "\r\n")
	return []byte("From: " + bob + "\r\nTo: alice@corp.example\r\nSubject: " + subject + "\r\n" +
		"Message-ID: <" + subject + "@test>\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=b1\r\n\r\n" +
		"--b1\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSee the attachment.\r\n" +
		"--b1\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		lines.String() + "--b1--\r\n")
}

func TestPieces(t *testing.T) {
	var rec *recorder
	e := newEnvWith(t, func(l net.Listener) net.Listener { rec = &recorder{Listener: l}; return rec })
	att := bytes.Repeat([]byte("attachment bytes "), 4000) // 68 KB
	big := withAttachment("Big", att)
	up := login(t, e.provider, nil)
	appendMsg(t, up, "INBOX", big)
	appendMsg(t, up, "INBOX", plain(bob, "Small", "Hello."))

	c := login(t, e.proxy, nil)
	waitSyncing(t, e.b, alice)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	rec.reset()
	text := &imap.FetchItemBodySection{Part: []int{1}, Peek: true}
	head := &imap.FetchItemBodySection{Partial: &imap.SectionPartial{Offset: 0, Size: 300}, Peek: true}
	bin := &imap.FetchItemBinarySection{Part: []int{2}, Partial: &imap.SectionPartial{Offset: 0, Size: 100}, Peek: true}
	msgs, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{UID: true, BodyStructure: &imap.FetchItemBodyStructure{},
		BodySection: []*imap.FetchItemBodySection{text, head}, BinarySection: []*imap.FetchItemBinarySection{bin},
		BinarySectionSize: []*imap.FetchItemBinarySectionSize{{Part: []int{2}}}}).Collect()
	if err != nil || len(msgs) != 1 {
		t.Fatalf("fetch: %v", err)
	}
	m := msgs[0]
	if got := string(m.FindBodySection(text)); got != "See the attachment." {
		t.Fatalf("BODY[1] %q", got)
	}
	if got := m.FindBodySection(head); !bytes.Equal(got, big[:300]) {
		t.Fatalf("BODY[]<0.300> %q", got)
	}
	if got := m.FindBinarySection(bin); !bytes.Equal(got, att[:100]) {
		t.Fatalf("BINARY[2]<0.100> %q", got)
	}
	if n, _ := m.FindBinarySectionSize([]int{2}); n != uint32(len(att)) {
		t.Fatalf("BINARY.SIZE[2] %d, want %d", n, len(att))
	}
	sent := rec.sent()
	if regexp.MustCompile(`BODY\.PEEK\[\]( |\))`).MatchString(sent) {
		t.Fatalf("the whole message was asked for:\n%s", sent)
	}
	if !strings.Contains(sent, "BODY.PEEK[1]") {
		t.Fatalf("the text was not asked for:\n%s", sent)
	}

	// The same pieces again come from the cache.
	rec.reset()
	if _, err := c.Fetch(imap.SeqSetNum(1), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{text}}).Collect(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(rec.sent(), "FETCH") {
		t.Fatalf("asked the provider again:\n%s", rec.sent())
	}

	// A small message is read whole.
	rec.reset()
	if _, err := c.Fetch(imap.SeqSetNum(2), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{text}}).Collect(); err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`BODY\.PEEK\[\]`).MatchString(rec.sent()) {
		t.Fatalf("the small message was not read whole:\n%s", rec.sent())
	}

	// Searching text asks the provider, for a message the proxy does not
	// change.
	rec.reset()
	res, err := c.UIDSearch(&imap.SearchCriteria{Body: []string{"attachment"}}, nil).Wait()
	if err != nil || len(res.AllUIDs()) != 1 {
		t.Fatalf("search: %v %v", res, err)
	}
	if !strings.Contains(rec.sent(), "SEARCH") || regexp.MustCompile(`BODY\.PEEK\[\]`).MatchString(rec.sent()) {
		t.Fatalf("the search was not the provider's:\n%s", rec.sent())
	}
}

func TestDecodePartLocally(t *testing.T) {
	att := bytes.Repeat([]byte("décodé "), 50)
	enc := base64.StdEncoding.EncodeToString(att)
	wrapped := enc[:40] + "\r\n" + enc[40:]
	if got, err := decodeForTest(wrapped, "base64"); err != nil || !bytes.Equal(got, att) {
		t.Fatalf("base64: %v", err)
	}
	if got, err := decodeForTest("caf=C3=A9 =\r\nbar", "quoted-printable"); err != nil || string(got) != "café bar" {
		t.Fatalf("quoted-printable: %q %v", got, err)
	}
}

// TestUnseenFirst checks that a FETCH of many uncached messages answers
// the unseen ones first, newest first, a batch at a time.
func TestUnseenFirst(t *testing.T) {
	e := newEnv(t)
	up := login(t, e.provider, nil)
	for i := 1; i <= 30; i++ {
		appendMsg(t, up, "INBOX", withID(plain(bob, fmt.Sprintf("M%d", i), "Body."), fmt.Sprintf("<unseen-%d@test>", i)))
	}
	if _, err := up.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	if err := up.Store(imap.SeqSetNum(1, 2, 3, 4, 5), &imap.StoreFlags{Op: imap.StoreFlagsAdd, Silent: true, Flags: []imap.Flag{imap.FlagSeen}}, nil).Close(); err != nil {
		t.Fatal(err)
	}
	rc := dialRaw(t, e.proxy)
	rc.ok(`LOGIN "` + alice + `" "` + password + `"`)
	waitSyncing(t, e.b, alice)
	rc.ok("SELECT INBOX")
	var order []int
	for _, l := range rc.ok("FETCH 1:30 (BODY.PEEK[])") {
		var n int
		if _, err := fmt.Sscanf(l, "* %d FETCH", &n); err == nil {
			order = append(order, n)
		}
	}
	var want []int
	for i := 6; i <= 30; i++ {
		want = append(want, i)
	}
	want = append(want, 1, 2, 3, 4, 5)
	if fmt.Sprint(order) != fmt.Sprint(want) {
		t.Fatalf("order %v, want %v", order, want)
	}
}

func decodeForTest(body, encoding string) ([]byte, error) {
	return engine.DecodePart([]byte(body), encoding)
}
