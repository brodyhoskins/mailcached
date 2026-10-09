package imapproxy

import (
	"bufio"
	"bytes"
	"compress/flate"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/emersion/go-imap/v2"
	"github.com/emersion/go-imap/v2/imapclient"

	"github.com/brodyhoskins/mailcached/engine"
	"github.com/brodyhoskins/mailcached/internal/imapraw"
	"github.com/brodyhoskins/mailcached/internal/inflate"
	"io"
)

// recordingListener keeps the compressConns it accepts, to check that
// compression was turned on.
type recordingListener struct {
	compressListener
	mu    sync.Mutex
	conns []*compressConn
}

func (l *recordingListener) Accept() (net.Conn, error) {
	c, err := l.compressListener.Accept()
	if cc, ok := c.(*compressConn); ok {
		l.mu.Lock()
		l.conns = append(l.conns, cc)
		l.mu.Unlock()
	}
	return c, err
}

func (l *recordingListener) compressed() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, c := range l.conns {
		c.wmu.Lock()
		if c.fw != nil {
			n++
		}
		c.wmu.Unlock()
	}
	return n
}

// TestUpstreamCompression checks that the proxy turns on COMPRESS=DEFLATE
// toward a provider that offers it, and that mail is still transformed.
func TestUpstreamCompression(t *testing.T) {
	var rec *recordingListener
	e := newEnvWith(t, func(l net.Listener) net.Listener {
		rec = &recordingListener{compressListener: compressListener{Listener: l, offer: true}}
		return rec
	})
	up := login(t, e.provider, nil)
	uid := appendMsg(t, up, "INBOX", sealed("Squeezed", strings.Repeat("The secret number is 42. ", 400)))

	c := login(t, e.proxy, nil)
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	full := &imap.FetchItemBodySection{Peek: true}
	msgs, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{full}}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if body := msgs[0].FindBodySection(full); !bytes.Contains(body, []byte("X-Opened: yes")) {
		t.Fatalf("not transformed:\n%.300s", body)
	}
	// The test's own client does not compress; the proxy's session (and
	// its background sync) do.
	if n := rec.compressed(); n < 1 {
		t.Fatalf("%d provider connections compressed, want the proxy's", n)
	}
}

// TestClientCompression turns on COMPRESS=DEFLATE as a mail client would,
// then reads a transformed message through the compressed stream.
func TestClientCompression(t *testing.T) {
	e := newEnv(t)
	up := login(t, e.provider, nil)
	uid := appendMsg(t, up, "INBOX", sealed("Squeezed", "The secret number is 42."))

	conn, err := net.Dial("tcp", e.proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	h := imapraw.New(conn)
	if _, err := h.Greeting(); err != nil {
		t.Fatal(err)
	}
	if err := h.Command("COMPRESS DEFLATE"); err == nil {
		t.Fatal("COMPRESS accepted before login")
	}
	if err := h.Command("LOGIN", alice, password); err != nil {
		t.Fatal(err)
	}
	if err := h.Command("CAPABILITY"); err != nil {
		t.Fatal(err)
	}
	if !h.HasCap("COMPRESS=DEFLATE") {
		t.Fatalf("capabilities %v lack COMPRESS=DEFLATE", h.Caps)
	}
	if err := h.Command("COMPRESS DEFLATE"); err != nil {
		t.Fatal(err)
	}

	fw, _ := flate.NewWriter(conn, flate.DefaultCompression)
	sc := &deflateConn{Conn: conn, r: io.MultiReader(strings.NewReader("* PREAUTH [CAPABILITY IMAP4rev1] test\r\n"), flate.NewReader(h.BR)),
		w: inflate.NewFlushWriter(fw)}
	c := imapclient.New(sc, nil)
	defer c.Close()
	if _, err := c.Select("INBOX", nil).Wait(); err != nil {
		t.Fatal(err)
	}
	full := &imap.FetchItemBodySection{Peek: true}
	msgs, err := c.Fetch(imap.UIDSetNum(uid), &imap.FetchOptions{BodySection: []*imap.FetchItemBodySection{full}}).Collect()
	if err != nil {
		t.Fatal(err)
	}
	if body := msgs[0].FindBodySection(full); !bytes.Contains(body, []byte("The secret number is 42.")) {
		t.Fatalf("compressed fetch returned:\n%.300s", body)
	}
}

// TestImplicitTLSAllowsLogin checks that the compression wrapper inside
// implicit TLS still lets clients log in: go-imap cannot see through the
// wrapper to the TLS connection.
func TestImplicitTLSAllowsLogin(t *testing.T) {
	cert := selfSigned(t)
	eng := &engine.Engine{
		Route: func(string) (engine.Upstream, bool) { return engine.Upstream{}, false },
		Cache: &engine.Cache{MaxBytes: 1 << 20},
		Log:   testLog,
	}
	t.Cleanup(eng.Close)
	b := &Server{
		Engine:      eng,
		TLSConfig:   &tls.Config{Certificates: []tls.Certificate{cert}},
		ImplicitTLS: true,
		Log:         testLog,
	}
	l := listen(t)
	go b.Serve(l)
	t.Cleanup(func() { b.Close() })

	conn, err := tls.Dial("tcp", l.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	h := imapraw.New(conn)
	if _, err := h.Greeting(); err != nil {
		t.Fatal(err)
	}
	if err := h.Command("CAPABILITY"); err != nil {
		t.Fatal(err)
	}
	if h.HasCap("LOGINDISABLED") || !h.HasCap("AUTH=PLAIN") || !h.HasCap("COMPRESS=DEFLATE") {
		t.Fatalf("capabilities over implicit TLS = %v", h.Caps)
	}
}

func selfSigned(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// TestClientPartialFlush sends a command compressed the way Apple's clients
// compress, with zlib's Z_PARTIAL_FLUSH, and expects an answer. Go's own
// inflater waits for more input here and never answers.
func TestClientPartialFlush(t *testing.T) {
	e := newEnv(t)
	conn, err := net.Dial("tcp", e.proxy)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	h := imapraw.New(conn)
	if _, err := h.Greeting(); err != nil {
		t.Fatal(err)
	}
	if err := h.Command("LOGIN", alice, password); err != nil {
		t.Fatal(err)
	}
	if err := h.Command("COMPRESS DEFLATE"); err != nil {
		t.Fatal(err)
	}
	// B3 LIST "" "*", from zlib.compressobj(6, zlib.DEFLATED, -15) with
	// c.flush(zlib.Z_PARTIAL_FLUSH).
	cmd, _ := hex.DecodeString("723256f0f10c0e5150525250d252e2e50208")
	if _, err := conn.Write(cmd); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(inflate.NewReader(h.BR))
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			t.Fatalf("no answer to a partially flushed command: %v", err)
		}
		if strings.HasPrefix(line, "B3 ") {
			if !strings.HasPrefix(line, "B3 OK") {
				t.Fatalf("answer %q", line)
			}
			return
		}
	}
}

func TestFixUIDZero(t *testing.T) {
	for in, want := range map[string]string{
		"28.4 UID FETCH 0:961 (FLAGS)\r\n":     "28.4 UID FETCH 1:961 (FLAGS)\r\n",
		"a uid fetch 5,0,10:0 BODY[]\r\n":      "a uid fetch 5,0,10:1 BODY[]\r\n",
		"a UID STORE 0 +FLAGS (\\Deleted)\r\n": "a UID STORE 0 +FLAGS (\\Deleted)\r\n",
		"a UID EXPUNGE 0,7\r\n":                "a UID EXPUNGE 0,7\r\n",
		"a UID FETCH 100:200,0:5 (FLAGS)\r\n":  "a UID FETCH 100:200,1:5 (FLAGS)\r\n",
		"a UID FETCH 10:20 (FLAGS)\r\n":        "a UID FETCH 10:20 (FLAGS)\r\n",
		"a UID STORE 0:* +FLAGS (\\Seen)\r\n":  "a UID STORE 1:* +FLAGS (\\Seen)\r\n",
		"a FETCH 0:5 (FLAGS)\r\n":              "a FETCH 0:5 (FLAGS)\r\n",
		"a UID SEARCH TEXT 0\r\n":              "a UID SEARCH TEXT 0\r\n",
	} {
		if got := string(fixUIDZero([]byte(in))); got != want {
			t.Errorf("fixUIDZero(%q) = %q, want %q", in, got, want)
		}
	}
}

// The reply trace logs replies, never lines of the messages in literals,
// however the writes split them.
func TestTraceSkipsLiterals(t *testing.T) {
	msg := "Subject: NO secrets here\r\nX-Spam-Flag: NO\r\n\r\nA OK body line\r\n* NO not a reply\r\n"
	out := fmt.Sprintf("* 1 FETCH (UID 7 BODY[] {%d}\r\n%s)\r\n4.4 OK UID FETCH completed\r\n* 2 EXISTS\r\n", len(msg), msg)
	for _, size := range []int{1, 3, 7, 64, len(out)} {
		var buf syncBuffer
		c := &compressConn{trace: slog.New(slog.NewTextHandler(&buf, nil))}
		for p := []byte(out); len(p) > 0; {
			n := min(size, len(p))
			c.traceReplies(p[:n])
			p = p[n:]
		}
		got := buf.String()
		for _, bad := range []string{"secrets", "X-Spam-Flag", "body line", "not a reply"} {
			if strings.Contains(got, bad) {
				t.Errorf("writes of %d: the trace has message contents %q:\n%s", size, bad, got)
			}
		}
		for _, want := range []string{"4.4 OK UID FETCH completed", "* 2 EXISTS"} {
			if !strings.Contains(got, want) {
				t.Errorf("writes of %d: the trace lacks %q:\n%s", size, want, got)
			}
		}
	}
}

// deflateConn is a client connection after COMPRESS DEFLATE, with a
// greeting for go-imap in front.
type deflateConn struct {
	net.Conn
	r io.Reader
	w io.Writer
}

func (c *deflateConn) Read(p []byte) (int, error)  { return c.r.Read(p) }
func (c *deflateConn) Write(p []byte) (int, error) { return c.w.Write(p) }
