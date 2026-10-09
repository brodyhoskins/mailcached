package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func load(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "mailcached.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

const base = `
tls: {cert_file: /c.pem, key_file: /k.pem}
imap: {listen: ":993"}
smtp: {listen: ":465"}
`

func TestDefaultsAndRoute(t *testing.T) {
	c, err := load(t, base+`
accounts:
  - match: "@Example.com"
    imap: {upstream: "imap.example.com:993"}
    smtp: {upstream: "smtp.example.com:587", upstream_tls: starttls}
  - match: "boss@example.com"
    imap: {upstream: "imap.other.example:993"}
`)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		svc, login, want, tls string
		ok                    bool
	}{
		{"imap", "alice@example.com", "imap.example.com:993", TLSImplicit, true},
		{"imap", "Alice@EXAMPLE.com", "imap.example.com:993", TLSImplicit, true},
		{"smtp", "alice@example.com", "smtp.example.com:587", TLSStartTLS, true},
		// An address match wins over a domain match, whatever the order.
		{"imap", "boss@example.com", "imap.other.example:993", TLSImplicit, true},
		// The address account has no SMTP server.
		{"smtp", "boss@example.com", "", "", false},
		{"imap", "alice@example.org", "", "", false},
		{"imap", "alice", "", "", false},
	} {
		u, _, ok := c.Route(tc.svc, tc.login)
		if ok != tc.ok || (ok && (u.Upstream != tc.want || u.UpstreamTLS != tc.tls)) {
			t.Errorf("Route(%s, %s) = %+v, %v; want %s %s, %v", tc.svc, tc.login, u, ok, tc.want, tc.tls, tc.ok)
		}
	}
}

func TestAutodetectDefault(t *testing.T) {
	c, err := load(t, base)
	if err != nil {
		t.Fatal(err)
	}
	if !*c.Autodetect {
		t.Error("autodetect defaults to false")
	}
	if _, match, ok := c.Route("imap", "alice@example.org"); ok || match != "" {
		t.Errorf("Route without accounts = %q, %v", match, ok)
	}
}

// TestExtend checks that a program can add settings of its own to the
// file, next to mailcached's.
func TestExtend(t *testing.T) {
	var c struct {
		Config `yaml:",inline"`
		Extra  bool `yaml:"extra"`
	}
	p := filepath.Join(t.TempDir(), "x.yaml")
	if err := os.WriteFile(p, []byte(base+"extra: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Decode(p, &c); err != nil {
		t.Fatal(err)
	}
	if err := c.Finish(); err != nil {
		t.Fatal(err)
	}
	if !c.Extra || !slices.Equal(c.IMAP.Listen, Addrs{":993"}) || c.CacheMaxAge == 0 {
		t.Errorf("decoded %+v", c)
	}
	if err := os.WriteFile(p, []byte(base+"other: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Decode(p, &c); err == nil || !strings.Contains(err.Error(), "field other not found") {
		t.Errorf("unknown setting: err = %v", err)
	}
}

func TestRejects(t *testing.T) {
	acct := "accounts: [{match: \"@x.example\", imap: {upstream: \"x:993\"}, smtp: {upstream: \"x:465\"}}]\n"
	for _, tc := range []struct{ yaml, want string }{
		{acct, "none of imap.listen, smtp.listen, jmap.listen and activesync.listen"},
		{"jmap: {listen: \":443\", tls: starttls}\n" + acct, "jmap.tls must be implicit or none"},
		{"activesync: {listen: \":443\", tls: starttls}\n" + acct, "activesync.tls must be implicit or none"},
		{"imap: {listen: \":993\"}\ntls: {cert_file: /c, key_file: /k}\naccounts: [{match: \"@x.example\", activesync: {upstream: \"mail.x.example\"}}]\n", "activesync.upstream must be an https:// URL"},
		{"imap: {listen: \":993\"}\ntls: {cert_file: /c, key_file: /k}\naccounts: [{match: \"@x.example\", activesync: {upstream: \"https://m.x.example\"}, jmap: {upstream: \"https://j.x.example/jmap\"}}]\n", "both jmap and activesync"},
		{"imap: {listen: \":993\"}\ntls: {cert_file: /c, key_file: /k}\nautodetect_activesync: always\n", "autodetect_activesync"},
		{base + "autodetect: false\n", "accounts is empty and autodetect is off"},
		{base + "accounts: [{imap: {upstream: \"x:993\"}}]\n", "match must be"},
		{base + "accounts: [{match: \"x.example\", imap: {upstream: \"x:993\"}}]\n", "match must be"},
		{base + "accounts: [{match: \"*@x.example\", imap: {upstream: \"x:993\"}}]\n", "match must be"},
		{base + "accounts: [{match: \"@x.example\"}]\n", "none of imap.upstream, smtp.upstream, jmap.upstream and activesync.upstream"},
		{base + "accounts: [{match: \"@x.example\", jmap: {upstream: \"jmap.x.example\"}}]\n", "must be an https:// URL"},
		{base + "accounts: [{match: \"@x.example\", jmap: {upstream: \"http://x.example/jmap\"}}]\n", "http sends passwords"},
		{base + "accounts: [{match: \"@x.example\", jmap: {upstream: \"https://x.example/jmap\", auth: token}}]\n", "auth must be basic or bearer"},
		{base + "accounts: [{match: \"@x.example\", jmap: {upstream: \"https://x.example/jmap\", upstream_tls: none}}]\n", "the URL's scheme says it"},
		{base + "accounts: [{match: \"@x.example\", imap: {upstream: \"x:993\", auth: bearer}}]\n", "imap.auth is for jmap only"},
		{base + "accounts: [{match: \"@x.example\", imap: {upstream: \"x\"}}]\n", "accounts[0].imap.upstream"},
		{base + "accounts: [{match: \"@x.example\", imap: {upstream: \"x:993\"}}, {match: \"@X.example\", imap: {upstream: \"y:993\"}}]\n", "listed twice"},
		{base + "accounts: [{match: \"@x.example\", smtp: {upstream: \"x:25\", upstream_tls: none}}]\n", "accounts[0].smtp.upstream_tls: none sends passwords"},
		{base + "accounts: [{match: \"@x.example\", smtp: {upstream: \"x:25\", upstream_tls: ssl}}]\n", "must be implicit, starttls or none"},
		{"imap: {listen: \"127.0.0.1:143\", tls: none}\n" + acct, "imap.tls: none sends passwords"},
		{"imap: {listen: \":993\"}\n" + acct, "tls.cert_file"},
		{"unknown: {}\n", "field unknown not found"},
		{base + "listen_addresses: [\"eth0:993\"]\n" + acct, "listen_addresses"},
		{base + "upstream_source: \"10.0.0.1:0\"\n" + acct, "upstream_source"},
		{base + "accounts: [{match: \"@x.example\", imap: {upstream: \"x:993\", source: \"wg0 eth0\"}}]\n", "accounts[0].imap.source"},
		{"tls: {cert_file: /c, key_file: /k}\nimap: {listen: [\":993\", \"eth0\"]}\n" + acct, "imap.listen"},
		{"tls: {cert_file: /c, key_file: /k}\nimap: {listen: \":993\", upstream: \"x:993\"}\n" + acct, "field upstream not found"},
	} {
		_, err := load(t, tc.yaml)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: err = %v, want %q", tc.yaml, err, tc.want)
		}
	}
}

// TestExample keeps examples/mailcached.yaml loadable.
func TestExample(t *testing.T) {
	c, err := Load("../examples/mailcached.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if u, _, ok := c.Route("smtp", "alice@example.org"); !ok || u.UpstreamTLS != TLSStartTLS {
		t.Errorf("alice@example.org smtp = %+v, %v", u, ok)
	}
}

func TestParseMinFree(t *testing.T) {
	for _, c := range []struct {
		in      string
		percent float64
		bytes   int64
		ok      bool
	}{
		{"5%", 5, 0, true},
		{" 2.5 % ", 2.5, 0, true},
		{"2GiB", 0, 2 << 30, true},
		{"500 MB", 0, 500e6, true},
		{"1048576", 0, 1 << 20, true},
		{"0", 0, 0, true},
		{"100%", 0, 0, false},
		{"5 parsecs", 0, 0, false},
		{"-1GB", 0, 0, false},
		{"", 0, 0, false},
	} {
		p, b, err := ParseMinFree(c.in)
		if (err == nil) != c.ok || p != c.percent || b != c.bytes {
			t.Errorf("ParseMinFree(%q) = %v, %v, %v", c.in, p, b, err)
		}
	}
}

// TestActiveSyncAccount adds the endpoint path to a bare URL.
func TestActiveSyncAccount(t *testing.T) {
	c, err := load(t, "imap: {listen: \":993\"}\ntls: {cert_file: /c, key_file: /k}\n"+
		"accounts: [{match: \"@x.example\", activesync: {upstream: \"https://mail.x.example\"}}]\n")
	if err != nil {
		t.Fatal(err)
	}
	u, match, ok := c.Route("activesync", "a@x.example")
	if !ok || match != "@x.example" || u.Upstream != "https://mail.x.example/Microsoft-Server-ActiveSync" {
		t.Fatalf("%+v %q %v", u, match, ok)
	}
	if c.AutodetectActiveSync != "fallback" {
		t.Fatalf("autodetect_activesync %q", c.AutodetectActiveSync)
	}
}

func TestListenAndSource(t *testing.T) {
	c, err := load(t, `
tls: {cert_file: /c.pem, key_file: /k.pem}
listen_addresses: [eth0, "fd00::10"]
upstream_source: tailscale0
imap: {listen: [":993", "127.0.0.1:143"]}
smtp: {listen: "wg0:465"}
accounts:
  - match: "@a.example"
    imap: {upstream: "imap.a.example:993", source: wg0}
    smtp: {upstream: "smtp.a.example:465"}
`)
	if err != nil {
		t.Fatal(err)
	}
	if want := (Addrs{"eth0:993", "[fd00::10]:993", "127.0.0.1:143"}); !slices.Equal(c.IMAP.Listen, want) {
		t.Errorf("imap.listen %q, want %q", c.IMAP.Listen, want)
	}
	if want := (Addrs{"wg0:465"}); !slices.Equal(c.SMTP.Listen, want) {
		t.Errorf("smtp.listen %q, want %q", c.SMTP.Listen, want)
	}
	if u, _, _ := c.Route("imap", "x@a.example"); u.Source != "wg0" {
		t.Errorf("imap source %q, want wg0", u.Source)
	}
	if u, _, _ := c.Route("smtp", "x@a.example"); u.Source != "tailscale0" {
		t.Errorf("smtp source %q, want the default tailscale0", u.Source)
	}
}
