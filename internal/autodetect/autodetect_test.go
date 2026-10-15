package autodetect

import (
	"context"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/brodyhoskins/mailcached/config"
)

// fake is a network: HTTP answers by URL (query string ignored), DNS
// records by name, and the servers that accept connections.
type fake struct {
	pages map[string]string
	srv   map[string][]*net.SRV
	mx    map[string][]*net.MX
	up    map[string]bool
	gets  atomic.Int32
}

func (f *fake) detector() *Detector {
	page := func(u string) ([]byte, error) {
		u, _, _ = strings.Cut(u, "?")
		if p, ok := f.pages[u]; ok {
			return []byte(p), nil
		}
		return nil, errors.New("404")
	}
	return &Detector{
		Get: func(_ context.Context, u string) ([]byte, error) {
			f.gets.Add(1)
			return page(u)
		},
		Post: func(_ context.Context, u string, _ []byte) ([]byte, error) { return page(u) },
		LookupSRV: func(_ context.Context, service, proto, name string) ([]*net.SRV, error) {
			return f.srv["_"+service+"._"+proto+"."+name], nil
		},
		LookupMX: func(_ context.Context, name string) ([]*net.MX, error) { return f.mx[name], nil },
		Usable:   func(_ context.Context, _ string, u config.Upstream) bool { return f.up[u.Upstream] },
	}
}

const ispdbGandi = `<clientConfig version="1.1"><emailProvider id="gandi.net">
<incomingServer type="pop3"><hostname>mail.gandi.net</hostname><port>995</port><socketType>SSL</socketType></incomingServer>
<incomingServer type="imap"><hostname>mail.gandi.net</hostname><port>143</port><socketType>STARTTLS</socketType>
  <authentication>password-cleartext</authentication><username>%EMAILADDRESS%</username></incomingServer>
<incomingServer type="imap"><hostname>mail.gandi.net</hostname><port>993</port><socketType>SSL</socketType>
  <authentication>password-cleartext</authentication><username>%EMAILADDRESS%</username></incomingServer>
<outgoingServer type="smtp"><hostname>plain.gandi.net</hostname><port>25</port><socketType>plain</socketType></outgoingServer>
<outgoingServer type="smtp"><hostname>oauth.gandi.net</hostname><port>465</port><socketType>SSL</socketType>
  <authentication>OAuth2</authentication></outgoingServer>
<outgoingServer type="smtp"><hostname>local.gandi.net</hostname><port>465</port><socketType>SSL</socketType>
  <username>%EMAILLOCALPART%</username></outgoingServer>
<outgoingServer type="smtp"><hostname>smtp.%EMAILDOMAIN%</hostname><port>465</port><socketType>SSL</socketType></outgoingServer>
</emailProvider></clientConfig>`

func up(addr, mode string) config.Upstream {
	return config.Upstream{Upstream: addr, UpstreamTLS: mode}
}

// TestISPDBThroughMX finds a custom domain's provider from its MX record,
// and skips plaintext, OAuth2-only and local-part servers.
func TestISPDBThroughMX(t *testing.T) {
	f := &fake{
		pages: map[string]string{ISPDB + "gandi.net": ispdbGandi},
		mx:    map[string][]*net.MX{"next.example": {{Host: "spool.mail.gandi.net.", Pref: 10}}},
		up:    map[string]bool{"mail.gandi.net:993": true, "mail.gandi.net:143": true, "smtp.next.example:465": true, "plain.gandi.net:25": true, "oauth.gandi.net:465": true, "local.gandi.net:465": true},
	}
	r, err := f.detector().Lookup("Brody@Next.example")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.IMAP.Upstream, up("mail.gandi.net:993", config.TLSImplicit)) || r.IMAP.From != "ispdb gandi.net" {
		t.Errorf("imap = %+v", r.IMAP)
	}
	if !reflect.DeepEqual(r.SMTP.Upstream, up("smtp.next.example:465", config.TLSImplicit)) {
		t.Errorf("smtp = %+v", r.SMTP)
	}
}

// TestOrder prefers the domain's own sources to the MX provider's, SRV to
// the ISP database, and skips servers that do not accept connections.
func TestOrder(t *testing.T) {
	f := &fake{
		pages: map[string]string{
			ISPDB + "example.com": ispdbGandi,
			"https://autodiscover.example.com/autodiscover/autodiscover.xml": `<Autodiscover><Response><Account><Protocol>
				<Type>IMAP</Type><Server>ad.example.com</Server><Port>993</Port><SSL>on</SSL></Protocol></Account></Response></Autodiscover>`,
		},
		srv: map[string][]*net.SRV{
			"_imaps._tcp.example.com":       {{Target: "down.example.com.", Port: 993}, {Target: "imap.example.com.", Port: 993}},
			"_submission._tcp.example.com":  {{Target: "smtp.example.com.", Port: 587}},
			"_submissions._tcp.example.com": {{Target: ".", Port: 0}},
			"_imaps._tcp.provider.example":  {{Target: "imap.provider.example.", Port: 993}},
		},
		mx: map[string][]*net.MX{"example.com": {{Host: "mx.provider.example."}}},
		up: map[string]bool{"imap.example.com:993": true, "smtp.example.com:587": true, "imap.provider.example:993": true, "ad.example.com:993": true},
	}
	r, err := f.detector().Lookup("alice@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.IMAP.Upstream, up("imap.example.com:993", config.TLSImplicit)) || r.IMAP.From != "srv example.com" {
		t.Errorf("imap = %+v", r.IMAP)
	}
	if !reflect.DeepEqual(r.SMTP.Upstream, up("smtp.example.com:587", config.TLSStartTLS)) {
		t.Errorf("smtp = %+v", r.SMTP)
	}
}

// TestAutodiscover reads Exchange POX answers and refuses plaintext.
func TestAutodiscover(t *testing.T) {
	f := &fake{
		pages: map[string]string{
			"https://ex.example/autodiscover/autodiscover.xml": `<?xml version="1.0"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
<Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a"><Account>
<Protocol><Type>IMAP</Type><Server>plain.ex.example</Server><Port>143</Port><Encryption>None</Encryption></Protocol>
<Protocol><Type>IMAP</Type><Server>mail.ex.example</Server><Port>993</Port><Encryption>SSL</Encryption><LoginName>bob@ex.example</LoginName></Protocol>
<Protocol><Type>SMTP</Type><Server>mail.ex.example</Server><Port>587</Port><Encryption>TLS</Encryption></Protocol>
</Account></Response></Autodiscover>`,
		},
		up: map[string]bool{"plain.ex.example:143": true, "mail.ex.example:993": true, "mail.ex.example:587": true},
	}
	r, err := f.detector().Lookup("bob@ex.example")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.IMAP.Upstream, up("mail.ex.example:993", config.TLSImplicit)) || r.IMAP.From != "autodiscover ex.example" {
		t.Errorf("imap = %+v", r.IMAP)
	}
	if !reflect.DeepEqual(r.SMTP.Upstream, up("mail.ex.example:587", config.TLSStartTLS)) {
		t.Errorf("smtp = %+v", r.SMTP)
	}
}

// TestNotFoundAndCache checks the error, and that a domain is detected once.
func TestNotFoundAndCache(t *testing.T) {
	f := &fake{}
	d := f.detector()
	if _, err := d.Lookup("a@nowhere.example"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	n := f.gets.Load()
	if _, err := d.Lookup("b@nowhere.example"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if f.gets.Load() != n {
		t.Error("second lookup for the domain was not served from the cache")
	}
	for _, a := range []string{"nowhere", "@x.example", "a@", "a@b@c"} {
		if _, err := d.Lookup(a); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("Lookup(%q) err = %v", a, err)
		}
	}
}
