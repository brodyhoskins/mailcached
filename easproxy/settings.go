package easproxy

// Settings, Provision and Autodiscover.

import (
	"crypto/rand"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
)

func (req *request) settings() (*node, error) {
	if req.doc == nil {
		return el("Settings:Settings", tx("Settings:Status", "2")), nil
	}
	out := []*node{tx("Settings:Status", "1")}
	for _, k := range req.doc.Kids {
		switch {
		case k.Is("DeviceInformation"):
			out = append(out, el("Settings:DeviceInformation", tx("Settings:Status", "1")))
		case k.Is("UserInformation"):
			addr := tx("Settings:SmtpAddress", req.c.login)
			var get *node
			if req.versionAtLeast("14.1") {
				get = el("Settings:Get", el("Settings:Accounts", el("Settings:Account",
					el("Settings:EmailAddresses", tx("Settings:PrimarySmtpAddress", req.c.login), addr))))
			} else {
				get = el("Settings:Get", el("Settings:EmailAddresses", addr))
			}
			out = append(out, el("Settings:UserInformation", tx("Settings:Status", "1"), get))
		case k.Is("Oof"):
			if k.Child("Get") != nil {
				out = append(out, el("Settings:Oof", tx("Settings:Status", "1"),
					el("Settings:Get", tx("Settings:OofState", "0"))))
			} else {
				// Out-of-office replies are the provider's business.
				out = append(out, el("Settings:Oof", tx("Settings:Status", "2")))
			}
		case k.Is("DevicePassword"):
			out = append(out, el("Settings:DevicePassword", tx("Settings:Status", "1")))
		}
	}
	return el("Settings:Settings", out...), nil
}

// policyType is the policy format of ActiveSync 12 and later.
const policyType = "MS-EAS-Provisioning-WBXML"

// policyDoc is a policy that asks nothing of the device.
func policyDoc() *node {
	var kids []*node
	for _, kv := range [][2]string{
		{"DevicePasswordEnabled", "0"}, {"AlphanumericDevicePasswordRequired", "0"},
		{"PasswordRecoveryEnabled", "0"}, {"RequireStorageCardEncryption", "0"}, {"AttachmentsEnabled", "1"},
		{"AllowSimpleDevicePassword", "1"}, {"AllowStorageCard", "1"}, {"AllowCamera", "1"},
		{"RequireDeviceEncryption", "0"}, {"AllowUnsignedApplications", "1"},
		{"AllowUnsignedInstallationPackages", "1"}, {"AllowWiFi", "1"}, {"AllowTextMessaging", "1"},
		{"AllowPOPIMAPEmail", "1"}, {"AllowBluetooth", "2"}, {"AllowIrDA", "1"},
		{"RequireManualSyncWhenRoaming", "0"}, {"AllowDesktopSync", "1"}, {"MaxCalendarAgeFilter", "0"},
		{"AllowHTMLEmail", "1"}, {"MaxEmailAgeFilter", "0"}, {"RequireSignedSMIMEMessages", "0"},
		{"RequireEncryptedSMIMEMessages", "0"}, {"AllowSMIMESoftCerts", "1"}, {"AllowBrowser", "1"},
		{"AllowConsumerEmail", "1"}, {"AllowRemoteDesktop", "1"}, {"AllowInternetSharing", "1"},
	} {
		kids = append(kids, tx("Provision:"+kv[0], kv[1]))
	}
	return el("Provision:EASProvisionDoc", kids...)
}

// newPolicyKey makes a policy key: a number, as devices expect.
func newPolicyKey() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<31-2))
	return fmt.Sprint(n.Int64() + 1)
}

// provision answers Provision. The server asks for nothing, so any device
// is let in; a device that asks gets the policy and a key. A remote wipe
// is never asked for.
func (req *request) provision() (*node, error) {
	if req.doc == nil {
		return el("Provision:Provision", tx("Provision:Status", "2")), nil
	}
	var out []*node
	if di := req.doc.Child("Settings:DeviceInformation"); di != nil {
		out = append(out, el("Settings:DeviceInformation", tx("Settings:Status", "1")))
	}
	out = append(out, tx("Provision:Status", "1"))
	if req.doc.Child("RemoteWipe") != nil {
		out = append(out, el("Provision:RemoteWipe", tx("Provision:Status", "1")))
		return el("Provision:Provision", out...), nil
	}
	pol := req.doc.Child("Policies").Child("Policy")
	if pol == nil {
		return el("Provision:Provision", out...), nil
	}
	typ := pol.Value("PolicyType")
	if typ != policyType {
		out = append(out, el("Provision:Policies", el("Provision:Policy",
			tx("Provision:PolicyType", typ), tx("Provision:Status", "3"))))
		return el("Provision:Provision", out...), nil
	}
	dv := req.dv
	dv.mu.Lock()
	defer dv.mu.Unlock()
	key := newPolicyKey()
	dv.st.PolicyKey = key
	if err := dv.save(); err != nil {
		return nil, err
	}
	p := []*node{tx("Provision:PolicyType", policyType), tx("Provision:Status", "1"), tx("Provision:PolicyKey", key)}
	if pol.Value("PolicyKey") == "" {
		// The first step: the device gets the policy, and acknowledges it
		// with this key for the final one.
		p = append(p, el("Provision:Data", policyDoc()))
	}
	out = append(out, el("Provision:Policies", el("Provision:Policy", p...)))
	return el("Provision:Provision", out...), nil
}

// The Autodiscover request and response (MS-ASCMD 2.2.3.15).
type autodiscoverRequest struct {
	Request struct {
		EMailAddress             string
		AcceptableResponseSchema string
	}
}

const (
	adResponseNS = "http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006"
	adMobileNS   = "http://schemas.microsoft.com/exchange/autodiscover/mobilesync/responseschema/2006"
)

// serveAutodiscover tells a device where the ActiveSync server is: here.
func (s *Server) serveAutodiscover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	c, ok := s.authenticate(w, r)
	if !ok {
		return
	}
	var req autodiscoverRequest
	if r.Method == http.MethodPost {
		_ = xml.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req)
	}
	email := req.Request.EMailAddress
	if email == "" {
		email = c.login
	}
	scheme := "https"
	if s.TLSConfig == nil && r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
		scheme = "http"
	}
	url := scheme + "://" + r.Host + "/Microsoft-Server-ActiveSync"
	esc := func(v string) string {
		var b strings.Builder
		_ = xml.EscapeText(&b, []byte(v))
		return b.String()
	}
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="%s">
  <Response xmlns="%s">
    <Culture>en:us</Culture>
    <User>
      <DisplayName>%s</DisplayName>
      <EMailAddress>%s</EMailAddress>
    </User>
    <Action>
      <Settings>
        <Server>
          <Type>MobileSync</Type>
          <Url>%s</Url>
          <Name>%s</Name>
        </Server>
      </Settings>
    </Action>
  </Response>
</Autodiscover>
`, adResponseNS, adMobileNS, esc(email), esc(email), esc(url), esc(url))
}
