package engine

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"net/textproto"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/emersion/go-msgauth/authres"
	"github.com/emersion/go-msgauth/dmarc"
	"golang.org/x/net/publicsuffix"
)

// parseAuthResults strips comments first: authres misreads one after the
// authserv-id as a version.
func parseAuthResults(v string) (string, []authres.Result, error) {
	return authres.Parse(stripComments(v))
}

// stripComments removes RFC 5322 comments outside quoted strings.
func stripComments(v string) string {
	var b strings.Builder
	depth, quoted, escaped := 0, false, false
	for _, r := range v {
		switch {
		case escaped:
			escaped = false
			if depth == 0 {
				b.WriteRune(r)
			}
			continue
		case r == '\\':
			escaped = true
		case quoted:
			if r == '"' {
				quoted = false
			}
		case r == '"' && depth == 0:
			quoted = true
		case r == '(':
			depth++
			continue
		case r == ')' && depth > 0:
			depth--
			continue
		}
		if depth == 0 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isCheck(r authres.Result) bool {
	switch r.(type) {
	case *authres.DMARCResult, *authres.DKIMResult, *authres.SPFResult:
		return true
	}
	return false
}

type headerField struct{ name, value string }

func headerFields(hdr []byte) []headerField {
	var out []headerField
	var value strings.Builder // of the last field, being unfolded
	done := func() {
		if len(out) > 0 {
			out[len(out)-1].value = value.String()
		}
		value.Reset()
	}
	r := bufio.NewReader(bytes.NewReader(hdr))
	for {
		line, err := r.ReadString('\n')
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if (line[0] == ' ' || line[0] == '\t') && len(out) > 0 {
			value.WriteByte(' ')
			value.WriteString(strings.TrimSpace(line))
		} else if name, v, ok := strings.Cut(line, ":"); ok {
			done()
			out = append(out, headerField{name: textproto.CanonicalMIMEHeaderKey(strings.TrimSpace(name))})
			value.WriteString(strings.TrimSpace(v))
		}
		if err != nil {
			break
		}
	}
	done()
	return out
}

type checks struct {
	dmarc      authres.ResultValue
	dkim       authres.ResultValue // pass if any signature passed
	dkimPass   []string            // passing d= domains
	dkimUnsure bool                // temperror, or pass without d=
	spf        authres.ResultValue
	spfPass    string
	checked    bool
}

// providerPart returns the fields above the provider's ingress Received
// (the first one below the topmost Authentication-Results).
func providerPart(fields []headerField) []headerField {
	top := slices.IndexFunc(fields, func(f headerField) bool { return f.name == "Authentication-Results" })
	if top < 0 {
		return nil
	}
	if end := slices.IndexFunc(fields[top:], func(f headerField) bool { return f.name == "Received" }); end >= 0 {
		return fields[:top+end]
	}
	return fields
}

// providerResults collects stamp results from providerPart; the topmost
// result per method wins.
func providerResults(hdr []byte, stamp []string) checks {
	fields := providerPart(headerFields(hdr))
	var c checks
	found := false    // a field with a name in stamp
	var spf []spfVote // the SPF results, in order
	for _, f := range fields {
		if f.name != "Authentication-Results" {
			continue
		}
		got, rs, err := parseAuthResults(f.value)
		if err != nil || !slices.ContainsFunc(stamp, func(id string) bool { return strings.EqualFold(got, id) }) {
			continue
		}
		found = true
		for _, res := range rs {
			switch res := res.(type) {
			case *authres.DMARCResult:
				c.checked = true
				if c.dmarc == "" {
					c.dmarc = res.Value
				}
			case *authres.DKIMResult:
				c.checked = true
				if c.dkim == "" || res.Value == authres.ResultPass {
					c.dkim = res.Value
				}
				c.dkimUnsure = c.dkimUnsure || res.Value == authres.ResultTempError
				// Only header.d names the signing domain.
				if res.Value == authres.ResultPass && res.Domain != "" {
					c.dkimPass = append(c.dkimPass, strings.ToLower(res.Domain))
				} else if res.Value == authres.ResultPass {
					c.dkimUnsure = true
				}
			case *authres.SPFResult:
				c.checked = true
				spf = append(spf, spfVoteOf(res.Value, res.From, res.Helo, ""))
			}
		}
	}
	if !found {
		return c
	}
	for _, f := range fields {
		if f.name != "Received-Spf" {
			continue
		}
		result, from, helo, identity := parseReceivedSPF(f.value)
		c.checked = true
		spf = append(spf, spfVoteOf(authres.ResultValue(result), from, helo, identity))
		break
	}
	// MAIL FROM wins over HELO (RFC 7489 3.1.2).
	if i := slices.IndexFunc(spf, func(v spfVote) bool { return v.mailFrom }); i >= 0 {
		spf = spf[i:]
	}
	if len(spf) > 0 {
		c.spf = spf[0].value
		if c.spf == authres.ResultPass {
			c.spfPass = spf[0].domain
		}
	}
	return c
}

type spfVote struct {
	value    authres.ResultValue
	domain   string // the domain checked
	mailFrom bool
}

// spfVoteOf treats a null MAIL FROM as a HELO check. An absent MAIL FROM
// leaves the domain unknown.
func spfVoteOf(value authres.ResultValue, mailFrom, helo, identity string) spfVote {
	if mailFrom == "" && !strings.EqualFold(identity, "helo") {
		return spfVote{value: value}
	}
	if strings.EqualFold(identity, "helo") || strings.Trim(mailFrom, "<> ") == "" {
		return spfVote{value: value, domain: spfDomain("", helo)}
	}
	return spfVote{value: value, domain: spfDomain(mailFrom, ""), mailFrom: true}
}

func spfDomain(mailFrom, helo string) string {
	d := strings.Trim(mailFrom, "<> ")
	if i := strings.LastIndexByte(d, '@'); i >= 0 {
		d = d[i+1:]
	}
	if d == "" {
		d = helo
	}
	return strings.ToLower(strings.Trim(d, "<> "))
}

// spfParam matches key=value; quoted values may contain \".
var spfParam = regexp.MustCompile(`([A-Za-z][A-Za-z0-9-]*)=("(?:[^"\\]|\\.)*"|[^;\s]+)`)

var unescapeQuoted = strings.NewReplacer(`\"`, `"`, `\\`, `\`)

func parseReceivedSPF(v string) (result, from, helo, identity string) {
	v = stripComments(v)
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return "", "", "", ""
	}
	result = strings.ToLower(strings.TrimRight(fields[0], ";"))
	for _, m := range spfParam.FindAllStringSubmatch(v, -1) {
		val := m[2]
		if len(val) >= 2 && val[0] == '"' {
			val = unescapeQuoted.Replace(val[1 : len(val)-1])
		}
		switch strings.ToLower(m[1]) {
		case "envelope-from":
			from = val
		case "helo":
			helo = val
		case "identity":
			identity = val
		}
	}
	return result, from, helo, identity
}

// --- Working out DMARC -----------------------------------------------------

const dmarcTTL = time.Hour

type dmarcEntry struct {
	rec *dmarc.Record // nil for none
	own bool          // rec is the domain's own, not its organizational domain's
	at  time.Time
}

// dmarcPolicy returns p, or sp for an inherited record; "" if unreadable.
func (b *Engine) dmarcPolicy(ctx context.Context, domain string) string {
	rec, own, err := b.dmarcRecord(ctx, domain)
	if err != nil || rec == nil {
		return ""
	}
	p := rec.Policy
	if !own && rec.SubdomainPolicy != "" {
		p = rec.SubdomainPolicy
	}
	return string(p)
}

// evaluateDMARC works out DMARC from the provider's DKIM and SPF results.
func (b *Engine) evaluateDMARC(ctx context.Context, domain string, c checks) (AuthStatus, string) {
	rec, _, err := b.dmarcRecord(ctx, domain)
	if err != nil {
		return AuthUnknown, "the sender's DMARC record could not be read: " + err.Error()
	}
	if rec == nil {
		return AuthNoPolicy, "worked out: no DMARC record"
	}
	for _, d := range c.dkimPass {
		if alignedMode(d, domain, rec.DKIMAlignment) {
			return AuthPass, "worked out: dmarc=pass by DKIM " + d
		}
	}
	if c.spfPass != "" && alignedMode(c.spfPass, domain, rec.SPFAlignment) {
		return AuthPass, "worked out: dmarc=pass by SPF " + c.spfPass
	}
	switch {
	case c.dkimUnsure || c.spf == authres.ResultTempError:
		return AuthUnknown, "worked out: no DKIM or SPF pass, but a temporary error or a DKIM pass without its domain"
	case c.dkim == "" || c.spf == "" || c.spf == authres.ResultPass && c.spfPass == "":
		return AuthUnknown, "worked out: no DKIM or SPF pass, but DKIM or SPF unreported, or SPF passed for no domain"
	}
	return AuthFail, "worked out: dmarc=fail, no DKIM or SPF pass for the From domain"
}

func alignedMode(d, from string, mode dmarc.AlignmentMode) bool {
	if mode == dmarc.AlignmentStrict {
		return strings.EqualFold(strings.TrimSuffix(d, "."), strings.TrimSuffix(from, "."))
	}
	return aligned(d, from)
}

// dmarcRecord looks up domain's record, falling back to its organizational
// domain; own reports which. Errors are not cached.
func (b *Engine) dmarcRecord(ctx context.Context, domain string) (rec *dmarc.Record, own bool, err error) {
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	b.dmarcMu.Lock()
	if e, ok := b.dmarcRecords[domain]; ok && time.Since(e.at) < dmarcTTL {
		b.dmarcMu.Unlock()
		return e.rec, e.own, nil
	}
	b.dmarcMu.Unlock()
	opts := &dmarc.LookupOptions{LookupTXT: b.lookupTXT(ctx)}
	rec, err = dmarc.LookupWithOptions(domain, opts)
	own = err == nil
	if errors.Is(err, dmarc.ErrNoPolicy) {
		if org, oerr := publicsuffix.EffectiveTLDPlusOne(domain); oerr == nil && org != domain {
			rec, err = dmarc.LookupWithOptions(org, opts)
		}
	}
	if errors.Is(err, dmarc.ErrNoPolicy) {
		rec, err = nil, nil
	}
	if err != nil {
		return nil, false, err
	}
	b.dmarcMu.Lock()
	if b.dmarcRecords == nil || len(b.dmarcRecords) > 10000 {
		b.dmarcRecords = map[string]dmarcEntry{}
	}
	b.dmarcRecords[domain] = dmarcEntry{rec: rec, own: own, at: time.Now()}
	b.dmarcMu.Unlock()
	return rec, own, nil
}

func (b *Engine) lookupTXT(ctx context.Context) func(string) ([]string, error) {
	if b.LookupTXT != nil {
		return func(name string) ([]string, error) { return b.LookupTXT(ctx, name) }
	}
	return func(name string) ([]string, error) { return net.DefaultResolver.LookupTXT(ctx, name) }
}
