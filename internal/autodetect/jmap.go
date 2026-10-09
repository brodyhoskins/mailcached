package autodetect

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/brodyhoskins/mailcached/config"
)

// jmapCandidates are the JMAP session resources to try for dom: those DNS
// SRV records name (RFC 8620 section 2.2), then dom's well-known URL.
func (d *Detector) jmapCandidates(ctx context.Context, dom string) []candidate {
	var cs []candidate
	if srvs, err := d.LookupSRV(ctx, "jmap", "tcp", dom); err == nil {
		for _, s := range srvs {
			if s.Target == "." || s.Target == "" || s.Port == 0 {
				break // "." says the service is not offered
			}
			host := strings.TrimSuffix(s.Target, ".")
			if s.Port != 443 {
				host += ":" + strconv.Itoa(int(s.Port))
			}
			cs = append(cs, candidate{config.Upstream{Upstream: "https://" + host + "/.well-known/jmap"}, "srv " + dom})
		}
	}
	return append(cs, candidate{config.Upstream{Upstream: "https://" + dom + "/.well-known/jmap"}, "well-known " + dom})
}

// pickJMAP returns the first candidate that answers as a JMAP server.
func (d *Detector) pickJMAP(ctx context.Context, cs []candidate) Found {
	tried := map[string]bool{}
	for _, c := range cs {
		if tried[c.u.Upstream] {
			continue
		}
		tried[c.u.Upstream] = true
		if d.UsableJMAP(ctx, c.u.Upstream) {
			return Found{Upstream: c.u, From: c.from}
		}
	}
	return Found{}
}

// usableJMAP reports whether a URL answers as a JMAP session resource,
// without credentials: a 401 that asks for them, or a session with the
// mail capability. hc refuses redirects to anything but HTTPS.
func usableJMAP(hc *http.Client) func(ctx context.Context, u string) bool {
	return func(ctx context.Context, u string) bool {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return false
		}
		req.Header.Set("Accept", "application/json")
		resp, err := hc.Do(req)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return resp.Header.Get("WWW-Authenticate") != ""
		case http.StatusOK:
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			return strings.Contains(resp.Header.Get("Content-Type"), "json") &&
				strings.Contains(string(b), "urn:ietf:params:jmap:mail")
		}
		return false
	}
}
