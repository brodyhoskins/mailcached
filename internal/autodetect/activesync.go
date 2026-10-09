package autodetect

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/brodyhoskins/mailcached/config"
)

// activeSyncPath is where ActiveSync servers answer.
const activeSyncPath = "/Microsoft-Server-ActiveSync"

// activeSyncCandidates are the ActiveSync endpoints to try for dom: on
// the IMAP server's host, if one was found, then on mail.<dom>, dom
// itself, and autodiscover.<dom>, where Exchange servers often are.
func activeSyncCandidates(imapHost string, domains []string) []candidate {
	var cs []candidate
	if imapHost != "" {
		cs = append(cs, candidate{config.Upstream{Upstream: "https://" + imapHost + activeSyncPath}, "imap host " + imapHost})
	}
	for _, dom := range domains {
		for _, h := range []string{"mail." + dom, dom, "autodiscover." + dom} {
			cs = append(cs, candidate{config.Upstream{Upstream: "https://" + h + activeSyncPath}, "guess " + dom})
		}
	}
	return cs
}

// pickActiveSync returns the first candidate that answers as an
// ActiveSync server.
func (d *Detector) pickActiveSync(ctx context.Context, cs []candidate) Found {
	tried := map[string]bool{}
	for _, c := range cs {
		if tried[c.u.Upstream] {
			continue
		}
		tried[c.u.Upstream] = true
		if d.UsableActiveSync(ctx, c.u.Upstream) {
			return Found{Upstream: c.u, From: c.from}
		}
	}
	return Found{}
}

// usableActiveSync reports whether a URL answers as an ActiveSync
// endpoint, without credentials: OPTIONS gets a 401 that asks for Basic
// credentials, or the protocol versions. A server that asks for
// credentials at any path (a login wall) is not taken: a made-up path on
// the same host must not get the same 401.
func usableActiveSync(hc *http.Client) func(ctx context.Context, u string) bool {
	probe := func(ctx context.Context, u string) (int, http.Header) {
		req, err := http.NewRequestWithContext(ctx, http.MethodOptions, u, nil)
		if err != nil {
			return 0, nil
		}
		resp, err := hc.Do(req)
		if err != nil {
			return 0, nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		return resp.StatusCode, resp.Header
	}
	return func(ctx context.Context, u string) bool {
		code, h := probe(ctx, u)
		switch {
		case code == http.StatusOK && h.Get("MS-ASProtocolVersions") != "":
			return true
		case code != http.StatusUnauthorized:
			return false
		case h.Get("MS-ASProtocolVersions") != "":
			return true
		case !strings.Contains(strings.ToLower(strings.Join(h.Values("WWW-Authenticate"), " ")), "basic"):
			return false
		}
		var b [8]byte
		_, _ = rand.Read(b[:])
		other := strings.TrimSuffix(u, activeSyncPath) + "/mailcached-probe-" + hex.EncodeToString(b[:])
		code, _ = probe(ctx, other)
		return code != http.StatusUnauthorized && code != 0
	}
}

// hostOf returns the host of host:port.
func hostOf(addr string) string {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return ""
	}
	return h
}
