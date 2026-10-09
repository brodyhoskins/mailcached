// Package certs serves a TLS certificate from files and reloads it when the
// files change, so a renewed certificate is used without a restart.
package certs

import (
	"crypto/tls"
	"fmt"
	"os"
	"sync"
	"time"
)

// Reloader loads CertFile and KeyFile, and loads them again on a handshake
// after either file's modification time changes.
type Reloader struct {
	CertFile, KeyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	modTime time.Time
}

// Load reads the certificate now, so a bad path fails at startup.
func (r *Reloader) Load() error {
	_, err := r.GetCertificate(nil)
	return err
}

func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	mod, err := r.newest()
	if err != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.cert != nil {
			// Mid-renewal: keep serving the old certificate.
			return r.cert, nil
		}
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cert != nil && mod.Equal(r.modTime) {
		return r.cert, nil
	}
	c, err := tls.LoadX509KeyPair(r.CertFile, r.KeyFile)
	if err != nil {
		if r.cert != nil {
			return r.cert, nil
		}
		return nil, fmt.Errorf("tls certificate: %w", err)
	}
	r.cert, r.modTime = &c, mod
	return r.cert, nil
}

func (r *Reloader) newest() (time.Time, error) {
	var t time.Time
	for _, f := range []string{r.CertFile, r.KeyFile} {
		fi, err := os.Stat(f)
		if err != nil {
			return time.Time{}, err
		}
		if fi.ModTime().After(t) {
			t = fi.ModTime()
		}
	}
	return t, nil
}

// Config returns a server TLS configuration that uses r.
func (r *Reloader) Config() *tls.Config {
	return &tls.Config{GetCertificate: r.GetCertificate, MinVersion: tls.VersionTLS12}
}
