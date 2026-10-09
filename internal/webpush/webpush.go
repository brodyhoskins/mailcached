// Package webpush sends Web Push messages as an application server: the
// message encryption of RFC 8291 (aes128gcm, RFC 8188) and the VAPID
// signature of RFC 8292.
package webpush

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

var b64 = base64.RawURLEncoding

// Keys are a subscription's keys: the user agent's P-256 public key, in
// uncompressed form, and its 16-byte authentication secret.
type Keys struct {
	P256DH []byte
	Auth   []byte
}

// ParseKeys reads keys in URL-safe base64, with or without padding.
func ParseKeys(p256dh, auth string) (*Keys, error) {
	dec := func(s string) ([]byte, error) {
		for len(s)%4 != 0 && len(s) > 0 && s[len(s)-1] == '=' {
			s = s[:len(s)-1]
		}
		if b, err := b64.DecodeString(s); err == nil {
			return b, nil
		}
		return base64.URLEncoding.DecodeString(s)
	}
	pub, err := dec(p256dh)
	if err != nil {
		return nil, fmt.Errorf("p256dh: %w", err)
	}
	if _, err := ecdh.P256().NewPublicKey(pub); err != nil {
		return nil, fmt.Errorf("p256dh: %w", err)
	}
	a, err := dec(auth)
	if err != nil {
		return nil, fmt.Errorf("auth: %w", err)
	}
	if len(a) != 16 {
		return nil, errors.New("auth: not 16 bytes")
	}
	return &Keys{P256DH: pub, Auth: a}, nil
}

func hkdf(salt, ikm, info []byte, n int) []byte {
	m := hmac.New(sha256.New, salt)
	m.Write(ikm)
	prk := m.Sum(nil)
	m = hmac.New(sha256.New, prk)
	m.Write(info)
	m.Write([]byte{1})
	return m.Sum(nil)[:n]
}

// Encrypt encrypts a message for the keys: one aes128gcm record, with
// the header the push service needs.
func Encrypt(k *Keys, plaintext []byte) ([]byte, error) {
	ua, err := ecdh.P256().NewPublicKey(k.P256DH)
	if err != nil {
		return nil, err
	}
	as, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	secret, err := as.ECDH(ua)
	if err != nil {
		return nil, err
	}
	asPub := as.PublicKey().Bytes()
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	info := append(append([]byte("WebPush: info\x00"), k.P256DH...), asPub...)
	ikm := hkdf(k.Auth, secret, info, 32)
	cek := hkdf(salt, ikm, []byte("Content-Encoding: aes128gcm\x00"), 16)
	nonce := hkdf(salt, ikm, []byte("Content-Encoding: nonce\x00"), 12)
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	// The last (and only) record ends with the delimiter 2.
	record := gcm.Seal(nil, nonce, append(append([]byte{}, plaintext...), 2), nil)
	out := make([]byte, 0, 16+4+1+len(asPub)+len(record))
	out = append(out, salt...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(record)+1))
	out = append(out, byte(len(asPub)))
	out = append(out, asPub...)
	return append(out, record...), nil
}

// Decrypt is Encrypt's reverse, for the user agent with private key
// priv: for tests.
func Decrypt(priv *ecdh.PrivateKey, auth, msg []byte) ([]byte, error) {
	if len(msg) < 21 {
		return nil, errors.New("short message")
	}
	salt, idlen := msg[:16], int(msg[20])
	if len(msg) < 21+idlen {
		return nil, errors.New("short message")
	}
	asPub, record := msg[21:21+idlen], msg[21+idlen:]
	as, err := ecdh.P256().NewPublicKey(asPub)
	if err != nil {
		return nil, err
	}
	secret, err := priv.ECDH(as)
	if err != nil {
		return nil, err
	}
	info := append(append([]byte("WebPush: info\x00"), priv.PublicKey().Bytes()...), asPub...)
	ikm := hkdf(auth, secret, info, 32)
	block, err := aes.NewCipher(hkdf(salt, ikm, []byte("Content-Encoding: aes128gcm\x00"), 16))
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	pt, err := gcm.Open(nil, hkdf(salt, ikm, []byte("Content-Encoding: nonce\x00"), 12), record, nil)
	if err != nil {
		return nil, err
	}
	if len(pt) == 0 || pt[len(pt)-1] != 2 {
		return nil, errors.New("bad padding delimiter")
	}
	return pt[:len(pt)-1], nil
}

// VAPID is an application server's signing key (RFC 8292).
type VAPID struct {
	key *ecdsa.PrivateKey
	// Subject is the contact for push services: a mailto: or https: URL.
	Subject string
}

// LoadVAPID reads the key in file, or makes one and saves it there. With
// file "", the key lives in memory only.
func LoadVAPID(file string) (*VAPID, error) {
	if file != "" {
		if b, err := os.ReadFile(file); err == nil {
			blk, _ := pem.Decode(b)
			if blk == nil {
				return nil, fmt.Errorf("%s: no PEM block", file)
			}
			k, err := x509.ParseECPrivateKey(blk.Bytes)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", file, err)
			}
			return &VAPID{key: k}, nil
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	if file != "" {
		der, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			return nil, err
		}
		tmp := file + ".tmp"
		if err := os.WriteFile(tmp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, err
		}
		if err := os.Rename(tmp, file); err != nil {
			return nil, err
		}
	}
	return &VAPID{key: k}, nil
}

// PublicKey is the application server key, uncompressed and in URL-safe
// base64, as a JMAP session advertises it (RFC 9749).
func (v *VAPID) PublicKey() string {
	pub, _ := v.key.PublicKey.ECDH()
	return b64.EncodeToString(pub.Bytes())
}

// Authorization is the header value for a push to endpoint.
func (v *VAPID) Authorization(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	sub := v.Subject
	if sub == "" {
		sub = "mailto:postmaster@localhost"
	}
	claims, _ := json.Marshal(map[string]any{"aud": u.Scheme + "://" + u.Host, "exp": time.Now().Add(12 * time.Hour).Unix(), "sub": sub})
	unsigned := b64.EncodeToString([]byte(`{"typ":"JWT","alg":"ES256"}`)) + "." + b64.EncodeToString(claims)
	h := sha256.Sum256([]byte(unsigned))
	r, s, err := ecdsa.Sign(rand.Reader, v.key, h[:])
	if err != nil {
		return "", err
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return "vapid t=" + unsigned + "." + b64.EncodeToString(sig) + ", k=" + v.PublicKey(), nil
}

// Verify checks an Authorization header against the key: for tests.
func (v *VAPID) Verify(header string) bool {
	var t, k string
	if _, err := fmt.Sscanf(header, "vapid t=%s k=%s", &t, &k); err != nil {
		return false
	}
	t = t[:len(t)-1] // the comma
	if k != v.PublicKey() {
		return false
	}
	i := len(t) - 1
	for i >= 0 && t[i] != '.' {
		i--
	}
	if i < 0 {
		return false
	}
	sig, err := b64.DecodeString(t[i+1:])
	if err != nil || len(sig) != 64 {
		return false
	}
	h := sha256.Sum256([]byte(t[:i]))
	return ecdsa.Verify(&v.key.PublicKey, h[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:]))
}
