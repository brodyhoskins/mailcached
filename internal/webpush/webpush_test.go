package webpush

import (
	"crypto/ecdh"
	"crypto/rand"
	"path/filepath"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	ua, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	auth := make([]byte, 16)
	rand.Read(auth)
	k, err := ParseKeys(b64.EncodeToString(ua.PublicKey().Bytes())+"", b64.EncodeToString(auth)+"==")
	if err != nil {
		t.Fatal(err)
	}
	msg, err := Encrypt(k, []byte(`{"@type":"StateChange"}`))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decrypt(ua, auth, msg)
	if err != nil || string(got) != `{"@type":"StateChange"}` {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := ParseKeys("bad", b64.EncodeToString(auth)); err == nil {
		t.Fatal("a bad key was taken")
	}
}

// TestRFC8291Example decrypts the example of RFC 8291 section 5.
func TestRFC8291Example(t *testing.T) {
	d := func(s string) []byte {
		b, err := b64.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	priv, err := ecdh.P256().NewPrivateKey(d("q1dXpw3UpT5VOmu_cf_v6ih07Aems3njxI-JWgLcM94"))
	if err != nil {
		t.Fatal(err)
	}
	msg := d("DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN")
	got, err := Decrypt(priv, d("BTBZMqHH6r4Tts7J_aSIgg"), msg)
	if err != nil || string(got) != "When I grow up, I want to be a watermelon" {
		t.Fatalf("%q %v", got, err)
	}
}

func TestVAPID(t *testing.T) {
	file := filepath.Join(t.TempDir(), "vapid.pem")
	v, err := LoadVAPID(file)
	if err != nil {
		t.Fatal(err)
	}
	again, err := LoadVAPID(file)
	if err != nil || again.PublicKey() != v.PublicKey() || len(d64(t, v.PublicKey())) != 65 {
		t.Fatal("the key was not kept")
	}
	h, err := v.Authorization("https://push.example.net/x/y")
	if err != nil || !v.Verify(h) {
		t.Fatalf("%q %v", h, err)
	}
}

func d64(t *testing.T, s string) []byte {
	b, err := b64.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
