package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"
)

func TestTOTPRecoveryLogin(t *testing.T) {
	d := t.TempDir()
	m, pw, e := New(d, d+"/boot", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	sec, _, e := m.BeginTOTP("admin")
	if e != nil {
		t.Fatal(e)
	}
	code, _ := totpCode(sec, time.Now())
	recovery, e := m.ConfirmTOTP("admin", code)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.LoginWithMFA("admin", pw, "", "127.0.0.1"); e != ErrMFARequired {
		t.Fatalf("want MFA required got %v", e)
	}
	code, _ = totpCode(sec, time.Now())
	if _, e = m.LoginWithMFA("admin", pw, code, "127.0.0.1"); e != nil {
		t.Fatal(e)
	}
	if _, e = m.LoginWithMFA("admin", pw, recovery[0], "127.0.0.2"); e != nil {
		t.Fatal(e)
	}
	if _, e = m.LoginWithMFA("admin", pw, recovery[0], "127.0.0.3"); e == nil {
		t.Fatal("recovery code reused")
	}
}
func clen(n int) []byte {
	if n < 24 {
		return []byte{byte(n)}
	}
	return []byte{24, byte(n)}
}
func ct(s string) []byte { h := clen(len(s)); h[0] |= 0x60; return append(h, []byte(s)...) }
func cb(b []byte) []byte { h := clen(len(b)); h[0] |= 0x40; return append(h, b...) }
func ci(v int) []byte {
	if v >= 0 {
		h := clen(v)
		return h
	}
	n := -1 - v
	h := clen(n)
	h[0] |= 0x20
	return h
}
func cmap(kv ...[]byte) []byte {
	h := clen(len(kv) / 2)
	h[0] |= 0xa0
	out := h
	for _, x := range kv {
		out = append(out, x...)
	}
	return out
}
func encClient(typ, ch, origin string) string {
	b, _ := json.Marshal(map[string]string{"type": typ, "challenge": ch, "origin": origin})
	return base64.RawURLEncoding.EncodeToString(b)
}
func TestWebAuthnRegisterAndAuthenticate(t *testing.T) {
	d := t.TempDir()
	m, _, e := New(d, d+"/boot", time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	rp, origin := "localhost", "https://localhost"
	o, e := m.BeginWebAuthnRegistration("admin", rp, origin)
	if e != nil {
		t.Fatal(e)
	}
	priv, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	x := priv.X.FillBytes(make([]byte, 32))
	y := priv.Y.FillBytes(make([]byte, 32))
	cose := cmap(ci(1), ci(2), ci(3), ci(-7), ci(-1), ci(1), ci(-2), cb(x), ci(-3), cb(y))
	rph := sha256.Sum256([]byte(rp))
	cred := []byte("credential-123")
	ad := append([]byte{}, rph[:]...)
	ad = append(ad, 0x45)
	cnt := make([]byte, 4)
	ad = append(ad, cnt...)
	ad = append(ad, make([]byte, 16)...)
	ln := make([]byte, 2)
	binary.BigEndian.PutUint16(ln, uint16(len(cred)))
	ad = append(ad, ln...)
	ad = append(ad, cred...)
	ad = append(ad, cose...)
	att := cmap(ct("fmt"), ct("none"), ct("authData"), cb(ad), ct("attStmt"), cmap())
	reg := WebAuthnRegistrationResponse{ClientDataJSON: encClient("webauthn.create", o.Challenge, origin), AttestationObject: base64.RawURLEncoding.EncodeToString(att), Name: "Laptop"}
	if e = m.FinishWebAuthnRegistration("admin", reg); e != nil {
		t.Fatal(e)
	}
	ao, e := m.BeginWebAuthnAssertion("admin", rp, origin)
	if e != nil {
		t.Fatal(e)
	}
	client := encClient("webauthn.get", ao.Challenge, origin)
	cdb, _ := base64.RawURLEncoding.DecodeString(client)
	ad2 := append([]byte{}, rph[:]...)
	ad2 = append(ad2, 0x05)
	count := make([]byte, 4)
	binary.BigEndian.PutUint32(count, 1)
	ad2 = append(ad2, count...)
	hc := sha256.Sum256(cdb)
	signed := append(append([]byte{}, ad2...), hc[:]...)
	h := sha256.Sum256(signed)
	sig, e := ecdsa.SignASN1(rand.Reader, priv, h[:])
	if e != nil {
		t.Fatal(e)
	}
	a := WebAuthnAssertionResponse{CredentialID: base64.RawURLEncoding.EncodeToString(cred), ClientDataJSON: client, AuthenticatorData: base64.RawURLEncoding.EncodeToString(ad2), Signature: base64.RawURLEncoding.EncodeToString(sig)}
	s, e := m.FinishWebAuthnAssertion("admin", a)
	if e != nil {
		t.Fatal(e)
	}
	if s.AuthType != "passkey" {
		t.Fatalf("%+v", s)
	}
}

func TestInvalidMFAAttemptIsThrottled(t *testing.T) {
	d := t.TempDir()
	m, pw, err := New(d, filepath.Join(d, "boot"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	secret, _, err := m.BeginTOTP("admin")
	if err != nil {
		t.Fatal(err)
	}
	code, err := totpCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.ConfirmTOTP("admin", code); err != nil {
		t.Fatal(err)
	}
	remote := "192.0.2.55"
	if _, err = m.LoginWithMFA("admin", pw, "000000", remote); err == nil || err.Error() != "invalid MFA code" {
		t.Fatalf("expected invalid MFA code, got %v", err)
	}
	key := remote + "|admin"
	m.mu.Lock()
	failure := m.failures[key]
	m.mu.Unlock()
	if failure.Count != 1 || !failure.Until.After(time.Now()) {
		t.Fatalf("MFA failure was not throttled: %+v", failure)
	}
	if _, err = m.LoginWithMFA("admin", pw, "000000", remote); err == nil || err.Error() != "login temporarily throttled" {
		t.Fatalf("expected throttle after invalid MFA attempt, got %v", err)
	}
}
