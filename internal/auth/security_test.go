package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"
)

func TestPasswordChangeRequiresCurrentPassword(t *testing.T) {
	m, pw, err := New(t.TempDir(), "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.ChangePassword("admin", "", pw); err == nil {
		t.Fatal("empty current password bypassed verification")
	}
	if err := m.ResetPassword("admin", pw); err != nil {
		t.Fatal(err)
	}
}

func TestSessionFollowsCurrentAccount(t *testing.T) {
	m, _, err := New(t.TempDir(), "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.CreateExternalSession("operator", "administrator")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateExternalSession("operator", "read_only"); err != nil {
		t.Fatal(err)
	}
	if current, ok := m.Session(s.ID); !ok || current.Role != "read_only" {
		t.Fatalf("session retained obsolete privileges: %+v %v", current, ok)
	}
	m.mu.Lock()
	u := m.users["operator"]
	u.Disabled = true
	m.users["operator"] = u
	m.mu.Unlock()
	if _, ok := m.Session(s.ID); ok {
		t.Fatal("disabled account still authenticates")
	}
}

func TestExternalIdentityCannotCrossProviders(t *testing.T) {
	m, _, err := New(t.TempDir(), "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateExternalSessionScoped("operator", "administrator", "", "oidc"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateExternalSessionScoped("operator", "read_only", "", "ldap"); err == nil {
		t.Fatal("LDAP identity replaced an OIDC account")
	}
}

func TestPasswordChangePersistenceFailureIsAtomic(t *testing.T) {
	m, pw, err := New(t.TempDir(), "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.Login("admin", pw, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	before := m.users["admin"]
	m.path = filepath.Join(m.path, "unwritable.json")
	if err := m.ResetPassword("admin", pw); err == nil {
		t.Fatal("expected write failure")
	}
	if m.users["admin"].PasswordHash != before.PasswordHash {
		t.Fatal("failed change mutated account")
	}
	if _, ok := m.Session(s.ID); !ok {
		t.Fatal("failed change revoked session")
	}
}

func TestRejectMalformedPasswordHashes(t *testing.T) {
	for _, hash := range []string{"pbkdf2-sha256$10000$$", "pbkdf2-sha256$10000$AA$"} {
		if verify(hash, "any password") {
			t.Fatal("malformed empty hash accepted")
		}
	}
}

func TestCBORRejectsMalformedInput(t *testing.T) {
	for name, input := range map[string][]byte{
		"array map key": {0xa1, 0x80, 0x00},
		"duplicate key": {0xa2, 0x01, 0x02, 0x01, 0x03},
		"deep nesting":  append(bytes.Repeat([]byte{0x81}, 128), 0x00),
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("malformed CBOR panicked: %v", r)
				}
			}()
			d := cborDec{b: input}
			if _, err := d.any(); err == nil {
				t.Fatal("malformed CBOR accepted")
			}
		})
	}
}

func TestPasskeyRequiresUserVerification(t *testing.T) {
	m, _, err := New(t.TempDir(), "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	rp := "localhost"
	rph := sha256.Sum256([]byte(rp))
	ad := append(rph[:], 0x41)
	ad = append(ad, make([]byte, 20)...)
	ad = append(ad, 0, 1, 'x')
	ad = append(ad, cmap(ci(1), ci(2), ci(3), ci(-7), ci(-1), ci(1), ci(-2), cb(make([]byte, 32)), ci(-3), cb(make([]byte, 32)))...)
	o, err := m.BeginWebAuthnRegistration("admin", rp, "https://localhost")
	if err != nil {
		t.Fatal(err)
	}
	att := cmap(ct("fmt"), ct("none"), ct("authData"), cb(ad), ct("attStmt"), cmap())
	err = m.FinishWebAuthnRegistration("admin", WebAuthnRegistrationResponse{ClientDataJSON: encClient("webauthn.create", o.Challenge, "https://localhost"), AttestationObject: base64.RawURLEncoding.EncodeToString(att)})
	if err == nil {
		t.Fatal("unverified invalid passkey accepted")
	}
}

func BenchmarkPasswordDerivation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		pbkdf2([]byte("benchmark-input"), []byte("0123456789abcdef"), 310000, 32)
	}
}
