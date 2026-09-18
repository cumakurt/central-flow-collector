package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"image/png"
	"net/http"
	"strings"
	"testing"
)

func TestAuthenticatorQRAndRetiredLoginRoutes(t *testing.T) {
	f := newV17Fixture(t)
	h := f.srv.Handler()
	r := doBearer(h, "POST", "/api/v1/auth/mfa/totp/begin", f.adminToken, "{}")
	if r.Code != http.StatusOK {
		t.Fatalf("enrollment: %d %s", r.Code, r.Body.String())
	}
	if r.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("enrollment response must not be cached")
	}
	var setup map[string]string
	if err := json.Unmarshal(r.Body.Bytes(), &setup); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(setup["otpauth_uri"], "secret="+setup["secret"]) {
		t.Fatal("enrollment URI mismatch")
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(setup["qr_code"], "data:image/png;base64,"))
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if img.Bounds().Dx() != 256 || img.Bounds().Dy() != 256 {
		t.Fatal("unexpected QR size")
	}
	for _, path := range []string{"/api/v1/auth/webauthn/assert/options", "/api/v1/auth/webauthn/assert/finish", "/api/v1/auth/webauthn/register/options", "/api/v1/auth/webauthn/register/finish", "/api/v1/auth/oidc/start", "/api/v1/auth/oidc/callback", "/api/v1/auth/ldap/login"} {
		for _, method := range []string{"GET", "POST"} {
			if got := doBearer(h, method, path, "", "{}"); got.Code != http.StatusNotFound {
				t.Errorf("%s %s = %d", method, path, got.Code)
			}
		}
	}
}
