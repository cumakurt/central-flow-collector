package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
func signJWT(t *testing.T, key *rsa.PrivateKey, kid string, c map[string]any) string {
	h, _ := json.Marshal(map[string]any{"alg": "RS256", "typ": "JWT", "kid": kid})
	p, _ := json.Marshal(c)
	base := b64(h) + "." + b64(p)
	sum := sha256.Sum256([]byte(base))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return base + "." + b64(sig)
}
func TestOIDCFullValidation(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kid := "test-key"
	var srv *httptest.Server
	nonce := ""
	mux := http.NewServeMux()
	srv = httptest.NewServer(mux)
	defer srv.Close()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL, "authorization_endpoint": srv.URL + "/authorize", "token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		e := big.NewInt(int64(key.PublicKey.E)).Bytes()
		json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]any{{"kty": "RSA", "kid": kid, "alg": "RS256", "n": b64(key.PublicKey.N.Bytes()), "e": b64(e)}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		claims := map[string]any{"iss": srv.URL, "aud": "client1", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Second).Unix(), "nonce": nonce, "sub": "sub-1", "preferred_username": "alice", "email": "alice@example.test"}
		json.NewEncoder(w).Encode(map[string]any{"id_token": signJWT(t, key, kid, claims)})
	})
	m, err := New(context.Background(), Config{Issuer: srv.URL, ClientID: "client1", ClientSecret: "secret", RedirectURL: "http://127.0.0.1/callback", DefaultRole: "read_only"})
	if err != nil {
		t.Fatal(err)
	}
	u, err := m.Start()
	if err != nil {
		t.Fatal(err)
	}
	pu, _ := url.Parse(u)
	state := pu.Query().Get("state")
	nonce = pu.Query().Get("nonce")
	if state == "" || nonce == "" {
		t.Fatal("state/nonce missing")
	}
	id, err := m.Callback(context.Background(), state, "code1")
	if err != nil {
		t.Fatal(err)
	}
	if id.Username != "alice" || id.Subject != "sub-1" {
		t.Fatalf("bad identity %#v", id)
	}
	if _, err = m.Callback(context.Background(), state, "replay"); err == nil {
		t.Fatal("replayed state accepted")
	}
}
func TestAudienceHelpers(t *testing.T) {
	if !audContains("a", "a") || !audContains([]any{"x", "a"}, "a") || audContains([]any{"x"}, "a") {
		t.Fatal("aud logic")
	}
	_ = strconv.Itoa
	_ = strings.TrimSpace
}
func TestGroupRoleMapping(t *testing.T) {
	m := &Manager{cfg: Config{DefaultRole: "read_only", GroupRoleMap: "SOC-Analysts=analyst;SOC-Operators=operator"}}
	if r := m.resolveGroups([]string{"SOC-Analysts"}); r != "analyst" {
		t.Fatalf("role=%s", r)
	}
	if r := m.resolveGroups([]string{"SOC-Operators"}); r != "analyst" {
		t.Fatalf("legacy role should normalize to analyst, got %s", r)
	}
}
