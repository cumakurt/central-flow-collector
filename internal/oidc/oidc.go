package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Config struct{ Issuer, ClientID, ClientSecret, RedirectURL, DefaultRole, GroupRoleMap string }
type discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}
type pending struct {
	Nonce    string
	Verifier string
	Expires  time.Time
}
type Identity struct {
	Subject  string   `json:"sub"`
	Username string   `json:"username"`
	Email    string   `json:"email"`
	Groups   []string `json:"groups,omitempty"`
	Role     string   `json:"role,omitempty"`
}
type Manager struct {
	cfg    Config
	disc   discovery
	client *http.Client
	mu     sync.Mutex
	states map[string]pending
	keys   map[string]*rsa.PublicKey
	keysAt time.Time
}

type tokenResponse struct {
	IDToken          string `json:"id_token"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}
type jwks struct {
	Keys []struct {
		Kty string `json:"kty"`
		Kid string `json:"kid"`
		Alg string `json:"alg"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

type claims struct {
	Iss               string   `json:"iss"`
	Aud               any      `json:"aud"`
	AZP               string   `json:"azp"`
	Exp               int64    `json:"exp"`
	Iat               int64    `json:"iat"`
	Nonce             string   `json:"nonce"`
	Sub               string   `json:"sub"`
	Email             string   `json:"email"`
	PreferredUsername string   `json:"preferred_username"`
	Name              string   `json:"name"`
	Groups            []string `json:"groups"`
}

func New(ctx context.Context, cfg Config) (*Manager, error) {
	cfg.Issuer = strings.TrimRight(strings.TrimSpace(cfg.Issuer), "/")
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, errors.New("oidc issuer, client_id and redirect_url are required")
	}
	m := &Manager{cfg: cfg, client: &http.Client{Timeout: 10 * time.Second}, states: map[string]pending{}, keys: map[string]*rsa.PublicKey{}}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.Issuer+"/.well-known/openid-configuration", nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("oidc discovery HTTP %s", resp.Status)
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&m.disc); err != nil {
		return nil, err
	}
	if m.disc.Issuer != cfg.Issuer {
		return nil, fmt.Errorf("oidc issuer mismatch: discovery=%q config=%q", m.disc.Issuer, cfg.Issuer)
	}
	if m.disc.AuthorizationEndpoint == "" || m.disc.TokenEndpoint == "" || m.disc.JWKSURI == "" {
		return nil, errors.New("oidc discovery missing required endpoints")
	}
	if cfg.DefaultRole == "" {
		m.cfg.DefaultRole = "read_only"
	}
	m.cfg.DefaultRole = normalizeRole(m.cfg.DefaultRole)
	return m, nil
}
func random(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func (m *Manager) Start() (string, error) {
	state, err := random(24)
	if err != nil {
		return "", err
	}
	nonce, err := random(24)
	if err != nil {
		return "", err
	}
	verifier, err := random(32)
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	for k, v := range m.states {
		if time.Now().After(v.Expires) {
			delete(m.states, k)
		}
	}
	if len(m.states) >= 4096 {
		m.mu.Unlock()
		return "", errors.New("too many pending OIDC logins")
	}
	m.states[state] = pending{Nonce: nonce, Verifier: verifier, Expires: time.Now().Add(10 * time.Minute)}
	m.mu.Unlock()
	u, err := url.Parse(m.disc.AuthorizationEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", m.cfg.ClientID)
	q.Set("redirect_uri", m.cfg.RedirectURL)
	q.Set("scope", "openid profile email")
	q.Set("state", state)
	q.Set("nonce", nonce)
	challenge := sha256.Sum256([]byte(verifier))
	q.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}
func (m *Manager) Callback(ctx context.Context, state, code string) (Identity, error) {
	m.mu.Lock()
	p, ok := m.states[state]
	delete(m.states, state)
	m.mu.Unlock()
	if !ok || time.Now().After(p.Expires) {
		return Identity{}, errors.New("invalid or expired oidc state")
	}
	if code == "" {
		return Identity{}, errors.New("missing oidc code")
	}
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {m.cfg.RedirectURL}, "client_id": {m.cfg.ClientID}}
	form.Set("code_verifier", p.Verifier)
	if m.cfg.ClientSecret != "" {
		form.Set("client_secret", m.cfg.ClientSecret)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.disc.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return Identity{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := m.client.Do(req)
	if err != nil {
		return Identity{}, fmt.Errorf("oidc token exchange: %w", err)
	}
	defer resp.Body.Close()
	var tr tokenResponse
	if err = json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&tr); err != nil {
		return Identity{}, err
	}
	if resp.StatusCode/100 != 2 || tr.Error != "" {
		return Identity{}, fmt.Errorf("oidc token exchange rejected: %s %s", tr.Error, tr.ErrorDescription)
	}
	if tr.IDToken == "" {
		return Identity{}, errors.New("oidc response missing id_token")
	}
	cl, err := m.verifyIDToken(ctx, tr.IDToken, p.Nonce)
	if err != nil {
		return Identity{}, err
	}
	username := strings.TrimSpace(cl.PreferredUsername)
	if username == "" {
		username = strings.TrimSpace(cl.Email)
	}
	if username == "" {
		username = cl.Sub
	}
	if username == "" {
		return Identity{}, errors.New("oidc identity has no usable subject")
	}
	role := m.resolveGroups(cl.Groups)
	return Identity{Subject: cl.Sub, Username: username, Email: cl.Email, Groups: cl.Groups, Role: role}, nil
}
func (m *Manager) DefaultRole() string { return m.cfg.DefaultRole }
func parseMapping(s string) map[string]string {
	out := map[string]string{}
	for _, x := range strings.Split(s, ";") {
		x = strings.TrimSpace(x)
		i := strings.LastIndex(x, "=")
		if i > 0 && i < len(x)-1 {
			out[strings.ToLower(strings.TrimSpace(x[:i]))] = strings.TrimSpace(x[i+1:])
		}
	}
	return out
}
func normalizeRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "administrator":
		return "administrator"
	case "analyst", "operator", "network_operator", "security_admin":
		return "analyst"
	default:
		return "read_only"
	}
}
func (m *Manager) resolveGroups(groups []string) string {
	role := normalizeRole(m.cfg.DefaultRole)
	ranks := map[string]int{"read_only": 1, "analyst": 2, "administrator": 3}
	rm := parseMapping(m.cfg.GroupRoleMap)
	for _, g := range groups {
		k := strings.ToLower(strings.TrimSpace(g))
		if r := normalizeRole(rm[k]); rm[k] != "" && ranks[r] > ranks[role] {
			role = r
		}
	}
	return role
}
func audContains(a any, want string) bool {
	switch v := a.(type) {
	case string:
		return v == want
	case []any:
		for _, x := range v {
			if s, ok := x.(string); ok && s == want {
				return true
			}
		}
	}
	return false
}
func (m *Manager) verifyIDToken(ctx context.Context, tok, nonce string) (claims, error) {
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return claims{}, errors.New("invalid oidc id_token")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return claims{}, err
	}
	var h struct{ Alg, Kid string }
	if json.Unmarshal(hb, &h) != nil || h.Alg != "RS256" || h.Kid == "" {
		return claims{}, errors.New("only OIDC RS256 tokens with kid are supported")
	}
	key, err := m.key(ctx, h.Kid)
	if err != nil {
		return claims{}, err
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return claims{}, err
	}
	sum := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err = rsa.VerifyPKCS1v15(key, crypto.SHA256, sum[:], sig); err != nil {
		return claims{}, errors.New("oidc id_token signature verification failed")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return claims{}, err
	}
	var c claims
	if err = json.Unmarshal(pb, &c); err != nil {
		return claims{}, err
	}
	now := time.Now().Unix()
	if c.Iss != m.disc.Issuer {
		return claims{}, errors.New("oidc issuer claim mismatch")
	}
	if !audContains(c.Aud, m.cfg.ClientID) {
		return claims{}, errors.New("oidc audience mismatch")
	}
	if c.Sub == "" || (c.AZP != "" && c.AZP != m.cfg.ClientID) {
		return claims{}, errors.New("oidc subject or authorized party is invalid")
	}
	if audiences, ok := c.Aud.([]any); ok && len(audiences) > 1 && c.AZP != m.cfg.ClientID {
		return claims{}, errors.New("oidc multiple audiences require authorized party")
	}
	if c.Exp == 0 || now >= c.Exp {
		return claims{}, errors.New("oidc id_token expired")
	}
	if c.Iat > now+120 {
		return claims{}, errors.New("oidc id_token issued in the future")
	}
	if c.Nonce != nonce {
		return claims{}, errors.New("oidc nonce mismatch")
	}
	return c, nil
}
func (m *Manager) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	m.mu.Lock()
	if k := m.keys[kid]; k != nil && time.Since(m.keysAt) < time.Hour {
		m.mu.Unlock()
		return k, nil
	}
	m.mu.Unlock()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.disc.JWKSURI, nil)
	if err != nil {
		return nil, err
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc jwks: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("oidc jwks HTTP %s", resp.Status)
	}
	var set jwks
	if err = json.NewDecoder(io.LimitReader(resp.Body, 2<<20)).Decode(&set); err != nil {
		return nil, err
	}
	keys := map[string]*rsa.PublicKey{}
	for _, j := range set.Keys {
		if j.Kty != "RSA" || j.Kid == "" || j.N == "" || j.E == "" {
			continue
		}
		nb, e1 := base64.RawURLEncoding.DecodeString(j.N)
		eb, e2 := base64.RawURLEncoding.DecodeString(j.E)
		if e1 != nil || e2 != nil {
			continue
		}
		n := new(big.Int).SetBytes(nb)
		ei := 0
		for _, b := range eb {
			ei = ei<<8 + int(b)
		}
		if ei > 0 {
			keys[j.Kid] = &rsa.PublicKey{N: n, E: ei}
		}
	}
	m.mu.Lock()
	m.keys = keys
	m.keysAt = time.Now()
	k := keys[kid]
	m.mu.Unlock()
	if k == nil {
		return nil, errors.New("oidc signing key not found")
	}
	return k, nil
}
