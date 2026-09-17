package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type PasskeyCredential struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	PublicKeyX string    `json:"public_key_x"`
	PublicKeyY string    `json:"public_key_y"`
	SignCount  uint32    `json:"sign_count"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsed   time.Time `json:"last_used,omitempty"`
}

type User struct {
	Username       string              `json:"username"`
	PasswordHash   string              `json:"password_hash"`
	Role           string              `json:"role"`
	Tenant         string              `json:"-"`
	MustChange     bool                `json:"must_change"`
	Disabled       bool                `json:"disabled"`
	AuthSource     string              `json:"auth_source,omitempty"`
	MFAEnabled     bool                `json:"mfa_enabled,omitempty"`
	TOTPSecret     string              `json:"totp_secret,omitempty"`
	RecoveryHashes []string            `json:"recovery_hashes,omitempty"`
	Passkeys       []PasskeyCredential `json:"passkeys,omitempty"`
}
type Session struct {
	ID, Username, Role, Tenant, CSRF string
	Expires                          time.Time
	AuthType                         string
	Scopes                           []string
	TokenID                          string
}

type APIToken struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Owner        string    `json:"owner"`
	Role         string    `json:"role"`
	Tenant       string    `json:"-"`
	Hash         string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastUsed     time.Time `json:"last_used,omitempty"`
	Scopes       []string  `json:"scopes,omitempty"`
	AllowedCIDRs []string  `json:"allowed_cidrs,omitempty"`
}

type apiTokenDisk struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	Owner        string    `json:"owner"`
	Role         string    `json:"role"`
	Tenant       string    `json:"tenant,omitempty"`
	Hash         string    `json:"hash"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	LastUsed     time.Time `json:"last_used,omitempty"`
	Scopes       []string  `json:"scopes,omitempty"`
	AllowedCIDRs []string  `json:"allowed_cidrs,omitempty"`
}
type failure struct {
	Count int
	Until time.Time
}
type Manager struct {
	mu                         sync.RWMutex
	users                      map[string]User
	sessions                   map[string]Session
	failures                   map[string]failure
	path, bootstrap, tokenPath string
	tokens                     map[string]apiTokenDisk
	tokenByHash                map[string]string
	ttl                        time.Duration
	pendingTOTP                map[string]string
	webauthnReg                map[string]webauthnChallenge
	webauthnAuth               map[string]webauthnChallenge
}

func New(dataDir, bootstrap string, ttl time.Duration) (*Manager, string, error) {
	m := &Manager{users: map[string]User{}, sessions: map[string]Session{}, failures: map[string]failure{}, tokens: map[string]apiTokenDisk{}, tokenByHash: map[string]string{}, pendingTOTP: map[string]string{}, webauthnReg: map[string]webauthnChallenge{}, webauthnAuth: map[string]webauthnChallenge{}, path: filepath.Join(dataDir, "users.json"), tokenPath: filepath.Join(dataDir, "api-tokens.json"), bootstrap: bootstrap, ttl: ttl}
	if ttl <= 0 {
		m.ttl = 8 * time.Hour
	}
	if b, e := os.ReadFile(m.path); e == nil {
		var us []User
		if e = json.Unmarshal(b, &us); e != nil {
			return nil, "", e
		}
		for _, u := range us {
			if u.AuthSource == "" {
				if u.PasswordHash != "" {
					u.AuthSource = "local"
				} else {
					u.AuthSource = "oidc"
				}
			}
			u.Role = normalizeRole(u.Role)
			if u.Role == "" {
				u.Role = "read_only"
			}
			// v4 is single-organization. Retain the legacy field only so old
			// files can be read, then erase the obsolete security boundary.
			u.Tenant = ""
			m.users[u.Username] = u
		}
	} else if !os.IsNotExist(e) {
		return nil, "", e
	}
	if b, e := os.ReadFile(m.tokenPath); e == nil {
		var ts []apiTokenDisk
		if e = json.Unmarshal(b, &ts); e != nil {
			return nil, "", e
		}
		for _, t := range ts {
			t.Tenant = ""
			t.Role = normalizeRole(t.Role)
			m.tokens[t.ID] = t
			if t.Hash != "" {
				m.tokenByHash[t.Hash] = t.ID
			}
		}
	} else if !os.IsNotExist(e) {
		return nil, "", e
	}
	if len(m.users) == 0 {
		pw, err := randomPassword(24)
		if err != nil {
			return nil, "", err
		}
		h, err := HashPassword(pw)
		if err != nil {
			return nil, "", err
		}
		m.users["admin"] = User{Username: "admin", PasswordHash: h, Role: "administrator", MustChange: true, AuthSource: "local"}
		if err = m.saveLocked(); err != nil {
			return nil, "", err
		}
		if bootstrap != "" {
			if err = os.MkdirAll(filepath.Dir(bootstrap), 0750); err == nil {
				_ = os.WriteFile(bootstrap, []byte("username: admin\npassword: "+pw+"\nIMPORTANT: change this password immediately after first login.\n"), 0600)
			}
		}
		return m, pw, nil
	}
	return m, "", nil
}

func HashPassword(pw string) (string, error) {
	if err := ValidatePassword(pw); err != nil {
		return "", err
	}
	salt := make([]byte, 16)
	if _, e := rand.Read(salt); e != nil {
		return "", e
	}
	const iter = 310000
	dk := pbkdf2([]byte(pw), salt, iter, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", iter, base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(dk)), nil
}
func verify(stored, pw string) bool {
	p := strings.Split(stored, "$")
	if len(p) != 4 || p[0] != "pbkdf2-sha256" {
		return false
	}
	var iter int
	if _, e := fmt.Sscanf(p[1], "%d", &iter); e != nil || iter < 10000 {
		return false
	}
	salt, e1 := base64.RawStdEncoding.DecodeString(p[2])
	want, e2 := base64.RawStdEncoding.DecodeString(p[3])
	if e1 != nil || e2 != nil {
		return false
	}
	got := pbkdf2([]byte(pw), salt, iter, len(want))
	return hmac.Equal(got, want)
}
func pbkdf2(password, salt []byte, iter, keyLen int) []byte {
	hLen := 32
	blocks := (keyLen + hLen - 1) / hLen
	out := make([]byte, 0, blocks*hLen)
	for i := 1; i <= blocks; i++ {
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		var ib [4]byte
		binary.BigEndian.PutUint32(ib[:], uint32(i))
		_, _ = mac.Write(ib[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for j := 1; j < iter; j++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for k := range t {
				t[k] ^= u[k]
			}
		}
		out = append(out, t...)
	}
	return out[:keyLen]
}
func ValidatePassword(p string) error {
	if len(p) < 12 {
		return errors.New("password must be at least 12 characters")
	}
	var lo, up, num, sym bool
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z':
			lo = true
		case r >= 'A' && r <= 'Z':
			up = true
		case r >= '0' && r <= '9':
			num = true
		default:
			sym = true
		}
	}
	if !(lo && up && num && sym) {
		return errors.New("password must include upper, lower, number and symbol")
	}
	return nil
}
func (m *Manager) Login(username, pw, remote string) (Session, error) {
	key := remote + "|" + strings.ToLower(username)
	now := time.Now()

	// PBKDF2 is intentionally expensive. Do not hold the manager-wide mutex while
	// deriving the password key, otherwise one login attempt serializes unrelated
	// session/token operations and creates an avoidable authentication DoS vector.
	m.mu.Lock()
	if f := m.failures[key]; now.Before(f.Until) {
		m.mu.Unlock()
		return Session{}, errors.New("login temporarily throttled")
	}
	u, ok := m.users[username]
	storedHash := u.PasswordHash
	disabled := u.Disabled
	m.mu.Unlock()

	valid := ok && !disabled && verify(storedHash, pw)

	m.mu.Lock()
	defer m.mu.Unlock()
	// Re-read the account after the expensive check so a concurrent password
	// reset, disable, role change, or tenant change takes effect immediately.
	current, stillExists := m.users[username]
	if !valid || !stillExists || current.Disabled || current.PasswordHash != storedHash {
		f := m.failures[key]
		f.Count++
		delay := time.Duration(f.Count*f.Count) * time.Second
		if delay > 60*time.Second {
			delay = 60 * time.Second
		}
		f.Until = time.Now().Add(delay)
		m.failures[key] = f
		return Session{}, errors.New("invalid credentials")
	}
	delete(m.failures, key)
	sid, err := token(32)
	if err != nil {
		return Session{}, err
	}
	csrf, err := token(24)
	if err != nil {
		return Session{}, err
	}
	s := Session{ID: sid, Username: current.Username, Role: normalizeRole(current.Role), CSRF: csrf, Expires: time.Now().Add(m.ttl), AuthType: "session"}
	m.sessions[sid] = s
	return s, nil
}
func (m *Manager) Session(id string) (Session, bool) {
	m.mu.RLock()
	s, ok := m.sessions[id]
	m.mu.RUnlock()
	if !ok || time.Now().After(s.Expires) {
		if ok {
			m.mu.Lock()
			delete(m.sessions, id)
			m.mu.Unlock()
		}
		return Session{}, false
	}
	return s, true
}
func (m *Manager) Logout(id string) { m.mu.Lock(); delete(m.sessions, id); m.mu.Unlock() }
func (m *Manager) ChangePassword(username, old, new string) error {
	if e := ValidatePassword(new); e != nil {
		return e
	}

	// PBKDF2 verification and derivation are deliberately expensive. Keep them
	// outside the manager-wide mutex, then verify that the account password did
	// not change concurrently before committing the new hash.
	m.mu.RLock()
	u, ok := m.users[username]
	storedHash := u.PasswordHash
	m.mu.RUnlock()
	if !ok {
		return errors.New("user not found")
	}
	if old != "" && !verify(storedHash, old) {
		return errors.New("current password incorrect")
	}
	h, e := HashPassword(new)
	if e != nil {
		return e
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok = m.users[username]
	if !ok {
		return errors.New("user not found")
	}
	if u.PasswordHash != storedHash {
		return errors.New("password changed concurrently; retry")
	}
	u.PasswordHash = h
	u.MustChange = false
	m.users[username] = u
	for id, s := range m.sessions {
		if s.Username == username {
			delete(m.sessions, id)
		}
	}
	if e = m.saveLocked(); e != nil {
		return e
	}
	if m.bootstrap != "" {
		_ = os.Remove(m.bootstrap)
	}
	return nil
}
func (m *Manager) ResetPassword(username, new string) error {
	return m.ChangePassword(username, "", new)
}
func (m *Manager) Users() []User {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]User, 0, len(m.users))
	for _, u := range m.users {
		u.PasswordHash = ""
		u.TOTPSecret = ""
		u.RecoveryHashes = nil
		out = append(out, u)
	}
	return out
}

// normalizeRole migrates pre-v4 role names into the deliberately small
// single-organization RBAC model.
func normalizeRole(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "administrator":
		return "administrator"
	case "analyst", "security_admin", "network_operator", "operator":
		return "analyst"
	case "read_only", "viewer", "":
		return "read_only"
	}
	return ""
}

func (m *Manager) AddUser(username, password, role string) error {
	return m.AddUserTenant(username, password, role, "")
}

// AddUserTenant is retained as an upgrade/API compatibility shim. v4 ignores
// tenant because a deployment represents exactly one organization.
func (m *Manager) AddUserTenant(username, password, role, _ string) error {
	username = strings.TrimSpace(username)
	role = normalizeRole(role)
	if username == "" {
		return errors.New("username required")
	}
	if !validRole(role) {
		return errors.New("invalid role")
	}
	h, e := HashPassword(password)
	if e != nil {
		return e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[username]; ok {
		return errors.New("user exists")
	}
	m.users[username] = User{Username: username, PasswordHash: h, Role: role, MustChange: true, AuthSource: "local"}
	return m.saveLocked()
}
func (m *Manager) User(username string) (User, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[username]
	u.PasswordHash = ""
	u.TOTPSecret = ""
	u.RecoveryHashes = nil
	return u, ok
}
func (m *Manager) saveLocked() error {
	if e := os.MkdirAll(filepath.Dir(m.path), 0750); e != nil {
		return e
	}
	us := make([]User, 0, len(m.users))
	for _, u := range m.users {
		us = append(us, u)
	}
	b, _ := json.MarshalIndent(us, "", "  ")
	tmp := m.path + ".tmp"
	if e := os.WriteFile(tmp, b, 0600); e != nil {
		return e
	}
	return os.Rename(tmp, m.path)
}
func token(n int) (string, error) {
	b := make([]byte, n)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func randomPassword(n int) (string, error) {
	const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-+"
	b := make([]byte, n)
	r := make([]byte, n)
	if _, e := rand.Read(r); e != nil {
		return "", e
	}
	for i := range b {
		b[i] = chars[int(r[i])%len(chars)]
	}
	b[0] = 'A'
	b[1] = 'a'
	b[2] = '7'
	b[3] = '!'
	return string(b), nil
}
func rolePermissions(role string) map[string]bool {
	all := func(xs ...string) map[string]bool {
		m := map[string]bool{}
		for _, x := range xs {
			m[x] = true
		}
		return m
	}
	switch normalizeRole(role) {
	case "administrator":
		return map[string]bool{"*": true}
	case "analyst":
		return all("view", "flows.read", "flows.export", "analytics.read", "analytics.manage", "topology.read", "collectors.read", "storage.read", "reports.read", "reports.manage")
	case "read_only":
		return all("view", "flows.read", "analytics.read", "topology.read", "collectors.read", "storage.read", "reports.read")
	}
	return map[string]bool{}
}

var legacyPermissionAliases = map[string][]string{
	"view":     {"flows.read", "analytics.read", "topology.read", "collectors.read", "storage.read", "reports.read"},
	"settings": {"system.manage"}, "users": {"users.manage"}, "audit": {"audit.read"}, "listeners": {"collectors.manage"},
}

func HasPermission(role, perm string) bool {
	p := rolePermissions(role)
	if p["*"] || p[perm] {
		return true
	}
	for legacy, modern := range legacyPermissionAliases {
		if perm == legacy {
			for _, x := range modern {
				if p[x] {
					return true
				}
			}
		}
	}
	return false
}

func Permissions(role string) []string {
	p := rolePermissions(role)
	if p["*"] {
		return []string{"*"}
	}
	out := make([]string, 0, len(p))
	for x := range p {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

func ScopeAllows(scopes []string, perm string) bool {
	if len(scopes) == 0 {
		return true
	}
	for _, s := range scopes {
		if s == "*" || s == perm {
			return true
		}
	}
	return false
}

func validScope(scope string) bool {
	if scope == "*" {
		return true
	}
	known := map[string]bool{}
	for _, r := range []string{"analyst", "read_only"} {
		for _, p := range Permissions(r) {
			known[p] = true
		}
	}
	for p := range legacyPermissionAliases {
		known[p] = true
	}
	for _, p := range []string{"system.manage", "storage.manage", "cluster.manage", "cluster.read", "tokens.manage", "users.manage", "audit.read", "diagnostics.read", "enrichment.manage", "reports.manage", "analytics.manage", "collectors.manage", "policies.manage"} {
		known[p] = true
	}
	return known[scope]
}

func hashAPIToken(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

func validRole(role string) bool {
	switch normalizeRole(role) {
	case "administrator", "analyst", "read_only":
		return true
	}
	return false
}

func (m *Manager) CreateAPIToken(owner, name string, days int) (APIToken, string, error) {
	return m.CreateAPITokenAdvanced(owner, name, days, nil, nil)
}

func (m *Manager) CreateAPITokenAdvanced(owner, name string, days int, scopes, allowedCIDRs []string) (APIToken, string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return APIToken{}, "", errors.New("token name is required")
	}
	if days < 1 || days > 365 {
		return APIToken{}, "", errors.New("token expiry must be 1..365 days")
	}
	cleanScopes := make([]string, 0, len(scopes))
	seen := map[string]bool{}
	for _, scope := range scopes {
		scope = strings.TrimSpace(scope)
		if scope == "" || seen[scope] {
			continue
		}
		if !validScope(scope) {
			return APIToken{}, "", fmt.Errorf("invalid token scope %q", scope)
		}
		seen[scope] = true
		cleanScopes = append(cleanScopes, scope)
	}
	cleanCIDRs := make([]string, 0, len(allowedCIDRs))
	for _, cidr := range allowedCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		if net.ParseIP(cidr) != nil {
			if strings.Contains(cidr, ":") {
				cidr += "/128"
			} else {
				cidr += "/32"
			}
		}
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			return APIToken{}, "", fmt.Errorf("invalid allowed CIDR %q", cidr)
		}
		cleanCIDRs = append(cleanCIDRs, cidr)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[owner]
	if !ok || u.Disabled {
		return APIToken{}, "", errors.New("user not found or disabled")
	}
	for _, scope := range cleanScopes {
		if scope != "*" && !HasPermission(u.Role, scope) {
			return APIToken{}, "", fmt.Errorf("scope %q exceeds owner permissions", scope)
		}
	}
	id, err := token(9)
	if err != nil {
		return APIToken{}, "", err
	}
	rnd, err := token(32)
	if err != nil {
		return APIToken{}, "", err
	}
	secret := "fc_" + id + "_" + rnd
	now := time.Now().UTC()
	t := apiTokenDisk{ID: id, Name: name, Owner: owner, Role: normalizeRole(u.Role), Hash: hashAPIToken(secret), CreatedAt: now, ExpiresAt: now.Add(time.Duration(days) * 24 * time.Hour), Scopes: cleanScopes, AllowedCIDRs: cleanCIDRs}
	m.tokens[id] = t
	m.tokenByHash[t.Hash] = id
	if err := m.saveTokensLocked(); err != nil {
		delete(m.tokens, id)
		delete(m.tokenByHash, t.Hash)
		return APIToken{}, "", err
	}
	return tokenView(t), secret, nil
}

func tokenView(t apiTokenDisk) APIToken {
	return APIToken{ID: t.ID, Name: t.Name, Owner: t.Owner, Role: normalizeRole(t.Role), CreatedAt: t.CreatedAt, ExpiresAt: t.ExpiresAt, LastUsed: t.LastUsed, Scopes: append([]string(nil), t.Scopes...), AllowedCIDRs: append([]string(nil), t.AllowedCIDRs...)}
}

func (m *Manager) APITokens(owner string) []APIToken {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]APIToken, 0)
	for _, t := range m.tokens {
		if t.Owner == owner {
			out = append(out, tokenView(t))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}

func (m *Manager) RevokeAPIToken(owner, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[id]
	if !ok || t.Owner != owner {
		return errors.New("api token not found")
	}
	delete(m.tokens, id)
	delete(m.tokenByHash, t.Hash)
	return m.saveTokensLocked()
}

func (m *Manager) AuthenticateBearer(secret string) (Session, bool) {
	return m.AuthenticateBearerFrom(secret, "")
}

func (m *Manager) AuthenticateBearerFrom(secret, remote string) (Session, bool) {
	secret = strings.TrimSpace(secret)
	if secret == "" {
		return Session{}, false
	}
	h := hashAPIToken(secret)
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()

	// Hash-indexed lookup keeps bearer authentication O(1). Previous versions
	// scanned every token and rewrote api-tokens.json on every authenticated API
	// request, turning token count and request rate directly into latency/disk I/O.
	id, ok := m.tokenByHash[h]
	if !ok {
		return Session{}, false
	}
	t, ok := m.tokens[id]
	if !ok || !hmac.Equal([]byte(t.Hash), []byte(h)) {
		return Session{}, false
	}
	if !t.ExpiresAt.IsZero() && now.After(t.ExpiresAt) {
		return Session{}, false
	}
	if len(t.AllowedCIDRs) > 0 {
		ip := net.ParseIP(strings.TrimSpace(remote))
		if ip == nil {
			return Session{}, false
		}
		allowed := false
		for _, cidr := range t.AllowedCIDRs {
			_, n, e := net.ParseCIDR(cidr)
			if e == nil && n.Contains(ip) {
				allowed = true
				break
			}
		}
		if !allowed {
			return Session{}, false
		}
	}
	u, ok := m.users[t.Owner]
	if !ok || u.Disabled || !validRole(u.Role) {
		return Session{}, false
	}
	// Role/tenant follow the user's current account state immediately. Last-used
	// remains accurate in memory without forcing a synchronous fsync-style write
	// into the hot request path. It is persisted by later token mutations.
	t.Role = normalizeRole(u.Role)
	t.Tenant = ""
	t.LastUsed = now
	m.tokens[id] = t
	return Session{ID: "api:" + id, Username: t.Owner, Role: normalizeRole(u.Role), Expires: t.ExpiresAt, AuthType: "api_token", Scopes: append([]string(nil), t.Scopes...), TokenID: id}, true
}

func (m *Manager) CreateExternalSession(username, role string) (Session, error) {
	return m.CreateExternalSessionScoped(username, role, "", "oidc")
}
func (m *Manager) CreateExternalSessionScoped(username, role, _tenant, source string) (Session, error) {
	username = strings.TrimSpace(username)
	role = normalizeRole(role)
	source = strings.TrimSpace(source)
	if username == "" {
		return Session{}, errors.New("external username is required")
	}
	if !validRole(role) {
		role = "read_only"
	}
	if source == "" {
		source = "external"
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[username]
	if ok && u.AuthSource == "local" {
		return Session{}, errors.New("external identity conflicts with a local account")
	}
	if !ok {
		u = User{Username: username, Role: role, MustChange: false, AuthSource: source}
	} else {
		u.Role = role
		u.Tenant = ""
		u.AuthSource = source
	}
	if u.Disabled {
		return Session{}, errors.New("user disabled")
	}
	u.Tenant = ""
	m.users[username] = u
	if err := m.saveLocked(); err != nil {
		return Session{}, err
	}
	return m.newSessionLocked(u, source)
}

func (m *Manager) saveTokensLocked() error {
	if err := os.MkdirAll(filepath.Dir(m.tokenPath), 0750); err != nil {
		return err
	}
	ts := make([]apiTokenDisk, 0, len(m.tokens))
	for _, t := range m.tokens {
		ts = append(ts, t)
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].CreatedAt.Before(ts[j].CreatedAt) })
	b, err := json.MarshalIndent(ts, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.tokenPath + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, m.tokenPath)
}

// CleanupExpiredSessions removes expired in-memory sessions and returns the
// number removed. It is safe to run from the maintenance control plane.
func (m *Manager) CleanupExpiredSessions(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, s := range m.sessions {
		if !s.Expires.After(now) {
			delete(m.sessions, id)
			n++
		}
	}
	return n
}
