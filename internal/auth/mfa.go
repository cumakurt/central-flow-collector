package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

var ErrMFARequired = errors.New("multi-factor authentication required")

type MFAStatus struct {
	TOTPEnabled   bool `json:"totp_enabled"`
	RecoveryCodes int  `json:"recovery_codes"`
}

type webauthnChallenge struct {
	Challenge string
	Username  string
	RPID      string
	Origin    string
	Expires   time.Time
}

type WebAuthnCredentialCreation struct {
	Challenge        string `json:"challenge"`
	RPID             string `json:"rp_id"`
	RPName           string `json:"rp_name"`
	UserID           string `json:"user_id"`
	Username         string `json:"username"`
	UserVerification string `json:"user_verification"`
}

type WebAuthnAssertionOptions struct {
	Challenge        string   `json:"challenge"`
	RPID             string   `json:"rp_id"`
	CredentialIDs    []string `json:"credential_ids"`
	UserVerification string   `json:"user_verification"`
}

type WebAuthnRegistrationResponse struct {
	ClientDataJSON    string `json:"client_data_json"`
	AttestationObject string `json:"attestation_object"`
	Name              string `json:"name"`
}

type WebAuthnAssertionResponse struct {
	CredentialID      string `json:"credential_id"`
	ClientDataJSON    string `json:"client_data_json"`
	AuthenticatorData string `json:"authenticator_data"`
	Signature         string `json:"signature"`
}

func recoveryHash(code string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(code)))
	return hex.EncodeToString(h[:])
}

func (m *Manager) MFAStatus(username string) MFAStatus {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u := m.users[username]
	return MFAStatus{TOTPEnabled: u.MFAEnabled, RecoveryCodes: len(u.RecoveryHashes)}
}

func (m *Manager) BeginTOTP(username string) (string, string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	m.mu.Lock()
	u, ok := m.users[username]
	if !ok {
		m.mu.Unlock()
		return "", "", errors.New("user not found")
	}
	if u.MFAEnabled {
		m.mu.Unlock()
		return "", "", errors.New("disable existing TOTP before enrolling a replacement")
	}
	m.pendingTOTP[username] = secret
	m.mu.Unlock()
	label := url.QueryEscape("Central Flow Collector:" + username)
	uri := fmt.Sprintf("otpauth://totp/%s?secret=%s&issuer=Central%%20Flow%%20Collector&algorithm=SHA1&digits=6&period=30", label, secret)
	return secret, uri, nil
}

func totpCode(secret string, when time.Time) (string, error) {
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	counter := uint64(when.Unix() / 30)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], counter)
	mac := hmac.New(sha1.New, raw)
	_, _ = mac.Write(b[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	n := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", n%1000000), nil
}

func verifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(code)
	if len(code) != 6 {
		return false
	}
	for d := -1; d <= 1; d++ {
		c, err := totpCode(secret, now.Add(time.Duration(d)*30*time.Second))
		if err == nil && hmac.Equal([]byte(c), []byte(code)) {
			return true
		}
	}
	return false
}

func (m *Manager) ConfirmTOTP(username, code string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	secret := m.pendingTOTP[username]
	if secret == "" || !verifyTOTP(secret, code, time.Now()) {
		return nil, errors.New("invalid TOTP code")
	}
	u, ok := m.users[username]
	if !ok {
		return nil, errors.New("user not found")
	}
	if u.MFAEnabled {
		return nil, errors.New("TOTP is already enabled")
	}
	previous := u
	codes := make([]string, 10)
	hashes := make([]string, 10)
	for i := range codes {
		x, err := token(9)
		if err != nil {
			return nil, err
		}
		codes[i] = strings.ToUpper(x[:12])
		hashes[i] = recoveryHash(codes[i])
	}
	u.TOTPSecret = secret
	u.MFAEnabled = true
	u.RecoveryHashes = hashes
	m.users[username] = u
	if err := m.saveLocked(); err != nil {
		m.users[username] = previous
		return nil, err
	}
	delete(m.pendingTOTP, username)
	return codes, nil
}

func (m *Manager) DisableTOTP(username, code string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[username]
	if !ok {
		return errors.New("user not found")
	}
	previous := u
	if !u.MFAEnabled {
		return errors.New("TOTP is not enabled")
	}
	if !m.verifySecondFactorLocked(&u, code, time.Now()) {
		return errors.New("invalid MFA code")
	}
	u.MFAEnabled = false
	u.TOTPSecret = ""
	u.RecoveryHashes = nil
	m.users[username] = u
	if err := m.saveLocked(); err != nil {
		m.users[username] = previous
		return err
	}
	return nil
}

func (m *Manager) verifySecondFactorLocked(u *User, code string, now time.Time) bool {
	if u.TOTPSecret != "" && verifyTOTP(u.TOTPSecret, code, now) {
		return true
	}
	h := recoveryHash(code)
	for i, x := range u.RecoveryHashes {
		if hmac.Equal([]byte(x), []byte(h)) {
			u.RecoveryHashes = append(append([]string(nil), u.RecoveryHashes[:i]...), u.RecoveryHashes[i+1:]...)
			return true
		}
	}
	return false
}

func (m *Manager) LoginWithMFA(username, pw, code, remote string) (Session, error) {
	if len(username) > 256 || len(pw) > 4096 || len(code) > 128 || len(remote) > 256 {
		return Session{}, errors.New("invalid credentials")
	}
	select {
	case m.loginSlots <- struct{}{}:
		defer func() { <-m.loginSlots }()
	default:
		return Session{}, errors.New("login temporarily throttled")
	}
	key := remote + "|" + strings.ToLower(username)
	now := time.Now()

	// Password verification is intentionally expensive. Snapshot the account under
	// lock, derive the password key without the manager-wide mutex, then re-check
	// the account before creating a session. This keeps unrelated session/token
	// operations responsive during login attempts.
	m.mu.Lock()
	m.cleanupAuthLocked(now)
	if f := m.failures[key]; now.Before(f.Until) || f.InFlight {
		m.mu.Unlock()
		return Session{}, errors.New("login temporarily throttled")
	}
	if _, exists := m.failures[key]; !exists && len(m.failures) >= 4096 {
		m.mu.Unlock()
		return Session{}, errors.New("login temporarily throttled")
	}
	f := m.failures[key]
	f.InFlight = true
	m.failures[key] = f
	u, ok := m.users[username]
	storedHash := u.PasswordHash
	disabled := u.Disabled
	m.mu.Unlock()

	validPassword := ok && !disabled && verify(storedHash, pw)

	m.mu.Lock()
	defer m.mu.Unlock()
	defer func() {
		if f, exists := m.failures[key]; exists {
			f.InFlight = false
			m.failures[key] = f
		}
	}()
	current, stillExists := m.users[username]
	recordFailure := func() {
		f := m.failures[key]
		if f.Count < 8 {
			f.Count++
		}
		delay := time.Duration(f.Count*f.Count) * time.Second
		if delay > 60*time.Second {
			delay = 60 * time.Second
		}
		f.Until = time.Now().Add(delay)
		m.failures[key] = f
	}
	if !validPassword || !stillExists || current.Disabled || current.PasswordHash != storedHash {
		recordFailure()
		return Session{}, errors.New("invalid credentials")
	}

	authType := "session"
	if current.MFAEnabled {
		if code == "" {
			return Session{}, ErrMFARequired
		}
		if !m.verifySecondFactorLocked(&current, code, time.Now()) {
			recordFailure()
			return Session{}, errors.New("invalid MFA code")
		}
		m.users[username] = current
		if err := m.saveLocked(); err != nil {
			m.users[username] = u
			return Session{}, err
		}
		authType = "session+mfa"
	}
	delete(m.failures, key)
	return m.newSessionLocked(current, authType)
}

func (m *Manager) newSessionLocked(u User, typ string) (Session, error) {
	m.cleanupAuthLocked(time.Now())
	if len(m.sessions) >= 10000 {
		return Session{}, errors.New("session capacity reached")
	}
	sid, err := token(32)
	if err != nil {
		return Session{}, err
	}
	csrf, err := token(24)
	if err != nil {
		return Session{}, err
	}
	s := Session{ID: sid, Username: u.Username, Role: u.Role, Tenant: u.Tenant, CSRF: csrf, Expires: time.Now().Add(m.ttl), AuthType: typ}
	m.sessions[sid] = s
	return s, nil
}

func (m *Manager) cleanupAuthLocked(now time.Time) {
	if now.Sub(m.lastCleanup) < time.Minute {
		return
	}
	m.lastCleanup = now
	for key, f := range m.failures {
		if !f.InFlight && !now.Before(f.Until) {
			delete(m.failures, key)
		}
	}
	for key, s := range m.sessions {
		if !now.Before(s.Expires) {
			delete(m.sessions, key)
		}
	}
	for key, ch := range m.webauthnAuth {
		if !now.Before(ch.Expires) {
			delete(m.webauthnAuth, key)
		}
	}
	for key, ch := range m.webauthnReg {
		if !now.Before(ch.Expires) {
			delete(m.webauthnReg, key)
		}
	}
}

func (m *Manager) BeginWebAuthnRegistration(username, rpID, origin string) (WebAuthnCredentialCreation, error) {
	if !validRPOrigin(rpID, origin) {
		return WebAuthnCredentialCreation{}, errors.New("invalid WebAuthn rp/origin")
	}
	ch, err := token(32)
	if err != nil {
		return WebAuthnCredentialCreation{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[username]; !ok {
		return WebAuthnCredentialCreation{}, errors.New("user not found")
	}
	m.webauthnReg[username] = webauthnChallenge{Challenge: ch, Username: username, RPID: rpID, Origin: origin, Expires: time.Now().Add(5 * time.Minute)}
	return WebAuthnCredentialCreation{Challenge: ch, RPID: rpID, RPName: "Central Flow Collector", UserID: base64.RawURLEncoding.EncodeToString([]byte(username)), Username: username, UserVerification: "required"}, nil
}

func (m *Manager) FinishWebAuthnRegistration(username string, resp WebAuthnRegistrationResponse) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.webauthnReg[username]
	delete(m.webauthnReg, username)
	if !ok || time.Now().After(p.Expires) {
		return errors.New("expired WebAuthn registration challenge")
	}
	cd, err := decodeClientData(resp.ClientDataJSON, "webauthn.create", p.Challenge, p.Origin)
	if err != nil {
		return err
	}
	_ = cd
	att, err := base64.RawURLEncoding.DecodeString(resp.AttestationObject)
	if err != nil {
		return err
	}
	authData, err := extractAttestationAuthData(att)
	if err != nil {
		return err
	}
	credID, x, y, count, err := parseAttestedCredential(authData, p.RPID)
	if err != nil {
		return err
	}
	u := m.users[username]
	for _, pk := range u.Passkeys {
		if pk.ID == credID {
			return errors.New("passkey already registered")
		}
	}
	u.Passkeys = append(u.Passkeys, PasskeyCredential{ID: credID, Name: strings.TrimSpace(resp.Name), PublicKeyX: x, PublicKeyY: y, SignCount: count, CreatedAt: time.Now().UTC()})
	m.users[username] = u
	return m.saveLocked()
}

func (m *Manager) BeginWebAuthnAssertion(username, rpID, origin string) (WebAuthnAssertionOptions, error) {
	if !validRPOrigin(rpID, origin) {
		return WebAuthnAssertionOptions{}, errors.New("invalid WebAuthn rp/origin")
	}
	ch, err := token(32)
	if err != nil {
		return WebAuthnAssertionOptions{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[username]
	if !ok || len(u.Passkeys) == 0 {
		return WebAuthnAssertionOptions{}, errors.New("no passkeys registered")
	}
	m.webauthnAuth[username] = webauthnChallenge{Challenge: ch, Username: username, RPID: rpID, Origin: origin, Expires: time.Now().Add(5 * time.Minute)}
	ids := make([]string, 0, len(u.Passkeys))
	for _, pk := range u.Passkeys {
		ids = append(ids, pk.ID)
	}
	return WebAuthnAssertionOptions{Challenge: ch, RPID: rpID, CredentialIDs: ids, UserVerification: "required"}, nil
}

func (m *Manager) FinishWebAuthnAssertion(username string, resp WebAuthnAssertionResponse) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.webauthnAuth[username]
	delete(m.webauthnAuth, username)
	if !ok || time.Now().After(p.Expires) {
		return Session{}, errors.New("expired WebAuthn assertion challenge")
	}
	if _, err := decodeClientData(resp.ClientDataJSON, "webauthn.get", p.Challenge, p.Origin); err != nil {
		return Session{}, err
	}
	ad, err := base64.RawURLEncoding.DecodeString(resp.AuthenticatorData)
	if err != nil {
		return Session{}, err
	}
	if len(ad) < 37 {
		return Session{}, errors.New("short authenticator data")
	}
	wantRP := sha256.Sum256([]byte(p.RPID))
	if !hmac.Equal(ad[:32], wantRP[:]) {
		return Session{}, errors.New("WebAuthn rpIdHash mismatch")
	}
	if ad[32]&0x05 != 0x05 {
		return Session{}, errors.New("WebAuthn user presence or verification flag missing")
	}
	u, ok := m.users[username]
	if !ok || u.Disabled {
		return Session{}, errors.New("user unavailable")
	}
	idx := -1
	for i, pk := range u.Passkeys {
		if pk.ID == resp.CredentialID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return Session{}, errors.New("unknown passkey credential")
	}
	pk := u.Passkeys[idx]
	xb, _ := base64.RawURLEncoding.DecodeString(pk.PublicKeyX)
	yb, _ := base64.RawURLEncoding.DecodeString(pk.PublicKeyY)
	pub := ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(xb), Y: new(big.Int).SetBytes(yb)}
	cdb, err := base64.RawURLEncoding.DecodeString(resp.ClientDataJSON)
	if err != nil {
		return Session{}, err
	}
	hcd := sha256.Sum256(cdb)
	signed := append(append([]byte(nil), ad...), hcd[:]...)
	digest := sha256.Sum256(signed)
	sig, err := base64.RawURLEncoding.DecodeString(resp.Signature)
	if err != nil {
		return Session{}, err
	}
	if !ecdsa.VerifyASN1(&pub, digest[:], sig) {
		return Session{}, errors.New("WebAuthn signature verification failed")
	}
	count := binary.BigEndian.Uint32(ad[33:37])
	if (pk.SignCount != 0 || count != 0) && count <= pk.SignCount {
		return Session{}, errors.New("WebAuthn sign counter did not increase")
	}
	pk.SignCount = count
	pk.LastUsed = time.Now().UTC()
	u.Passkeys = append([]PasskeyCredential(nil), u.Passkeys...)
	u.Passkeys[idx] = pk
	previous := m.users[username]
	m.users[username] = u
	if err := m.saveLocked(); err != nil {
		m.users[username] = previous
		return Session{}, err
	}
	return m.newSessionLocked(u, "passkey")
}

func validRPOrigin(rpID, origin string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Hostname() == "" || rpID == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return false
	}
	h := u.Hostname()
	if u.Scheme != "https" && !(u.Scheme == "http" && h == "localhost") {
		return false
	}
	return h == rpID || strings.HasSuffix(h, "."+rpID)
}

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

func decodeClientData(enc, typ, ch, origin string) (clientData, error) {
	b, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return clientData{}, err
	}
	var c clientData
	if json.Unmarshal(b, &c) != nil {
		return c, errors.New("invalid clientDataJSON")
	}
	if c.Type != typ || c.Challenge != ch || c.Origin != origin || c.CrossOrigin {
		return c, errors.New("WebAuthn client data mismatch")
	}
	return c, nil
}

// Minimal CBOR helpers sufficient for WebAuthn attestationObject and COSE EC2 keys.
type cborDec struct {
	b     []byte
	i     int
	depth int
}

func (d *cborDec) head() (major byte, n uint64, err error) {
	if d.i >= len(d.b) {
		return 0, 0, errors.New("CBOR eof")
	}
	x := d.b[d.i]
	d.i++
	major = x >> 5
	ai := x & 31
	switch {
	case ai < 24:
		n = uint64(ai)
	case ai == 24:
		if d.i+1 > len(d.b) {
			return 0, 0, errors.New("CBOR eof")
		}
		n = uint64(d.b[d.i])
		d.i++
	case ai == 25:
		if d.i+2 > len(d.b) {
			return 0, 0, errors.New("CBOR eof")
		}
		n = uint64(binary.BigEndian.Uint16(d.b[d.i : d.i+2]))
		d.i += 2
	case ai == 26:
		if d.i+4 > len(d.b) {
			return 0, 0, errors.New("CBOR eof")
		}
		n = uint64(binary.BigEndian.Uint32(d.b[d.i : d.i+4]))
		d.i += 4
	default:
		return 0, 0, errors.New("unsupported CBOR length")
	}
	return
}
func (d *cborDec) any() (any, error) {
	if d.depth >= 32 {
		return nil, errors.New("CBOR nesting limit exceeded")
	}
	d.depth++
	defer func() { d.depth-- }()
	m, n, e := d.head()
	if e != nil {
		return nil, e
	}
	switch m {
	case 0:
		return int64(n), nil
	case 1:
		return -1 - int64(n), nil
	case 2:
		if n > uint64(len(d.b)-d.i) {
			return nil, errors.New("CBOR bytes overflow")
		}
		x := append([]byte(nil), d.b[d.i:d.i+int(n)]...)
		d.i += int(n)
		return x, nil
	case 3:
		if n > uint64(len(d.b)-d.i) {
			return nil, errors.New("CBOR text overflow")
		}
		x := string(d.b[d.i : d.i+int(n)])
		d.i += int(n)
		return x, nil
	case 4:
		if n > uint64(len(d.b)-d.i) {
			return nil, errors.New("CBOR array length exceeds input")
		}
		a := make([]any, 0, n)
		for j := uint64(0); j < n; j++ {
			v, e := d.any()
			if e != nil {
				return nil, e
			}
			a = append(a, v)
		}
		return a, nil
	case 5:
		if n > uint64(len(d.b)-d.i)/2 {
			return nil, errors.New("CBOR map length exceeds input")
		}
		mp := map[any]any{}
		for j := uint64(0); j < n; j++ {
			k, e := d.any()
			if e != nil {
				return nil, e
			}
			switch k.(type) {
			case string, int64:
			default:
				return nil, errors.New("unsupported CBOR map key")
			}
			if _, exists := mp[k]; exists {
				return nil, errors.New("duplicate CBOR map key")
			}
			v, e := d.any()
			if e != nil {
				return nil, e
			}
			mp[k] = v
		}
		return mp, nil
	default:
		return nil, errors.New("unsupported CBOR major")
	}
}
func extractAttestationAuthData(b []byte) ([]byte, error) {
	d := cborDec{b: b}
	v, e := d.any()
	if e != nil {
		return nil, e
	}
	if d.i != len(b) {
		return nil, errors.New("trailing attestation data")
	}
	mp, ok := v.(map[any]any)
	if !ok {
		return nil, errors.New("attestation object is not CBOR map")
	}
	x, ok := mp["authData"].([]byte)
	if !ok {
		return nil, errors.New("attestation authData missing")
	}
	return x, nil
}
func parseAttestedCredential(ad []byte, rpID string) (id, xs, ys string, count uint32, err error) {
	if len(ad) < 55 {
		return "", "", "", 0, errors.New("short attested auth data")
	}
	want := sha256.Sum256([]byte(rpID))
	if !hmac.Equal(ad[:32], want[:]) {
		return "", "", "", 0, errors.New("registration rpIdHash mismatch")
	}
	if ad[32]&0x45 != 0x45 {
		return "", "", "", 0, errors.New("registration flags missing UP/UV/AT")
	}
	count = binary.BigEndian.Uint32(ad[33:37])
	pos := 53
	ln := int(binary.BigEndian.Uint16(ad[pos : pos+2]))
	pos += 2
	if ln < 1 || pos+ln > len(ad) {
		return "", "", "", 0, errors.New("invalid credential id length")
	}
	cred := ad[pos : pos+ln]
	pos += ln
	d := cborDec{b: ad[pos:]}
	v, e := d.any()
	if e != nil {
		return "", "", "", 0, e
	}
	mp, ok := v.(map[any]any)
	if !ok {
		return "", "", "", 0, errors.New("COSE key invalid")
	}
	if mp[int64(1)] != int64(2) || mp[int64(3)] != int64(-7) || mp[int64(-1)] != int64(1) {
		return "", "", "", 0, errors.New("only ES256 P-256 passkeys are supported")
	}
	get := func(k int64) []byte {
		for kk, v := range mp {
			if ki, ok := kk.(int64); ok && ki == k {
				if b, ok := v.([]byte); ok {
					return b
				}
			}
		}
		return nil
	}
	x := get(-2)
	y := get(-3)
	if len(x) != 32 || len(y) != 32 {
		return "", "", "", 0, errors.New("only ES256 P-256 passkeys are supported")
	}
	if !elliptic.P256().IsOnCurve(new(big.Int).SetBytes(x), new(big.Int).SetBytes(y)) {
		return "", "", "", 0, errors.New("invalid P-256 public key")
	}
	return base64.RawURLEncoding.EncodeToString(cred), base64.RawURLEncoding.EncodeToString(x), base64.RawURLEncoding.EncodeToString(y), count, nil
}
