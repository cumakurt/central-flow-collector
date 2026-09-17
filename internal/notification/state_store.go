package notification

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

type storedChannel struct {
	Config ChannelConfig `json:"config"`
	Secret string        `json:"secret"`
}
type Delivery struct {
	ID            string           `json:"id"`
	ChannelID     string           `json:"channel_id"`
	ChannelType   string           `json:"channel_type"`
	ChannelName   string           `json:"channel_name"`
	Status        string           `json:"status"`
	Attempts      int              `json:"attempts"`
	Created       time.Time        `json:"created"`
	Due           time.Time        `json:"due"`
	DurationMS    int64            `json:"duration_ms"`
	Result        string           `json:"result"`
	Context       MessageContext   `json:"context"`
	Digest        []MessageContext `json:"digest,omitempty"`
	DigestSeconds int              `json:"digest_seconds,omitempty"`
	Delayed       bool             `json:"delayed"`
}
type PlatformSettings struct {
	PortalURL     string `json:"portal_url"`
	RetentionDays int    `json:"retention_days"`
	MaxAttempts   int    `json:"max_attempts"`
	MaxAgeSeconds int    `json:"max_age_seconds"`
}
type platformState struct {
	Version    int                           `json:"version"`
	Settings   PlatformSettings              `json:"settings"`
	Channels   map[string]storedChannel      `json:"channels"`
	Policies   map[string]NotificationPolicy `json:"policies"`
	Rules      map[string]RuleDefinition     `json:"rules"`
	Revisions  map[string][]RuleDefinition   `json:"revisions"`
	Alerts     map[string]AlertInstance      `json:"alerts"`
	Events     []AlertEvent                  `json:"events"`
	Deliveries []Delivery                    `json:"deliveries"`
	Silences   map[string]Silence            `json:"silences"`
}

func emptyState() platformState {
	return platformState{Version: 1, Settings: PlatformSettings{RetentionDays: 90, MaxAttempts: 5, MaxAgeSeconds: 86400}, Channels: map[string]storedChannel{}, Policies: map[string]NotificationPolicy{}, Rules: map[string]RuleDefinition{}, Revisions: map[string][]RuleDefinition{}, Alerts: map[string]AlertInstance{}, Events: []AlertEvent{}, Deliveries: []Delivery{}, Silences: map[string]Silence{}}
}

func atomicPrivateWrite(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".notification-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = os.Rename(name, path); e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func openVault(dir string) (cipher.AEAD, error) {
	p := filepath.Join(dir, "notification-key")
	key, e := os.ReadFile(p)
	if os.IsNotExist(e) {
		key = make([]byte, 32)
		if _, e = rand.Read(key); e != nil {
			return nil, e
		}
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, err
		}
		_, e = f.Write(key)
		if e == nil {
			e = f.Sync()
		}
		ce := f.Close()
		if e == nil {
			e = ce
		}
	}
	if e != nil {
		return nil, e
	}
	if len(key) != 32 {
		return nil, errors.New("invalid notification encryption key")
	}
	b, e := aes.NewCipher(key)
	if e != nil {
		return nil, e
	}
	return cipher.NewGCM(b)
}
func (p *Platform) seal(id, secret string) (string, error) {
	if secret == "" {
		return "", nil
	}
	nonce := make([]byte, p.vault.NonceSize())
	if _, e := io.ReadFull(rand.Reader, nonce); e != nil {
		return "", e
	}
	return base64.StdEncoding.EncodeToString(p.vault.Seal(nonce, nonce, []byte(secret), []byte(id))), nil
}
func (p *Platform) unseal(id, v string) (string, error) {
	if v == "" {
		return "", nil
	}
	b, e := base64.StdEncoding.DecodeString(v)
	if e != nil || len(b) < p.vault.NonceSize() {
		return "", errors.New("channel secret unavailable")
	}
	s, e := p.vault.Open(nil, b[:p.vault.NonceSize()], b[p.vault.NonceSize():], []byte(id))
	if e != nil {
		return "", errors.New("channel secret unavailable")
	}
	return string(s), nil
}

// Each mutation is committed before becoming visible. This follows the existing
// single-node JSON control-plane convention. Bounded definitions/history keep
// snapshot work independent of incoming flow volume.
func (p *Platform) transaction(fn func(*platformState) error) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	b, e := json.Marshal(p.state)
	if e != nil {
		return e
	}
	var next platformState
	if e = json.Unmarshal(b, &next); e != nil {
		return e
	}
	if e = fn(&next); e != nil {
		return e
	}
	pruneState(&next, time.Now().UTC())
	b, e = json.Marshal(next)
	if e != nil {
		return e
	}
	if len(b) > 32<<20 {
		return errors.New("notification state exceeds 32 MiB; reduce rules or history")
	}
	if e = atomicPrivateWrite(p.path, b); e != nil {
		p.persistenceError = true
		return errors.New("notification state persistence failed")
	}
	p.state = next
	p.persistenceError = false
	return nil
}
func pruneState(s *platformState, now time.Time) {
	cut := now.Add(-time.Duration(s.Settings.RetentionDays) * 24 * time.Hour)
	keep := s.Deliveries[:0]
	for _, d := range s.Deliveries {
		if d.Created.After(cut) || d.Status == "PENDING" || d.Status == "RETRYING" || d.Status == "SENDING" {
			keep = append(keep, d)
		}
	}
	s.Deliveries = keep
	if len(s.Events) > 20000 {
		s.Events = append([]AlertEvent(nil), s.Events[len(s.Events)-20000:]...)
	}
	for k, a := range s.Alerts {
		if (a.State == "NORMAL" || a.State == "RECOVERED") && now.Sub(a.LastEvaluated) > 24*time.Hour {
			delete(s.Alerts, k)
		}
	}
	for k, si := range s.Silences {
		if now.Sub(si.Until) > 24*time.Hour {
			delete(s.Silences, k)
		}
	}
}
