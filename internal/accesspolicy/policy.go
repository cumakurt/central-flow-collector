package accesspolicy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Rule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	CIDR    string `json:"cidr"`
	Action  string `json:"action"`
	Enabled bool   `json:"enabled"`
}

type Document struct {
	Version       int    `json:"version"`
	DefaultAction string `json:"default_action"`
	Rules         []Rule `json:"rules"`
}

type Manager struct {
	mu   sync.RWMutex
	path string
	doc  Document
}

func New(path string) (*Manager, error) {
	m := &Manager{path: path, doc: Document{Version: 1, DefaultAction: "allow"}}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &m.doc); err != nil {
			return nil, fmt.Errorf("decode access policy: %w", err)
		}
		if err := validateDocument(m.doc); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return m, nil
}

func validateDocument(d Document) error {
	if d.DefaultAction != "allow" && d.DefaultAction != "deny" {
		return errors.New("default access action must be allow or deny")
	}
	seen := map[string]bool{}
	for i, r := range d.Rules {
		if strings.TrimSpace(r.ID) == "" {
			return fmt.Errorf("access rule %d has no id", i)
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate access rule id %q", r.ID)
		}
		seen[r.ID] = true
		if r.Action != "allow" && r.Action != "deny" {
			return fmt.Errorf("access rule %q has invalid action", r.ID)
		}
		if _, _, err := net.ParseCIDR(strings.TrimSpace(r.CIDR)); err != nil {
			return fmt.Errorf("access rule %q has invalid CIDR: %w", r.ID, err)
		}
	}
	if len(d.Rules) > 512 {
		return errors.New("at most 512 access rules are allowed")
	}
	return nil
}

func (m *Manager) Snapshot() Document {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d := m.doc
	d.Rules = append([]Rule(nil), m.doc.Rules...)
	return d
}

func (m *Manager) Replace(d Document) error {
	if d.Version == 0 {
		d.Version = 1
	}
	if err := validateDocument(d); err != nil {
		return err
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0750); err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, m.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	m.mu.Lock()
	m.doc = d
	m.mu.Unlock()
	return nil
}

func (m *Manager) Allowed(remote string) bool {
	ip := net.ParseIP(strings.TrimSpace(remote))
	if ip == nil {
		return false
	}
	m.mu.RLock()
	d := m.doc
	m.mu.RUnlock()
	for _, r := range d.Rules {
		if !r.Enabled {
			continue
		}
		_, n, err := net.ParseCIDR(r.CIDR)
		if err != nil || !n.Contains(ip) {
			continue
		}
		return r.Action == "allow"
	}
	return d.DefaultAction == "allow"
}
