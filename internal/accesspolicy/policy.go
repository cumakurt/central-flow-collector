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
	mu       sync.RWMutex
	path     string
	doc      Document
	networks []*net.IPNet
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
	m.compile()
	return m, nil
}

func parseNetwork(value string) (*net.IPNet, error) {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(value); ip != nil {
		bits := 128
		if v4 := ip.To4(); v4 != nil {
			ip = v4
			bits = 32
		}
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}, nil
	}
	_, network, err := net.ParseCIDR(value)
	return network, err
}

func (m *Manager) compile() {
	m.networks = make([]*net.IPNet, len(m.doc.Rules))
	for i, rule := range m.doc.Rules {
		m.networks[i], _ = parseNetwork(rule.CIDR)
	}
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
		if _, err := parseNetwork(r.CIDR); err != nil {
			return fmt.Errorf("access rule %q has invalid IP or subnet: %w", r.ID, err)
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
	d.Rules = append([]Rule(nil), d.Rules...)
	if d.Version == 0 {
		d.Version = 1
	}
	if err := validateDocument(d); err != nil {
		return err
	}
	for i := range d.Rules {
		network, _ := parseNetwork(d.Rules[i].CIDR)
		d.Rules[i].CIDR = network.String()
	}
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0750); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	f, err := os.CreateTemp(filepath.Dir(m.path), ".access-policy-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, err = f.Write(append(b, '\n'))
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, m.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	m.doc = d
	m.compile()
	return nil
}

func (m *Manager) Allowed(remote string) bool {
	ip := net.ParseIP(strings.TrimSpace(remote))
	if ip == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	for i, r := range m.doc.Rules {
		if !r.Enabled {
			continue
		}
		n := m.networks[i]
		if n == nil || !n.Contains(ip) {
			continue
		}
		return r.Action == "allow"
	}
	return m.doc.DefaultAction == "allow"
}
