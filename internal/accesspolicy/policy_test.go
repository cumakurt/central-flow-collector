package accesspolicy

import (
	"path/filepath"
	"testing"
)

func TestPolicyCIDRMatchingAndPersistence(t *testing.T) {
	m, err := New(filepath.Join(t.TempDir(), "access-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Replace(Document{Version: 1, DefaultAction: "deny", Rules: []Rule{{ID: "office", CIDR: "192.0.2.0/24", Action: "allow", Enabled: true}}}); err != nil {
		t.Fatal(err)
	}
	if !m.Allowed("192.0.2.20") || m.Allowed("198.51.100.10") {
		t.Fatal("CIDR policy result incorrect")
	}
	m2, err := New(m.path)
	if err != nil {
		t.Fatal(err)
	}
	if !m2.Allowed("192.0.2.20") {
		t.Fatal("persisted policy not loaded")
	}
}

func TestPolicyRejectsInvalidRules(t *testing.T) {
	m, err := New(filepath.Join(t.TempDir(), "access-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Replace(Document{DefaultAction: "allow", Rules: []Rule{{ID: "x", CIDR: "not-cidr", Action: "deny", Enabled: true}}}); err == nil {
		t.Fatal("invalid CIDR accepted")
	}
}
