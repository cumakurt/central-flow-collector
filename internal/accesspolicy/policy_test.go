package accesspolicy

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestIPSubnetOrderAndConcurrentPersistence(t *testing.T) {
	m, err := New(filepath.Join(t.TempDir(), "access-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	d := Document{DefaultAction: "deny", Rules: []Rule{
		{ID: "host", CIDR: " 192.0.2.4 ", Action: "deny", Enabled: true},
		{ID: "network", CIDR: "192.0.2.10/24", Action: "allow", Enabled: true},
		{ID: "ipv6", CIDR: "2001:db8::4", Action: "allow", Enabled: true},
		{ID: "disabled", CIDR: "198.51.100.0/24", Action: "allow", Enabled: false},
	}}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := m.Replace(d); err != nil {
				t.Error(err)
			}
			m.Allowed("192.0.2.5")
		}()
	}
	wg.Wait()
	reloaded, err := New(m.path)
	if err != nil {
		t.Fatal(err)
	}
	for ip, expected := range map[string]bool{"192.0.2.4": false, "192.0.2.5": true, "2001:db8::4": true, "2001:db8::5": false, "198.51.100.1": false} {
		if m.Allowed(ip) != expected || reloaded.Allowed(ip) != expected {
			t.Errorf("incorrect decision for %s", ip)
		}
	}
	if m.Snapshot().Rules[0].CIDR != "192.0.2.4/32" {
		t.Fatal("IP not normalized")
	}
}

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
