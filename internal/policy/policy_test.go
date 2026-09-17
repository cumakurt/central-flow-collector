package policy

import (
	"path/filepath"
	"testing"
)

func TestPolicyPriority(t *testing.T) {
	e, err := New(filepath.Join(t.TempDir(), "p.json"), "deny")
	if err != nil {
		t.Fatal(err)
	}
	if err = e.Upsert(Rule{ID: "allow-net", Priority: 100, Action: "allow", Source: "10.0.0.0/8", Protocol: "netflow", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err = e.Upsert(Rule{ID: "deny-host", Priority: 10, Action: "deny", Source: "10.1.2.3", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if e.Decide("10.1.2.3", "netflow", "x", 2055).Allowed {
		t.Fatal("expected deny")
	}
	if !e.Decide("10.2.3.4", "netflow", "x", 2055).Allowed {
		t.Fatal("expected allow")
	}
}

func TestSimulationTrace(t *testing.T) {
	d := t.TempDir() + "/policies.json"
	e, err := New(d, "deny")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Upsert(Rule{ID: "wrong", Priority: 10, Action: "allow", Source: "192.0.2.0/24", Protocol: "netflow", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := e.Upsert(Rule{ID: "right", Priority: 20, Action: "allow", Source: "10.0.0.0/8", Protocol: "netflow", Listener: "nf", DestPort: 2055, Enabled: true}); err != nil {
		t.Fatal(err)
	}
	s := e.Simulate("10.1.2.3", "netflow", "nf", 2055)
	if !s.Decision.Allowed || s.Decision.RuleID != "right" || len(s.Trace) != 2 || s.Trace[0].Matched || !s.Trace[1].Matched {
		t.Fatalf("simulation=%+v", s)
	}
}
