package analytics

import (
	"path/filepath"
	"testing"

	"central-flow-collector/internal/model"
)

func TestRulePersistenceAndLargeTransferThreshold(t *testing.T) {
	e := New()
	p := filepath.Join(t.TempDir(), "alert-rules.json")
	if err := e.ConfigureRules(p); err != nil {
		t.Fatal(err)
	}
	r := e.Rule("large_transfer")
	r.Threshold = 1024
	r.Severity = "critical"
	if err := e.UpsertRule(r); err != nil {
		t.Fatal(err)
	}
	e.Observe(model.Flow{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Bytes: 2048})
	a := e.Alerts()
	if len(a) != 1 {
		t.Fatalf("expected alert, got %d", len(a))
	}
	if a[0].Severity != "critical" || a[0].Threshold != 1024 {
		t.Fatalf("unexpected alert: %+v", a[0])
	}
	e2 := New()
	if err := e2.ConfigureRules(p); err != nil {
		t.Fatal(err)
	}
	if got := e2.Rule("large_transfer"); got.Threshold != 1024 || got.Severity != "critical" {
		t.Fatalf("rule not persisted: %+v", got)
	}
}

func TestDeleteRuleDisablesDefault(t *testing.T) {
	e := New()
	p := filepath.Join(t.TempDir(), "rules.json")
	if err := e.ConfigureRules(p); err != nil {
		t.Fatal(err)
	}
	if err := e.DeleteRule("large_transfer"); err != nil {
		t.Fatal(err)
	}
	e.Observe(model.Flow{SrcIP: "a", DstIP: "b", Bytes: 999999999})
	if len(e.Alerts()) != 0 {
		t.Fatal("disabled rule produced alert")
	}
}
