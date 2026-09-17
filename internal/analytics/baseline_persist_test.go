package analytics

import (
	"central-flow-collector/internal/model"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBaselinePersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "baseline-state.json")
	e := New()
	e.ConfigureBaseline(true, 7)
	now := time.Now().UTC()
	e.mu.Lock()
	st := &hostBaselineState{Minute: now.Unix() / 60, Bytes: 1234, Flows: 2, LastAlert: now.Add(-time.Minute), Buckets: map[int]baselineBucket{}}
	st.Buckets[4] = baselineBucket{Count: 9, Mean: 500, M2: 123, EWMA: 450}
	e.baselineHosts["10.0.0.8"] = st
	e.mu.Unlock()
	if err := e.SaveBaseline(p); err != nil {
		t.Fatal(err)
	}
	e2 := New()
	if err := e2.LoadBaseline(p); err != nil {
		t.Fatal(err)
	}
	s := e2.BaselineStatus()
	if s.Hosts != 1 || s.MinSamples != 7 || s.Buckets != 1 {
		t.Fatalf("unexpected restored status: %+v", s)
	}
	e2.mu.RLock()
	got := e2.baselineHosts["10.0.0.8"]
	e2.mu.RUnlock()
	if got == nil || got.Buckets[4].Count != 9 || got.Buckets[4].EWMA != 450 {
		t.Fatalf("state not restored: %+v", got)
	}
	_ = model.Flow{} // keep model import representative of engine usage
}

func TestBaselinePersistenceRejectsCorrupt(t *testing.T) {
	p := filepath.Join(t.TempDir(), "baseline-state.json")
	if err := os.WriteFile(p, []byte(`{"version":1,"hosts":{"10.0.0.1":{"buckets":[]}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	e := New()
	if err := e.LoadBaseline(p); err == nil {
		t.Fatal("expected corrupt snapshot rejection")
	}
}
