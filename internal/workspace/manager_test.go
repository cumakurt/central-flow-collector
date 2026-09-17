package workspace

import "testing"

func TestSavedViewPersistence(t *testing.T) {
	d := t.TempDir()
	m, err := New(d)
	if err != nil {
		t.Fatal(err)
	}
	x, err := m.UpsertSaved("alice", SavedSearch{Name: "Internet Traffic", Query: map[string]string{"direction": "outbound"}, Columns: []string{"src_ip", "dst_ip", "bytes"}, Sort: "bytes:desc", GroupBy: "dst_country", Visualization: "bar", TimeConfig: "24h"})
	if err != nil {
		t.Fatal(err)
	}
	if x.ID == "" {
		t.Fatal("missing saved view id")
	}
	m2, err := New(d)
	if err != nil {
		t.Fatal(err)
	}
	got := m2.Saved("alice")
	if len(got) != 1 || got[0].Name != "Internet Traffic" || got[0].GroupBy != "dst_country" {
		t.Fatalf("saved=%+v", got)
	}
	if err := m2.DeleteSaved("alice", x.ID); err != nil {
		t.Fatal(err)
	}
}

func TestSearchHistoryBounded(t *testing.T) {
	m, _ := New(t.TempDir())
	for i := 0; i < 120; i++ {
		m.RecordHistory("alice", map[string]string{"src_ip": "10.0.0.1"}, i)
	}
	if got := len(m.History("alice", 100)); got > 100 {
		t.Fatalf("history=%d", got)
	}
}
