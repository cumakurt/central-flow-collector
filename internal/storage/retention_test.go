package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLocalRetentionPersistsAndPurges(t *testing.T) {
	d := t.TempDir()
	l, err := NewLocal(d, 64, 7)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.SetRetention(context.Background(), 3); err != nil {
		t.Fatal(err)
	}
	if got := LoadRetentionOverride(d, 7); got != 3 {
		t.Fatalf("retention override=%d", got)
	}
	old := time.Now().UTC().AddDate(0, 0, -10).Format("2006-01-02") + ".jsonl"
	p := filepath.Join(d, "flows", old)
	if err := os.WriteFile(p, []byte("{}\n"), 0640); err != nil {
		t.Fatal(err)
	}
	r, err := l.Purge(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if r.DeletedFiles != 1 {
		t.Fatalf("deleted=%d", r.DeletedFiles)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("expired partition still exists")
	}
	_ = l.Close()
}
