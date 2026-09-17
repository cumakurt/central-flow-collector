package dr

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBackupVerifyRestore(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	os.MkdirAll(data, 0750)
	cfg := filepath.Join(root, "config.yaml")
	os.WriteFile(cfg, []byte("web:\n  port: 8080\n"), 0640)
	os.WriteFile(filepath.Join(data, "users.json"), []byte("[]"), 0600)
	os.MkdirAll(filepath.Join(data, "flows"), 0750)
	os.WriteFile(filepath.Join(data, "flows", "x.jsonl"), []byte("{}\n"), 0640)
	arc := filepath.Join(root, "b.tar.gz")
	m, e := Create(cfg, data, arc, false)
	if e != nil {
		t.Fatal(e)
	}
	if m.IncludesFlows {
		t.Fatal("unexpected flows")
	}
	v, e := Verify(arc)
	if e != nil || !v.Valid {
		t.Fatalf("verify %#v %v", v, e)
	}
	os.WriteFile(filepath.Join(data, "users.json"), []byte("bad"), 0600)
	if e = Restore(arc, cfg, data, true); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(filepath.Join(data, "users.json"))
	if string(b) != "[]" {
		t.Fatalf("restored=%q", b)
	}
}

func TestBackupSkipsBackupDirectoryAndDataOnlyRestore(t *testing.T) {
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := os.MkdirAll(filepath.Join(data, "backups"), 0750); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(cfg, []byte("original-config"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "users.json"), []byte("[1]"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "backups", "old.tar.gz"), []byte("do-not-nest"), 0600); err != nil {
		t.Fatal(err)
	}
	arc := filepath.Join(root, "metadata.tar.gz")
	m, err := Create(cfg, data, arc, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range m.Entries {
		if e.Path == "data/backups/old.tar.gz" {
			t.Fatal("backup recursively included prior backup")
		}
	}
	if err := os.WriteFile(cfg, []byte("live-base-config"), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(data, "users.json"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := RestoreDataOnly(arc, data, true); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(cfg)
	if string(b) != "live-base-config" {
		t.Fatalf("base config was mutated: %q", b)
	}
	b, _ = os.ReadFile(filepath.Join(data, "users.json"))
	if string(b) != "[1]" {
		t.Fatalf("data was not restored: %q", b)
	}
}
