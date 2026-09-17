package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"central-flow-collector/internal/config"
)

func TestResolveEnvAndFile(t *testing.T) {
	t.Setenv("CFC_SECRET_TEST", "env-value")
	if got, err := Resolve("@env:CFC_SECRET_TEST"); err != nil || got != "env-value" {
		t.Fatalf("env got=%q err=%v", got, err)
	}
	p := filepath.Join(t.TempDir(), "s")
	if err := os.WriteFile(p, []byte(" file-value\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got, err := Resolve("@file:" + p); err != nil || got != "file-value" {
		t.Fatalf("file got=%q err=%v", got, err)
	}
	if got, err := Resolve("literal"); err != nil || got != "literal" {
		t.Fatal(got, err)
	}
}

func TestApply(t *testing.T) {
	t.Setenv("CH_SECRET", "pw")
	c := config.Default()
	c.Storage.ClickHousePassword = "@env:CH_SECRET"
	if err := Apply(&c); err != nil {
		t.Fatal(err)
	}
	if c.Storage.ClickHousePassword != "pw" {
		t.Fatal("secret not resolved")
	}
}
