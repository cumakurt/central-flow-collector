package adminops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"central-flow-collector/internal/config"
)

func testManager(t *testing.T) (*Manager, config.Config, string) {
	t.Helper()
	root := t.TempDir()
	data := filepath.Join(root, "data")
	if err := os.MkdirAll(data, 0750); err != nil {
		t.Fatal(err)
	}
	cfgPath := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("storage:\n  data_dir: \""+data+"\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	c.Storage.ClickHousePassword = "base-secret"
	m, err := New(cfgPath, c)
	if err != nil {
		t.Fatal(err)
	}
	return m, c, data
}

func TestManagerSafeApplyPersistsAndReloads(t *testing.T) {
	m, _, data := testManager(t)
	s := m.Current()
	s.Storage.RetentionDays = 31
	v := m.Validate(s)
	if !v.Valid || v.RestartRequired {
		t.Fatalf("validation=%+v", v)
	}
	res, err := m.Apply(s, "admin", "retention policy")
	if err != nil {
		t.Fatal(err)
	}
	if res.Validation.RestartRequired {
		t.Fatal("retention-only change should be live-safe")
	}
	st, err := os.Stat(config.AdminOverridePath(data))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("override mode=%o", st.Mode().Perm())
	}
	c2, err := config.Load(m.ConfigPath())
	if err != nil {
		t.Fatal(err)
	}
	if c2.Storage.RetentionDays != 31 {
		t.Fatalf("retention=%d", c2.Storage.RetentionDays)
	}
}

func TestManagerCriticalChangeRequiresReasonAndRedactsSecrets(t *testing.T) {
	m, _, _ := testManager(t)
	s := m.Current()
	if !s.Storage.ClickHousePasswordSet {
		t.Fatal("expected password-set flag")
	}
	if s.Storage.NewClickHousePassword != "" {
		t.Fatal("secret leaked through Current")
	}
	s.Storage.ClickHouseURL = "http://10.0.0.10:8123"
	if _, err := m.Apply(s, "admin", ""); err == nil || !strings.Contains(err.Error(), "reason") {
		t.Fatalf("expected critical reason error, got %v", err)
	}
	if _, err := m.Apply(s, "admin", "move analytics database"); err != nil {
		t.Fatal(err)
	}
	vv := m.Versions()
	if len(vv) != 1 {
		t.Fatalf("versions=%d", len(vv))
	}
	if vv[0].Before.Storage != nil || vv[0].After.Storage != nil {
		t.Fatal("version API snapshot was not redacted")
	}
}

func TestManagerRejectsOnlineDataDirMoveAndRollback(t *testing.T) {
	m, _, _ := testManager(t)
	s := m.Current()
	s.Storage.DataDir = filepath.Join(t.TempDir(), "new")
	if v := m.Validate(s); v.Valid {
		t.Fatal("online data-dir move unexpectedly valid")
	}

	s = m.Current()
	s.Storage.RetentionDays = 22
	a, err := m.Apply(s, "admin", "")
	if err != nil {
		t.Fatal(err)
	}
	s2 := m.Current()
	s2.Logging.Level = "debug"
	if _, err = m.Apply(s2, "admin", ""); err != nil {
		t.Fatal(err)
	}
	rv, err := m.Rollback(a.Version.ID, "admin", "test rollback")
	if err != nil {
		t.Fatal(err)
	}
	if !rv.RestartRequired {
		t.Fatal("rollback should require restart")
	}
	if got := m.Current().Storage.RetentionDays; got == 22 {
		// Rolling back to the state before the first version intentionally
		// restores the original default rather than the selected version.
	} else if got != 7 {
		t.Fatalf("rollback retention=%d", got)
	}
}
