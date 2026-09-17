package api

import (
	"central-flow-collector/internal/adminops"
	"central-flow-collector/internal/config"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func attachV20Admin(t *testing.T, f *v17Fixture) *adminops.Manager {
	t.Helper()
	cfg := config.Default()
	cfg.Storage.DataDir = f.dir
	cfg.Listeners = nil
	cfgPath := filepath.Join(f.dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(fmt.Sprintf("storage:\n  backend: local\n  data_dir: %q\n  retention_days: 7\nlisteners:\n", f.dir)), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := adminops.New(cfgPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.srv.SetAdminOps(m)
	return m
}

func TestV20AdministrationSettingsMaintenanceBackupAndRBAC(t *testing.T) {
	f := newV17Fixture(t)
	m := attachV20Admin(t, f)
	h := f.srv.Handler()

	// Administration is reserved for the settings permission / administrator.
	w := doBearer(h, http.MethodGet, "/api/v1/admin/overview", f.aliceToken, "")
	if w.Code != http.StatusForbidden {
		t.Fatalf("non-admin overview status=%d body=%s", w.Code, w.Body.String())
	}

	w = doBearer(h, http.MethodGet, "/api/v1/admin/overview", f.adminToken, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"audit_integrity"`) {
		t.Fatalf("overview=%d %s", w.Code, w.Body.String())
	}

	w = doBearer(h, http.MethodGet, "/api/v1/admin/settings", f.adminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("settings=%d %s", w.Code, w.Body.String())
	}
	var s adminops.Settings
	if err := json.Unmarshal(w.Body.Bytes(), &s); err != nil {
		t.Fatal(err)
	}
	if s.Storage.NewClickHousePassword != "" || s.OIDC.NewClientSecret != "" || s.LDAP.NewBindPassword != "" {
		t.Fatal("secret material leaked in administration settings response")
	}

	// A live-safe retention change is applied without a restart and reaches storage.
	s.Storage.RetentionDays = 11
	body, _ := json.Marshal(map[string]any{"settings": s, "reason": "retention test"})
	w = doBearer(h, http.MethodPost, "/api/v1/admin/settings/apply", f.adminToken, string(body))
	if w.Code != http.StatusOK {
		t.Fatalf("retention apply=%d %s", w.Code, w.Body.String())
	}
	if got := f.st.Retention(); got != 11 {
		t.Fatalf("live retention=%d want 11", got)
	}

	// Critical DB changes require an operator reason even if otherwise valid.
	s = m.Current()
	s.Storage.Backend = "clickhouse"
	s.Storage.ClickHouseURL = "http://127.0.0.1:18123"
	body, _ = json.Marshal(map[string]any{"settings": s, "reason": ""})
	w = doBearer(h, http.MethodPost, "/api/v1/admin/settings/apply", f.adminToken, string(body))
	if w.Code != http.StatusBadRequest || !strings.Contains(strings.ToLower(w.Body.String()), "reason") {
		t.Fatalf("critical no-reason=%d %s", w.Code, w.Body.String())
	}

	w = doBearer(h, http.MethodPost, "/api/v1/admin/maintenance/audit_verify", f.adminToken, `{}`)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("audit maintenance=%d %s", w.Code, w.Body.String())
	}

	w = doBearer(h, http.MethodPost, "/api/v1/admin/backups/create", f.adminToken, `{"kind":"metadata","include_flows":false}`)
	if w.Code != http.StatusOK {
		t.Fatalf("backup create=%d %s", w.Code, w.Body.String())
	}
	w = doBearer(h, http.MethodGet, "/api/v1/admin/backups", f.adminToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("backup list=%d %s", w.Code, w.Body.String())
	}
	var backups []adminBackupItem
	if err := json.Unmarshal(w.Body.Bytes(), &backups); err != nil {
		t.Fatal(err)
	}
	if len(backups) == 0 || backups[0].Kind != "metadata" {
		t.Fatalf("backups=%+v", backups)
	}
	vb, _ := json.Marshal(map[string]string{"name": backups[0].Name})
	w = doBearer(h, http.MethodPost, "/api/v1/admin/backups/verify", f.adminToken, string(vb))
	if w.Code != http.StatusOK {
		t.Fatalf("backup verify=%d %s", w.Code, w.Body.String())
	}

	w = doBearer(h, http.MethodGet, "/api/v1/admin/config/versions", f.adminToken, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"storage.retention_days"`) {
		t.Fatalf("config history=%d %s", w.Code, w.Body.String())
	}
}

func TestV20ClickHouseConnectionProbe(t *testing.T) {
	fake := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		switch {
		case strings.Contains(q, "version()"):
			_, _ = w.Write([]byte("24.8.1.1\n"))
		case strings.Contains(q, "system.databases"):
			_, _ = w.Write([]byte("1\n"))
		case strings.Contains(q, "system.tables"):
			_, _ = w.Write([]byte("1\n"))
		case strings.HasPrefix(q, "CHECK GRANT INSERT"):
			_, _ = w.Write([]byte("\n"))
		default:
			_, _ = w.Write([]byte("1\n"))
		}
	}))
	defer fake.Close()

	f := newV17Fixture(t)
	m := attachV20Admin(t, f)
	s := m.Current()
	s.Storage.Backend = "clickhouse"
	s.Storage.ClickHouseURL = fake.URL
	s.Storage.ClickHouseDatabase = "flowcollector"
	s.Storage.ClickHouseTable = "flows"
	b, _ := json.Marshal(s)
	w := doBearer(f.srv.Handler(), http.MethodPost, "/api/v1/admin/database/test", f.adminToken, string(b))
	if w.Code != http.StatusOK {
		t.Fatalf("database probe=%d %s", w.Code, w.Body.String())
	}
	var p adminops.ClickHouseProbe
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if !p.OK || !p.DatabaseExists || !p.TableExists || !p.WriteProbe || p.ServerVersion != "24.8.1.1" {
		t.Fatalf("probe=%+v", p)
	}
}

func TestAdminIngestionPasswordAndHealth(t *testing.T) {
	f := newV17Fixture(t)
	attachV20Admin(t, f)
	h := f.srv.Handler()
	if w := doBearer(h, http.MethodPost, "/api/v1/admin/ingestion/stop", f.aliceToken, `{}`); w.Code != http.StatusForbidden {
		t.Fatalf("analyst stop=%d", w.Code)
	}
	for _, action := range []string{"stop", "start"} {
		w := doBearer(h, http.MethodPost, "/api/v1/admin/ingestion/"+action, f.adminToken, `{}`)
		if w.Code != http.StatusOK || f.srv.Collector.Paused() != (action == "stop") {
			t.Fatalf("ingestion %s=%d %s", action, w.Code, w.Body.String())
		}
	}
	if w := doBearer(h, http.MethodPost, "/api/v1/users/alice/password", f.aliceToken, `{"password":"NewPassw0rd!"}`); w.Code != http.StatusForbidden {
		t.Fatalf("analyst reset=%d", w.Code)
	}
	w := doBearer(h, http.MethodPost, "/api/v1/users/alice/password", f.adminToken, `{"password":"NewPassw0rd!"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("admin reset=%d %s", w.Code, w.Body.String())
	}
	if w = doBearer(h, http.MethodGet, "/api/v1/admin/database/health", f.adminToken, ""); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"local"`) || !strings.Contains(w.Body.String(), `"clickhouse"`) {
		t.Fatalf("health=%d %s", w.Code, w.Body.String())
	}
}
