package api

import (
	"bytes"
	"central-flow-collector/internal/analytics"
	"central-flow-collector/internal/audit"
	"central-flow-collector/internal/auth"
	"central-flow-collector/internal/cluster"
	"central-flow-collector/internal/collector"
	"central-flow-collector/internal/config"
	"central-flow-collector/internal/enrichment"
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/policy"
	"central-flow-collector/internal/storage"
	"central-flow-collector/internal/workspace"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// v17Fixture is kept as the fixture type name for older administration tests,
// but the contents model the v4 single-organisation Flow Analytics product.
type v17Fixture struct {
	dir        string
	srv        *Server
	am         *auth.Manager
	st         storage.Backend
	an         *analytics.Engine
	reg        *cluster.Registry
	aliceToken string
	adminToken string
}

func newV17Fixture(t *testing.T) *v17Fixture {
	t.Helper()
	dir := t.TempDir()
	am, _, err := auth.New(dir, filepath.Join(dir, "bootstrap.txt"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err := am.AddUser("alice", "GoodPassw0rd!", "analyst"); err != nil {
		t.Fatal(err)
	}
	_, aliceSecret, err := am.CreateAPIToken("alice", "analyst-test", 1)
	if err != nil {
		t.Fatal(err)
	}
	_, adminSecret, err := am.CreateAPIToken("admin", "admin-test", 1)
	if err != nil {
		t.Fatal(err)
	}

	st, err := storage.NewLocal(dir, 256, 7)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	now := time.Now().UTC()
	flows := []model.Flow{
		{ReceiveTime: now.Add(-2 * time.Minute), SrcIP: "10.1.1.1", DstIP: "8.8.8.8", DstCountry: "US", DstAS: 15169, DstPort: 443, Protocol: "netflow5", IPProtocol: 6, AppName: "https", Exporter: "192.0.2.10", IngressIf: 1, EgressIf: 2, Bytes: 5000, Packets: 5},
		{ReceiveTime: now.Add(-time.Minute), SrcIP: "10.2.2.2", DstIP: "1.1.1.1", DstCountry: "AU", DstAS: 13335, DstPort: 53, Protocol: "netflow5", IPProtocol: 17, AppName: "dns", Exporter: "192.0.2.11", IngressIf: 3, EgressIf: 4, Bytes: 9000, Packets: 9},
	}
	for _, f := range flows {
		if err := st.Write(f); err != nil {
			t.Fatal(err)
		}
	}

	an := analytics.New()
	pe, err := policy.New(filepath.Join(dir, "policies.json"), "deny")
	if err != nil {
		t.Fatal(err)
	}
	en, err := enrichment.New(dir, false, "")
	if err != nil {
		t.Fatal(err)
	}
	ws, err := workspace.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Storage.DataDir = dir
	cfg.Listeners = nil
	col := collector.New(cfg, pe, st, an, en)
	srv := New(am, pe, col, st, an, audit.New(dir), en, ws)
	reg, err := cluster.NewRegistry(filepath.Join(dir, "cluster-nodes.json"), "cluster-secret", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	srv.SetCluster(reg)
	return &v17Fixture{dir: dir, srv: srv, am: am, st: st, an: an, reg: reg, aliceToken: aliceSecret, adminToken: adminSecret}
}

func doBearer(h http.Handler, method, path, token, body string) *httptest.ResponseRecorder {
	b := bytes.NewReader([]byte(body))
	r := httptest.NewRequest(method, "http://collector"+path, b)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
