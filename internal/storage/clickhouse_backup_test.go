package storage

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClickHouseLogicalBackupVerifyRestore(t *testing.T) {
	rows := "{\"receive_time\":\"2026-01-01 00:00:00.000\",\"collector_node\":\"n1\"}\n{\"receive_time\":\"2026-01-01 00:00:01.000\",\"collector_node\":\"n1\"}\n"
	inserts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		switch {
		case strings.HasPrefix(q, "CREATE"), strings.HasPrefix(q, "ALTER"):
			w.WriteHeader(200)
		case strings.HasPrefix(q, "SELECT *"):
			_, _ = w.Write([]byte(rows))
		case strings.HasPrefix(q, "INSERT INTO"):
			inserts++
			w.WriteHeader(200)
		default:
			w.WriteHeader(200)
		}
	}))
	defer ts.Close()
	c, e := NewClickHouse(ClickHouseConfig{URL: ts.URL, Database: "flowcollector", Table: "flows", DataDir: t.TempDir(), RetentionDays: 7})
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	p := filepath.Join(t.TempDir(), "flows.jsonl.gz")
	m, e := c.LogicalBackup(context.Background(), p, zeroTime(), zeroTime())
	if e != nil {
		t.Fatal(e)
	}
	if m.Rows != 2 {
		t.Fatalf("rows=%d", m.Rows)
	}
	if _, e = VerifyClickHouseBackup(p); e != nil {
		t.Fatal(e)
	}
	if _, e = c.LogicalRestore(context.Background(), p, true); e != nil {
		t.Fatal(e)
	}
	if inserts != 1 {
		t.Fatalf("inserts=%d", inserts)
	}
	b, _ := os.ReadFile(p + ".manifest.json")
	var mm ClickHouseBackupManifest
	if json.Unmarshal(b, &mm) != nil || mm.SHA256 == "" {
		t.Fatal("manifest")
	}
}
func zeroTime() (z time.Time) { return }
