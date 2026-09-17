package api

import (
	"central-flow-collector/internal/auth"
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/storage"
	"encoding/csv"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFlowExportLimitsAndFormats(t *testing.T) {
	store, err := storage.NewLocal(t.TempDir(), 16384, 7)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Now().UTC().Truncate(time.Second)
	for i := 0; i < 10001; i++ {
		if err := store.Write(model.Flow{ReceiveTime: now, SrcIP: "192.0.2.1", DstIP: "198.51.100.1", Bytes: 42}); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{Store: store}
	for _, format := range []string{"csv", "json"} {
		for _, tc := range []struct {
			limit string
			count int
		}{{"10000", 10000}, {"5001", 5001}, {"1", 1}, {"", 500}} {
			t.Run(format+"/"+tc.limit, func(t *testing.T) {
				r := httptest.NewRequest("GET", "/api/v1/flows/export?format="+format+"&limit="+tc.limit+"&src_ip=192.0.2.1", nil)
				w := httptest.NewRecorder()
				s.flowExport(w, r, auth.Session{})
				if w.Code != 200 {
					t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
				}
				if got := w.Header().Get("Content-Disposition"); got != "attachment; filename=flows."+format {
					t.Fatalf("disposition=%q", got)
				}
				if format == "json" {
					var rows []model.Flow
					if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil {
						t.Fatal(err)
					}
					if len(rows) != tc.count {
						t.Fatalf("rows=%d want=%d", len(rows), tc.count)
					}
				} else {
					rows, err := csv.NewReader(w.Body).ReadAll()
					if err != nil {
						t.Fatal(err)
					}
					if len(rows)-1 != tc.count {
						t.Fatalf("rows=%d want=%d", len(rows)-1, tc.count)
					}
				}
			})
		}
	}
	for _, query := range []string{"limit=10001", "limit=0", "limit=-1", "limit=abc", "limit=10000&src_cidr=invalid", "limit=10000&from=invalid"} {
		w := httptest.NewRecorder()
		s.flowExport(w, httptest.NewRequest("GET", "/api/v1/flows/export?"+query, nil), auth.Session{})
		if w.Code != 400 {
			t.Errorf("query=%s status=%d", query, w.Code)
		}
	}
	w := httptest.NewRecorder()
	s.flowExport(w, httptest.NewRequest("GET", "/api/v1/flows/export?format=json&limit=10000&src_ip=203.0.113.1", nil), auth.Session{})
	if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "[]" {
		t.Fatalf("nonmatching filter: status=%d body=%s", w.Code, w.Body.String())
	}
	if _, err := storage.ParseQuery(map[string][]string{"limit": {"5001"}}); err == nil {
		t.Fatal("regular query must retain its 5000-row limit")
	}
}
