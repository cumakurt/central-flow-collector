package api

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestServiceCatalogAndSeriesEndpoints(t *testing.T) {
	f := newV17Fixture(t)
	h := f.srv.Handler()
	w := doBearer(h, http.MethodGet, "/api/v1/analytics/service-catalog", f.aliceToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("catalog status=%d body=%s", w.Code, w.Body.String())
	}
	var catalog struct {
		Services []struct {
			ID    string `json:"id"`
			Rules []struct {
				Port      uint16   `json:"port"`
				Protocols []uint16 `json:"protocols"`
			} `json:"rules"`
		} `json:"services"`
		Max int `json:"max_series"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &catalog); err != nil {
		t.Fatal(err)
	}
	if catalog.Max != 8 || len(catalog.Services) < 15 {
		t.Fatalf("catalog=%+v", catalog)
	}
	if len(catalog.Services[0].Rules) == 0 || len(catalog.Services[0].Rules[0].Protocols) == 0 || catalog.Services[0].Rules[0].Protocols[0] != 6 {
		t.Fatalf("catalog protocol JSON must be a numeric array, got %+v", catalog.Services[0].Rules)
	}

	w = doBearer(h, http.MethodGet, "/api/v1/analytics/service-series?series_service=dns&series_service=https&series_port=tcp%3A8443", f.aliceToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("series status=%d body=%s", w.Code, w.Body.String())
	}
	var out struct {
		Series []struct {
			Selector struct {
				Label     string   `json:"label"`
				Protocols []uint16 `json:"protocols"`
			} `json:"selector"`
			Totals struct {
				Flows uint64 `json:"flows"`
			} `json:"totals"`
		} `json:"series"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Series) != 3 || out.Series[0].Totals.Flows != 1 || out.Series[1].Totals.Flows != 1 {
		t.Fatalf("series=%+v", out.Series)
	}
	if got := out.Series[2].Selector.Protocols; len(got) != 1 || got[0] != 6 {
		t.Fatalf("custom port selector protocol JSON must be [6], got %v", got)
	}
}

func TestServiceSeriesRejectsInvalidAndTooManySelectors(t *testing.T) {
	f := newV17Fixture(t)
	h := f.srv.Handler()
	for _, path := range []string{
		"/api/v1/analytics/service-series?series_service=unknown",
		"/api/v1/analytics/service-series?series_port=tcp%3A70000",
		"/api/v1/analytics/service-series?series_service=smtp&series_service=dns&series_service=https&series_service=ssh&series_service=rdp&series_service=imap&series_service=pop3&series_service=ntp&series_service=snmp",
	} {
		w := doBearer(h, http.MethodGet, path, f.aliceToken, "")
		if w.Code != http.StatusBadRequest {
			t.Fatalf("path=%s status=%d body=%s", path, w.Code, w.Body.String())
		}
	}
}
