package api

import (
	"central-flow-collector/internal/engineering"
	"encoding/json"
	"net/http"
	"testing"
)

func TestEngineeringAPIAndSimulator(t *testing.T) {
	f := newV17Fixture(t)
	f.srv.EngineeringRoutes = engineering.NewRouteProvider()
	h := f.srv.Handler()
	for _, path := range []string{"/api/v1/engineering/qos", "/api/v1/engineering/nat", "/api/v1/engineering/routing", "/api/v1/engineering/coverage"} {
		w := doBearer(h, http.MethodGet, path, f.aliceToken, "")
		if w.Code != 200 {
			t.Fatalf("%s %d %s", path, w.Code, w.Body.String())
		}
		var x engineering.EngineeringSummary
		if e := json.Unmarshal(w.Body.Bytes(), &x); e != nil {
			t.Fatal(e)
		}
	}
	w := doBearer(h, http.MethodPost, "/api/v1/capacity/simulate", f.aliceToken, `{"current_raw_days":30,"proposed_raw_days":90,"current_aggregate_days":90,"proposed_aggregate_days":180,"current_sampling":100,"proposed_sampling":500,"current_daily_bytes":1000000000000,"free_bytes":20000000000000}`)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = doBearer(h, http.MethodPost, "/api/v1/engineering/routes", f.aliceToken, `[{"prefix":"10.0.0.0/8","origin_asn":64512}]`)
	if w.Code != 403 {
		t.Fatalf("analyst route mutation %d", w.Code)
	}
}
