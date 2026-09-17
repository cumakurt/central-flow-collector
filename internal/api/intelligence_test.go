package api

import (
	"central-flow-collector/internal/intelligence"
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/notification"
	"context"
	"encoding/csv"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestIntelligenceAPI(t *testing.T) {
	f := newV17Fixture(t)
	h := f.srv.Handler()
	for _, kind := range []string{"changes", "concentration", "distribution", "relationships", "diversity", "temporal", "quality", "persistence", "anomalies"} {
		dimension := "application"
		if kind == "distribution" {
			dimension = "bytes"
		}
		w := doBearer(h, "GET", "/api/v1/analytics/query?kind="+kind+"&dimension="+dimension, f.aliceToken, "")
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", kind, w.Code, w.Body.String())
		}
		var result intelligence.Result
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if result.Summary["observed_flows"] != 2 {
			t.Fatal(result)
		}
	}
	for _, query := range []string{"kind=bad", "dimension=sql", "metric=bad", "top=101", "bins=1000", "threshold=NaN", "threshold=101", "bucket=1", "format=pdf", "from=bad"} {
		w := doBearer(h, "GET", "/api/v1/analytics/query?"+query, f.aliceToken, "")
		if w.Code != 400 {
			t.Fatalf("%s: %d", query, w.Code)
		}
	}
	for _, format := range []string{"csv", "json"} {
		w := doBearer(h, "GET", "/api/v1/analytics/query?format="+format, f.adminToken, "")
		if w.Code != 200 || w.Header().Get("Content-Disposition") == "" {
			t.Fatal(w.Code, w.Body.String())
		}
		if format == "csv" {
			if _, err := csv.NewReader(w.Body).ReadAll(); err != nil {
				t.Fatal(err)
			}
		}
	}
	w := doBearer(h, http.MethodGet, "/api/v1/analytics/query", "", "")
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	f.srv.intelligenceState.active.Store(2)
	w = doBearer(h, "GET", "/api/v1/analytics/query", f.aliceToken, "")
	if w.Code != 429 {
		t.Fatal(w.Code)
	}
	f.srv.intelligenceState.active.Store(0)
}

func TestAnomalyHistoricalAPI(t *testing.T) {
	f := newV17Fixture(t)
	to := time.Now().UTC().Truncate(time.Hour)
	from := to.AddDate(0, 0, -30)
	for hour := 1; hour <= 2; hour++ {
		for week := 0; week <= 4; week++ {
			value := uint64(10_000_000)
			if week == 0 {
				value = 20_000_000
			}
			err := f.srv.Store.Write(model.Flow{ReceiveTime: to.Add(-time.Duration(hour)*time.Hour).AddDate(0, 0, -7*week), SrcIP: "192.0.2.9", DstIP: "198.51.100.9", AppName: "anomaly-fixture", Bytes: value, Packets: 100, Sampling: 1})
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	w := doBearer(f.srv.Handler(), "GET", "/api/v1/analytics/query?kind=anomalies&dimension=application&src_ip=192.0.2.9&from="+from.Format(time.RFC3339)+"&to="+to.Format(time.RFC3339), f.aliceToken, "")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var r intelligence.Result
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Anomalies == nil || len(r.Anomalies.Events) != 1 || r.Anomalies.Events[0].State != "ACTIVE" || r.Anomalies.Comparison.Summary["delta"] != 10_000_000 {
		t.Fatalf("%s", w.Body.String())
	}
	var rule notification.RuleDefinition
	for _, v := range notification.RuleTemplates() {
		if v.Kind == "seasonal" {
			rule = v
		}
	}
	rule.GroupBy = []string{"src_ip"}
	rule.Condition = notification.Condition{Op: "eq", Field: "src_ip", Values: []string{"192.0.2.9"}}
	obs, err := f.srv.EvaluateNotificationRule(context.Background(), rule, to.Add(time.Minute))
	if err != nil || len(obs) != 1 || obs[0].Baseline.Expected != 10_000_000 || obs[0].Value != 20_000_000 {
		t.Fatal(obs, err)
	}
}
