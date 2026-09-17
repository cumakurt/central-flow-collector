package storage

import (
	"central-flow-collector/internal/intelligence"
	"central-flow-collector/internal/model"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func intelligenceSpec() intelligence.Spec {
	return intelligence.Spec{Kind: "changes", Dimension: "application", Metric: "bytes", Peer: "dst_ip", Bucket: 3600, Top: 25, Bins: 24, Strategy: "linear", Threshold: 99}
}
func TestIntelligenceHalfOpenFiltersAndSampling(t *testing.T) {
	l, e := NewLocal(t.TempDir(), 32, 7)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	from := time.Now().UTC().Truncate(time.Hour)
	to := from.Add(time.Hour)
	for _, f := range []model.Flow{{ReceiveTime: from.Add(-time.Hour), SrcIP: "a", Bytes: 10}, {ReceiveTime: from, SrcIP: "a", Bytes: 20, Sampling: 100}, {ReceiveTime: to, SrcIP: "a", Bytes: 99}, {ReceiveTime: from, SrcIP: "b", Bytes: 99}} {
		if e := l.Write(f); e != nil {
			t.Fatal(e)
		}
	}
	gs, e := l.IntelligenceGroups(context.Background(), Query{From: from, To: to, SrcIP: "a"}, intelligenceSpec())
	if e != nil {
		t.Fatal(e)
	}
	r := intelligence.Calculate(intelligenceSpec(), gs, from, to)
	if r.Summary["current"] != 20 || r.Summary["previous"] != 10 || r.Summary["sampled_records"] != 1 {
		t.Fatal(r.Summary)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e = l.IntelligenceGroups(ctx, Query{From: from, To: to}, intelligenceSpec()); e == nil {
		t.Fatal("cancel ignored")
	}
}
func TestIntelligenceCardinalityBound(t *testing.T) {
	l, e := NewLocal(t.TempDir(), 32768, 7)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	now := time.Now().UTC()
	for i := 0; i <= intelligence.MaxGroups; i++ {
		if e = l.Write(model.Flow{ReceiveTime: now, SrcIP: fmt.Sprint(i), Bytes: 1}); e != nil {
			t.Fatal(e)
		}
	}
	s := intelligenceSpec()
	s.Dimension = "src_ip"
	_, e = l.IntelligenceGroups(context.Background(), Query{From: now.Add(-time.Hour), To: now.Add(time.Second)}, s)
	if !errors.Is(e, intelligence.ErrCardinality) {
		t.Fatalf("got %v", e)
	}
}
func TestIntelligenceSQLParameterized(t *testing.T) {
	s := intelligenceSpec()
	q := Query{From: time.Now(), To: time.Now().Add(time.Hour), App: "' OR 1=1 --"}
	sql, values := buildIntelligenceSQL(q, s, "flows", q.From)
	if strings.Contains(sql, q.App) || values["param_app"][0] != q.App {
		t.Fatal("unsafe filter")
	}
	if !strings.Contains(sql, "receive_time <") || !strings.Contains(sql, "GROUP BY") {
		t.Fatal(sql)
	}
	s.Dimension = "src_ip); DROP TABLE flows"
	if s.Validate() == nil {
		t.Fatal("unsafe dimension")
	}
}

func TestDirectionalCohortFilters(t *testing.T) {
	q, e := ParseQuery(map[string][]string{"src_site": {"Users"}, "dst_site": {"Services"}, "src_country": {"TR"}, "dst_country": {"DE"}})
	if e != nil {
		t.Fatal(e)
	}
	f := model.Flow{SrcSite: "Users", DstSite: "Services", SrcCountry: "TR", DstCountry: "DE"}
	if !match(f, q) {
		t.Fatal("expected directional cohort")
	}
	f.SrcSite = "Services"
	f.DstSite = "Users"
	if match(f, q) {
		t.Fatal("reverse cohort must not match")
	}
	sql, params := chAnalysisWhere(q)
	for _, key := range []string{"src_site", "dst_site", "src_country", "dst_country"} {
		if !strings.Contains(sql, key+" = {"+key+":String}") || len(params["param_"+key]) != 1 {
			t.Fatal(sql)
		}
	}
}
