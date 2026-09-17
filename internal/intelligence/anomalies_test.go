package intelligence

import (
	"fmt"
	"testing"
	"time"
)

func TestMedianMAD(t *testing.T) {
	m, d := MedianMAD([]float64{100, 102, 98, 101, 99, 100})
	closeTo(t, m, 100)
	closeTo(t, d, 1)
	m, d = MedianMAD([]float64{100, 100, 100, 100, 1000})
	closeTo(t, m, 100)
	closeTo(t, d, 0)
	m, d = MedianMAD([]float64{1, 2})
	closeTo(t, m, 1.5)
	closeTo(t, d, .5)
}

func anomalyFixture(values []uint64) (Spec, []Group, time.Time, time.Time) {
	s := spec("anomalies")
	s.Metric = "flows"
	s.Top = 100
	start := time.Date(2026, 9, 14, 0, 0, 0, 0, time.UTC)
	groups := []Group{}
	for hour, value := range values {
		at := start.Add(time.Duration(hour) * time.Hour)
		groups = append(groups, Group{Key: "A", Bucket: at.Unix(), Flows: value, Period: 1})
		for week := 1; week <= 4; week++ {
			groups = append(groups, Group{Key: "A", Bucket: at.AddDate(0, 0, -7*week).Unix(), Flows: 1000, Period: 1})
		}
	}
	return s, groups, start.AddDate(0, 0, -28), start.Add(time.Duration(len(values)) * time.Hour)
}

func TestAnomalySustainedRecoveryAndSingleSpike(t *testing.T) {
	s, g, from, to := anomalyFixture([]uint64{1000, 2000, 2000, 1000})
	a := analyzeAnomalies(s, g, from, to)
	if a.Status != "evaluated" || len(a.Events) != 1 || a.Events[0].State != "RECOVERED" || a.Events[0].Type != "Persistent Traffic Level Change" {
		t.Fatalf("%+v", a)
	}
	closeTo(t, a.Events[0].Expected, 1000)
	if a.Events[0].RobustZ != nil {
		t.Fatal("zero MAD must not produce an infinite robust z-score")
	}
	s, g, from, to = anomalyFixture([]uint64{1000, 2000, 1000, 1000})
	a = analyzeAnomalies(s, g, from, to)
	if len(a.Events) != 1 || a.Events[0].Type == "Persistent Traffic Level Change" {
		t.Fatalf("single spike: %+v", a.Events)
	}
	// Drops are detected with the same absolute/relative gate.
	s, g, from, to = anomalyFixture([]uint64{1000, 200, 200})
	a = analyzeAnomalies(s, g, from, to)
	if len(a.Events) != 1 || a.Events[0].State != "ACTIVE" || a.Events[0].Delta != -800 {
		t.Fatalf("drop: %+v", a.Events)
	}
}

func TestAnomalySamplingAndHistoryGates(t *testing.T) {
	s, g, from, to := anomalyFixture([]uint64{2000, 2000})
	for i := range g {
		g[i].Sampled = g[i].Flows
	}
	a := analyzeAnomalies(s, g, from, to)
	if a.SamplingWithheld != 2 || len(a.Events) != 0 {
		t.Fatalf("sampled: %+v", a)
	}
	s, g, from, to = anomalyFixture([]uint64{2000, 2000})
	a = analyzeAnomalies(s, g, to.Add(-24*time.Hour), to)
	if a.Status != "baseline_learning" || a.Insufficient != 2 || len(a.Events) != 0 {
		t.Fatalf("warmup: %+v", a)
	}
}

func TestAnomalyMissingAndPartialIntervals(t *testing.T) {
	s, g, from, to := anomalyFixture([]uint64{2000, 2000, 2000})
	// A missing middle interval must break persistence, not become a zero.
	middle := to.Add(-2 * time.Hour).Unix()
	filtered := []Group{}
	for _, x := range g {
		if x.Bucket != middle {
			filtered = append(filtered, x)
		}
	}
	a := analyzeAnomalies(s, filtered, from, to.Add(-30*time.Minute))
	if a.Evaluated != 1 || a.EventCount != 1 || a.Events[0].State != "PENDING" {
		t.Fatalf("partial/gap: %+v", a)
	}
}

func TestAnomalyComparisonFractionalReconciliation(t *testing.T) {
	s := spec("anomalies")
	s.Top = 1
	r := anomalyComparison(s, []Group{{Key: "A", Period: 0, Value: 1.5}, {Key: "A", Period: 1, Value: 3}, {Key: "B", Period: 0, Value: 4}, {Key: "B", Period: 1, Value: 2}}, time.Time{}, time.Time{})
	closeTo(t, r.Summary["previous"], 5.5)
	closeTo(t, r.Summary["delta"], -.5)
	closeTo(t, r.Summary["other_delta"]+r.Rows[0].Delta, -.5)
}

func TestAnomalyCardinalityGuard(t *testing.T) {
	s := spec("anomalies")
	a := analyzeAnomalies(s, make([]Group, MaxGroups+1), time.Now().Add(-time.Hour), time.Now())
	if a.Status != "unavailable" {
		t.Fatal(a)
	}
}

func TestAnomalyStateFilterBeforeLimit(t *testing.T) {
	s, g, from, to := anomalyFixture([]uint64{1000, 2000, 2000, 1000, 2000, 2000})
	s.Top = 1
	s.EventState = "RECOVERED"
	a := analyzeAnomalies(s, g, from, to)
	if len(a.Events) != 1 || a.Events[0].State != "RECOVERED" || a.EventCount != 1 {
		t.Fatalf("%+v", a)
	}
	s.EventState = "invalid"
	if s.Validate() == nil {
		t.Fatal("invalid episode state accepted")
	}
}

func BenchmarkSeasonalAnomalies(b *testing.B) {
	s, g, from, to := anomalyFixture([]uint64{1000, 2000, 2000, 1000})
	rows := make([]Group, 0, 20000)
	for i := 0; i < 1000; i++ {
		for _, x := range g {
			x.Key = fmt.Sprintf("entity-%d", i)
			rows = append(rows, x)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		analyzeAnomalies(s, rows, from, to)
	}
}
