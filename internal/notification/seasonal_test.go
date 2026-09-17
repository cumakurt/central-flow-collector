package notification

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"central-flow-collector/internal/intelligence"
)

func seasonalRule() RuleDefinition {
	r := testRule()
	r.Kind = "seasonal"
	r.WindowSeconds = 3600
	r.IntervalSeconds = 3600
	r.ForSeconds = 3600
	r.Threshold = 4
	r.MinimumCurrent = 100
	r.CooldownSeconds = 86400
	x := 2.0
	r.RecoveryThreshold = &x
	return r
}

func TestSeasonalFiveBoundedWindowsAndSampling(t *testing.T) {
	r := seasonalRule()
	at := time.Date(2026, 9, 16, 10, 30, 0, 0, time.UTC)
	calls := 0
	fn := func(ctx context.Context, q RuleDefinition, end time.Time) ([]Observation, error) {
		if q.Kind != "aggregate" || q.WindowSeconds != 3600 || end.Minute() != 0 {
			t.Fatal(q, end)
		}
		v := 1000.0
		if calls == 0 {
			v = 2000
		}
		calls++
		return []Observation{{Entity: "router", Value: v, Records: 10}}, nil
	}
	obs, err := EvaluateSeasonal(context.Background(), r, at, fn)
	if err != nil || calls != 5 || len(obs) != 1 || obs[0].Baseline.Expected != 1000 || obs[0].Baseline.History != 4 {
		t.Fatal(obs, err, calls)
	}
	if !obs[0].Baseline.WindowEnd.Equal(at.Truncate(time.Hour)) {
		t.Fatal(obs)
	}
	withheld := func(context.Context, RuleDefinition, time.Time) ([]Observation, error) {
		return []Observation{{Entity: "router", Value: 1000, Records: 10, SamplingUnavailable: 1}}, nil
	}
	obs, err = EvaluateSeasonal(context.Background(), r, at, withheld)
	if err != nil || len(obs) != 0 {
		t.Fatal("sampling must withhold observations", obs, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = EvaluateSeasonal(ctx, r, at, fn); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestSeasonalLifecycleMissingDoesNotRecover(t *testing.T) {
	s := testState()
	r := seasonalRule()
	at := time.Date(2026, 9, 16, 12, 1, 0, 0, time.UTC)
	step := func(hour int, value float64) {
		t.Helper()
		end := at.Add(time.Duration(hour) * time.Hour).Truncate(time.Hour)
		b := intelligence.SeasonalBounds([]float64{1000, 1000, 1000, 1000}, 4, 100)
		b.WindowEnd = end
		if _, err := applyEvaluation(&s, r, []Observation{{Entity: "router", Value: value, Baseline: &b}}, at.Add(time.Duration(hour)*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	step(0, 2000)
	step(1, 2000)
	key := alertKey(r.ID, "router")
	if s.Alerts[key].State != "FIRING" || len(s.Deliveries) != 2 {
		t.Fatal(s.Alerts, len(s.Deliveries))
	}
	if _, err := applyEvaluation(&s, r, nil, at.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if s.Alerts[key].State != "FIRING" || len(s.Deliveries) != 2 {
		t.Fatal("missing baseline falsely recovered")
	}
	step(3, 1200) // Outside recovery range (125), inside entry range (250).
	if s.Alerts[key].State != "FIRING" {
		t.Fatal("hysteresis lost")
	}
	step(4, 1100)
	if s.Alerts[key].State != "RECOVERED" || len(s.Deliveries) != 4 {
		t.Fatal("recovery not delivered")
	}
	c := s.Deliveries[2].Context
	if !strings.Contains(c.Summary, "Expected 1000") || c.Threshold != 1250 || c.State != "RECOVERED" {
		t.Fatal(c)
	}
	// Production renderer and previews share this context.
	m, err := RenderMessage(c, "")
	if err != nil || !strings.Contains(m.HTML, "Expected 1000") || !strings.Contains(m.Telegram, "RECOVERED") {
		t.Fatal(m, err)
	}
}

func TestSeasonalPendingGapAndRepeatedWindow(t *testing.T) {
	s := testState()
	r := seasonalRule()
	at := time.Date(2026, 9, 16, 12, 1, 0, 0, time.UTC)
	b := intelligence.SeasonalBounds([]float64{1000, 1000, 1000}, 4, 100)
	b.WindowEnd = at.Truncate(time.Hour)
	o := Observation{Entity: "router", Value: 2000, Baseline: &b}
	if _, err := applyEvaluation(&s, r, []Observation{o}, at); err != nil {
		t.Fatal(err)
	}
	if _, err := applyEvaluation(&s, r, []Observation{o}, at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(s.Deliveries) != 0 {
		t.Fatal("same interval counted twice")
	}
	next := b
	next.WindowEnd = next.WindowEnd.Add(2 * time.Hour)
	o.Baseline = &next
	if _, err := applyEvaluation(&s, r, []Observation{o}, at.Add(2*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(s.Deliveries) != 0 || s.Alerts[alertKey(r.ID, "router")].State != "PENDING" {
		t.Fatal("gap must reset pending continuity")
	}
}

func TestSeasonalSimulationUsesProductionLifecycleAndPreview(t *testing.T) {
	r := seasonalRule()
	start := time.Date(2020, 9, 14, 10, 1, 0, 0, time.UTC)
	end := start.Truncate(time.Hour)
	fn := func(ctx context.Context, q RuleDefinition, at time.Time) ([]Observation, error) {
		return EvaluateSeasonal(ctx, q, at, func(_ context.Context, _ RuleDefinition, bucket time.Time) ([]Observation, error) {
			value := 1000.0
			if bucket.After(end) && !bucket.After(end.Add(2*time.Hour)) {
				value = 2000
			}
			return []Observation{{Entity: "router", Value: value, Records: 10}}, nil
		})
	}
	p, err := OpenPlatform(t.TempDir(), fn)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	if err = p.transaction(func(s *platformState) error { *s = testState(); return nil }); err != nil {
		t.Fatal(err)
	}
	out, err := p.Simulate(context.Background(), r, start, start.Add(3*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if out.Counts.AfterDedup != 1 || out.Counts.Recoveries != 1 || out.Notifications["email"] != 2 || out.Notifications["telegram"] != 2 || out.Latest == nil {
		t.Fatalf("%+v", out)
	}
	if !strings.Contains(out.Latest.HTML, "Expected 1000") || !strings.Contains(out.Latest.Telegram, "RECOVERED") {
		t.Fatal(out.Latest)
	}
	if len(p.state.Alerts) != 0 || len(p.state.Deliveries) != 0 {
		t.Fatal("simulation mutated live state")
	}
}

func TestSeasonalBaselineSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	p, err := OpenPlatform(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := seasonalRule()
	at := time.Date(2020, 9, 14, 10, 1, 0, 0, time.UTC)
	b := intelligence.SeasonalBounds([]float64{1000, 1000, 1000}, 4, 100)
	b.WindowEnd = at.Truncate(time.Hour)
	if err = p.transaction(func(s *platformState) error {
		*s = testState()
		_, err := applyEvaluation(s, r, []Observation{{Entity: "router", Value: 2000, Baseline: &b}}, at)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	p.Close()
	restored, err := OpenPlatform(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	a := restored.state.Alerts[alertKey(r.ID, "router")]
	if a.State != "PENDING" || a.Baseline == nil || a.Baseline.Expected != 1000 || !a.Baseline.WindowEnd.Equal(b.WindowEnd) {
		t.Fatal(a)
	}
}

func TestSeasonalRejectsExcessGroups(t *testing.T) {
	fn := func(context.Context, RuleDefinition, time.Time) ([]Observation, error) {
		return make([]Observation, MaxGroups+1), nil
	}
	if _, err := EvaluateSeasonal(context.Background(), seasonalRule(), time.Now(), fn); err == nil {
		t.Fatal("unbounded seasonal groups accepted")
	}
}

func BenchmarkSeasonalRule1000Groups(b *testing.B) {
	rows := make([]Observation, 1000)
	for i := range rows {
		rows[i] = Observation{Entity: fmt.Sprintf("entity-%d", i), Value: 1000, Records: 10}
	}
	fn := func(context.Context, RuleDefinition, time.Time) ([]Observation, error) { return rows, nil }
	r := seasonalRule()
	at := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := EvaluateSeasonal(context.Background(), r, at, fn); err != nil {
			b.Fatal(err)
		}
	}
}
