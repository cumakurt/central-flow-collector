package intelligence

import (
	"testing"
	"time"
)

func TestCapacityLinearDailyP95(t *testing.T) {
	from := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	s := spec("temporal")
	s.CapacityBPS = 1000
	gs := []Group{}
	for day := 0; day < 10; day++ {
		for hour := 0; hour < 24; hour++ {
			gs = append(gs, Group{Period: 1, Bucket: from.Add(time.Duration(day*24+hour) * time.Hour).Unix(), Bytes: uint64((100 + day*10) * 3600 / 8), Flows: 1})
		}
	}
	r := Calculate(s, gs, from, from.Add(10*24*time.Hour))
	closeTo(t, r.Summary["daily_p95_slope_bps"], 10)
	closeTo(t, r.Summary["forecast_r_squared"], 1)
	closeTo(t, r.Summary["projected_p95_30d_bps"], 490)
	closeTo(t, r.Summary["estimated_days_to_capacity"], 81)
	r = Calculate(s, gs[:24], from, from.Add(24*time.Hour))
	if _, ok := r.Summary["projected_p95_30d_bps"]; ok {
		t.Fatal("insufficient history")
	}
}
