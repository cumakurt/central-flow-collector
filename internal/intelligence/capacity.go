package intelligence

import (
	"math"
	"sort"
	"time"
)

// capacity derives a transparent linear forecast from complete UTC daily P95s.
// It does not interpret missing records as verified telemetry completeness.
func capacity(r *Result) {
	if r.Spec.CapacityBPS > 0 {
		c := r.Spec.CapacityBPS
		r.Summary["p95_utilization_percent"] = 100 * r.Summary["p95"] / c
		r.Summary["peak_utilization_percent"] = 100 * r.Summary["peak_rate"] / c
		r.Summary["headroom_percent"] = 100 - r.Summary["p95_utilization_percent"]
		r.Notes = append(r.Notes, "Capacity is an operator-supplied assumption for this filtered view, not discovered interface metadata.")
	}
	if r.Spec.Metric != "bytes" || r.Spec.Bucket >= 86400 {
		return
	}
	days := map[int64][]float64{}
	for _, p := range r.Curve {
		day := int64(p.X) / 1000 / 86400
		days[day] = append(days[day], p.Y)
	}
	keys := []int64{}
	for day, values := range days {
		start := time.Unix(day*86400, 0)
		if !start.Before(r.From) && !start.Add(24*time.Hour).After(r.To) && len(values) == 86400/r.Spec.Bucket {
			keys = append(keys, day)
		}
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
	if len(keys) < 7 {
		r.Notes = append(r.Notes, "Capacity forecast unavailable: at least seven complete UTC days are required.")
		return
	}
	n := float64(len(keys))
	var sx, sy float64
	points := make([]Point, 0, len(keys))
	for _, day := range keys {
		values := days[day]
		sort.Float64s(values)
		y := values[int(math.Ceil(.95*float64(len(values))))-1]
		x := float64(day - keys[0])
		points = append(points, Point{x, y})
		sx += x
		sy += y
	}
	mx, my := sx/n, sy/n
	var xy, xx, yy float64
	for _, p := range points {
		xy += (p.X - mx) * (p.Y - my)
		xx += (p.X - mx) * (p.X - mx)
		yy += (p.Y - my) * (p.Y - my)
	}
	slope := ratio(xy, xx)
	intercept := my - slope*mx
	last := float64(keys[len(keys)-1] - keys[0])
	estimate := intercept + slope*last
	r.Summary["forecast_history_days"] = n
	r.Summary["daily_p95_slope_bps"] = slope
	r.Summary["forecast_r_squared"] = ratio(xy*xy, xx*yy)
	r.Summary["projected_p95_30d_bps"] = max(0, estimate+30*slope)
	if r.Spec.CapacityBPS > 0 && slope > 0 {
		r.Summary["estimated_days_to_capacity"] = max(0, (r.Spec.CapacityBPS-estimate)/slope)
	}
	r.Notes = append(r.Notes, "Forecast is an estimate: ordinary least squares on complete UTC daily P95s, projected 30 days beyond the last complete day. R² describes fit, not confidence. Telemetry gaps can bias it; no exhaustion date is reported for a non-positive slope.")
}
