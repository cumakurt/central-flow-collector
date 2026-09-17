package intelligence

import (
	"crypto/sha256"
	"fmt"
	"math"
	"sort"
	"time"
)

// AnomalyAnalysis is a bounded retrospective reconstruction, not a live alert.
type AnomalyAnalysis struct {
	Method           string         `json:"method"`
	Status           string         `json:"status"`
	Reason           string         `json:"reason"`
	MinimumHistory   int            `json:"minimum_history"`
	Evaluated        int            `json:"evaluated"`
	Insufficient     int            `json:"insufficient_history"`
	SamplingWithheld int            `json:"sampling_withheld"`
	Missing          int            `json:"missing_intervals"`
	Events           []AnomalyEvent `json:"events"`
	EventCount       int            `json:"event_count"`
	Timeline         []AnomalyPoint `json:"timeline"`
	Comparison       *Result        `json:"comparison,omitempty"`
}

type AnomalyPoint struct {
	Time     int64   `json:"time"`
	Observed float64 `json:"observed"`
	Expected float64 `json:"expected"`
	Lower    float64 `json:"lower"`
	Upper    float64 `json:"upper"`
	Eligible int     `json:"eligible_entities"`
}

type AnomalyEvent struct {
	ID           string   `json:"id"`
	Type         string   `json:"type"`
	Metric       string   `json:"metric"`
	Scope        string   `json:"scope"`
	Entity       string   `json:"entity"`
	State        string   `json:"state"`
	Start        int64    `json:"start"`
	End          int64    `json:"end"`
	Observed     float64  `json:"observed"`
	Expected     float64  `json:"expected"`
	Lower        float64  `json:"lower"`
	Upper        float64  `json:"upper"`
	Delta        float64  `json:"delta"`
	Percent      *float64 `json:"deviation_percent"`
	RobustZ      *float64 `json:"robust_z"`
	History      int      `json:"history_depth"`
	Confidence   string   `json:"confidence"`
	DataCoverage *float64 `json:"data_coverage"`
	Reason       string   `json:"reason"`
}

func median(values []float64) float64 {
	x := append([]float64(nil), values...)
	sort.Float64s(x)
	if len(x) == 0 {
		return 0
	}
	i := len(x) / 2
	if len(x)%2 == 0 {
		return x[i-1]/2 + x[i]/2
	}
	return x[i]
}

// MedianMAD returns the ordinary midpoint median and unscaled MAD.
func MedianMAD(values []float64) (float64, float64) {
	m := median(values)
	d := make([]float64, len(values))
	for i, v := range values {
		d[i] = math.Abs(v - m)
	}
	return m, median(d)
}

// SeasonalEstimate contains raw counter/rate units, never a disguised score.
type SeasonalEstimate struct {
	Expected  float64   `json:"expected"`
	Scale     float64   `json:"scale"`
	Lower     float64   `json:"lower"`
	Upper     float64   `json:"upper"`
	History   int       `json:"history"`
	WindowEnd time.Time `json:"window_end"`
}

func SeasonalBounds(history []float64, multiplier, absoluteFloor float64) SeasonalEstimate {
	expected, mad := MedianMAD(history)
	width := max(multiplier*1.4826*mad, .25*expected, absoluteFloor)
	return SeasonalEstimate{Expected: expected, Scale: 1.4826 * mad, Lower: max(0, expected-width), Upper: expected + width, History: len(history)}
}

func anomalyFloor(metric string) float64 {
	switch metric {
	case "bytes":
		return 1_000_000
	case "packets":
		return 1000
	default:
		return 100
	}
}

func analyzeAnomalies(s Spec, groups []Group, from, to time.Time) *AnomalyAnalysis {
	a := &AnomalyAnalysis{Method: "Seasonal UTC median ± max(4 × 1.4826 × MAD, 25% × median, absolute floor). Three comparable weeks; two consecutive intervals. Observed counters only.", Status: "baseline_learning", Reason: "Insufficient historical data", MinimumHistory: 3, Events: []AnomalyEvent{}, Timeline: []AnomalyPoint{}}
	// Storage rejects excess cardinality before this function. Defend direct callers too.
	if len(groups) > MaxGroups {
		a.Status = "unavailable"
		a.Reason = ErrCardinality.Error()
		return a
	}
	if s.Bucket < 60 || !to.After(from) || to.Sub(from) > 31*24*time.Hour {
		a.Status = "unavailable"
		a.Reason = "Invalid bounded anomaly interval"
		return a
	}
	step := int64(s.Bucket)
	end := to.Unix() / step * step
	start := max((from.Unix()+step-1)/step*step, end-86400)
	if (end-start)/step > 2000 {
		a.Status = "unavailable"
		a.Reason = "Too many evaluation intervals"
		return a
	}
	byEntity := map[string]map[int64]Group{}
	for _, g := range groups {
		if time.Unix(g.Bucket, 0).Before(from) || g.Bucket+step > end {
			continue
		}
		if byEntity[g.Key] == nil {
			byEntity[g.Key] = map[int64]Group{}
		}
		h := byEntity[g.Key][g.Bucket]
		h.Bytes += g.Bytes
		h.Packets += g.Packets
		h.Flows += g.Flows
		h.Sampled += g.Sampled
		h.SamplingUnknown += g.SamplingUnknown
		byEntity[g.Key][g.Bucket] = h
	}
	keys := make([]string, 0, len(byEntity))
	for k := range byEntity {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	points := map[int64]*AnomalyPoint{}
	comparison := []Group{}
	for _, key := range keys {
		buckets := byEntity[key]
		var episode *AnomalyEvent
		streak := 0
		direction := 0.0
		flush := func(reason string) {
			if episode != nil {
				if reason != "" {
					episode.Reason = reason
				}
				if s.EventState == "" || s.EventState == episode.State {
					a.Events = append(a.Events, *episode)
				}
			}
			episode = nil
			streak = 0
			direction = 0
		}
		for at := start; at < end; at += step {
			current, exists := buckets[at]
			if !exists {
				a.Missing++
				flush("Continuity ended: no observed records; recovery cannot be established.")
				continue
			}
			history := []float64{}
			badSampling := current.Sampled > 0 || current.SamplingUnknown > 0
			for week := 1; week <= 4; week++ {
				h, ok := buckets[at-int64(week)*7*86400]
				if !ok {
					continue
				}
				badSampling = badSampling || h.Sampled > 0 || h.SamplingUnknown > 0
				history = append(history, h.Weight(s.Metric))
			}
			if len(history) < 3 {
				a.Insufficient++
				flush("Insufficient comparable history; continuity is unknown.")
				continue
			}
			if badSampling {
				a.SamplingWithheld++
				flush("Sampling is reported or unknown; automatic deviation classification withheld.")
				continue
			}
			baseline := SeasonalBounds(history, 4, anomalyFloor(s.Metric))
			expected, scale := baseline.Expected, baseline.Scale
			width := baseline.Upper - expected
			observed := current.Weight(s.Metric)
			delta := observed - expected
			a.Evaluated++
			p := points[at]
			if p == nil {
				p = &AnomalyPoint{Time: at * 1000}
				points[at] = p
			}
			p.Observed += observed
			p.Expected += expected
			p.Lower += max(0, expected-width)
			p.Upper += expected + width
			p.Eligible++
			if at == end-step {
				// Value holds fractional medians; comparison below uses them directly.
				comparison = append(comparison, Group{Key: key, Value: expected, Period: 0}, Group{Key: key, Value: observed, Period: 1})
			}
			if episode != nil && (math.Abs(delta) <= width/2 || delta*direction <= 0) {
				episode.State = "RECOVERED"
				episode.End = at * 1000
				flush("")
			}
			if math.Abs(delta) > width {
				if episode == nil {
					direction = delta
					hash := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%s/%d", s.Dimension, key, s.Metric, at)))
					episode = &AnomalyEvent{ID: fmt.Sprintf("deviation-%x", hash[:12]), Type: "Traffic Volume Deviation", Metric: s.Metric, Scope: s.Dimension, Entity: key, State: "PENDING", Start: at * 1000, Confidence: "Limited", Reason: "Three or four comparable weeks; historical exporter completeness is unavailable."}
				}
				streak++
				if streak >= 2 {
					episode.State = "ACTIVE"
					episode.Type = "Persistent Traffic Level Change"
				}
			} else if episode != nil && episode.State == "PENDING" {
				flush("Entry condition was not sustained for two consecutive intervals.")
			}
			if episode != nil {
				episode.End = (at + step) * 1000
				episode.Observed = observed
				episode.Expected = expected
				episode.Lower = max(0, expected-width)
				episode.Upper = expected + width
				episode.Delta = delta
				episode.History = len(history)
				if expected > 0 {
					v := 100 * delta / expected
					episode.Percent = &v
				}
				if scale > 0 {
					v := delta / scale
					episode.RobustZ = &v
				}
			}
		}
		flush("")
	}
	for _, p := range points {
		a.Timeline = append(a.Timeline, *p)
	}
	sort.Slice(a.Timeline, func(i, j int) bool { return a.Timeline[i].Time < a.Timeline[j].Time })
	sort.Slice(a.Events, func(i, j int) bool {
		if a.Events[i].Start == a.Events[j].Start {
			return a.Events[i].ID < a.Events[j].ID
		}
		return a.Events[i].Start > a.Events[j].Start
	})
	a.EventCount = len(a.Events)
	if len(a.Events) > s.Top {
		a.Events = a.Events[:s.Top]
	}
	if a.Evaluated > 0 {
		a.Status = "evaluated"
		a.Reason = "Retrospective complete-interval analysis; missing telemetry does not establish zero traffic."
	}
	if len(comparison) > 0 {
		a.Comparison = anomalyComparison(s, comparison, time.Unix(end-step, 0), time.Unix(end, 0))
	}
	return a
}

// Reuse complete-population categorical statistics with exact fractional medians.
func anomalyComparison(s Spec, groups []Group, from, to time.Time) *Result {
	r := &Result{Spec: s, From: from, To: to, Summary: map[string]float64{}, Rows: []Row{}, Notes: []string{"Last complete interval; eligible entities only. Sum of entity medians is the comparison baseline."}}
	for i := range groups {
		groups[i].FractionalWeight = &groups[i].Value
	}
	r.Spec.Kind = "changes"
	categorical(r, groups)
	return r
}
