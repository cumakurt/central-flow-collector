package analytics

import (
	"central-flow-collector/internal/model"
	"fmt"
	"math"
	"time"
)

type baselineBucket struct {
	Count          uint64
	Mean, M2, EWMA float64
}
type hostBaselineState struct {
	Minute       int64
	Bytes, Flows uint64
	Buckets      map[int]baselineBucket
	LastAlert    time.Time
}
type BaselineStatus struct {
	Enabled    bool `json:"enabled"`
	Hosts      int  `json:"hosts"`
	MinSamples int  `json:"min_samples"`
	Buckets    int  `json:"populated_buckets"`
}

func (e *Engine) ConfigureBaseline(enabled bool, minSamples int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.baselineEnabled = enabled
	if minSamples >= 5 {
		e.baselineMinSamples = minSamples
	}
	if e.baselineHosts == nil {
		e.baselineHosts = map[string]*hostBaselineState{}
	}
}
func weekBucket(t time.Time) int {
	t = t.UTC()
	d := (int(t.Weekday()) + 6) % 7
	return d*24 + t.Hour()
}
func updateBucket(b *baselineBucket, x float64) {
	b.Count++
	delta := x - b.Mean
	b.Mean += delta / float64(b.Count)
	b.M2 += delta * (x - b.Mean)
	if b.EWMA == 0 {
		b.EWMA = x
	} else {
		b.EWMA = 0.15*x + 0.85*b.EWMA
	}
}
func bucketStd(b baselineBucket) float64 {
	if b.Count < 2 {
		return 0
	}
	return math.Sqrt(b.M2 / float64(b.Count-1))
}

func (e *Engine) finalizeBaselineMinuteLocked(host string, st *hostBaselineState, now time.Time) {
	if st.Minute == 0 || st.Flows == 0 {
		return
	}
	idx := weekBucket(time.Unix(st.Minute*60, 0).UTC())
	b := st.Buckets[idx]
	x := float64(st.Bytes)
	rule := e.ruleLocked("baseline_anomaly")
	minSamples := e.baselineMinSamples
	if rule.MinSamples > minSamples {
		minSamples = rule.MinSamples
	}
	if e.baselineEnabled && rule.Enabled && int(b.Count) >= minSamples {
		sd := bucketStd(b)
		threshold := b.Mean + rule.Threshold*sd
		if sd == 0 {
			threshold = b.Mean * 2.5
		}
		if threshold < 1_000_000 {
			threshold = 1_000_000
		}
		if x > threshold && now.Sub(st.LastAlert) > 5*time.Minute {
			st.LastAlert = now
			e.addAlert(model.Alert{ID: fmt.Sprintf("baseline-%s-%d", host, st.Minute/5), Type: "baseline_anomaly", Severity: rule.Severity, Title: "Traffic baseline deviation", Reason: "The host's completed one-minute byte volume exceeded its historical hour-of-week baseline", Evidence: fmt.Sprintf("host=%s observed=%.0fB baseline_mean=%.0fB stddev=%.0f threshold=%.0f samples=%d hour_of_week=%d", host, x, b.Mean, sd, threshold, b.Count, idx), FirstSeen: now, LastSeen: now, Count: 1, Entity: host, Observed: x, Threshold: threshold, Status: "open"})
		}
	}
	updateBucket(&b, x)
	st.Buckets[idx] = b
}
func (e *Engine) observeBaselineLocked(f model.Flow, now time.Time) {
	if !e.baselineEnabled || f.SrcIP == "" {
		return
	}
	minute := now.Unix() / 60
	key := f.SrcIP
	st := e.baselineHosts[key]
	if st == nil {
		if e.maxTrackedHosts > 0 && len(e.baselineHosts) >= e.maxTrackedHosts {
			e.stateDrops++
			return
		}
		st = &hostBaselineState{Minute: minute, Buckets: map[int]baselineBucket{}}
		e.baselineHosts[key] = st
	}
	if st.Buckets == nil {
		st.Buckets = map[int]baselineBucket{}
	}
	if st.Minute != minute {
		e.finalizeBaselineMinuteLocked(f.SrcIP, st, now)
		st.Minute = minute
		st.Bytes = 0
		st.Flows = 0
	}
	st.Bytes += f.Bytes
	st.Flows++
}
func (e *Engine) BaselineStatus() BaselineStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	n := 0
	for _, h := range e.baselineHosts {
		for _, b := range h.Buckets {
			if b.Count > 0 {
				n++
			}
		}
	}
	return BaselineStatus{Enabled: e.baselineEnabled, Hosts: len(e.baselineHosts), MinSamples: e.baselineMinSamples, Buckets: n}
}
