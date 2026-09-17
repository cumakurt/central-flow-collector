package analytics

import (
	"central-flow-collector/internal/model"
	"fmt"
	"sort"
	"sync"
	"time"
)

type second struct {
	sec                   int64
	flows, packets, bytes uint64
}

// Engine keeps only operational flow-analytics state. It deliberately avoids
// host behavior profiling, attack correlation, IOC scoring, and other NDR/SIEM
// responsibilities. Cardinality-sensitive live maps are bounded.
type Engine struct {
	mu                                   sync.RWMutex
	totalFlows, totalPackets, totalBytes uint64
	bySrc                                map[string]uint64
	byDst                                map[string]uint64
	byProto                              map[uint8]uint64
	seconds                              [120]second
	alerts                               []model.Alert
	baselineEnabled                      bool
	baselineMinSamples                   int
	baselineHosts                        map[string]*hostBaselineState
	maxTrackedHosts                      int
	maxDimensionKeys                     int
	stateDrops                           uint64
	ewma                                 float64
	alertSink                            func(model.Alert)
	rules                                map[string]Rule
	rulesPath                            string
}

func New() *Engine {
	return &Engine{
		bySrc: map[string]uint64{}, byDst: map[string]uint64{}, byProto: map[uint8]uint64{},
		baselineEnabled: true, baselineMinSamples: 20, baselineHosts: map[string]*hostBaselineState{},
		maxTrackedHosts: 20000, maxDimensionKeys: 100000, rules: defaultRules(),
	}
}

// ConfigureStateLimits bounds seasonal-baseline hosts and live Top-N key maps.
// The second parameter is retained for v3 configuration compatibility, but in
// v4 it represents the maximum number of live dimension keys rather than
// security-analysis transient states.
func (e *Engine) ConfigureStateLimits(maxTrackedHosts, maxDimensionKeys int) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if maxTrackedHosts >= 1000 {
		e.maxTrackedHosts = maxTrackedHosts
	}
	if maxDimensionKeys >= 1000 {
		e.maxDimensionKeys = maxDimensionKeys
	}
}

type CapacityStatus struct {
	MaxTrackedHosts  int    `json:"max_tracked_hosts"`
	MaxDimensionKeys int    `json:"max_dimension_keys"`
	BaselineHosts    int    `json:"baseline_hosts"`
	SourceKeys       int    `json:"source_keys"`
	DestinationKeys  int    `json:"destination_keys"`
	StateDrops       uint64 `json:"state_drops"`
}

func (e *Engine) CapacityStatus() CapacityStatus {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return CapacityStatus{MaxTrackedHosts: e.maxTrackedHosts, MaxDimensionKeys: e.maxDimensionKeys, BaselineHosts: len(e.baselineHosts), SourceKeys: len(e.bySrc), DestinationKeys: len(e.byDst), StateDrops: e.stateDrops}
}

func (e *Engine) SetAlertSink(fn func(model.Alert)) { e.mu.Lock(); e.alertSink = fn; e.mu.Unlock() }

func (e *Engine) Observe(f model.Flow) {
	e.mu.Lock()
	e.observeLocked(f, time.Now())
	e.mu.Unlock()
}

// ObserveBatch applies a decoded packet's flows under one analytics lock. Flow
// ordering and accounting are preserved while avoiding one global mutex handoff
// per flow on high-cardinality exporters.
func (e *Engine) ObserveBatch(flows []model.Flow) {
	if len(flows) == 0 {
		return
	}
	now := time.Now()
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range flows {
		e.observeLocked(flows[i], now)
	}
}

func (e *Engine) observeLocked(f model.Flow, now time.Time) {
	e.totalFlows++
	e.totalPackets += f.Packets
	e.totalBytes += f.Bytes
	if f.SrcIP != "" && boundedIncBy(e.bySrc, f.SrcIP, f.Bytes, e.maxDimensionKeys) {
		e.stateDrops++
	}
	if f.DstIP != "" && boundedIncBy(e.byDst, f.DstIP, f.Bytes, e.maxDimensionKeys) {
		e.stateDrops++
	}
	e.byProto[f.IPProtocol] += f.Bytes

	idx := now.Unix() % int64(len(e.seconds))
	s := &e.seconds[idx]
	if s.sec != now.Unix() {
		s.sec = now.Unix()
		s.flows, s.packets, s.bytes = 0, 0, 0
	}
	s.flows++
	s.packets += f.Packets
	s.bytes += f.Bytes

	// Operational anomaly only: compare observed bitrate with an EWMA. This
	// describes network-usage deviation and does not infer malicious intent.
	rate := float64(s.bytes * 8)
	if e.ewma == 0 {
		e.ewma = rate
	} else {
		baseline := e.ewma
		e.ewma = 0.2*rate + 0.8*e.ewma
		rule := e.ruleLocked("traffic_spike")
		if rule.Enabled && baseline > 1_000_000 && rate > baseline*rule.Threshold {
			e.addAlert(model.Alert{ID: fmt.Sprintf("traffic-%d", now.Unix()/60), Type: "traffic_spike", Severity: rule.Severity, Title: "Traffic baseline deviation", Reason: fmt.Sprintf("Current bitrate exceeds the EWMA baseline by more than %.2fx", rule.Threshold), Evidence: fmt.Sprintf("observed %.0f bps vs baseline %.0f bps", rate, baseline), FirstSeen: now, LastSeen: now, Count: 1, Observed: rate, Threshold: baseline * rule.Threshold, Status: "open"})
		}
	}

	// Large individual flows are capacity/usage signals, not security events.
	lr := e.ruleLocked("large_transfer")
	if lr.Enabled && float64(f.Bytes) >= lr.Threshold {
		e.addAlert(model.Alert{ID: fmt.Sprintf("large-%s-%d", f.SrcIP, now.Unix()/300), Type: "large_transfer", Severity: lr.Severity, Title: "Large flow observed", Reason: "A single flow exceeded the configured byte threshold", Evidence: fmt.Sprintf("%s -> %s bytes=%d", f.SrcIP, f.DstIP, f.Bytes), FirstSeen: now, LastSeen: now, Count: 1, Entity: f.SrcIP, Observed: float64(f.Bytes), Threshold: lr.Threshold, Status: "open"})
	}

	e.observeBaselineLocked(f, now)
}

func boundedIncBy[K comparable](m map[K]uint64, k K, delta uint64, max int) bool {
	if _, ok := m[k]; ok {
		m[k] += delta
		return false
	}
	if max > 0 && len(m) >= max {
		return true
	}
	m[k] = delta
	return false
}

func (e *Engine) ReportAlert(a model.Alert) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if a.FirstSeen.IsZero() {
		a.FirstSeen = time.Now()
	}
	if a.LastSeen.IsZero() {
		a.LastSeen = a.FirstSeen
	}
	if a.Count == 0 {
		a.Count = 1
	}
	if a.Status == "" {
		a.Status = "open"
	}
	e.addAlert(a)
}

func (e *Engine) addAlert(a model.Alert) {
	for i := range e.alerts {
		if e.alerts[i].ID == a.ID {
			e.alerts[i].LastSeen = a.LastSeen
			e.alerts[i].Count++
			e.alerts[i].Evidence = a.Evidence
			return
		}
	}
	e.alerts = append(e.alerts, a)
	if e.alertSink != nil {
		e.alertSink(a)
	}
	if len(e.alerts) > 1000 {
		e.alerts = e.alerts[len(e.alerts)-1000:]
	}
}

func (e *Engine) Alerts() []model.Alert {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := append([]model.Alert(nil), e.alerts...)
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	return out
}
func (e *Engine) Ack(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i := range e.alerts {
		if e.alerts[i].ID == id {
			e.alerts[i].Status = "acknowledged"
			return true
		}
	}
	return false
}

type Top struct {
	Key   string `json:"key"`
	Value uint64 `json:"value"`
}
type LivePoint struct {
	Timestamp int64  `json:"timestamp"`
	Flows     uint64 `json:"flows"`
	Packets   uint64 `json:"packets"`
	Bits      uint64 `json:"bits"`
}
type Snapshot struct {
	TotalFlows      uint64      `json:"total_flows"`
	TotalPackets    uint64      `json:"total_packets"`
	TotalBytes      uint64      `json:"total_bytes"`
	FlowsPerSec     uint64      `json:"flows_per_sec"`
	PacketsPerSec   uint64      `json:"packets_per_sec"`
	BitsPerSec      uint64      `json:"bits_per_sec"`
	TopSources      []Top       `json:"top_sources"`
	TopDestinations []Top       `json:"top_destinations"`
	Protocols       []Top       `json:"protocols"`
	Timeline        []LivePoint `json:"timeline"`
	ActiveAlerts    int         `json:"active_alerts"`
}

func (e *Engine) Snapshot() Snapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	now := time.Now().Unix()
	var fs, ps, bs uint64
	for _, s := range e.seconds {
		if s.sec >= now-4 {
			fs += s.flows
			ps += s.packets
			bs += s.bytes
		}
	}
	a := 0
	for _, x := range e.alerts {
		if x.Status == "open" {
			a++
		}
	}
	timeline := make([]LivePoint, 0, 60)
	for sec := now - 59; sec <= now; sec++ {
		p := LivePoint{Timestamp: sec}
		for _, s := range e.seconds {
			if s.sec == sec {
				p.Flows = s.flows
				p.Packets = s.packets
				p.Bits = s.bytes * 8
				break
			}
		}
		timeline = append(timeline, p)
	}
	return Snapshot{TotalFlows: e.totalFlows, TotalPackets: e.totalPackets, TotalBytes: e.totalBytes, FlowsPerSec: fs / 5, PacketsPerSec: ps / 5, BitsPerSec: bs * 8 / 5, TopSources: top(e.bySrc, 10), TopDestinations: top(e.byDst, 10), Protocols: topProto(e.byProto, 10), Timeline: timeline, ActiveAlerts: a}
}
func top(m map[string]uint64, n int) []Top {
	a := make([]Top, 0, len(m))
	for k, v := range m {
		if k != "" {
			a = append(a, Top{k, v})
		}
	}
	sort.Slice(a, func(i, j int) bool { return a[i].Value > a[j].Value })
	if len(a) > n {
		a = a[:n]
	}
	return a
}
func topProto(m map[uint8]uint64, n int) []Top {
	x := map[string]uint64{}
	for k, v := range m {
		x[fmt.Sprint(k)] = v
	}
	return top(x, n)
}
