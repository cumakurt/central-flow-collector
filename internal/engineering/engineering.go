package engineering

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"central-flow-collector/internal/model"
)

const MaxRows = 100000

type PrefixRoute struct {
	Prefix       string    `json:"prefix"`
	OriginASN    uint32    `json:"origin_asn,omitempty"`
	PeerASN      uint32    `json:"peer_asn,omitempty"`
	NextHop      string    `json:"next_hop,omitempty"`
	VRF          string    `json:"vrf,omitempty"`
	RouteSource  string    `json:"route_source,omitempty"`
	ASPathLength int       `json:"as_path_length,omitempty"`
	UpdatedAt    time.Time `json:"updated_at"`
}
type RouteContext struct {
	PrefixRoute
	MatchedPrefix string `json:"matched_prefix,omitempty"`
}
type RouteProvider struct {
	mu      sync.RWMutex
	routes  []PrefixRoute
	v4      *routeNode
	v6      *routeNode
	version string
	updated time.Time
}

type routeNode struct {
	child [2]*routeNode
	route *PrefixRoute
}

func NewRouteProvider() *RouteProvider { return &RouteProvider{version: "static-v1"} }
func (p *RouteProvider) Replace(routes []PrefixRoute) error {
	if len(routes) > 1000000 {
		return errors.New("routing table exceeds one million prefixes")
	}
	for i := range routes {
		pr := &routes[i]
		if _, e := netip.ParsePrefix(pr.Prefix); e != nil {
			return errors.New("invalid route prefix")
		}
		if pr.ASPathLength < 0 || pr.ASPathLength > 512 {
			return errors.New("invalid AS path length")
		}
		if pr.UpdatedAt.IsZero() {
			pr.UpdatedAt = time.Now().UTC()
		}
	}
	stored := append([]PrefixRoute(nil), routes...)
	v4, v6 := &routeNode{}, &routeNode{}
	for i := range stored {
		pr := &stored[i]
		prefix, _ := netip.ParsePrefix(pr.Prefix)
		root := v6
		bits := prefix.Bits()
		if prefix.Addr().Is4() {
			root = v4
		}
		node := root
		addr := prefix.Addr()
		for bit := 0; bit < bits; bit++ {
			idx := prefixBit(addr, bit)
			if node.child[idx] == nil {
				node.child[idx] = &routeNode{}
			}
			node = node.child[idx]
		}
		node.route = pr
	}
	p.mu.Lock()
	p.routes = stored
	p.v4, p.v6 = v4, v6
	p.updated = time.Now().UTC()
	p.version = "static-" + p.updated.Format("20060102150405")
	p.mu.Unlock()
	return nil
}
func (p *RouteProvider) Lookup(ip string) (RouteContext, bool) {
	a, e := netip.ParseAddr(ip)
	if e != nil {
		return RouteContext{}, false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	node := p.v6
	maxBits := 128
	if a.Is4() {
		node, maxBits = p.v4, 32
	}
	if node == nil {
		return RouteContext{}, false
	}
	var best *PrefixRoute
	if node.route != nil {
		best = node.route
	}
	for bit := 0; bit < maxBits; bit++ {
		idx := addrBit(a, bit)
		if node.child[idx] == nil {
			break
		}
		node = node.child[idx]
		if node.route != nil {
			best = node.route
		}
	}
	if best == nil {
		return RouteContext{}, false
	}
	return RouteContext{PrefixRoute: *best, MatchedPrefix: best.Prefix}, true
}

func prefixBit(addr netip.Addr, bit int) int { return addrBit(addr, bit) }
func addrBit(addr netip.Addr, bit int) int {
	if addr.Is4() {
		a := addr.As4()
		return int((a[bit/8] >> (7 - bit%8)) & 1)
	}
	a := addr.As16()
	return int((a[bit/8] >> (7 - bit%8)) & 1)
}
func (p *RouteProvider) Snapshot() (string, time.Time, int) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.version, p.updated, len(p.routes)
}
func (p *RouteProvider) Routes() []PrefixRoute {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return append([]PrefixRoute(nil), p.routes...)
}

var dscpNames = map[uint8]string{0: "CS0", 8: "CS1", 16: "CS2", 24: "CS3", 32: "CS4", 40: "CS5", 48: "CS6", 56: "CS7", 10: "AF11", 12: "AF12", 14: "AF13", 18: "AF21", 20: "AF22", 22: "AF23", 26: "AF31", 28: "AF32", 30: "AF33", 34: "AF41", 36: "AF42", 38: "AF43", 46: "EF"}

func DSCPName(v uint8) string {
	if n, ok := dscpNames[v]; ok {
		return n
	}
	return "DSCP " + itoa(int(v))
}
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	b := []byte{}
	for v > 0 {
		b = append([]byte{byte('0' + v%10)}, b...)
		v /= 10
	}
	return string(b)
}

type Ranked struct {
	Key     string  `json:"key"`
	Bytes   uint64  `json:"bytes"`
	Packets uint64  `json:"packets"`
	Flows   uint64  `json:"flows"`
	Share   float64 `json:"share"`
}
type Coverage struct {
	Field    string  `json:"field"`
	Category string  `json:"category"`
	Present  uint64  `json:"present"`
	Total    uint64  `json:"total"`
	Ratio    float64 `json:"ratio"`
}
type EngineeringSummary struct {
	From          time.Time         `json:"from"`
	To            time.Time         `json:"to"`
	ObservedFlows uint64            `json:"observed_flows"`
	ObservedBytes uint64            `json:"observed_bytes"`
	DSCP          []Ranked          `json:"dscp"`
	NAT           []Ranked          `json:"nat"`
	NextHops      []Ranked          `json:"next_hops"`
	OriginASNs    []Ranked          `json:"origin_asns"`
	Prefixes      []Ranked          `json:"prefixes"`
	Coverage      []Coverage        `json:"coverage"`
	Sampling      map[string]uint64 `json:"sampling"`
	RouteVersion  string            `json:"route_version,omitempty"`
	RoutePrefixes int               `json:"route_prefixes,omitempty"`
}

func add(m map[string]*Ranked, key string, f model.Flow) {
	r := m[key]
	if r == nil {
		r = &Ranked{Key: key}
		m[key] = r
	}
	r.Bytes += f.Bytes
	r.Packets += f.Packets
	r.Flows++
}
func rank(m map[string]*Ranked, total uint64) []Ranked {
	out := make([]Ranked, 0, len(m))
	for _, r := range m {
		if total > 0 {
			r.Share = float64(r.Bytes) * 100 / float64(total)
		}
		out = append(out, *r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}
func present(f model.Flow, field string) bool {
	switch field {
	case "src_ip", "dst_ip":
		return f.SrcIP != "" && f.DstIP != ""
	case "next_hop":
		return f.NextHop != ""
	case "src_prefix":
		return f.SrcPrefix != ""
	case "dst_prefix":
		return f.DstPrefix != ""
	case "dscp":
		return f.Custom != nil && f.Custom["dscp_present"] == "1"
	case "nat":
		return f.Custom != nil && f.Custom["nat_present"] == "1"
	case "tcp_flags":
		return f.TCPFlags != 0
	case "sampling":
		return f.Sampling != 0
	case "vrf":
		return f.VRF != ""
	case "asn":
		return f.SrcAS != 0 || f.DstAS != 0
	case "interface":
		return f.IngressIf != 0 || f.EgressIf != 0
	case "geo":
		return f.SrcCountry != "" || f.DstCountry != ""
	}
	return false
}
func natKey(f model.Flow) string {
	if f.NATSrcIP == "" && f.NATDstIP == "" && f.NATSrcPort == 0 && f.NATDstPort == 0 {
		return "untranslated"
	}
	return strings.Join([]string{f.SrcIP + ":" + itoa(int(f.SrcPort)), f.NATSrcIP + ":" + itoa(int(f.NATSrcPort)), f.DstIP + ":" + itoa(int(f.DstPort)), f.NATDstIP + ":" + itoa(int(f.NATDstPort))}, " → ")
}
func Summarize(ctx context.Context, rows []model.Flow, from, to time.Time, p *RouteProvider) (EngineeringSummary, error) {
	if len(rows) > MaxRows {
		return EngineeringSummary{}, errors.New("engineering result exceeds 100,000 rows; narrow the time range")
	}
	s := EngineeringSummary{From: from, To: to, Sampling: map[string]uint64{}}
	dscp, nat, next, asn, prefix := map[string]*Ranked{}, map[string]*Ranked{}, map[string]*Ranked{}, map[string]*Ranked{}, map[string]*Ranked{}
	fields := []string{"src_ip", "dst_ip", "next_hop", "src_prefix", "dst_prefix", "dscp", "nat", "tcp_flags", "sampling", "vrf", "asn", "interface", "geo"}
	counts := map[string][2]uint64{}
	for _, f := range rows {
		select {
		case <-ctx.Done():
			return s, ctx.Err()
		default:
		}
		if !f.ReceiveTime.Before(to) || f.ReceiveTime.Before(from) {
			continue
		}
		s.ObservedFlows++
		s.ObservedBytes += f.Bytes
		add(dscp, DSCPName(f.DSCP), f)
		add(nat, natKey(f), f)
		if f.NextHop != "" {
			add(next, f.NextHop, f)
		}
		// Prefer native routing fields. When they are absent, enrich the summary
		// from the configured longest-prefix-match provider without mutating the
		// stored flow. This keeps old rows useful while preserving provenance in
		// the route snapshot metadata.
		routeDst, hasRouteDst := RouteContext{}, false
		if p != nil && f.DstIP != "" {
			routeDst, hasRouteDst = p.Lookup(f.DstIP)
		}
		if f.DstAS != 0 {
			add(asn, itoa(int(f.DstAS)), f)
		} else if hasRouteDst && routeDst.OriginASN != 0 {
			add(asn, itoa(int(routeDst.OriginASN)), f)
		} else if f.SrcAS != 0 {
			add(asn, itoa(int(f.SrcAS)), f)
		}
		if f.DstPrefix != "" {
			add(prefix, f.DstPrefix, f)
		} else if hasRouteDst {
			add(prefix, routeDst.MatchedPrefix, f)
		}
		if f.Sampling == 0 {
			s.Sampling["unknown"]++
		} else {
			s.Sampling["1:"+itoa(int(f.Sampling))]++
		}
		for _, field := range fields {
			x := counts[field]
			x[1]++
			if present(f, field) {
				x[0]++
			}
			counts[field] = x
		}
	}
	for _, field := range fields {
		x := counts[field]
		s.Coverage = append(s.Coverage, Coverage{Field: field, Category: category(field), Present: x[0], Total: x[1], Ratio: ratio(x[0], x[1])})
	}
	s.DSCP = rank(dscp, s.ObservedBytes)
	s.NAT = rank(nat, s.ObservedBytes)
	s.NextHops = rank(next, s.ObservedBytes)
	s.OriginASNs = rank(asn, s.ObservedBytes)
	s.Prefixes = rank(prefix, s.ObservedBytes)
	if p != nil {
		s.RouteVersion, _, s.RoutePrefixes = p.Snapshot()
	}
	return s, nil
}
func ratio(a, b uint64) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) * 100 / float64(b)
}
func category(f string) string {
	switch f {
	case "next_hop", "src_prefix", "dst_prefix", "asn", "vrf":
		return "routing"
	case "interface":
		return "interface"
	case "dscp":
		return "qos"
	case "nat":
		return "nat"
	case "sampling":
		return "sampling"
	case "geo":
		return "enrichment"
	}
	return "flow"
}

type StorageModel struct {
	RawRetentionDays       int     `json:"raw_retention_days"`
	AggregateRetentionDays int     `json:"aggregate_retention_days"`
	DailyRawBytes          float64 `json:"daily_raw_bytes"`
	DailyAggregateBytes    float64 `json:"daily_aggregate_bytes"`
	CurrentBytes           float64 `json:"current_bytes"`
	FreeBytes              float64 `json:"free_bytes"`
}
type SimulationInput struct {
	CurrentRawDays        int     `json:"current_raw_days"`
	ProposedRawDays       int     `json:"proposed_raw_days"`
	CurrentAggregateDays  int     `json:"current_aggregate_days"`
	ProposedAggregateDays int     `json:"proposed_aggregate_days"`
	CurrentSampling       uint32  `json:"current_sampling"`
	ProposedSampling      uint32  `json:"proposed_sampling"`
	CurrentDailyBytes     float64 `json:"current_daily_bytes"`
	FreeBytes             float64 `json:"free_bytes"`
	StorageCostPerTB      float64 `json:"storage_cost_per_tb"`
}
type SimulationResult struct {
	CurrentBytes  float64  `json:"current_bytes"`
	ProposedBytes float64  `json:"proposed_bytes"`
	DeltaBytes    float64  `json:"delta_bytes"`
	DeltaPercent  float64  `json:"delta_percent"`
	CurrentDays   float64  `json:"current_days"`
	ProposedDays  float64  `json:"proposed_days"`
	HeadroomBytes float64  `json:"headroom_bytes"`
	MonthlyCost   float64  `json:"monthly_cost"`
	Confidence    string   `json:"confidence"`
	Assumptions   []string `json:"assumptions"`
	Impact        []string `json:"impact"`
}

func Simulate(in SimulationInput) (SimulationResult, error) {
	if in.CurrentRawDays < 1 || in.ProposedRawDays < 1 || in.CurrentAggregateDays < 0 || in.ProposedAggregateDays < 0 || in.CurrentSampling < 1 || in.ProposedSampling < 1 || in.CurrentDailyBytes <= 0 || in.FreeBytes < 0 {
		return SimulationResult{}, errors.New("retention and sampling inputs must be positive")
	}
	if in.CurrentRawDays > 3650 || in.ProposedRawDays > 3650 || in.CurrentAggregateDays > 3650 || in.ProposedAggregateDays > 3650 || in.CurrentSampling > 1000000 || in.ProposedSampling > 1000000 {
		return SimulationResult{}, errors.New("simulation input exceeds safe bounds")
	}
	current := in.CurrentDailyBytes * float64(in.CurrentRawDays)
	proposedDaily := in.CurrentDailyBytes * float64(in.CurrentSampling) / float64(in.ProposedSampling)
	proposed := proposedDaily * float64(in.ProposedRawDays)
	if in.CurrentAggregateDays > in.CurrentRawDays {
		current += in.CurrentDailyBytes * .15 * float64(in.CurrentAggregateDays-in.CurrentRawDays)
	}
	if in.ProposedAggregateDays > in.ProposedRawDays {
		proposed += proposedDaily * .15 * float64(in.ProposedAggregateDays-in.ProposedRawDays)
	}
	r := SimulationResult{CurrentBytes: current, ProposedBytes: proposed, DeltaBytes: proposed - current, CurrentDays: current / in.CurrentDailyBytes, ProposedDays: proposed / in.CurrentDailyBytes, HeadroomBytes: in.FreeBytes - proposed, Confidence: "Medium", Assumptions: []string{"Uses observed daily raw growth as the base rate", "Sampling reduction scales estimated ingest and storage linearly", "Aggregate tiers use a 15% raw daily storage factor", "Simulation only; no configuration changes are applied."}, Impact: []string{"Top talkers and large-flow volume: usually low impact", "Unique peers and very small flows: medium to high impact", "Short-duration flow and percentile analysis: high impact"}}
	if current > 0 {
		r.DeltaPercent = r.DeltaBytes * 100 / current
	}
	if in.StorageCostPerTB > 0 {
		r.MonthlyCost = proposed / 1e12 * in.StorageCostPerTB
	}
	if in.CurrentDailyBytes > 0 && in.CurrentRawDays >= 14 {
		r.Confidence = "High"
	}
	return r, nil
}
func LoadRoutes(path string) (*RouteProvider, error) {
	p := NewRouteProvider()
	b, e := os.ReadFile(path)
	if os.IsNotExist(e) {
		return p, nil
	}
	if e != nil {
		return nil, e
	}
	var routes []PrefixRoute
	if e = json.Unmarshal(b, &routes); e != nil {
		return nil, e
	}
	if e = p.Replace(routes); e != nil {
		return nil, e
	}
	return p, nil
}
