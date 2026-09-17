package intelligence

import (
	"fmt"
	"math"
	"sort"
	"time"
)

func ratio(a, b float64) float64 {
	if b == 0 {
		return 0
	}
	return a / b
}
func Percentile(values []Group, p float64) float64 {
	var n uint64
	for _, g := range values {
		n += g.Flows
	}
	if n == 0 {
		return 0
	}
	rank := uint64(math.Ceil(p * float64(n)))
	var seen uint64
	for _, g := range values {
		seen += g.Flows
		if seen >= rank {
			return g.Value
		}
	}
	return values[len(values)-1].Value
}
func quantiles(r *Result, values []Group) {
	sort.Slice(values, func(i, j int) bool { return values[i].Value < values[j].Value })
	for _, p := range []float64{50, 75, 90, 95, 99, 99.9} {
		r.Summary[fmt.Sprintf("p%g", p)] = Percentile(values, p/100)
	}
}

// Calculate requires complete aggregates. The storage layer rejects excess cardinality.
func Calculate(s Spec, groups []Group, from, to time.Time) Result {
	r := Result{Spec: s, From: from, To: to, Generated: time.Now().UTC(), Source: "raw", Groups: len(groups), Summary: map[string]float64{}, Rows: []Row{}, Curve: []Point{}, Histogram: []Bin{}, Notes: []string{"Observed record counters; no sampling extrapolation. Zero activity does not establish telemetry availability.", "UTC half-open periods [from,to). Population calculations precede Top-N selection."}}
	for _, g := range groups {
		if g.Period == 1 {
			r.Summary["observed_flows"] += float64(g.Flows)
			r.Summary["sampled_records"] += float64(g.Sampled)
			r.Summary["sampling_unknown_records"] += float64(g.SamplingUnknown)
			r.Summary["invalid_records"] += float64(g.Invalid)
		}
	}
	switch s.Kind {
	case "anomalies":
		r.Anomalies = analyzeAnomalies(s, groups, from, to)
	case "changes", "concentration":
		categorical(&r, groups)
	case "distribution":
		distribution(&r, groups)
	case "relationships", "diversity":
		relationships(&r, groups)
	case "temporal":
		temporal(&r, groups)
		capacity(&r)
	case "quality":
		quality(&r, groups)
	case "persistence":
		persistence(&r, groups)
	}
	if r.Summary["observed_flows"] == 0 {
		r.Notes = append(r.Notes, "No flow records in the selected period.")
	}
	return r
}

func categorical(r *Result, groups []Group) {
	m := map[string]*Row{}
	var current, previous float64
	for _, g := range groups {
		x := m[g.Key]
		if x == nil {
			x = &Row{Key: g.Key}
			m[g.Key] = x
		}
		if g.Period == 1 {
			x.Current += g.Weight(r.Spec.Metric)
			current += g.Weight(r.Spec.Metric)
		} else {
			x.Previous += g.Weight(r.Spec.Metric)
			previous += g.Weight(r.Spec.Metric)
		}
	}
	rows := make([]Row, 0, len(m))
	for _, x := range m {
		rows = append(rows, *x)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Previous == rows[j].Previous {
			return rows[i].Key < rows[j].Key
		}
		return rows[i].Previous > rows[j].Previous
	})
	for i := range rows {
		if rows[i].Previous > 0 {
			rows[i].PreviousRank = i + 1
		}
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Current == rows[j].Current {
			return rows[i].Key < rows[j].Key
		}
		return rows[i].Current > rows[j].Current
	})
	delta := current - previous
	var entropy, hhi, js float64
	weights := []float64{}
	for i := range rows {
		x := &rows[i]
		p, q := ratio(x.Current, current), ratio(x.Previous, previous)
		mid := (p + q) / 2
		if p > 0 {
			entropy -= p * math.Log2(p)
			hhi += p * p
			weights = append(weights, p)
			x.Rank = i + 1
		}
		if p > 0 && previous > 0 {
			js += .5 * p * math.Log2(p/mid)
		}
		if q > 0 && current > 0 {
			js += .5 * q * math.Log2(q/mid)
		}
		x.Delta = x.Current - x.Previous
		x.Share = 100 * p
		x.ShareDelta = 100 * (p - q)
		if delta != 0 {
			v := 100 * x.Delta / delta
			x.Contribution = &v
		}
		x.Status = "persistent"
		if x.Previous == 0 && x.Current > 0 {
			x.Status = "new_in_window"
		}
		if x.Current == 0 && x.Previous > 0 {
			x.Status = "inactive_in_window"
		}
	}
	r.Summary["current"] = current
	r.Summary["previous"] = previous
	r.Summary["delta"] = delta
	r.Summary["entities"] = float64(len(weights))
	r.Summary["entropy_bits"] = entropy
	r.Summary["hhi"] = hhi
	if len(weights) > 1 {
		r.Summary["normalized_entropy"] = entropy / math.Log2(float64(len(weights)))
	} else {
		r.Summary["normalized_entropy"] = 0
	}
	if current > 0 && previous > 0 {
		r.Summary["jensen_shannon_bits"] = js
	} else {
		r.Notes = append(r.Notes, "Distribution distance unavailable when either period has zero total weight.")
	}
	for _, p := range []int{1, 5, 10, 20} {
		n := int(math.Ceil(float64(len(weights)) * float64(p) / 100))
		var sum float64
		for i := 0; i < n; i++ {
			sum += weights[i]
		}
		r.Summary[fmt.Sprintf("top_%d_percent_share", p)] = 100 * sum
	}
	r.Curve = append(r.Curve, Point{})
	var cumulative float64
	for i := len(weights) - 1; i >= 0; i-- {
		cumulative += weights[i]
		if (len(weights)-i)%max(1, len(weights)/100) == 0 || i == 0 {
			r.Curve = append(r.Curve, Point{float64(len(weights)-i) / float64(len(weights)), cumulative})
		}
	}
	if r.Spec.Kind == "changes" {
		sort.Slice(rows, func(i, j int) bool {
			if math.Abs(rows[i].Delta) == math.Abs(rows[j].Delta) {
				return rows[i].Key < rows[j].Key
			}
			return math.Abs(rows[i].Delta) > math.Abs(rows[j].Delta)
		})
	}
	r.Rows = rows[:min(len(rows), r.Spec.Top)]
	var shown float64
	for _, x := range r.Rows {
		shown += x.Delta
	}
	r.Summary["other_delta"] = delta - shown
	r.Method = "Complete categorical population; delta=current-previous; contribution=delta/net change; share delta in percentage points. Entropy base 2, HHI=sum(p²), Jensen–Shannon base 2. Lorenz curve ascending traffic."
}

func distribution(r *Result, groups []Group) {
	values := make([]Group, 0, len(groups))
	var n, totalBytes, totalPackets uint64
	for _, g := range groups {
		if g.Invalid == 0 {
			values = append(values, g)
			n += g.Flows
			totalBytes += g.Bytes
			totalPackets += g.Packets
		}
	}
	quantiles(r, values)
	r.Summary["valid_records"] = float64(n)
	r.Method = "Exact weighted nearest-rank percentiles over distinct values; zero-duration valid records included; missing/negative durations and zero-packet ratios excluded. Histogram upper bound inclusive only in final bin. Elephant membership strictly above percentile threshold (ties excluded)."
	if n == 0 {
		return
	}
	low, high := values[0].Value, values[len(values)-1].Value
	forward := func(x float64) float64 { return x }
	inverse := forward
	if r.Spec.Strategy == "logarithmic" {
		forward = math.Log1p
		inverse = math.Expm1
	}
	lo, hi := forward(low), forward(high)
	bins := r.Spec.Bins
	if low == high {
		bins = 1
	}
	for i := 0; i < bins; i++ {
		r.Histogram = append(r.Histogram, Bin{From: inverse(lo + (hi-lo)*float64(i)/float64(bins)), To: inverse(lo + (hi-lo)*float64(i+1)/float64(bins))})
	}
	threshold := Percentile(values, r.Spec.Threshold/100)
	var elephants, elephantBytes, elephantPackets uint64
	for _, g := range values {
		idx := 0
		if hi > lo {
			idx = min(bins-1, int((forward(g.Value)-lo)/(hi-lo)*float64(bins)))
		}
		r.Histogram[idx].Count += g.Flows
		if g.Value > threshold {
			elephants += g.Flows
			elephantBytes += g.Bytes
			elephantPackets += g.Packets
		}
	}
	var count uint64
	for i := range r.Histogram {
		count += r.Histogram[i].Count
		r.Histogram[i].CDF = float64(count) / float64(n)
	}
	r.Summary["threshold_value"] = threshold
	r.Summary["elephant_flow_share"] = 100 * ratio(float64(elephants), float64(n))
	r.Summary["elephant_byte_share"] = 100 * ratio(float64(elephantBytes), float64(totalBytes))
	r.Summary["elephant_packet_share"] = 100 * ratio(float64(elephantPackets), float64(totalPackets))
	r.Summary["remaining_flow_share"] = 100 - r.Summary["elephant_flow_share"]
}

func relationships(r *Result, groups []Group) {
	type pair struct{ key, peer string }
	m := map[pair]*Row{}
	neighbors := map[string]map[string]bool{}
	for _, g := range groups {
		k := pair{g.Key, g.Peer}
		x := m[k]
		if x == nil {
			x = &Row{Key: g.Key, Peer: g.Peer, First: g.First}
			m[k] = x
		}
		x.Current += g.Weight(r.Spec.Metric)
		x.Bytes += g.Bytes
		x.Flows += g.Flows
		x.Active++
		x.First = min(x.First, g.First)
		x.Last = max(x.Last, g.Last)
		if neighbors[g.Key] == nil {
			neighbors[g.Key] = map[string]bool{}
		}
		neighbors[g.Key][g.Peer] = true
	}
	totalBuckets := int(math.Ceil(float64(r.To.UnixMilli())/float64(r.Spec.Bucket*1000)) - math.Floor(float64(r.From.UnixMilli())/float64(r.Spec.Bucket*1000)))
	if r.Spec.Kind == "diversity" {
		entities := map[string]*Row{}
		for _, x := range m {
			e := entities[x.Key]
			if e == nil {
				e = &Row{Key: x.Key, Peers: len(neighbors[x.Key])}
				entities[x.Key] = e
			}
			e.Bytes += x.Bytes
			e.Flows += x.Flows
			e.Current += x.Current
		}
		values := []Group{}
		for _, x := range entities {
			r.Rows = append(r.Rows, *x)
			values = append(values, Group{Value: float64(x.Peers), Flows: 1})
		}
		quantiles(r, values)
		sort.Slice(r.Rows, func(i, j int) bool {
			if r.Rows[i].Peers == r.Rows[j].Peers {
				return r.Rows[i].Key < r.Rows[j].Key
			}
			return r.Rows[i].Peers > r.Rows[j].Peers
		})
	} else {
		for _, x := range m {
			x.Recurrence = 100 * ratio(float64(x.Active), float64(totalBuckets))
			r.Rows = append(r.Rows, *x)
		}
		sort.Slice(r.Rows, func(i, j int) bool {
			if r.Rows[i].Current == r.Rows[j].Current {
				return r.Rows[i].Key+r.Rows[i].Peer < r.Rows[j].Key+r.Rows[j].Peer
			}
			return r.Rows[i].Current > r.Rows[j].Current
		})
	}
	r.Summary["relationships"] = float64(len(m))
	r.Summary["entities"] = float64(len(neighbors))
	r.Summary["window_buckets"] = float64(totalBuckets)
	r.Rows = r.Rows[:min(len(r.Rows), r.Spec.Top)]
	r.Method = "Directed observed pairs. Recurrence = active UTC buckets / all intersecting window buckets, including partial edges. Peer diversity is exact within selected filters. No service-dependency or application-layer certainty inferred."
}

func temporal(r *Result, groups []Group) {
	byTime := map[int64]float64{}
	for _, g := range groups {
		byTime[g.Bucket] += g.Weight(r.Spec.Metric)
	}
	values := []Group{}
	var sum, sumSq, peak float64
	factor := 1.
	if r.Spec.Metric == "bytes" {
		factor = 8
	}
	first := int64(math.Ceil(float64(r.From.UnixMilli())/float64(r.Spec.Bucket*1000))) * int64(r.Spec.Bucket)
	for t := first; t+int64(r.Spec.Bucket) <= r.To.Unix(); t += int64(r.Spec.Bucket) {
		v := byTime[t] * factor / float64(r.Spec.Bucket)
		values = append(values, Group{Value: v, Flows: 1})
		sum += v
		sumSq += v * v
		peak = max(peak, v)
		r.Curve = append(r.Curve, Point{float64(t) * 1000, v})
	}
	quantiles(r, values)
	n := float64(len(values))
	mean := ratio(sum, n)
	r.Summary["average_rate"] = mean
	r.Summary["peak_rate"] = peak
	r.Summary["peak_to_average"] = ratio(peak, mean)
	r.Summary["coefficient_of_variation"] = ratio(math.Sqrt(max(0, ratio(sumSq, n)-mean*mean)), mean)
	r.Summary["complete_buckets"] = n
	r.Method = "UTC full buckets only; missing record buckets zero-filled. Bytes converted to bit/s. Population coefficient of variation = standard deviation / mean. Nearest-rank bandwidth percentiles. Zero mean yields zero ratios."
	if n == 0 {
		r.Notes = append(r.Notes, "No complete buckets; choose a smaller bucket or longer range.")
	}
}

func quality(r *Result, groups []Group) {
	exporters := map[string]*Row{}
	for _, g := range groups {
		x := exporters[g.Key]
		if x == nil {
			x = &Row{Key: g.Key, First: g.First}
			exporters[g.Key] = x
		}
		x.Flows += g.Flows
		x.Bytes += g.Bytes
		x.Active++
		x.First = min(x.First, g.First)
		x.Last = max(x.Last, g.Last)
	}
	buckets := int(math.Ceil(float64(r.To.UnixMilli())/float64(r.Spec.Bucket*1000)) - math.Floor(float64(r.From.UnixMilli())/float64(r.Spec.Bucket*1000)))
	for _, x := range exporters {
		x.Recurrence = 100 * ratio(float64(x.Active), float64(buckets))
		r.Rows = append(r.Rows, *x)
	}
	sort.Slice(r.Rows, func(i, j int) bool { return r.Rows[i].Key < r.Rows[j].Key })
	r.Rows = r.Rows[:min(len(r.Rows), r.Spec.Top)]
	r.Summary["observed_exporters"] = float64(len(exporters))
	r.Summary["window_buckets"] = float64(buckets)
	r.Method = "Observed exporter activity buckets and record sampling metadata. Activity coverage is not data completeness."
	r.Notes = append(r.Notes, "Expected-exporter history, historical decode/sequence losses and sampling algorithm semantics are unavailable; no completeness score or normalized-byte estimate is calculated.")
}
