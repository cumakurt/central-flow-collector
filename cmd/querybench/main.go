package main

import (
	"central-flow-collector/internal/intelligence"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"runtime"
	"sort"
	"strings"
	"time"

	"central-flow-collector/internal/model"
	"central-flow-collector/internal/storage"
)

type result struct {
	Name           string  `json:"name"`
	Iterations     int     `json:"iterations"`
	P50MS          float64 `json:"p50_ms"`
	P95MS          float64 `json:"p95_ms"`
	P99MS          float64 `json:"p99_ms"`
	AllocatedBytes uint64  `json:"allocated_bytes_per_query"`
	Rows           int     `json:"result_items"`
}
type report struct {
	Rows    int      `json:"seed_rows"`
	Results []result `json:"results"`
}

func main() {
	rows := flag.Int("rows", 50000, "synthetic flow rows")
	iterations := flag.Int("iterations", 5, "iterations per query")
	advancedOnly := flag.Bool("advanced-only", false, "benchmark only the advanced analytical primitives")
	jsonOut := flag.Bool("json", false, "emit JSON")
	flag.Parse()
	if *rows < 1000 || *rows > 2_000_000 || *iterations < 1 || *iterations > 100 {
		fmt.Fprintln(os.Stderr, "invalid rows/iterations")
		os.Exit(2)
	}
	dir, err := os.MkdirTemp("", "flowcollector-querybench-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	st, err := storage.NewLocal(dir, 32768, 30)
	if err != nil {
		panic(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	seedDeadline := time.Now().Add(60 * time.Second)
	for i := 0; i < *rows; i++ {
		f := flow(i, now)
		for {
			if err := st.Write(f); err == nil {
				break
			} else if err.Error() != "storage queue full" {
				panic(err)
			}
			if time.Now().After(seedDeadline) {
				fmt.Fprintf(os.Stderr, "seed timeout at row=%d queue_depth=%d\n", i, st.Stats().QueueDepth)
				os.Exit(1)
			}
			time.Sleep(250 * time.Microsecond)
		}
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		x := st.Stats()
		if x.QueueDepth == 0 && x.Written >= uint64(*rows) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if x := st.Stats(); x.Written < uint64(*rows) {
		fmt.Fprintf(os.Stderr, "seed incomplete written=%d rows=%d\n", x.Written, *rows)
		os.Exit(1)
	}

	tests := []struct {
		name string
		fn   func(context.Context) (int, error)
	}{
		{"last_15m_top_sources", func(ctx context.Context) (int, error) {
			x, e := st.Analyze(ctx, storage.Query{From: now.Add(-15 * time.Minute), To: now}, 20)
			return len(x.Dimensions["src_ip"]), e
		}},
		{"last_24h_top_destinations", func(ctx context.Context) (int, error) {
			x, e := st.Analyze(ctx, storage.Query{From: now.Add(-24 * time.Hour), To: now}, 20)
			return len(x.Dimensions["dst_ip"]), e
		}},
		{"last_7d_traffic_trend", func(ctx context.Context) (int, error) {
			x, e := st.Analyze(ctx, storage.Query{From: now.Add(-7 * 24 * time.Hour), To: now}, 20)
			return len(x.Timeline), e
		}},
		{"ip_search", func(ctx context.Context) (int, error) {
			x, e := st.Query(ctx, storage.Query{From: now.Add(-7 * 24 * time.Hour), To: now, Host: "10.1.1.1", Limit: 1000})
			return len(x), e
		}},
		{"asn_aggregation", func(ctx context.Context) (int, error) {
			x, e := st.Analyze(ctx, storage.Query{From: now.Add(-24 * time.Hour), To: now}, 50)
			return len(x.Dimensions["asn"]), e
		}},
		{"country_aggregation", func(ctx context.Context) (int, error) {
			x, e := st.Analyze(ctx, storage.Query{From: now.Add(-24 * time.Hour), To: now}, 50)
			return len(x.Dimensions["country"]), e
		}},
		{"protocol_aggregation", func(ctx context.Context) (int, error) {
			x, e := st.Analyze(ctx, storage.Query{From: now.Add(-24 * time.Hour), To: now}, 20)
			return len(x.Dimensions["protocol"]), e
		}},
		{"exporter_statistics", func(ctx context.Context) (int, error) {
			x, e := st.Analyze(ctx, storage.Query{From: now.Add(-24 * time.Hour), To: now}, 50)
			return len(x.Dimensions["exporter"]), e
		}},
	}
	for _, kind := range []string{"changes", "concentration", "distribution", "relationships", "diversity", "temporal", "quality", "persistence", "anomalies"} {
		kind := kind
		tests = append(tests, struct {
			name string
			fn   func(context.Context) (int, error)
		}{"advanced_" + kind, func(ctx context.Context) (int, error) {
			spec := intelligence.Spec{Kind: kind, Dimension: "src_as", Peer: "dst_as", Metric: "bytes", Bucket: 86400, Top: 25, Bins: 24, Strategy: "logarithmic", Threshold: 99}
			if kind == "distribution" {
				spec.Dimension = "bytes"
			}
			if kind == "temporal" || kind == "anomalies" {
				spec.Bucket = 3600
			}
			from := now.Add(-7 * 24 * time.Hour)
			if kind == "anomalies" {
				from = now.Add(-30 * 24 * time.Hour)
			}
			groups, err := st.IntelligenceGroups(ctx, storage.Query{From: from, To: now}, spec)
			if err != nil {
				return 0, err
			}
			result := intelligence.Calculate(spec, groups, from, now)
			if result.Anomalies != nil {
				return result.Anomalies.Evaluated, nil
			}
			return len(result.Rows) + len(result.Histogram) + len(result.Curve), nil
		}})
	}

	rep := report{Rows: *rows}
	for _, tc := range tests {
		if *advancedOnly && !strings.HasPrefix(tc.name, "advanced_") {
			continue
		}
		ds := make([]time.Duration, 0, *iterations)
		items := 0
		var allocated uint64
		for i := 0; i < *iterations; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			t := time.Now()
			n, e := tc.fn(ctx)
			d := time.Since(t)
			runtime.ReadMemStats(&after)
			allocated += after.TotalAlloc - before.TotalAlloc
			cancel()
			if e != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", tc.name, e)
				os.Exit(1)
			}
			items = n
			ds = append(ds, d)
		}
		sort.Slice(ds, func(i, j int) bool { return ds[i] < ds[j] })
		pct := func(p float64) float64 {
			idx := max(0, int(math.Ceil(float64(len(ds))*p))-1)
			return float64(ds[idx].Microseconds()) / 1000
		}
		rep.Results = append(rep.Results, result{Name: tc.name, Iterations: *iterations, P50MS: pct(.50), P95MS: pct(.95), P99MS: pct(.99), AllocatedBytes: allocated / uint64(*iterations), Rows: items})
	}
	_ = st.Close()
	if *jsonOut {
		json.NewEncoder(os.Stdout).Encode(rep)
		return
	}
	fmt.Printf("Local query benchmark · %d synthetic flows\n", rep.Rows)
	for _, r := range rep.Results {
		fmt.Printf("%-28s p50=%8.2f ms p95=%8.2f ms items=%d\n", r.Name, r.P50MS, r.P95MS, r.Rows)
	}
}

func flow(i int, now time.Time) model.Flow {
	age := time.Duration(i%10080) * time.Minute // seven days
	sp := []uint16{443, 53, 80, 22, 123, 25}
	countries := []string{"TR", "US", "DE", "NL", "GB", "FR"}
	return model.Flow{ReceiveTime: now.Add(-age), StartTime: now.Add(-age - time.Second), EndTime: now.Add(-age), Exporter: fmt.Sprintf("10.250.0.%d", 1+i%16), Listener: "bench", Protocol: "netflow", SrcIP: fmt.Sprintf("10.%d.%d.%d", 1+(i/65000)%10, 1+(i/250)%250, 1+i%250), DstIP: fmt.Sprintf("203.0.%d.%d", 113+(i/250)%5, 1+i%250), SrcPort: uint16(1024 + i%50000), DstPort: sp[i%len(sp)], IPProtocol: []uint8{6, 17, 6, 6}[i%4], Packets: uint64(1 + i%100), Bytes: uint64(128*(1+i%17)) << uint(i%16), SrcAS: uint32(64510 + i%8), DstAS: uint32(64520 + i%12), SrcCountry: "TR", DstCountry: countries[i%len(countries)], IngressIf: uint32(1 + i%32), EgressIf: uint32(1 + (i/2)%32), AppName: []string{"HTTPS", "DNS", "HTTP", "SSH"}[i%4], Sampling: 1}
}
