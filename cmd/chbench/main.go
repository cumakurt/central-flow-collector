package main

import (
	"flag"
	"fmt"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"central-flow-collector/internal/model"
	"central-flow-collector/internal/storage"
)

func main() {
	url := flag.String("url", "http://127.0.0.1:8123", "ClickHouse HTTP URL")
	db := flag.String("database", "flowcollector", "database")
	table := flag.String("table", "flows_benchmark", "benchmark table")
	user := flag.String("user", "default", "user")
	password := flag.String("password", os.Getenv("CLICKHOUSE_PASSWORD"), "password (prefer CLICKHOUSE_PASSWORD env)")
	rows := flag.Int("rows", 1_000_000, "flow rows to write")
	batch := flag.Int("batch", 5000, "insert batch size")
	concurrency := flag.Int("concurrency", runtime.NumCPU(), "producer goroutines")
	queue := flag.Int("queue", 262144, "bounded storage queue size")
	timeout := flag.Duration("timeout", 5*time.Minute, "maximum benchmark duration")
	flag.Parse()
	if *rows < 1 || *rows > 100_000_000 || *concurrency < 1 || *concurrency > 512 {
		fmt.Fprintln(os.Stderr, "invalid rows/concurrency")
		os.Exit(2)
	}
	st, err := storage.NewClickHouse(storage.ClickHouseConfig{URL: *url, Database: *db, Table: *table, User: *user, Password: *password, RetentionDays: 1, BatchSize: *batch, FlushMS: 250, QueueSize: *queue})
	if err != nil {
		fmt.Fprintln(os.Stderr, "ERROR:", err)
		os.Exit(1)
	}
	defer st.Close()
	fmt.Printf("ClickHouse benchmark\nendpoint=%s database=%s table=%s rows=%d batch=%d concurrency=%d queue=%d\n", *url, *db, *table, *rows, *batch, *concurrency, *queue)
	start := time.Now()
	deadline := start.Add(*timeout)
	var next atomic.Int64
	var accepted atomic.Uint64
	var rejected atomic.Uint64
	var wg sync.WaitGroup
	for w := 0; w < *concurrency; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				n := int(next.Add(1)) - 1
				if n >= *rows {
					return
				}
				f := benchFlow(n, start)
				for {
					if time.Now().After(deadline) {
						rejected.Add(1)
						return
					}
					if err := st.Write(f); err == nil {
						accepted.Add(1)
						break
					}
					time.Sleep(100 * time.Microsecond)
				}
			}
		}()
	}
	wg.Wait()
	acceptedAt := time.Now()
	target := accepted.Load()
	for time.Now().Before(deadline) {
		s := st.Stats()
		if s.QueueDepth == 0 && s.Written+s.Dropped >= target {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	final := st.Stats()
	end := time.Now()
	acceptDur := acceptedAt.Sub(start)
	totalDur := end.Sub(start)
	fmt.Printf("accepted=%d rejected_by_producer=%d persisted=%d storage_dropped=%d write_errors=%d\n", accepted.Load(), rejected.Load(), final.Written, final.Dropped, final.WriteErrors)
	fmt.Printf("producer_seconds=%.3f producer_rate=%.0f rows/s\n", acceptDur.Seconds(), float64(accepted.Load())/max(acceptDur.Seconds(), 0.000001))
	fmt.Printf("end_to_end_seconds=%.3f persisted_rate=%.0f rows/s queue=%d/%d healthy=%v\n", totalDur.Seconds(), float64(final.Written)/max(totalDur.Seconds(), 0.000001), final.QueueDepth, final.QueueCapacity, final.Healthy)
	if final.Written < target || final.WriteErrors > 0 || final.Dropped > 0 {
		fmt.Fprintln(os.Stderr, "BENCHMARK INCOMPLETE: not all accepted rows were persisted cleanly")
		os.Exit(1)
	}
}

func benchFlow(n int, t time.Time) model.Flow {
	a := n%250 + 1
	b := (n/250)%250 + 1
	c := (n/62500)%250 + 1
	return model.Flow{ReceiveTime: t.Add(time.Duration(n%1000) * time.Microsecond), Exporter: fmt.Sprintf("10.250.%d.%d", c, b), Listener: "bench", Protocol: "ipfix", SrcIP: fmt.Sprintf("10.%d.%d.%d", c, b, a), DstIP: fmt.Sprintf("203.0.113.%d", a), SrcPort: uint16(1024 + n%50000), DstPort: uint16([]int{53, 80, 443, 22}[n%4]), IPProtocol: []uint8{6, 17}[n%2], Packets: uint64(1 + n%100), Bytes: uint64(64 + n%65536), SrcCountry: "TR", DstCountry: "US", SrcAS: 64510, DstAS: 64520, SrcASName: "Benchmark Source", DstASName: "Benchmark Destination", SrcSite: "bench-site", Sampling: 1}
}
func max(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
