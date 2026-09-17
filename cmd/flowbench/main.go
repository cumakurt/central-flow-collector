package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type report struct {
	Protocol         string  `json:"protocol"`
	Target           string  `json:"target"`
	DurationSeconds  float64 `json:"duration_seconds"`
	Workers          int     `json:"workers"`
	FlowsPerPacket   int     `json:"flows_per_packet"`
	Packets          uint64  `json:"packets"`
	Flows            uint64  `json:"flows"`
	Bytes            uint64  `json:"bytes"`
	Errors           uint64  `json:"errors"`
	PacketsPerSecond float64 `json:"packets_per_second"`
	FlowsPerSecond   float64 `json:"flows_per_second"`
	MiBPerSecond     float64 `json:"mib_per_second"`
	WriteP50US       float64 `json:"write_p50_us"`
	WriteP95US       float64 `json:"write_p95_us"`
	WriteP99US       float64 `json:"write_p99_us"`
	AllocBytes       uint64  `json:"alloc_bytes"`
	NumGC            uint32  `json:"num_gc"`
	GOMAXPROCS       int     `json:"gomaxprocs"`
}

type packetGenerator struct {
	data     func(int, uint32, *rand.Rand) []byte
	template func(uint32) []byte
}

func main() {
	protocol := flag.String("protocol", "netflow5", "netflow5|netflow9|ipfix|sflow")
	target := flag.String("target", "127.0.0.1:2055", "collector UDP address")
	duration := flag.Duration("duration", 10*time.Second, "benchmark duration")
	workers := flag.Int("workers", runtime.GOMAXPROCS(0), "parallel UDP writers")
	fpp := flag.Int("flows-per-packet", 30, "flow records per packet (1..30)")
	pps := flag.Int("pps", 0, "total packet/s target; 0=unlimited")
	sourceIPBase := flag.String("source-ip-base", "", "optional local IPv4 base; consecutive addresses are used per worker")
	jsonOut := flag.Bool("json", false, "emit JSON")
	flag.Parse()
	proto := strings.ToLower(strings.TrimSpace(*protocol))
	gen, ok := generator(proto)
	if !ok || *duration <= 0 || *workers < 1 || *workers > 1024 || *fpp < 1 || *fpp > 30 || *pps < 0 {
		fmt.Fprintln(os.Stderr, "invalid benchmark arguments")
		os.Exit(2)
	}
	addr, err := net.ResolveUDPAddr("udp", *target)
	if err != nil {
		fatal(err)
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	var packets, bytesN, errorsN atomic.Uint64
	start := time.Now()
	stop := start.Add(*duration)
	samples := make(chan int64, 65536)
	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			var localAddr *net.UDPAddr
			if *sourceIPBase != "" {
				ip, e := workerIPv4(*sourceIPBase, id)
				if e != nil {
					errorsN.Add(1)
					return
				}
				localAddr = &net.UDPAddr{IP: ip}
			}
			c, e := net.DialUDP("udp", localAddr, addr)
			if e != nil {
				errorsN.Add(1)
				return
			}
			defer c.Close()
			rng := rand.New(rand.NewSource(int64(1000 + id)))
			var ticker *time.Ticker
			perWorker := 0
			if *pps > 0 {
				perWorker = *pps / *workers
				if id < *pps%*workers {
					perWorker++
				}
				if perWorker < 1 {
					perWorker = 1
				}
				// Pace in 10 ms bursts. Per-packet tickers become scheduler-limited
				// above roughly 1 kHz and materially under-drive high-rate tests.
				ticker = time.NewTicker(10 * time.Millisecond)
				defer ticker.Stop()
			}
			seq := uint32(id + 1)
			if gen.template != nil {
				if _, e := c.Write(gen.template(seq)); e != nil {
					errorsN.Add(1)
					return
				}
			}
			local := uint64(0)
			burstRemaining := 0
			tokens := 0.0
			for time.Now().Before(stop) {
				if ticker != nil && burstRemaining == 0 {
					<-ticker.C
					tokens += float64(perWorker) / 100.0
					burstRemaining = int(tokens)
					tokens -= float64(burstRemaining)
					if burstRemaining == 0 {
						continue
					}
				}
				if ticker != nil {
					burstRemaining--
				}
				if gen.template != nil && local != 0 && local%16384 == 0 {
					if _, e := c.Write(gen.template(seq)); e != nil {
						errorsN.Add(1)
					}
				}
				b := gen.data(*fpp, seq, rng)
				t0 := time.Now()
				n, e := c.Write(b)
				dt := time.Since(t0)
				if e != nil {
					errorsN.Add(1)
					continue
				}
				packets.Add(1)
				bytesN.Add(uint64(n))
				local++
				if local&1023 == 0 {
					select {
					case samples <- dt.Nanoseconds():
					default:
					}
				}
				seq += uint32(*fpp)
			}
		}(w)
	}
	wg.Wait()
	close(samples)
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	lat := make([]int64, 0, len(samples))
	for x := range samples {
		lat = append(lat, x)
	}
	sort.Slice(lat, func(i, j int) bool { return lat[i] < lat[j] })
	pct := func(p float64) float64 {
		if len(lat) == 0 {
			return 0
		}
		i := int(float64(len(lat)-1) * p)
		return float64(lat[i]) / 1000
	}
	pk := packets.Load()
	by := bytesN.Load()
	secs := elapsed.Seconds()
	r := report{Protocol: proto, Target: *target, DurationSeconds: secs, Workers: *workers, FlowsPerPacket: *fpp, Packets: pk, Flows: pk * uint64(*fpp), Bytes: by, Errors: errorsN.Load(), PacketsPerSecond: float64(pk) / secs, FlowsPerSecond: float64(pk*uint64(*fpp)) / secs, MiBPerSecond: float64(by) / (1024 * 1024) / secs, WriteP50US: pct(.50), WriteP95US: pct(.95), WriteP99US: pct(.99), AllocBytes: after.TotalAlloc - before.TotalAlloc, NumGC: after.NumGC - before.NumGC, GOMAXPROCS: runtime.GOMAXPROCS(0)}
	if *jsonOut {
		_ = json.NewEncoder(os.Stdout).Encode(r)
		return
	}
	fmt.Printf("protocol=%s target=%s duration=%.2fs workers=%d flows/packet=%d\n", r.Protocol, r.Target, r.DurationSeconds, r.Workers, r.FlowsPerPacket)
	fmt.Printf("packets=%d flows=%d errors=%d throughput=%.0f pkt/s %.0f flow/s %.2f MiB/s\n", r.Packets, r.Flows, r.Errors, r.PacketsPerSecond, r.FlowsPerSecond, r.MiBPerSecond)
	fmt.Printf("udp-write latency p50=%.2fus p95=%.2fus p99=%.2fus alloc=%.2fMiB gc=%d GOMAXPROCS=%d\n", r.WriteP50US, r.WriteP95US, r.WriteP99US, float64(r.AllocBytes)/(1024*1024), r.NumGC, r.GOMAXPROCS)
}

func workerIPv4(base string, offset int) (net.IP, error) {
	ip := net.ParseIP(base).To4()
	if ip == nil {
		return nil, fmt.Errorf("source-ip-base must be IPv4")
	}
	v := binary.BigEndian.Uint32(ip)
	if uint64(v)+uint64(offset) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("source-ip-base range overflows IPv4")
	}
	out := make(net.IP, 4)
	binary.BigEndian.PutUint32(out, v+uint32(offset))
	return out, nil
}

func generator(protocol string) (packetGenerator, bool) {
	switch protocol {
	case "netflow5":
		return packetGenerator{data: nf5}, true
	case "netflow9":
		return packetGenerator{data: nf9Data, template: nf9Template}, true
	case "ipfix":
		return packetGenerator{data: ipfixData, template: ipfixTemplate}, true
	case "sflow":
		return packetGenerator{data: sflow5}, true
	default:
		return packetGenerator{}, false
	}
}

func fillRecord(b []byte, src, dst int, rng *rand.Rand) {
	b[0] = 10
	b[1] = byte(src%250 + 1)
	b[2] = byte(rng.Intn(250) + 1)
	b[3] = byte(rng.Intn(250) + 1)
	b[4] = 172
	b[5] = 16
	b[6] = byte(dst%250 + 1)
	b[7] = byte(rng.Intn(250) + 1)
}

func nf5(count int, seq uint32, rng *rand.Rand) []byte {
	b := make([]byte, 24+count*48)
	binary.BigEndian.PutUint16(b[0:2], 5)
	binary.BigEndian.PutUint16(b[2:4], uint16(count))
	binary.BigEndian.PutUint32(b[4:8], 600000)
	binary.BigEndian.PutUint32(b[8:12], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(b[16:20], seq)
	for i := 0; i < count; i++ {
		o := 24 + i*48
		fillRecord(b[o:o+8], i+int(seq), i, rng)
		binary.BigEndian.PutUint32(b[o+16:o+20], uint32(1+rng.Intn(50)))
		binary.BigEndian.PutUint32(b[o+20:o+24], uint32(500+rng.Intn(100000)))
		binary.BigEndian.PutUint32(b[o+24:o+28], 590000)
		binary.BigEndian.PutUint32(b[o+28:o+32], 599000)
		binary.BigEndian.PutUint16(b[o+32:o+34], uint16(1024+rng.Intn(50000)))
		ports := []uint16{53, 80, 443, 22, 3389}
		binary.BigEndian.PutUint16(b[o+34:o+36], ports[rng.Intn(len(ports))])
		b[o+37] = 0x12
		b[o+38] = 6
	}
	return b
}

func nf9Header(seq uint32, count int) []byte {
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[:2], 9)
	binary.BigEndian.PutUint16(b[2:4], uint16(count))
	binary.BigEndian.PutUint32(b[4:8], 600000)
	binary.BigEndian.PutUint32(b[8:12], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(b[12:16], seq)
	binary.BigEndian.PutUint32(b[16:20], 1)
	return b
}

func templateFields(set []byte, off int) {
	fields := [][2]uint16{{8, 4}, {12, 4}, {7, 2}, {11, 2}, {1, 4}}
	for _, x := range fields {
		binary.BigEndian.PutUint16(set[off:off+2], x[0])
		binary.BigEndian.PutUint16(set[off+2:off+4], x[1])
		off += 4
	}
}

func nf9Template(seq uint32) []byte {
	h := nf9Header(seq, 1)
	set := make([]byte, 4+4+5*4)
	binary.BigEndian.PutUint16(set[0:2], 0)
	binary.BigEndian.PutUint16(set[2:4], uint16(len(set)))
	binary.BigEndian.PutUint16(set[4:6], 256)
	binary.BigEndian.PutUint16(set[6:8], 5)
	templateFields(set, 8)
	return append(h, set...)
}

func nf9Data(count int, seq uint32, rng *rand.Rand) []byte {
	h := nf9Header(seq, count)
	set := make([]byte, 4+count*16)
	binary.BigEndian.PutUint16(set[:2], 256)
	binary.BigEndian.PutUint16(set[2:4], uint16(len(set)))
	ports := []uint16{53, 80, 443, 22, 3389}
	for i := 0; i < count; i++ {
		o := 4 + i*16
		fillRecord(set[o:o+8], i+int(seq), i, rng)
		binary.BigEndian.PutUint16(set[o+8:o+10], uint16(1024+rng.Intn(50000)))
		binary.BigEndian.PutUint16(set[o+10:o+12], ports[rng.Intn(len(ports))])
		binary.BigEndian.PutUint32(set[o+12:o+16], uint32(500+rng.Intn(100000)))
	}
	return append(h, set...)
}

func ipfixHeader(seq uint32) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint16(b[:2], 10)
	binary.BigEndian.PutUint32(b[4:8], uint32(time.Now().Unix()))
	binary.BigEndian.PutUint32(b[8:12], seq)
	binary.BigEndian.PutUint32(b[12:16], 1)
	return b
}

func ipfixTemplate(seq uint32) []byte {
	b := ipfixHeader(seq)
	set := make([]byte, 4+4+5*4)
	binary.BigEndian.PutUint16(set[:2], 2)
	binary.BigEndian.PutUint16(set[2:4], uint16(len(set)))
	binary.BigEndian.PutUint16(set[4:6], 256)
	binary.BigEndian.PutUint16(set[6:8], 5)
	templateFields(set, 8)
	b = append(b, set...)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	return b
}

func ipfixData(count int, seq uint32, rng *rand.Rand) []byte {
	b := ipfixHeader(seq)
	set := make([]byte, 4+count*16)
	binary.BigEndian.PutUint16(set[:2], 256)
	binary.BigEndian.PutUint16(set[2:4], uint16(len(set)))
	ports := []uint16{53, 80, 443, 22, 3389}
	for i := 0; i < count; i++ {
		o := 4 + i*16
		fillRecord(set[o:o+8], i+int(seq), i, rng)
		binary.BigEndian.PutUint16(set[o+8:o+10], uint16(1024+rng.Intn(50000)))
		binary.BigEndian.PutUint16(set[o+10:o+12], ports[rng.Intn(len(ports))])
		binary.BigEndian.PutUint32(set[o+12:o+16], uint32(500+rng.Intn(100000)))
	}
	b = append(b, set...)
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	return b
}

func sflow5(count int, seq uint32, rng *rand.Rand) []byte {
	b := make([]byte, 0, 64+count*40)
	add := func(v uint32) {
		var x [4]byte
		binary.BigEndian.PutUint32(x[:], v)
		b = append(b, x[:]...)
	}
	add(5)
	add(1)
	b = append(b, 127, 0, 0, 1)
	add(0)
	add(seq)
	add(600000)
	add(1)
	add(1)
	sampleLenPos := len(b)
	add(0)
	sampleData := len(b)
	add(seq)
	add(0)
	add(1)
	add(seq)
	add(0)
	add(0)
	add(0)
	add(uint32(count))
	ports := []uint16{53, 80, 443, 22, 3389}
	for i := 0; i < count; i++ {
		add(3)
		add(32)
		add(uint32(500 + rng.Intn(100000)))
		add(6)
		var rec [24]byte
		fillRecord(rec[:8], i+int(seq), i, rng)
		binary.BigEndian.PutUint32(rec[8:12], uint32(1024+rng.Intn(50000)))
		binary.BigEndian.PutUint32(rec[12:16], uint32(ports[rng.Intn(len(ports))]))
		binary.BigEndian.PutUint32(rec[16:20], 0x12)
		binary.BigEndian.PutUint32(rec[20:24], 0)
		b = append(b, rec[:]...)
	}
	binary.BigEndian.PutUint32(b[sampleLenPos:sampleLenPos+4], uint32(len(b)-sampleData))
	return b
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
