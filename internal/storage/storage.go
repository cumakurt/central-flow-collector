package storage

import (
	"bufio"
	"central-flow-collector/internal/model"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Query struct {
	SrcCountry, DstCountry, SrcSite, DstSite                                string
	IPProtocolSet                                                           bool
	From, To                                                                time.Time
	SrcIP, DstIP, Host, Exporter, Protocol, Listener, CollectorNode, Tenant string
	SrcCIDR, DstCIDR, CIDR, Country, Site, App, Service                     string
	SrcPort, DstPort, Port, IPProtocol, VLAN, IngressIf, EgressIf           int
	SrcAS, DstAS, ASN                                                       uint32
	TCPFlags                                                                uint16
	MinBytes, MaxBytes, MinPackets, MaxPackets                              uint64
	MinDurationMS, MaxDurationMS                                            int64
	Limit                                                                   int
}

type AggregateQuery struct {
	From, To time.Time
	Tenant   string
	Limit    int
	Filters  Query
	Metric   string
}

type AssetSummary struct {
	IP         string    `json:"ip"`
	BytesIn    uint64    `json:"bytes_in"`
	BytesOut   uint64    `json:"bytes_out"`
	PacketsIn  uint64    `json:"packets_in"`
	PacketsOut uint64    `json:"packets_out"`
	Flows      uint64    `json:"flows"`
	Peers      uint64    `json:"peers"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	Protocols  []int     `json:"protocols"`
	Country    string    `json:"country,omitempty"`
	Site       string    `json:"site,omitempty"`
	ASN        uint32    `json:"asn,omitempty"`
	ASName     string    `json:"as_name,omitempty"`
}

type ConversationSummary struct {
	AIP       string    `json:"a_ip"`
	APort     uint16    `json:"a_port"`
	BIP       string    `json:"b_ip"`
	BPort     uint16    `json:"b_port"`
	Protocol  uint8     `json:"protocol"`
	BytesAB   uint64    `json:"bytes_a_to_b"`
	BytesBA   uint64    `json:"bytes_b_to_a"`
	PacketsAB uint64    `json:"packets_a_to_b"`
	PacketsBA uint64    `json:"packets_b_to_a"`
	Flows     uint64    `json:"flows"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type HostQuery struct {
	IP       string
	Tenant   string
	From, To time.Time
	Limit    int
	Filters  Query
}

type RankedMetric struct {
	Key     string `json:"key"`
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Flows   uint64 `json:"flows"`
}

type PortMetric struct {
	Port     uint16 `json:"port"`
	Protocol uint8  `json:"protocol"`
	Bytes    uint64 `json:"bytes"`
	Packets  uint64 `json:"packets"`
	Flows    uint64 `json:"flows"`
}

type TimelineBucket struct {
	Timestamp  time.Time `json:"timestamp"`
	BytesIn    uint64    `json:"bytes_in"`
	BytesOut   uint64    `json:"bytes_out"`
	PacketsIn  uint64    `json:"packets_in"`
	PacketsOut uint64    `json:"packets_out"`
	Flows      uint64    `json:"flows"`
}

type HostInvestigation struct {
	IP         string           `json:"ip"`
	From       time.Time        `json:"from"`
	To         time.Time        `json:"to"`
	BytesIn    uint64           `json:"bytes_in"`
	BytesOut   uint64           `json:"bytes_out"`
	PacketsIn  uint64           `json:"packets_in"`
	PacketsOut uint64           `json:"packets_out"`
	Flows      uint64           `json:"flows"`
	FirstSeen  time.Time        `json:"first_seen"`
	LastSeen   time.Time        `json:"last_seen"`
	TopPeers   []RankedMetric   `json:"top_peers"`
	TopPorts   []PortMetric     `json:"top_ports"`
	Countries  []RankedMetric   `json:"countries"`
	Sites      []RankedMetric   `json:"sites"`
	Timeline   []TimelineBucket `json:"timeline"`
}

type Backend interface {
	Write(model.Flow) error
	Query(context.Context, Query) ([]model.Flow, error)
	Assets(context.Context, AggregateQuery) ([]AssetSummary, error)
	Conversations(context.Context, AggregateQuery) ([]ConversationSummary, error)
	InvestigateHost(context.Context, HostQuery) (HostInvestigation, error)
	Analyze(context.Context, Query, int) (AnalysisResult, error)
	AnalyzeTrafficSeries(context.Context, Query, []TrafficSelector) (TrafficSeriesResult, error)
	TrafficMatrix(context.Context, Query, int) ([]MatrixCell, error)
	Capacity(context.Context) (CapacityInfo, error)
	Retention() int
	SetRetention(context.Context, int) error
	Purge(context.Context) (PurgeResult, error)
	Close() error
	Stats() Stats
}

type PurgeResult struct {
	Backend       string `json:"backend"`
	RetentionDays int    `json:"retention_days"`
	DeletedFiles  int    `json:"deleted_files,omitempty"`
	FreedBytes    int64  `json:"freed_bytes,omitempty"`
	Action        string `json:"action"`
}

type persistedStorageSettings struct {
	RetentionDays int `json:"retention_days"`
}

func LoadRetentionOverride(dataDir string, fallback int) int {
	b, err := os.ReadFile(filepath.Join(dataDir, "storage-settings.json"))
	if err != nil {
		return fallback
	}
	var x persistedStorageSettings
	if json.Unmarshal(b, &x) == nil && x.RetentionDays >= 1 && x.RetentionDays <= 3650 {
		return x.RetentionDays
	}
	return fallback
}

func saveRetentionOverride(dataDir string, days int) error {
	if dataDir == "" {
		return nil
	}
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(persistedStorageSettings{RetentionDays: days}, "", "  ")
	p := filepath.Join(dataDir, "storage-settings.json")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0640); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

type Stats struct {
	Backend          string `json:"backend"`
	Healthy          bool   `json:"healthy"`
	LastError        string `json:"last_error,omitempty"`
	Written          uint64 `json:"written"`
	Dropped          uint64 `json:"dropped"`
	WriteErrors      uint64 `json:"write_errors"`
	QueueDepth       int    `json:"queue_depth"`
	QueueCapacity    int    `json:"queue_capacity"`
	BytesOnDisk      int64  `json:"bytes_on_disk"`
	SpoolFiles       int    `json:"spool_files,omitempty"`
	SpoolBytes       int64  `json:"spool_bytes,omitempty"`
	Spooled          uint64 `json:"spooled,omitempty"`
	Replayed         uint64 `json:"replayed,omitempty"`
	SpoolCorrupt     uint64 `json:"spool_corrupt,omitempty"`
	SpoolQuarantined uint64 `json:"spool_quarantined,omitempty"`
	SpoolRecovered   uint64 `json:"spool_recovered,omitempty"`
	SpoolLegacy      uint64 `json:"spool_legacy_replayed,omitempty"`
}

type Local struct {
	dir       string
	q         chan model.Flow
	stop      chan struct{}
	done      chan struct{}
	syncReq   chan chan struct{}
	written   atomic.Uint64
	dropped   atomic.Uint64
	errors    atomic.Uint64
	retention atomic.Int64
	mu        sync.Mutex
}

func NewLocal(dir string, queue, retention int) (*Local, error) {
	if queue < 64 {
		queue = 8192
	}
	if retention < 1 {
		retention = 7
	}
	if err := os.MkdirAll(filepath.Join(dir, "flows"), 0750); err != nil {
		return nil, err
	}
	l := &Local{dir: dir, q: make(chan model.Flow, queue), stop: make(chan struct{}), done: make(chan struct{}), syncReq: make(chan chan struct{})}
	l.retention.Store(int64(retention))
	go l.writer()
	return l, nil
}
func (l *Local) Write(f model.Flow) error {
	select {
	case l.q <- f:
		return nil
	default:
		l.dropped.Add(1)
		return errors.New("storage queue full")
	}
}
func (l *Local) writer() {
	defer close(l.done)
	tick := time.NewTicker(time.Second)
	purge := time.NewTicker(time.Hour)
	defer tick.Stop()
	defer purge.Stop()
	var file *os.File
	var bw *bufio.Writer
	var enc *json.Encoder
	day := ""
	flush := func() {
		if bw != nil {
			_ = bw.Flush()
		}
		if file != nil {
			_ = file.Sync()
		}
	}
	closeCurrent := func() {
		flush()
		if file != nil {
			_ = file.Close()
		}
		file = nil
		bw = nil
		enc = nil
		day = ""
	}
	writeOne := func(f model.Flow) {
		d := f.ReceiveTime.UTC().Format("2006-01-02")
		if f.ReceiveTime.IsZero() {
			d = time.Now().UTC().Format("2006-01-02")
		}
		if d != day || bw == nil {
			closeCurrent()
			p := filepath.Join(l.dir, "flows", d+".jsonl")
			var err error
			file, err = os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
			if err != nil {
				l.errors.Add(1)
				file = nil
				bw = nil
				return
			}
			bw = bufio.NewWriterSize(file, 1<<20)
			enc = json.NewEncoder(bw)
			day = d
		}
		if err := enc.Encode(f); err != nil {
			l.errors.Add(1)
			return
		}
		l.written.Add(1)
	}
	defer closeCurrent()
	for {
		select {
		case f := <-l.q:
			writeOne(f)
		case ack := <-l.syncReq:
			// Drain everything that was already queued before taking the snapshot,
			// then flush the buffered writer so immediate UI/API queries can see it.
			draining := true
			for draining {
				select {
				case f := <-l.q:
					writeOne(f)
				default:
					draining = false
				}
			}
			flush()
			close(ack)
		case <-tick.C:
			flush()
		case <-purge.C:
			l.purge()
		case <-l.stop:
			for {
				select {
				case f := <-l.q:
					writeOne(f)
				default:
					flush()
					return
				}
			}
		}
	}
}

func (l *Local) syncWrites(ctx context.Context) error {
	ack := make(chan struct{})
	select {
	case l.syncReq <- ack:
	case <-l.done:
		return errors.New("local storage is closed")
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-ack:
		return nil
	case <-l.done:
		return errors.New("local storage is closed")
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (l *Local) Close() error {
	select {
	case <-l.done:
		return nil
	default:
		close(l.stop)
		<-l.done
		return nil
	}
}
func (l *Local) Query(ctx context.Context, q Query) ([]model.Flow, error) {
	if err := l.syncWrites(ctx); err != nil {
		return nil, err
	}
	if q.Limit <= 0 || q.Limit > MaxExportRows {
		q.Limit = 500
	}
	if q.To.IsZero() {
		q.To = time.Now()
	}
	if q.From.IsZero() {
		q.From = q.To.Add(-time.Hour)
	}
	if q.To.Before(q.From) {
		return nil, errors.New("invalid time range")
	}
	if q.To.Sub(q.From) > 31*24*time.Hour {
		return nil, errors.New("time range exceeds 31 days")
	}
	var files []string
	for d := dateOnly(q.From.UTC()); !d.After(dateOnly(q.To.UTC())); d = d.AddDate(0, 0, 1) {
		files = append(files, filepath.Join(l.dir, "flows", d.Format("2006-01-02")+".jsonl"))
	}
	sort.Sort(sort.Reverse(sort.StringSlice(files)))
	out := make([]model.Flow, 0, q.Limit)
	for _, p := range files {
		select {
		case <-ctx.Done():
			return out, ctx.Err()
		default:
		}
		f, e := os.Open(p)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return out, e
		}
		sc := bufio.NewScanner(f)
		buf := make([]byte, 64*1024)
		sc.Buffer(buf, 2*1024*1024)
		var day []model.Flow
		for sc.Scan() {
			var x model.Flow
			if json.Unmarshal(sc.Bytes(), &x) != nil {
				continue
			}
			if !match(x, q) {
				continue
			}
			day = append(day, x)
		}
		_ = f.Close()
		if e := sc.Err(); e != nil {
			return out, e
		}
		for i := len(day) - 1; i >= 0 && len(out) < q.Limit; i-- {
			out = append(out, day[i])
		}
		if len(out) >= q.Limit {
			break
		}
	}
	return out, nil
}
func match(f model.Flow, q Query) bool {
	t := f.ReceiveTime
	if t.Before(q.From) || t.After(q.To) {
		return false
	}
	if q.SrcIP != "" && f.SrcIP != q.SrcIP {
		return false
	}
	if q.DstIP != "" && f.DstIP != q.DstIP {
		return false
	}
	if q.Host != "" && f.SrcIP != q.Host && f.DstIP != q.Host {
		return false
	}
	if q.Exporter != "" && f.Exporter != q.Exporter {
		return false
	}
	if q.CollectorNode != "" && f.CollectorNode != q.CollectorNode {
		return false
	}
	if q.Tenant != "" && f.Tenant != q.Tenant {
		return false
	}
	if q.Listener != "" && !strings.EqualFold(f.Listener, q.Listener) {
		return false
	}
	if q.Protocol != "" && !strings.EqualFold(f.Protocol, q.Protocol) {
		return false
	}
	if q.SrcPort > 0 && int(f.SrcPort) != q.SrcPort {
		return false
	}
	if q.DstPort > 0 && int(f.DstPort) != q.DstPort {
		return false
	}
	if q.Port > 0 && int(f.SrcPort) != q.Port && int(f.DstPort) != q.Port {
		return false
	}
	if q.Service != "" {
		selector, err := trafficSelectorForService(q.Service)
		if err != nil || !matchTrafficSelector(f, selector) {
			return false
		}
	}
	if (q.IPProtocolSet || q.IPProtocol > 0) && int(f.IPProtocol) != q.IPProtocol {
		return false
	}
	if q.VLAN > 0 && int(f.VLAN) != q.VLAN {
		return false
	}
	if q.IngressIf > 0 && int(f.IngressIf) != q.IngressIf {
		return false
	}
	if q.EgressIf > 0 && int(f.EgressIf) != q.EgressIf {
		return false
	}
	if q.SrcAS > 0 && f.SrcAS != q.SrcAS {
		return false
	}
	if q.DstAS > 0 && f.DstAS != q.DstAS {
		return false
	}
	if q.ASN > 0 && f.SrcAS != q.ASN && f.DstAS != q.ASN {
		return false
	}
	if q.TCPFlags > 0 && f.TCPFlags&q.TCPFlags != q.TCPFlags {
		return false
	}
	if q.Country != "" && !strings.EqualFold(f.SrcCountry, q.Country) && !strings.EqualFold(f.DstCountry, q.Country) {
		return false
	}
	for _, pair := range [][2]string{{q.SrcCountry, f.SrcCountry}, {q.DstCountry, f.DstCountry}, {q.SrcSite, f.SrcSite}, {q.DstSite, f.DstSite}} {
		if pair[0] != "" && pair[0] != pair[1] {
			return false
		}
	}
	if q.Site != "" && !strings.EqualFold(f.SrcSite, q.Site) && !strings.EqualFold(f.DstSite, q.Site) {
		return false
	}
	if q.App != "" && !strings.EqualFold(f.AppName, q.App) && !strings.EqualFold(f.AppID, q.App) {
		return false
	}
	if q.MinBytes > 0 && f.Bytes < q.MinBytes {
		return false
	}
	if q.MaxBytes > 0 && f.Bytes > q.MaxBytes {
		return false
	}
	if q.MinPackets > 0 && f.Packets < q.MinPackets {
		return false
	}
	if q.MaxPackets > 0 && f.Packets > q.MaxPackets {
		return false
	}
	if q.SrcCIDR != "" && !ipInCIDR(f.SrcIP, q.SrcCIDR) {
		return false
	}
	if q.DstCIDR != "" && !ipInCIDR(f.DstIP, q.DstCIDR) {
		return false
	}
	if q.CIDR != "" && !ipInCIDR(f.SrcIP, q.CIDR) && !ipInCIDR(f.DstIP, q.CIDR) {
		return false
	}
	dur := flowDurationMS(f)
	if q.MinDurationMS > 0 && dur < q.MinDurationMS {
		return false
	}
	if q.MaxDurationMS > 0 && dur > q.MaxDurationMS {
		return false
	}
	return true
}
func ipInCIDR(ip, cidr string) bool {
	p := net.ParseIP(ip)
	if p == nil {
		return false
	}
	_, n, e := net.ParseCIDR(cidr)
	return e == nil && n.Contains(p)
}
func flowDurationMS(f model.Flow) int64 {
	if f.StartTime.IsZero() || f.EndTime.IsZero() || f.EndTime.Before(f.StartTime) {
		return 0
	}
	return f.EndTime.Sub(f.StartTime).Milliseconds()
}
func dateOnly(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}
func (l *Local) purge()         { _, _ = l.Purge(context.Background()) }
func (l *Local) Retention() int { return int(l.retention.Load()) }
func (l *Local) SetRetention(ctx context.Context, days int) error {
	if days < 1 || days > 3650 {
		return errors.New("retention days must be 1..3650")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	if err := saveRetentionOverride(l.dir, days); err != nil {
		return err
	}
	l.retention.Store(int64(days))
	return nil
}
func (l *Local) Purge(ctx context.Context) (PurgeResult, error) {
	days := l.Retention()
	cut := time.Now().UTC().AddDate(0, 0, -days)
	dir := filepath.Join(l.dir, "flows")
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		return PurgeResult{}, err
	}
	r := PurgeResult{Backend: "local", RetentionDays: days, Action: "deleted expired local JSONL partitions"}
	for _, e := range entries {
		select {
		case <-ctx.Done():
			return r, ctx.Err()
		default:
		}
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".jsonl")
		d, er := time.Parse("2006-01-02", name)
		if er != nil || !d.Before(dateOnly(cut)) {
			continue
		}
		p := filepath.Join(dir, e.Name())
		if info, er := e.Info(); er == nil {
			r.FreedBytes += info.Size()
		}
		if er := os.Remove(p); er != nil {
			return r, er
		}
		r.DeletedFiles++
	}
	return r, nil
}
func (l *Local) Stats() Stats {
	return Stats{Backend: "local", Healthy: true, Written: l.written.Load(), Dropped: l.dropped.Load(), WriteErrors: l.errors.Load(), QueueDepth: len(l.q), QueueCapacity: cap(l.q), BytesOnDisk: dirSize(filepath.Join(l.dir, "flows"))}
}
func dirSize(dir string) int64 {
	var n int64
	_ = filepath.Walk(dir, func(_ string, i os.FileInfo, e error) error {
		if e == nil && i != nil && !i.IsDir() {
			n += i.Size()
		}
		return nil
	})
	return n
}

func normalizeAgg(q AggregateQuery) (AggregateQuery, error) {
	if q.To.IsZero() {
		q.To = time.Now()
	}
	if q.From.IsZero() {
		q.From = q.To.Add(-time.Hour)
	}
	if q.To.Before(q.From) {
		return q, errors.New("invalid time range")
	}
	if q.To.Sub(q.From) > 31*24*time.Hour {
		return q, errors.New("time range exceeds 31 days")
	}
	if q.Limit <= 0 || q.Limit > 1000 {
		q.Limit = 100
	}
	if q.Metric == "" {
		q.Metric = "bytes"
	}
	switch q.Metric {
	case "bytes", "packets", "flows", "peers":
	default:
		return q, errors.New("metric must be bytes, packets, flows or peers")
	}
	q.Filters.From, q.Filters.To, q.Filters.Tenant = q.From, q.To, q.Tenant
	return q, nil
}
func (l *Local) forEach(ctx context.Context, from, to time.Time, fn func(model.Flow)) error {
	if err := l.syncWrites(ctx); err != nil {
		return err
	}
	for d := dateOnly(from.UTC()); !d.After(dateOnly(to.UTC())); d = d.AddDate(0, 0, 1) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		f, e := os.Open(filepath.Join(l.dir, "flows", d.Format("2006-01-02")+".jsonl"))
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
		for sc.Scan() {
			if err := ctx.Err(); err != nil {
				_ = f.Close()
				return err
			}
			var x model.Flow
			if json.Unmarshal(sc.Bytes(), &x) != nil {
				continue
			}
			if x.ReceiveTime.Before(from) || x.ReceiveTime.After(to) {
				continue
			}
			fn(x)
		}
		e = sc.Err()
		_ = f.Close()
		if e != nil {
			return e
		}
	}
	return nil
}
func (l *Local) Assets(ctx context.Context, q AggregateQuery) ([]AssetSummary, error) {
	q, e := normalizeAgg(q)
	if e != nil {
		return nil, e
	}
	type acc struct {
		a      AssetSummary
		peers  map[string]struct{}
		protos map[uint8]struct{}
	}
	m := map[string]*acc{}
	get := func(ip string) *acc {
		if ip == "" {
			return nil
		}
		x := m[ip]
		if x == nil {
			x = &acc{a: AssetSummary{IP: ip}, peers: map[string]struct{}{}, protos: map[uint8]struct{}{}}
			m[ip] = x
		}
		return x
	}
	e = l.forEach(ctx, q.From, q.To, func(f model.Flow) {
		if !match(f, q.Filters) {
			return
		}
		if x := get(f.SrcIP); x != nil {
			x.a.BytesOut += f.Bytes
			x.a.PacketsOut += f.Packets
			x.a.Flows++
			if f.DstIP != "" {
				x.peers[f.DstIP] = struct{}{}
			}
			x.protos[f.IPProtocol] = struct{}{}
			if f.SrcCountry != "" {
				x.a.Country = f.SrcCountry
			}
			if f.SrcSite != "" {
				x.a.Site = f.SrcSite
			}
			if f.SrcAS != 0 {
				x.a.ASN = f.SrcAS
			}
			if f.SrcASName != "" {
				x.a.ASName = f.SrcASName
			}
			if x.a.FirstSeen.IsZero() || f.ReceiveTime.Before(x.a.FirstSeen) {
				x.a.FirstSeen = f.ReceiveTime
			}
			if f.ReceiveTime.After(x.a.LastSeen) {
				x.a.LastSeen = f.ReceiveTime
			}
		}
		if x := get(f.DstIP); x != nil {
			x.a.BytesIn += f.Bytes
			x.a.PacketsIn += f.Packets
			x.a.Flows++
			if f.SrcIP != "" {
				x.peers[f.SrcIP] = struct{}{}
			}
			x.protos[f.IPProtocol] = struct{}{}
			if f.DstCountry != "" {
				x.a.Country = f.DstCountry
			}
			if f.DstSite != "" {
				x.a.Site = f.DstSite
			}
			if f.DstAS != 0 {
				x.a.ASN = f.DstAS
			}
			if f.DstASName != "" {
				x.a.ASName = f.DstASName
			}
			if x.a.FirstSeen.IsZero() || f.ReceiveTime.Before(x.a.FirstSeen) {
				x.a.FirstSeen = f.ReceiveTime
			}
			if f.ReceiveTime.After(x.a.LastSeen) {
				x.a.LastSeen = f.ReceiveTime
			}
		}
	})
	if e != nil {
		return nil, e
	}
	out := make([]AssetSummary, 0, len(m))
	for _, x := range m {
		x.a.Peers = uint64(len(x.peers))
		for p := range x.protos {
			x.a.Protocols = append(x.a.Protocols, int(p))
		}
		sort.Slice(x.a.Protocols, func(i, j int) bool { return x.a.Protocols[i] < x.a.Protocols[j] })
		out = append(out, x.a)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := assetMetric(out[i], q.Metric), assetMetric(out[j], q.Metric)
		if a == b {
			return out[i].IP < out[j].IP
		}
		return a > b
	})
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

type convKey struct {
	aip, bip     string
	aport, bport uint16
	proto        uint8
}

func (l *Local) Conversations(ctx context.Context, q AggregateQuery) ([]ConversationSummary, error) {
	q, e := normalizeAgg(q)
	if e != nil {
		return nil, e
	}
	if q.Metric == "peers" {
		return nil, errors.New("conversation metric must be bytes, packets or flows")
	}
	m := map[convKey]*ConversationSummary{}
	e = l.forEach(ctx, q.From, q.To, func(f model.Flow) {
		if !match(f, q.Filters) {
			return
		}
		if f.SrcIP == "" || f.DstIP == "" {
			return
		}
		forward := f.SrcIP < f.DstIP || (f.SrcIP == f.DstIP && f.SrcPort <= f.DstPort)
		k := convKey{proto: f.IPProtocol}
		if forward {
			k.aip, k.aport, k.bip, k.bport = f.SrcIP, f.SrcPort, f.DstIP, f.DstPort
		} else {
			k.aip, k.aport, k.bip, k.bport = f.DstIP, f.DstPort, f.SrcIP, f.SrcPort
		}
		x := m[k]
		if x == nil {
			x = &ConversationSummary{AIP: k.aip, APort: k.aport, BIP: k.bip, BPort: k.bport, Protocol: k.proto}
			m[k] = x
		}
		if forward {
			x.BytesAB += f.Bytes
			x.PacketsAB += f.Packets
		} else {
			x.BytesBA += f.Bytes
			x.PacketsBA += f.Packets
		}
		x.Flows++
		if x.FirstSeen.IsZero() || f.ReceiveTime.Before(x.FirstSeen) {
			x.FirstSeen = f.ReceiveTime
		}
		if f.ReceiveTime.After(x.LastSeen) {
			x.LastSeen = f.ReceiveTime
		}
	})
	if e != nil {
		return nil, e
	}
	out := make([]ConversationSummary, 0, len(m))
	for _, x := range m {
		out = append(out, *x)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := conversationMetric(out[i], q.Metric), conversationMetric(out[j], q.Metric)
		if a == b {
			return conversationLess(out[i], out[j])
		}
		return a > b
	})
	if len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func normalizeHostQuery(q HostQuery) (HostQuery, error) {
	if strings.TrimSpace(q.IP) == "" {
		return q, errors.New("host IP required")
	}
	if net.ParseIP(q.IP) == nil {
		return q, errors.New("invalid host IP")
	}
	if q.To.IsZero() {
		q.To = time.Now()
	}
	if q.From.IsZero() {
		q.From = q.To.Add(-24 * time.Hour)
	}
	if q.To.Before(q.From) {
		return q, errors.New("invalid time range")
	}
	if q.To.Sub(q.From) > 31*24*time.Hour {
		return q, errors.New("time range exceeds 31 days")
	}
	if q.Limit <= 0 || q.Limit > 100 {
		q.Limit = 20
	}
	q.Filters.From, q.Filters.To, q.Filters.Tenant = q.From, q.To, q.Tenant
	return q, nil
}

func floor5m(t time.Time) time.Time {
	u := t.UTC()
	return u.Truncate(5 * time.Minute)
}

func rankMetrics(m map[string]*RankedMetric, limit int) []RankedMetric {
	out := make([]RankedMetric, 0, len(m))
	for _, x := range m {
		out = append(out, *x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (l *Local) InvestigateHost(ctx context.Context, q HostQuery) (HostInvestigation, error) {
	q, err := normalizeHostQuery(q)
	if err != nil {
		return HostInvestigation{}, err
	}
	out := HostInvestigation{IP: q.IP, From: q.From, To: q.To}
	peers := map[string]*RankedMetric{}
	countries := map[string]*RankedMetric{}
	sites := map[string]*RankedMetric{}
	type pk struct {
		port  uint16
		proto uint8
	}
	ports := map[pk]*PortMetric{}
	timeline := map[int64]*TimelineBucket{}
	addMetric := func(m map[string]*RankedMetric, key string, b, p uint64) {
		if key == "" {
			return
		}
		x := m[key]
		if x == nil {
			x = &RankedMetric{Key: key}
			m[key] = x
		}
		x.Bytes += b
		x.Packets += p
		x.Flows++
	}
	err = l.forEach(ctx, q.From, q.To, func(f model.Flow) {
		if !match(f, q.Filters) {
			return
		}
		isSrc := f.SrcIP == q.IP
		isDst := f.DstIP == q.IP
		if !isSrc && !isDst {
			return
		}
		out.Flows++
		if out.FirstSeen.IsZero() || f.ReceiveTime.Before(out.FirstSeen) {
			out.FirstSeen = f.ReceiveTime
		}
		if f.ReceiveTime.After(out.LastSeen) {
			out.LastSeen = f.ReceiveTime
		}
		bt := floor5m(f.ReceiveTime)
		tb := timeline[bt.Unix()]
		if tb == nil {
			tb = &TimelineBucket{Timestamp: bt}
			timeline[bt.Unix()] = tb
		}
		tb.Flows++
		if isSrc {
			out.BytesOut += f.Bytes
			out.PacketsOut += f.Packets
			tb.BytesOut += f.Bytes
			tb.PacketsOut += f.Packets
			addMetric(peers, f.DstIP, f.Bytes, f.Packets)
			addMetric(countries, f.DstCountry, f.Bytes, f.Packets)
			addMetric(sites, f.DstSite, f.Bytes, f.Packets)
			k := pk{f.DstPort, f.IPProtocol}
			x := ports[k]
			if x == nil {
				x = &PortMetric{Port: f.DstPort, Protocol: f.IPProtocol}
				ports[k] = x
			}
			x.Bytes += f.Bytes
			x.Packets += f.Packets
			x.Flows++
		}
		if isDst {
			out.BytesIn += f.Bytes
			out.PacketsIn += f.Packets
			tb.BytesIn += f.Bytes
			tb.PacketsIn += f.Packets
			addMetric(peers, f.SrcIP, f.Bytes, f.Packets)
			addMetric(countries, f.SrcCountry, f.Bytes, f.Packets)
			addMetric(sites, f.SrcSite, f.Bytes, f.Packets)
		}
	})
	if err != nil {
		return out, err
	}
	out.TopPeers = rankMetrics(peers, q.Limit)
	out.Countries = rankMetrics(countries, q.Limit)
	out.Sites = rankMetrics(sites, q.Limit)
	for _, x := range ports {
		out.TopPorts = append(out.TopPorts, *x)
	}
	sort.Slice(out.TopPorts, func(i, j int) bool { return out.TopPorts[i].Bytes > out.TopPorts[j].Bytes })
	if len(out.TopPorts) > q.Limit {
		out.TopPorts = out.TopPorts[:q.Limit]
	}
	for _, x := range timeline {
		out.Timeline = append(out.Timeline, *x)
	}
	sort.Slice(out.Timeline, func(i, j int) bool { return out.Timeline[i].Timestamp.Before(out.Timeline[j].Timestamp) })
	return out, nil
}

// MaxExportRows bounds raw flow downloads independently of interactive queries.
const MaxExportRows = 10000

func ParseQuery(v map[string][]string) (Query, error) {
	return parseQuery(v, 5000)
}

// ParseExportQuery applies the same flow validation with the export row ceiling.
func ParseExportQuery(v map[string][]string) (Query, error) {
	return parseQuery(v, MaxExportRows)
}

func parseQuery(v map[string][]string, maxRows int) (Query, error) {
	q := Query{Limit: 500}
	first := func(k string) string {
		if a := v[k]; len(a) > 0 {
			return strings.TrimSpace(a[0])
		}
		return ""
	}
	parseTime := func(k string) (time.Time, error) {
		s := first(k)
		if s == "" {
			return time.Time{}, nil
		}
		t, e := time.Parse(time.RFC3339, s)
		if e != nil {
			return time.Time{}, fmt.Errorf("invalid %s", k)
		}
		return t, nil
	}
	var err error
	if q.From, err = parseTime("from"); err != nil {
		return q, err
	}
	if q.To, err = parseTime("to"); err != nil {
		return q, err
	}
	q.SrcIP = first("src_ip")
	q.DstIP = first("dst_ip")
	q.Host = first("host")
	q.Exporter = first("exporter")
	q.CollectorNode = first("collector_node")
	q.Protocol = first("protocol")
	q.Listener = first("listener")
	q.SrcCIDR = first("src_cidr")
	q.DstCIDR = first("dst_cidr")
	q.CIDR = first("cidr")
	q.Country = first("country")
	q.SrcCountry = first("src_country")
	q.DstCountry = first("dst_country")
	q.SrcSite = first("src_site")
	q.DstSite = first("dst_site")
	q.Site = first("site")
	q.App = first("app")
	q.Service = strings.ToLower(first("service"))
	if q.Service != "" {
		if _, ok := ServiceByID(q.Service); !ok {
			return q, errors.New("invalid service")
		}
	}
	for _, x := range []struct {
		k        string
		dst      *int
		min, max int
	}{{"src_port", &q.SrcPort, 1, 65535}, {"dst_port", &q.DstPort, 1, 65535}, {"port", &q.Port, 1, 65535}, {"ip_protocol", &q.IPProtocol, 0, 255}, {"vlan", &q.VLAN, 1, 4095}, {"ingress_if", &q.IngressIf, 1, 1<<31 - 1}, {"egress_if", &q.EgressIf, 1, 1<<31 - 1}} {
		if s := first(x.k); s != "" {
			if x.k == "ip_protocol" {
				q.IPProtocolSet = true
				for code := 0; code <= 255; code++ {
					if strings.EqualFold(s, protocolName(uint8(code))) {
						s = strconv.Itoa(code)
						break
					}
				}
			}
			n, e := strconv.Atoi(s)
			if e != nil || n < x.min || n > x.max {
				return q, fmt.Errorf("invalid %s", x.k)
			}
			*x.dst = n
		}
	}
	parseU32 := func(k string, dst *uint32) error {
		if s := first(k); s != "" {
			n, e := strconv.ParseUint(s, 10, 32)
			if e != nil || n == 0 {
				return fmt.Errorf("invalid %s", k)
			}
			*dst = uint32(n)
		}
		return nil
	}
	if err = parseU32("src_as", &q.SrcAS); err != nil {
		return q, err
	}
	if err = parseU32("dst_as", &q.DstAS); err != nil {
		return q, err
	}
	if err = parseU32("asn", &q.ASN); err != nil {
		return q, err
	}
	if s := first("tcp_flags"); s != "" {
		n, e := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 16)
		if e != nil {
			return q, errors.New("invalid tcp_flags (use hex, e.g. 02 or 12)")
		}
		q.TCPFlags = uint16(n)
	}
	parseU64 := func(k string, dst *uint64) error {
		if s := first(k); s != "" {
			n, e := strconv.ParseUint(s, 10, 64)
			if e != nil {
				return fmt.Errorf("invalid %s", k)
			}
			*dst = n
		}
		return nil
	}
	for _, x := range []struct {
		k   string
		dst *uint64
	}{{"min_bytes", &q.MinBytes}, {"max_bytes", &q.MaxBytes}, {"min_packets", &q.MinPackets}, {"max_packets", &q.MaxPackets}} {
		if err = parseU64(x.k, x.dst); err != nil {
			return q, err
		}
	}
	parseI64 := func(k string, dst *int64) error {
		if s := first(k); s != "" {
			n, e := strconv.ParseInt(s, 10, 64)
			if e != nil || n < 0 {
				return fmt.Errorf("invalid %s", k)
			}
			*dst = n
		}
		return nil
	}
	if err = parseI64("min_duration_ms", &q.MinDurationMS); err != nil {
		return q, err
	}
	if err = parseI64("max_duration_ms", &q.MaxDurationMS); err != nil {
		return q, err
	}
	for _, x := range []struct{ k, v string }{{"src_cidr", q.SrcCIDR}, {"dst_cidr", q.DstCIDR}, {"cidr", q.CIDR}} {
		if x.v != "" {
			if _, _, e := net.ParseCIDR(x.v); e != nil {
				return q, fmt.Errorf("invalid %s", x.k)
			}
		}
	}
	if q.MaxBytes > 0 && q.MinBytes > q.MaxBytes {
		return q, errors.New("min_bytes exceeds max_bytes")
	}
	if q.MaxPackets > 0 && q.MinPackets > q.MaxPackets {
		return q, errors.New("min_packets exceeds max_packets")
	}
	if q.MaxDurationMS > 0 && q.MinDurationMS > q.MaxDurationMS {
		return q, errors.New("min_duration_ms exceeds max_duration_ms")
	}
	if s := first("limit"); s != "" {
		n, e := strconv.Atoi(s)
		if e != nil || n < 1 || n > maxRows {
			return q, errors.New("invalid limit")
		}
		q.Limit = n
	}
	return q, nil
}

func ParseAggregateQuery(v map[string][]string) (AggregateQuery, error) {
	q := AggregateQuery{Limit: 100}
	filters, err := ParseQuery(v)
	if err != nil {
		return q, err
	}
	q.Filters = filters
	if metric := v["metric"]; len(metric) > 0 {
		q.Metric = metric[0]
	}
	parseTime := func(k string) (time.Time, error) {
		s := ""
		if a := v[k]; len(a) > 0 {
			s = a[0]
		}
		if s == "" {
			return time.Time{}, nil
		}
		t, e := time.Parse(time.RFC3339, s)
		if e != nil {
			return time.Time{}, fmt.Errorf("invalid %s", k)
		}
		return t, nil
	}
	var e error
	q.From, e = parseTime("from")
	if e != nil {
		return q, e
	}
	q.To, e = parseTime("to")
	if e != nil {
		return q, e
	}
	if a := v["limit"]; len(a) > 0 && a[0] != "" {
		n, e := strconv.Atoi(a[0])
		if e != nil || n < 1 || n > 1000 {
			return q, errors.New("invalid limit")
		}
		q.Limit = n
	}
	return normalizeAgg(q)
}
