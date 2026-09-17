package collector

import (
	"central-flow-collector/internal/analytics"
	"central-flow-collector/internal/config"
	"central-flow-collector/internal/decoder/ipfix"
	"central-flow-collector/internal/decoder/netflow9"
	"central-flow-collector/internal/decoder/netflowfixed"
	"central-flow-collector/internal/decoder/sflow"
	"central-flow-collector/internal/dedup"
	"central-flow-collector/internal/enrichment"
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/policy"
	"central-flow-collector/internal/storage"
	"central-flow-collector/internal/templates"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type packet struct {
	data []byte
	ctx  model.PacketContext
}
type udpDatagram struct {
	data []byte
	n    int
	src  string
	port uint16
}
type packetBatchReader interface {
	Read(*sync.Pool) ([]udpDatagram, error)
}
type ListenerState struct {
	Name, Protocol, Bind      string
	Port                      int
	Packets, Bytes, Drops     uint64
	QueueDepth, QueueCapacity int
	Running                   bool
	LastError                 string
}
type ExporterHealth struct {
	Address          string    `json:"address"`
	Protocol         string    `json:"protocol"`
	Listener         string    `json:"listener"`
	Allowed          bool      `json:"allowed"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	PacketsReceived  uint64    `json:"packets_received"`
	PacketsRejected  uint64    `json:"packets_rejected"`
	Flows            uint64    `json:"flows"`
	DecodeErrors     uint64    `json:"decode_errors"`
	MissingTemplates uint64    `json:"missing_templates"`
	SequenceGaps     uint64    `json:"sequence_gaps"`
	HealthScore      int       `json:"health_score"`
	State            string    `json:"state"`
	SilenceSeconds   int64     `json:"silence_seconds"`
	PacketRate       float64   `json:"packet_rate"`
	FlowRate         float64   `json:"flow_rate"`
	DecodeErrorRate  float64   `json:"decode_error_rate"`
	TemplateStatus   string    `json:"template_status"`
	Reasons          []string  `json:"reasons"`
}
type Collector struct {
	cfg              config.Config
	policy           *policy.Engine
	store            storage.Backend
	analytics        *analytics.Engine
	enrichment       *enrichment.Engine
	deduper          *dedup.Detector
	globalDedup      func(model.Flow) (bool, error)
	globalAccepted   atomic.Uint64
	globalDuplicates atomic.Uint64
	globalErrors     atomic.Uint64
	templates        *templates.Cache
	nf9              *netflow9.Decoder
	ipfix            *ipfix.Decoder
	mu               sync.RWMutex
	exporters        map[string]*model.ExporterStat
	rejects          map[string]*model.RejectionStat
	listeners        map[string]*listenerRuntime
	healthAlerted    map[string]bool
	sequences        map[sequenceKey]sequenceState
	ctx              context.Context
	cancel           context.CancelFunc
	wg               sync.WaitGroup
	packetPool       sync.Pool
	smallPacketPool  sync.Pool
	mediumPacketPool sync.Pool
	paused           atomic.Bool
	rateMu           sync.Mutex
	rates            map[string]*rateState
	policyMu         sync.RWMutex
	policyTraffic    map[string]*PolicyTraffic
	timeline         [120]protocolTimelineSlot
	liveMu           sync.Mutex
	liveFlows        [512]model.Flow
	liveFlowNext     int
	liveFlowCount    int
	livePackets      [512]LivePacket
	livePacketNext   int
	livePacketCount  int
}
type PolicyTraffic struct {
	RuleID       string            `json:"rule_id"`
	Flows        uint64            `json:"flows"`
	Bytes        uint64            `json:"bytes"`
	Packets      uint64            `json:"packets"`
	InBytes      uint64            `json:"in_bytes"`
	OutBytes     uint64            `json:"out_bytes"`
	UnknownBytes uint64            `json:"unknown_bytes"`
	Protocols    map[string]uint64 `json:"protocols"`
	LastSeen     time.Time         `json:"last_seen,omitempty"`
}
type rateState struct {
	tokens float64
	last   time.Time
}

type listenerRuntime struct {
	cfg     config.Listener
	conn    io.Closer
	stream  net.Listener
	queues  []chan packet
	reader  packetBatchReader
	packets atomic.Uint64
	bytes   atomic.Uint64
	drops   atomic.Uint64
	running atomic.Bool
	lastErr atomic.Value
}

func New(cfg config.Config, p *policy.Engine, s storage.Backend, a *analytics.Engine, e *enrichment.Engine) *Collector {
	tc := templates.New(30 * time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	c := &Collector{cfg: cfg, policy: p, store: s, analytics: a, enrichment: e, templates: tc, nf9: netflow9.New(tc), ipfix: ipfix.New(tc), exporters: map[string]*model.ExporterStat{}, rejects: map[string]*model.RejectionStat{}, listeners: map[string]*listenerRuntime{}, healthAlerted: map[string]bool{}, rates: map[string]*rateState{}, policyTraffic: map[string]*PolicyTraffic{}, ctx: ctx, cancel: cancel}
	c.packetPool.New = func() any { return make([]byte, 65535) }
	c.smallPacketPool.New = func() any { return make([]byte, 2048) }
	c.mediumPacketPool.New = func() any { return make([]byte, 8192) }
	if cfg.Analytics.DedupEnabled {
		c.deduper = dedup.New(time.Duration(cfg.Analytics.DedupWindowSeconds)*time.Second, cfg.Analytics.DedupMaxEntries)
	}
	return c
}
func (c *Collector) SetGlobalDedup(fn func(model.Flow) (bool, error)) { c.globalDedup = fn }
func (c *Collector) Start() error {
	for _, lc := range c.cfg.Listeners {
		if !lc.Enabled {
			continue
		}
		if err := c.startListener(lc); err != nil {
			c.Stop()
			return err
		}
	}
	c.wg.Add(1)
	go c.healthLoop()
	return nil
}
func (c *Collector) allowExporterPacket(src, listener string, now time.Time) bool {
	rate := c.cfg.Security.ExporterPacketsPerSec
	if rate <= 0 {
		return true
	}
	burst := c.cfg.Security.ExporterBurst
	if burst <= 0 {
		burst = rate * 2
	}
	key := src + "|" + listener
	c.rateMu.Lock()
	defer c.rateMu.Unlock()
	rs := c.rates[key]
	if rs == nil {
		rs = &rateState{tokens: float64(burst), last: now}
		c.rates[key] = rs
	}
	elapsed := now.Sub(rs.last).Seconds()
	if elapsed > 0 {
		rs.tokens += elapsed * float64(rate)
		if rs.tokens > float64(burst) {
			rs.tokens = float64(burst)
		}
		rs.last = now
	}
	if rs.tokens < 1 {
		return false
	}
	rs.tokens -= 1
	return true
}

func (c *Collector) cleanupRates(now time.Time) {
	c.rateMu.Lock()
	defer c.rateMu.Unlock()
	for k, rs := range c.rates {
		if now.Sub(rs.last) > 10*time.Minute {
			delete(c.rates, k)
		}
	}
}

func (c *Collector) startListener(lc config.Listener) error {
	transport := strings.ToLower(strings.TrimSpace(lc.Transport))
	if transport == "" {
		transport = "udp"
	}
	if transport != "udp" {
		return c.startStreamListener(lc, transport)
	}
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(lc.Bind, fmt.Sprint(lc.Port)))
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return fmt.Errorf("listener %s: %w", lc.Name, err)
	}
	if lc.ReadBuffer > 0 {
		_ = conn.SetReadBuffer(lc.ReadBuffer)
	}
	perQueue := lc.QueueSize / lc.Workers
	if perQueue < 64 {
		perQueue = 64
	}
	rt := &listenerRuntime{cfg: lc, conn: conn, queues: make([]chan packet, lc.Workers)}
	for i := range rt.queues {
		rt.queues[i] = make(chan packet, perQueue)
	}
	rt.reader, err = newPacketBatchReader(conn, lc.BatchSize)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("listener %s batch reader: %w", lc.Name, err)
	}
	rt.running.Store(true)
	c.mu.Lock()
	c.listeners[lc.Name] = rt
	c.mu.Unlock()
	for i := 0; i < lc.Workers; i++ {
		c.wg.Add(1)
		go c.worker(rt, rt.queues[i])
	}
	c.wg.Add(1)
	go c.readLoop(rt)
	return nil
}

func (c *Collector) startStreamListener(lc config.Listener, transport string) error {
	if strings.ToLower(lc.Protocol) != "ipfix" {
		return fmt.Errorf("listener %s: %s transport is only supported for ipfix", lc.Name, transport)
	}
	var ln net.Listener
	var err error
	addr := net.JoinHostPort(lc.Bind, fmt.Sprint(lc.Port))
	if transport == "tcp" {
		ln, err = net.Listen("tcp", addr)
	} else {
		ln, err = listenSCTP(lc.Bind, lc.Port)
	}
	if err != nil {
		return fmt.Errorf("listener %s: %w", lc.Name, err)
	}
	perQueue := lc.QueueSize / lc.Workers
	if perQueue < 64 {
		perQueue = 64
	}
	rt := &listenerRuntime{cfg: lc, conn: ln, stream: ln, queues: make([]chan packet, lc.Workers)}
	for i := range rt.queues {
		rt.queues[i] = make(chan packet, perQueue)
	}
	rt.running.Store(true)
	c.mu.Lock()
	c.listeners[lc.Name] = rt
	c.mu.Unlock()
	for i := 0; i < lc.Workers; i++ {
		c.wg.Add(1)
		go c.worker(rt, rt.queues[i])
	}
	c.wg.Add(1)
	go c.acceptLoop(rt)
	return nil
}

func (c *Collector) acceptLoop(rt *listenerRuntime) {
	defer c.wg.Done()
	for {
		conn, err := rt.stream.Accept()
		if err != nil {
			if c.ctx.Err() != nil {
				return
			}
			rt.lastErr.Store(err.Error())
			continue
		}
		c.wg.Add(1)
		go c.streamConn(rt, conn)
	}
}

func (c *Collector) streamConn(rt *listenerRuntime, conn net.Conn) {
	defer c.wg.Done()
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	host, port := remote, 0
	if a, err := net.ResolveTCPAddr("tcp", remote); err == nil {
		host = a.IP.String()
		port = a.Port
	} else if h, p, e := net.SplitHostPort(remote); e == nil {
		host = h
		port, _ = strconv.Atoi(p)
	}
	for {
		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		size := int(binary.BigEndian.Uint16(header[2:]))
		if size < 16 || size > 65535 {
			return
		}
		packetBytes := make([]byte, size)
		copy(packetBytes, header)
		if _, err := io.ReadFull(conn, packetBytes[4:]); err != nil {
			return
		}
		c.dispatchStreamDatagram(rt, packetBytes, host, uint16(port))
	}
}

func (c *Collector) dispatchStreamDatagram(rt *listenerRuntime, b []byte, src string, port uint16) {
	rt.packets.Add(1)
	rt.bytes.Add(uint64(len(b)))
	if c.paused.Load() {
		rt.drops.Add(1)
		c.recordLivePacket(src, rt.cfg.Name, rt.cfg.Protocol, b, false, "paused")
		return
	}
	dec := policy.Decision{Allowed: true}
	if c.policy != nil {
		dec = c.policy.Decide(src, rt.cfg.Protocol, rt.cfg.Name, rt.cfg.Port)
	}
	c.recordLivePacket(src, rt.cfg.Name, rt.cfg.Protocol, b, dec.Allowed, dec.Reason)
	if !dec.Allowed {
		c.reject(src, rt.cfg.Protocol, rt.cfg.Name, len(b), dec.Reason)
		return
	}
	now := time.Now().UTC()
	if !c.allowExporterPacket(src, rt.cfg.Name, now) {
		rt.drops.Add(1)
		c.reject(src, rt.cfg.Protocol, rt.cfg.Name, len(b), "exporter packet rate limit exceeded")
		return
	}
	c.seenPacket(src, rt.cfg.Protocol, rt.cfg.Name, true)
	p := packet{data: b, ctx: model.PacketContext{Exporter: src, SourcePort: port, Listener: rt.cfg.Name, Protocol: rt.cfg.Protocol, RuleID: dec.RuleID, DestPort: rt.cfg.Port, Received: now}}
	q := rt.queues[shardIndex(src, len(rt.queues))]
	select {
	case q <- p:
	default:
		rt.drops.Add(1)
	}
}
func shardIndex(src string, n int) int {
	if n <= 1 {
		return 0
	}
	var h uint32 = 2166136261
	for i := 0; i < len(src); i++ {
		h ^= uint32(src[i])
		h *= 16777619
	}
	return int(h % uint32(n))
}

func (c *Collector) dispatchDatagram(rt *listenerRuntime, d udpDatagram) {
	rt.packets.Add(1)
	rt.bytes.Add(uint64(d.n))
	if c.paused.Load() {
		c.recordLivePacket(d.src, rt.cfg.Name, rt.cfg.Protocol, d.data[:d.n], false, "paused")
		rt.drops.Add(1)
		c.packetPool.Put(d.data[:cap(d.data)])
		return
	}
	src := d.src
	dec := c.policy.Decide(src, rt.cfg.Protocol, rt.cfg.Name, rt.cfg.Port)
	c.recordLivePacket(src, rt.cfg.Name, rt.cfg.Protocol, d.data[:d.n], dec.Allowed, dec.Reason)
	if !dec.Allowed {
		c.reject(src, rt.cfg.Protocol, rt.cfg.Name, d.n, dec.Reason)
		c.packetPool.Put(d.data[:cap(d.data)])
		return
	}
	now := time.Now().UTC()
	if !c.allowExporterPacket(src, rt.cfg.Name, now) {
		rt.drops.Add(1)
		c.reject(src, rt.cfg.Protocol, rt.cfg.Name, d.n, "exporter packet rate limit exceeded")
		c.packetPool.Put(d.data[:cap(d.data)])
		return
	}
	c.seenPacket(src, rt.cfg.Protocol, rt.cfg.Name, true)
	data := c.queuePacketBuffer(d.data, d.n)
	p := packet{data: data, ctx: model.PacketContext{Exporter: src, SourcePort: d.port, Listener: rt.cfg.Name, Protocol: rt.cfg.Protocol, RuleID: dec.RuleID, DestPort: rt.cfg.Port, Received: now}}
	q := rt.queues[shardIndex(src, len(rt.queues))]
	select {
	case q <- p:
	default:
		rt.drops.Add(1)
		c.releasePacketBuffer(data)
	}
}

func (c *Collector) queuePacketBuffer(src []byte, n int) []byte {
	if n <= 2048 {
		b := c.smallPacketPool.Get().([]byte)
		b = b[:n]
		copy(b, src[:n])
		c.packetPool.Put(src[:cap(src)])
		return b
	}
	if n <= 8192 {
		b := c.mediumPacketPool.Get().([]byte)
		b = b[:n]
		copy(b, src[:n])
		c.packetPool.Put(src[:cap(src)])
		return b
	}
	return src[:n]
}

func (c *Collector) releasePacketBuffer(b []byte) {
	switch cap(b) {
	case 2048:
		c.smallPacketPool.Put(b[:cap(b)])
	case 8192:
		c.mediumPacketPool.Put(b[:cap(b)])
	default:
		c.packetPool.Put(b[:cap(b)])
	}
}

func (c *Collector) readLoop(rt *listenerRuntime) {
	defer c.wg.Done()
	for {
		ds, err := rt.reader.Read(&c.packetPool)
		if err != nil {
			if c.ctx.Err() != nil {
				rt.running.Store(false)
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			rt.lastErr.Store(err.Error())
			continue
		}
		for _, d := range ds {
			c.dispatchDatagram(rt, d)
		}
	}
}
func (c *Collector) worker(rt *listenerRuntime, q <-chan packet) {
	defer c.wg.Done()
	for {
		select {
		case p := <-q:
			c.process(p)
			c.releasePacketBuffer(p.data)
		case <-c.ctx.Done():
			return
		}
	}
}
func (c *Collector) process(p packet) {
	var r model.DecodeResult
	var err error
	proto := strings.ToLower(p.ctx.Protocol)
	switch proto {
	case "netflow":
		if len(p.data) < 2 {
			err = errors.New("short packet")
			break
		}
		v := binary.BigEndian.Uint16(p.data[:2])
		if v == 1 || v == 5 || v == 7 || v == 8 {
			r, err = netflowfixed.Decode(p.data, p.ctx)
		} else if v == 9 {
			r, err = c.nf9.Decode(p.data, p.ctx)
		} else if v == 10 {
			r, err = c.ipfix.Decode(p.data, p.ctx)
		} else {
			err = fmt.Errorf("unsupported netflow version %d", v)
		}
	case "ipfix":
		r, err = c.ipfix.Decode(p.data, p.ctx)
	case "sflow":
		r, err = sflow.Decode(p.data, p.ctx)
	default:
		err = fmt.Errorf("unsupported listener protocol %s", proto)
	}
	if err == nil && r.MissingTemplate && len(r.Flows) == 0 && (proto == "netflow" || proto == "ipfix") {
		// UDP/template packets may be reordered, including by parallel listener workers.
		// Give a concurrently arriving template two short bounded chances before counting it missing.
		for attempt := 0; attempt < 2 && r.MissingTemplate && len(r.Flows) == 0; attempt++ {
			time.Sleep(time.Duration(attempt+1) * 2 * time.Millisecond)
			if proto == "ipfix" || (len(p.data) >= 2 && binary.BigEndian.Uint16(p.data[:2]) == 10) {
				r, err = c.ipfix.Decode(p.data, p.ctx)
			} else if len(p.data) >= 2 && binary.BigEndian.Uint16(p.data[:2]) == 9 {
				r, err = c.nf9.Decode(p.data, p.ctx)
			}
		}
	}
	if err != nil {
		c.decodeError(p.ctx.Exporter, p.ctx.Protocol, p.ctx.Listener)
		return
	}
	c.observeSequence(p, r)
	now := time.Now().UTC()
	accepted := r.Flows[:0]
	for _, f := range r.Flows {
		f.CollectorNode = c.cfg.Node.ID
		f.Tenant = "" // legacy storage field; v4 is single-organization
		if f.Sampling > 1 {
			f.Packets *= uint64(f.Sampling)
			f.Bytes *= uint64(f.Sampling)
		}
		if c.enrichment != nil {
			c.enrichment.Enrich(&f)
		}
		if f.AppName == "" {
			f.AppName = model.ApplicationName(f)
		}
		if c.deduper != nil && !c.deduper.Accept(f, now) {
			continue
		}
		if c.globalDedup != nil {
			ok, err := c.globalDedup(f)
			if err != nil {
				c.globalErrors.Add(1)
			} else if !ok {
				c.globalDuplicates.Add(1)
				continue
			} else {
				c.globalAccepted.Add(1)
			}
		}
		accepted = append(accepted, f)
	}
	if len(accepted) == 0 {
		return
	}
	c.analytics.ObserveBatch(accepted)
	for i := range accepted {
		f := accepted[i]
		_ = c.store.Write(f)
		c.recordPolicyFlow(p.ctx.RuleID, f)
	}
	c.recordLiveFlows(now, accepted)
}

func (c *Collector) recordPolicyFlow(id string, f model.Flow) {
	if id == "" {
		return
	}
	c.policyMu.Lock()
	defer c.policyMu.Unlock()
	x := c.policyTraffic[id]
	if x == nil {
		x = &PolicyTraffic{RuleID: id, Protocols: map[string]uint64{}}
		c.policyTraffic[id] = x
	}
	x.Flows++
	x.Bytes += f.Bytes
	x.Packets += f.Packets
	switch f.Direction {
	case 1:
		x.InBytes += f.Bytes
	case 2:
		x.OutBytes += f.Bytes
	default:
		x.UnknownBytes += f.Bytes
	}
	x.Protocols[f.Protocol]++
	x.LastSeen = time.Now().UTC()
}

func (c *Collector) PolicyTraffic() []PolicyTraffic {
	c.policyMu.RLock()
	defer c.policyMu.RUnlock()
	out := make([]PolicyTraffic, 0, len(c.policyTraffic))
	for _, x := range c.policyTraffic {
		copy := *x
		copy.Protocols = make(map[string]uint64, len(x.Protocols))
		for k, v := range x.Protocols {
			copy.Protocols[k] = v
		}
		out = append(out, copy)
	}
	return out
}
func (c *Collector) seenPacket(ip, proto, listener string, allowed bool) {
	k := ip + "|" + proto + "|" + listener
	c.mu.Lock()
	defer c.mu.Unlock()
	x := c.exporters[k]
	if x == nil {
		x = &model.ExporterStat{Address: ip, Protocol: proto, Listener: listener, Allowed: allowed, FirstSeen: time.Now().UTC()}
		c.exporters[k] = x
	}
	x.LastSeen = time.Now().UTC()
	x.PacketsReceived++
	x.Allowed = allowed
}
func (c *Collector) decodeError(ip, proto, listener string) {
	k := ip + "|" + proto + "|" + listener
	c.mu.Lock()
	defer c.mu.Unlock()
	x := c.exporters[k]
	if x == nil {
		x = &model.ExporterStat{Address: ip, Protocol: proto, Listener: listener, Allowed: true, FirstSeen: time.Now().UTC()}
		c.exporters[k] = x
	}
	x.LastSeen = time.Now().UTC()
	x.DecodeErrors++
}
func (c *Collector) reject(ip, proto, listener string, n int, reason string) {
	key := ip + "|" + proto + "|" + listener
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.rejects[key]
	if r == nil {
		r = &model.RejectionStat{SourceIP: ip, Protocol: proto, Listener: listener, FirstSeen: time.Now().UTC(), Reason: reason}
		c.rejects[key] = r
	}
	r.LastSeen = time.Now().UTC()
	r.Packets++
	r.Bytes += uint64(n)
	r.Reason = reason
	x := c.exporters[key]
	if x == nil {
		x = &model.ExporterStat{Address: ip, Protocol: proto, Listener: listener, Allowed: false, FirstSeen: r.FirstSeen}
		c.exporters[key] = x
	}
	x.LastSeen = r.LastSeen
	x.PacketsRejected++
	x.Allowed = false
}
func (c *Collector) DedupStats() dedup.Stats {
	if c.deduper == nil {
		return dedup.Stats{Enabled: false}
	}
	return c.deduper.Stats()
}

type GlobalDedupStats struct {
	Enabled    bool   `json:"enabled"`
	Accepted   uint64 `json:"accepted"`
	Duplicates uint64 `json:"duplicates"`
	Errors     uint64 `json:"errors"`
}

func (c *Collector) GlobalDedupStats() GlobalDedupStats {
	return GlobalDedupStats{Enabled: c.globalDedup != nil, Accepted: c.globalAccepted.Load(), Duplicates: c.globalDuplicates.Load(), Errors: c.globalErrors.Load()}
}

func (c *Collector) Exporters() []model.ExporterStat {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]model.ExporterStat, 0, len(c.exporters))
	for _, x := range c.exporters {
		out = append(out, *x)
	}
	return out
}
func (c *Collector) Rejections() []model.RejectionStat {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]model.RejectionStat, 0, len(c.rejects))
	for _, x := range c.rejects {
		out = append(out, *x)
	}
	return out
}
func (c *Collector) ExporterHealth() []ExporterHealth {
	now := time.Now().UTC()
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]ExporterHealth, 0, len(c.exporters))
	for _, x := range c.exporters {
		h := ExporterHealth{Address: x.Address, Protocol: x.Protocol, Listener: x.Listener, Allowed: x.Allowed, FirstSeen: x.FirstSeen, LastSeen: x.LastSeen, PacketsReceived: x.PacketsReceived, PacketsRejected: x.PacketsRejected, Flows: x.Flows, DecodeErrors: x.DecodeErrors, MissingTemplates: x.MissingTemplates, SequenceGaps: x.SequenceGaps, HealthScore: 100, TemplateStatus: "ok"}
		h.SilenceSeconds = int64(now.Sub(x.LastSeen).Seconds())
		if h.SilenceSeconds < 0 {
			h.SilenceSeconds = 0
		}
		dur := x.LastSeen.Sub(x.FirstSeen).Seconds()
		if dur < 1 {
			dur = 1
		}
		h.PacketRate = float64(x.PacketsReceived) / dur
		h.FlowRate = float64(x.Flows) / dur
		if x.PacketsReceived > 0 {
			h.DecodeErrorRate = float64(x.DecodeErrors) / float64(x.PacketsReceived)
		}
		if !x.Allowed {
			h.State = "blocked"
			h.HealthScore = 0
			h.Reasons = append(h.Reasons, "exporter is currently blocked by policy")
		} else if h.SilenceSeconds > 300 {
			h.State = "down"
			h.HealthScore -= 65
			h.Reasons = append(h.Reasons, fmt.Sprintf("no packet received for %ds", h.SilenceSeconds))
		} else if h.SilenceSeconds > 120 {
			h.State = "stale"
			h.HealthScore -= 30
			h.Reasons = append(h.Reasons, fmt.Sprintf("last packet was %ds ago", h.SilenceSeconds))
		} else {
			h.State = "healthy"
		}
		if h.DecodeErrorRate > 0.10 {
			h.HealthScore -= 30
			h.Reasons = append(h.Reasons, fmt.Sprintf("decode error rate %.1f%%", h.DecodeErrorRate*100))
		} else if h.DecodeErrorRate > 0.01 {
			h.HealthScore -= 10
			h.Reasons = append(h.Reasons, fmt.Sprintf("decode error rate %.1f%%", h.DecodeErrorRate*100))
		}
		if x.MissingTemplates > 0 {
			h.TemplateStatus = "degraded"
			h.HealthScore -= 10
			h.Reasons = append(h.Reasons, fmt.Sprintf("%d missing-template events", x.MissingTemplates))
		}
		if x.SequenceGaps > 0 {
			h.HealthScore -= 10
			h.Reasons = append(h.Reasons, fmt.Sprintf("%d sequence gaps observed", x.SequenceGaps))
		}
		if h.HealthScore < 0 {
			h.HealthScore = 0
		}
		if h.State == "healthy" && h.HealthScore < 80 {
			h.State = "degraded"
		}
		if len(h.Reasons) == 0 {
			h.Reasons = []string{"no material health issue observed"}
		}
		out = append(out, h)
	}
	return out
}

func (c *Collector) healthLoop() {
	defer c.wg.Done()
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			c.cleanupRates(time.Now())
			rule := c.analytics.Rule("exporter_down")
			for _, h := range c.ExporterHealth() {
				key := h.Address + "|" + h.Protocol + "|" + h.Listener
				if rule.Enabled && h.Allowed && float64(h.SilenceSeconds) >= rule.Threshold {
					c.mu.Lock()
					already := c.healthAlerted[key]
					if !already {
						c.healthAlerted[key] = true
					}
					c.mu.Unlock()
					if !already {
						now := time.Now().UTC()
						c.analytics.ReportAlert(model.Alert{ID: "exporter-down-" + key, Type: "exporter_down", Severity: rule.Severity, Title: "Exporter appears down", Reason: "No telemetry packet has been received for longer than the configured threshold", Evidence: fmt.Sprintf("exporter=%s listener=%s silence=%ds", h.Address, h.Listener, h.SilenceSeconds), FirstSeen: now, LastSeen: now, Entity: h.Address, Observed: float64(h.SilenceSeconds), Threshold: rule.Threshold, Status: "open"})
					}
				} else {
					c.mu.Lock()
					delete(c.healthAlerted, key)
					c.mu.Unlock()
				}
			}
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *Collector) ListenerStates() []ListenerState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]ListenerState, 0, len(c.listeners))
	for _, r := range c.listeners {
		depth, capacity := 0, 0
		for _, q := range r.queues {
			depth += len(q)
			capacity += cap(q)
		}
		s := ListenerState{Name: r.cfg.Name, Protocol: r.cfg.Protocol, Bind: r.cfg.Bind, Port: r.cfg.Port, Packets: r.packets.Load(), Bytes: r.bytes.Load(), Drops: r.drops.Load(), QueueDepth: depth, QueueCapacity: capacity, Running: r.running.Load() && !c.paused.Load()}
		if v := r.lastErr.Load(); v != nil {
			s.LastError = v.(string)
		}
		out = append(out, s)
	}
	return out
}

// SetPaused stops accepting new flow datagrams without tearing down the web
// control plane or the listener sockets. Already queued packets can finish.
func (c *Collector) SetPaused(paused bool) { c.paused.Store(paused) }
func (c *Collector) Paused() bool          { return c.paused.Load() }
func (c *Collector) Stop() {
	c.cancel()
	c.mu.RLock()
	for _, r := range c.listeners {
		_ = r.conn.Close()
	}
	c.mu.RUnlock()
	c.wg.Wait()
}

func (c *Collector) Templates() []templates.Info { return c.templates.Snapshot() }
