package storage

import (
	"bufio"
	"bytes"
	"central-flow-collector/internal/model"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type ClickHouseConfig struct {
	URL, Database, Table, User, Password, DataDir       string
	Cluster, DistributedTable, ReplicaPath, ReplicaName string
	RetentionDays, BatchSize, FlushMS, QueueSize        int
	SpoolEnabled                                        bool
	SpoolMaxBytes                                       int64
	SpoolReplaySeconds                                  int
	SpoolSegmentBytes                                   int64
	SpoolFsync                                          bool
	QueryTimeoutMS, MaxResultRows, MaxExecutionSeconds  int
	StoragePolicy, ColdVolume                           string
	ColdAfterDays                                       int
}

type ClickHouse struct {
	writeMu          sync.RWMutex
	closed           bool
	cfg              ClickHouseConfig
	localTable       string
	client           *http.Client
	q                chan model.Flow
	stop             chan struct{}
	done             chan struct{}
	written          atomic.Uint64
	dropped          atomic.Uint64
	writeErrors      atomic.Uint64
	healthy          atomic.Bool
	lastErrMu        sync.RWMutex
	lastErr          string
	retention        atomic.Int64
	spoolDir         string
	spooled          atomic.Uint64
	replayed         atomic.Uint64
	spoolSeq         atomic.Uint64
	spoolCorrupt     atomic.Uint64
	spoolQuarantined atomic.Uint64
	spoolRecovered   atomic.Uint64
	spoolLegacy      atomic.Uint64
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

var identRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func NewClickHouse(cfg ClickHouseConfig) (*ClickHouse, error) {
	if !identRE.MatchString(cfg.Database) || !identRE.MatchString(cfg.Table) {
		return nil, errors.New("clickhouse database/table must contain only letters, digits and underscore and may not start with a digit")
	}
	if cfg.Cluster != "" && !identRE.MatchString(cfg.Cluster) {
		return nil, errors.New("clickhouse cluster must be a safe identifier")
	}
	if cfg.StoragePolicy != "" && !identRE.MatchString(cfg.StoragePolicy) {
		return nil, errors.New("clickhouse storage policy must be a safe identifier")
	}
	if cfg.ColdVolume != "" && !identRE.MatchString(cfg.ColdVolume) {
		return nil, errors.New("clickhouse cold volume must be a safe identifier")
	}
	if (cfg.ColdAfterDays > 0) != (cfg.ColdVolume != "") {
		return nil, errors.New("clickhouse cold tier requires both cold volume and cold after days")
	}
	if cfg.ColdVolume != "" && cfg.StoragePolicy == "" {
		return nil, errors.New("clickhouse cold tier requires storage policy")
	}
	if cfg.ColdAfterDays >= cfg.RetentionDays && cfg.ColdAfterDays > 0 {
		return nil, errors.New("clickhouse cold-after days must be less than retention")
	}
	if cfg.Cluster != "" {
		if cfg.DistributedTable == "" {
			cfg.DistributedTable = cfg.Table + "_distributed"
		}
		if !identRE.MatchString(cfg.DistributedTable) {
			return nil, errors.New("clickhouse distributed table must be a safe identifier")
		}
		if cfg.ReplicaPath == "" {
			cfg.ReplicaPath = "/clickhouse/tables/{shard}/" + cfg.Database + "/" + cfg.Table
		}
		if cfg.ReplicaName == "" {
			cfg.ReplicaName = "{replica}"
		}
	}
	if cfg.BatchSize < 1 {
		cfg.BatchSize = 2000
	}
	if cfg.FlushMS < 50 {
		cfg.FlushMS = 1000
	}
	if cfg.QueueSize < 64 {
		cfg.QueueSize = 65536
	}
	if cfg.RetentionDays < 1 {
		cfg.RetentionDays = 7
	}
	if cfg.SpoolReplaySeconds < 1 {
		cfg.SpoolReplaySeconds = 5
	}
	if cfg.SpoolMaxBytes < 0 {
		cfg.SpoolMaxBytes = 0
	}
	if cfg.SpoolSegmentBytes < 1<<20 {
		cfg.SpoolSegmentBytes = 64 << 20
	}
	if cfg.QueryTimeoutMS < 100 {
		cfg.QueryTimeoutMS = 12000
	}
	if cfg.MaxResultRows < 100 {
		cfg.MaxResultRows = 100000
	}
	if cfg.MaxExecutionSeconds < 1 {
		cfg.MaxExecutionSeconds = 12
	}
	u, err := url.Parse(cfg.URL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("invalid ClickHouse URL %q", cfg.URL)
	}
	c := &ClickHouse{cfg: cfg, localTable: cfg.Table, client: &http.Client{Timeout: time.Duration(maxInt(cfg.QueryTimeoutMS, 15000)) * time.Millisecond}, q: make(chan model.Flow, cfg.QueueSize), stop: make(chan struct{}), done: make(chan struct{}), spoolDir: filepath.Join(cfg.DataDir, "clickhouse-spool")}
	if cfg.SpoolEnabled {
		_ = os.MkdirAll(c.spoolDir, 0750)
		c.recoverSpoolTemps()
	}
	c.retention.Store(int64(cfg.RetentionDays))
	if err := c.ensureSchema(context.Background()); err != nil {
		return nil, err
	}
	if cfg.Cluster != "" {
		c.cfg.Table = cfg.DistributedTable
	}
	c.healthy.Store(true)
	go c.writer()
	return c, nil
}

func (c *ClickHouse) endpoint(query string, extra url.Values) string {
	u, _ := url.Parse(c.cfg.URL)
	q := u.Query()
	q.Set("query", query)
	q.Set("date_time_input_format", "best_effort")
	for k, vv := range extra {
		for _, v := range vv {
			q.Add(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (c *ClickHouse) do(ctx context.Context, query string, body io.Reader, extra url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(query, extra), body)
	if err != nil {
		return nil, err
	}
	if c.cfg.User != "" {
		req.SetBasicAuth(c.cfg.User, c.cfg.Password)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		return nil, fmt.Errorf("clickhouse HTTP %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return resp, nil
}

func (c *ClickHouse) exec(ctx context.Context, q string) error {
	resp, err := c.do(ctx, q, nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}

func (c *ClickHouse) ttlExpression(days int) string {
	if c.cfg.ColdAfterDays > 0 && c.cfg.ColdVolume != "" {
		return fmt.Sprintf("receive_time + INTERVAL %d DAY TO VOLUME '%s', receive_time + INTERVAL %d DAY DELETE", c.cfg.ColdAfterDays, c.cfg.ColdVolume, days)
	}
	return fmt.Sprintf("receive_time + INTERVAL %d DAY", days)
}

func (c *ClickHouse) engineSettings() string {
	if c.cfg.StoragePolicy != "" {
		return fmt.Sprintf("SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1, storage_policy = '%s'", c.cfg.StoragePolicy)
	}
	return "SETTINGS index_granularity = 8192, ttl_only_drop_parts = 1"
}

func (c *ClickHouse) ensureSchema(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	onCluster := ""
	if c.cfg.Cluster != "" {
		onCluster = fmt.Sprintf(" ON CLUSTER `%s`", c.cfg.Cluster)
	}
	dbCreateErr := c.exec(ctx, fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s`%s", c.cfg.Database, onCluster))
	engine := "MergeTree"
	if c.cfg.Cluster != "" {
		engine = fmt.Sprintf("ReplicatedMergeTree('%s','%s')", strings.ReplaceAll(c.cfg.ReplicaPath, "'", "''"), strings.ReplaceAll(c.cfg.ReplicaName, "'", "''"))
	}
	ddl := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.%s%s (
receive_time DateTime64(3, 'UTC'), start_time Nullable(DateTime64(3, 'UTC')), end_time Nullable(DateTime64(3, 'UTC')),
collector_node LowCardinality(String), tenant LowCardinality(String), exporter String, listener LowCardinality(String), flow_protocol LowCardinality(String), observation_domain UInt32,
src_ip String, dst_ip String, src_port UInt16, dst_port UInt16, ip_protocol UInt8, packets UInt64, bytes UInt64,
tcp_flags UInt16, tos UInt8, dscp UInt8, ecn UInt8, ingress_if UInt32, egress_if UInt32, next_hop String,
src_as UInt32, dst_as UInt32, src_as_name String, dst_as_name String, src_country LowCardinality(String), dst_country LowCardinality(String), src_site LowCardinality(String), dst_site LowCardinality(String), src_prefix String, dst_prefix String, vlan UInt16, src_mac String, dst_mac String,
nat_src_ip String, nat_dst_ip String, nat_src_port UInt16, nat_dst_port UInt16, direction UInt8, sampling_rate UInt32,
sequence UInt32, application_id String, application_name String, vrf String, custom_json String
) ENGINE = %s
PARTITION BY toYYYYMM(receive_time)
ORDER BY (toStartOfHour(receive_time), tenant, exporter, src_ip, dst_ip, ip_protocol, dst_port)
TTL %s
%s`, c.cfg.Database, c.localTable, onCluster, engine, c.ttlExpression(c.cfg.RetentionDays), c.engineSettings())
	if err := c.exec(ctx, ddl); err != nil {
		if dbCreateErr != nil {
			return fmt.Errorf("clickhouse database bootstrap failed (%v); table bootstrap also failed: %w", dbCreateErr, err)
		}
		return fmt.Errorf("clickhouse create table: %w", err)
	}
	for _, col := range []string{"collector_node LowCardinality(String)", "tenant LowCardinality(String)", "src_as_name String", "dst_as_name String", "src_country LowCardinality(String)", "dst_country LowCardinality(String)", "src_site LowCardinality(String)", "dst_site LowCardinality(String)"} {
		if err := c.exec(ctx, fmt.Sprintf("ALTER TABLE `%s`.`%s`%s ADD COLUMN IF NOT EXISTS %s", c.cfg.Database, c.localTable, onCluster, col)); err != nil {
			return fmt.Errorf("clickhouse add column %s: %w", col, err)
		}
	}
	if err := c.exec(ctx, fmt.Sprintf("ALTER TABLE `%s`.`%s`%s MODIFY TTL %s", c.cfg.Database, c.localTable, onCluster, c.ttlExpression(c.cfg.RetentionDays))); err != nil {
		return fmt.Errorf("clickhouse update TTL: %w", err)
	}
	if c.cfg.Cluster != "" {
		dist := fmt.Sprintf("CREATE TABLE IF NOT EXISTS `%s`.`%s` ON CLUSTER `%s` AS `%s`.`%s` ENGINE = Distributed(`%s`, `%s`, `%s`, cityHash64(tenant,src_ip,dst_ip))", c.cfg.Database, c.cfg.DistributedTable, c.cfg.Cluster, c.cfg.Database, c.localTable, c.cfg.Cluster, c.cfg.Database, c.localTable)
		if err := c.exec(ctx, dist); err != nil {
			return fmt.Errorf("clickhouse create distributed table: %w", err)
		}
	}
	// Five-minute rollups keep dashboard/top-N queries bounded as raw flow volume grows.
	aggTable := c.localTable + "_5m"
	aggEngine := "SummingMergeTree((bytes,packets,flows))"
	if c.cfg.Cluster != "" {
		aggEngine = fmt.Sprintf("ReplicatedSummingMergeTree('%s_5m','%s',(bytes,packets,flows))", strings.ReplaceAll(c.cfg.ReplicaPath, "'", "''"), strings.ReplaceAll(c.cfg.ReplicaName, "'", "''"))
	}
	aggDDL := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s.%s%s (
 bucket DateTime('UTC'), tenant LowCardinality(String), src_ip String, dst_ip String, ip_protocol UInt8, dst_port UInt16, src_country LowCardinality(String), dst_country LowCardinality(String), bytes UInt64, packets UInt64, flows UInt64
) ENGINE = %s PARTITION BY toYYYYMM(bucket) ORDER BY (bucket,tenant,src_ip,dst_ip,ip_protocol,dst_port) TTL bucket + INTERVAL %d DAY`, c.cfg.Database, aggTable, onCluster, aggEngine, c.cfg.RetentionDays)
	if err := c.exec(ctx, aggDDL); err != nil {
		return fmt.Errorf("clickhouse create 5m aggregate table: %w", err)
	}
	mvDDL := fmt.Sprintf(`CREATE MATERIALIZED VIEW IF NOT EXISTS %s.%s_mv%s TO %s.%s AS SELECT toStartOfFiveMinutes(receive_time) AS bucket, tenant, src_ip, dst_ip, ip_protocol, dst_port, src_country, dst_country, sum(bytes) AS bytes, sum(packets) AS packets, count() AS flows FROM %s.%s GROUP BY bucket,tenant,src_ip,dst_ip,ip_protocol,dst_port,src_country,dst_country`, c.cfg.Database, aggTable, onCluster, c.cfg.Database, aggTable, c.cfg.Database, c.localTable)
	if err := c.exec(ctx, mvDDL); err != nil {
		return fmt.Errorf("clickhouse create 5m materialized view: %w", err)
	}
	return nil
}

func (c *ClickHouse) Retention() int { return int(c.retention.Load()) }
func (c *ClickHouse) SetRetention(ctx context.Context, days int) error {
	if days < 1 || days > 3650 {
		return errors.New("retention days must be 1..3650")
	}
	suffix := ""
	if c.cfg.Cluster != "" {
		suffix = fmt.Sprintf(" ON CLUSTER `%s`", c.cfg.Cluster)
	}
	if c.cfg.ColdAfterDays > 0 && days <= c.cfg.ColdAfterDays {
		return errors.New("retention days must exceed configured cold tier age")
	}
	q := fmt.Sprintf("ALTER TABLE `%s`.`%s`%s MODIFY TTL %s", c.cfg.Database, c.localTable, suffix, c.ttlExpression(days))
	if err := c.exec(ctx, q); err != nil {
		return err
	}
	if err := saveRetentionOverride(c.cfg.DataDir, days); err != nil {
		return err
	}
	c.retention.Store(int64(days))
	return nil
}
func (c *ClickHouse) Purge(ctx context.Context) (PurgeResult, error) {
	suffix := ""
	if c.cfg.Cluster != "" {
		suffix = fmt.Sprintf(" ON CLUSTER `%s`", c.cfg.Cluster)
	}
	q := fmt.Sprintf("ALTER TABLE `%s`.`%s`%s MATERIALIZE TTL", c.cfg.Database, c.localTable, suffix)
	if err := c.exec(ctx, q); err != nil {
		return PurgeResult{}, err
	}
	return PurgeResult{Backend: "clickhouse", RetentionDays: c.Retention(), Action: "requested ClickHouse TTL materialization"}, nil
}

func (c *ClickHouse) Write(f model.Flow) error {
	c.writeMu.RLock()
	defer c.writeMu.RUnlock()
	if c.closed {
		return errors.New("clickhouse storage is closed")
	}
	select {
	case c.q <- f:
		return nil
	default:
		c.dropped.Add(1)
		return errors.New("clickhouse storage queue full")
	}
}

func (c *ClickHouse) writer() {
	defer close(c.done)
	ticker := time.NewTicker(time.Duration(c.cfg.FlushMS) * time.Millisecond)
	replayTicker := time.NewTicker(time.Duration(c.cfg.SpoolReplaySeconds) * time.Second)
	defer ticker.Stop()
	defer replayTicker.Stop()
	batch := make([]model.Flow, 0, c.cfg.BatchSize)
	flush := func() {
		if len(batch) == 0 {
			return
		}
		c.flush(batch)
		batch = batch[:0]
	}
	for {
		select {
		case f := <-c.q:
			batch = append(batch, f)
			if len(batch) >= c.cfg.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-replayTicker.C:
			c.replaySpoolOne()
		case <-c.stop:
			for {
				select {
				case f := <-c.q:
					batch = append(batch, f)
					if len(batch) >= c.cfg.BatchSize {
						flush()
					}
				default:
					flush()
					return
				}
			}
		}
	}
}

type chInsertRow struct {
	ReceiveTime       string  `json:"receive_time"`
	CollectorNode     string  `json:"collector_node"`
	Tenant            string  `json:"tenant"`
	StartTime         *string `json:"start_time"`
	EndTime           *string `json:"end_time"`
	Exporter          string  `json:"exporter"`
	Listener          string  `json:"listener"`
	FlowProtocol      string  `json:"flow_protocol"`
	ObservationDomain uint32  `json:"observation_domain"`
	SrcIP             string  `json:"src_ip"`
	DstIP             string  `json:"dst_ip"`
	SrcPort           uint16  `json:"src_port"`
	DstPort           uint16  `json:"dst_port"`
	IPProtocol        uint8   `json:"ip_protocol"`
	Packets           uint64  `json:"packets"`
	Bytes             uint64  `json:"bytes"`
	TCPFlags          uint16  `json:"tcp_flags"`
	TOS               uint8   `json:"tos"`
	DSCP              uint8   `json:"dscp"`
	ECN               uint8   `json:"ecn"`
	IngressIf         uint32  `json:"ingress_if"`
	EgressIf          uint32  `json:"egress_if"`
	NextHop           string  `json:"next_hop"`
	SrcAS             uint32  `json:"src_as"`
	DstAS             uint32  `json:"dst_as"`
	SrcASName         string  `json:"src_as_name"`
	DstASName         string  `json:"dst_as_name"`
	SrcCountry        string  `json:"src_country"`
	DstCountry        string  `json:"dst_country"`
	SrcSite           string  `json:"src_site"`
	DstSite           string  `json:"dst_site"`
	SrcPrefix         string  `json:"src_prefix"`
	DstPrefix         string  `json:"dst_prefix"`
	VLAN              uint16  `json:"vlan"`
	SrcMAC            string  `json:"src_mac"`
	DstMAC            string  `json:"dst_mac"`
	NATSrcIP          string  `json:"nat_src_ip"`
	NATDstIP          string  `json:"nat_dst_ip"`
	NATSrcPort        uint16  `json:"nat_src_port"`
	NATDstPort        uint16  `json:"nat_dst_port"`
	Direction         uint8   `json:"direction"`
	Sampling          uint32  `json:"sampling_rate"`
	Sequence          uint32  `json:"sequence"`
	AppID             string  `json:"application_id"`
	AppName           string  `json:"application_name"`
	VRF               string  `json:"vrf"`
	CustomJSON        string  `json:"custom_json"`
}

func chTime(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05.000") }
func timePtr(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := chTime(t)
	return &s
}
func toInsert(f model.Flow) chInsertRow {
	cj := "{}"
	if len(f.Custom) > 0 {
		if b, e := json.Marshal(f.Custom); e == nil {
			cj = string(b)
		}
	}
	rt := f.ReceiveTime
	if rt.IsZero() {
		rt = time.Now().UTC()
	}
	return chInsertRow{ReceiveTime: chTime(rt), CollectorNode: f.CollectorNode, Tenant: f.Tenant, StartTime: timePtr(f.StartTime), EndTime: timePtr(f.EndTime), Exporter: f.Exporter, Listener: f.Listener, FlowProtocol: f.Protocol, ObservationDomain: f.ObsDomain, SrcIP: f.SrcIP, DstIP: f.DstIP, SrcPort: f.SrcPort, DstPort: f.DstPort, IPProtocol: f.IPProtocol, Packets: f.Packets, Bytes: f.Bytes, TCPFlags: f.TCPFlags, TOS: f.TOS, DSCP: f.DSCP, ECN: f.ECN, IngressIf: f.IngressIf, EgressIf: f.EgressIf, NextHop: f.NextHop, SrcAS: f.SrcAS, DstAS: f.DstAS, SrcASName: f.SrcASName, DstASName: f.DstASName, SrcCountry: f.SrcCountry, DstCountry: f.DstCountry, SrcSite: f.SrcSite, DstSite: f.DstSite, SrcPrefix: f.SrcPrefix, DstPrefix: f.DstPrefix, VLAN: f.VLAN, SrcMAC: f.SrcMAC, DstMAC: f.DstMAC, NATSrcIP: f.NATSrcIP, NATDstIP: f.NATDstIP, NATSrcPort: f.NATSrcPort, NATDstPort: f.NATDstPort, Direction: f.Direction, Sampling: f.Sampling, Sequence: f.Sequence, AppID: f.AppID, AppName: f.AppName, VRF: f.VRF, CustomJSON: cj}
}

func (c *ClickHouse) sendBatch(batch []model.Flow) error {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	for _, f := range batch {
		if err := enc.Encode(toInsert(f)); err != nil {
			return err
		}
	}
	query := fmt.Sprintf("INSERT INTO %s.%s FORMAT JSONEachRow", c.cfg.Database, c.cfg.Table)
	var err error
	for attempt := 0; attempt < 3; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		var resp *http.Response
		resp, err = c.do(ctx, query, bytes.NewReader(b.Bytes()), nil)
		cancel()
		if err == nil {
			resp.Body.Close()
			c.written.Add(uint64(len(batch)))
			c.healthy.Store(true)
			c.clearError()
			return nil
		}
		time.Sleep(time.Duration(attempt+1) * 150 * time.Millisecond)
	}
	return err
}

func (c *ClickHouse) flush(batch []model.Flow) {
	if err := c.sendBatch(batch); err == nil {
		return
	} else {
		c.writeErrors.Add(1)
		c.healthy.Store(false)
		c.setError(err)
		if spErr := c.spoolBatch(batch); spErr != nil {
			c.dropped.Add(uint64(len(batch)))
			c.setError(fmt.Errorf("clickhouse write failed: %v; spool failed: %w", err, spErr))
		}
	}
}

func (c *ClickHouse) Close() error {
	c.writeMu.Lock()
	if !c.closed {
		c.closed = true
		close(c.stop)
	}
	c.writeMu.Unlock()
	<-c.done
	return nil
}
func (c *ClickHouse) setError(err error) {
	c.lastErrMu.Lock()
	defer c.lastErrMu.Unlock()
	if err != nil {
		c.lastErr = err.Error()
	}
}
func (c *ClickHouse) clearError() { c.lastErrMu.Lock(); c.lastErr = ""; c.lastErrMu.Unlock() }
func (c *ClickHouse) Stats() Stats {
	c.lastErrMu.RLock()
	le := c.lastErr
	c.lastErrMu.RUnlock()
	files, bytesN, _ := c.spoolUsage()
	return Stats{Backend: "clickhouse", Healthy: c.healthy.Load(), LastError: le, Written: c.written.Load(), Dropped: c.dropped.Load(), WriteErrors: c.writeErrors.Load(), QueueDepth: len(c.q), QueueCapacity: cap(c.q), SpoolFiles: files, SpoolBytes: bytesN, Spooled: c.spooled.Load(), Replayed: c.replayed.Load(), SpoolCorrupt: c.spoolCorrupt.Load(), SpoolQuarantined: c.spoolQuarantined.Load(), SpoolRecovered: c.spoolRecovered.Load(), SpoolLegacy: c.spoolLegacy.Load()}
}

func (c *ClickHouse) Query(ctx context.Context, q Query) ([]model.Flow, error) {
	maxRows := c.cfg.MaxResultRows
	if maxRows <= 0 || maxRows > 1000000 {
		maxRows = 100000
	}
	if q.Limit <= 0 {
		q.Limit = 500
	}
	if q.Limit > maxRows {
		return nil, fmt.Errorf("query limit %d exceeds configured maximum %d", q.Limit, maxRows)
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
	where := []string{"receive_time >= {from:DateTime64(3)}", "receive_time <= {to:DateTime64(3)}"}
	vals := url.Values{"param_from": {chTime(q.From)}, "param_to": {chTime(q.To)}}
	vals.Set("max_execution_time", strconv.Itoa(c.cfg.MaxExecutionSeconds))
	vals.Set("max_result_rows", strconv.Itoa(maxRows))
	vals.Set("result_overflow_mode", "throw")
	addS := func(col, name, val string) {
		if val != "" {
			where = append(where, col+" = {"+name+":String}")
			vals.Set("param_"+name, val)
		}
	}
	addS("src_ip", "src_ip", q.SrcIP)
	addS("src_country", "src_country", q.SrcCountry)
	addS("dst_country", "dst_country", q.DstCountry)
	addS("src_site", "src_site", q.SrcSite)
	addS("dst_site", "dst_site", q.DstSite)
	addS("dst_ip", "dst_ip", q.DstIP)
	if q.Host != "" {
		where = append(where, "(src_ip = {host:String} OR dst_ip = {host:String})")
		vals.Set("param_host", q.Host)
	}
	addS("exporter", "exporter", q.Exporter)
	addS("collector_node", "collector_node", q.CollectorNode)
	addS("tenant", "tenant", q.Tenant)
	addS("flow_protocol", "protocol", q.Protocol)
	addS("listener", "listener", q.Listener)
	addS("application_name", "app_name", q.App)
	if q.App != "" {
		where[len(where)-1] = "(application_name = {app_name:String} OR application_id = {app_name:String})"
	}
	if q.Country != "" {
		where = append(where, "(src_country = {country:String} OR dst_country = {country:String})")
		vals.Set("param_country", q.Country)
	}
	if q.Site != "" {
		where = append(where, "(src_site = {site:String} OR dst_site = {site:String})")
		vals.Set("param_site", q.Site)
	}
	if q.SrcCIDR != "" {
		where = append(where, "isIPAddressInRange(src_ip, {src_cidr:String})")
		vals.Set("param_src_cidr", q.SrcCIDR)
	}
	if q.DstCIDR != "" {
		where = append(where, "isIPAddressInRange(dst_ip, {dst_cidr:String})")
		vals.Set("param_dst_cidr", q.DstCIDR)
	}
	if q.CIDR != "" {
		where = append(where, "(isIPAddressInRange(src_ip, {cidr:String}) OR isIPAddressInRange(dst_ip, {cidr:String}))")
		vals.Set("param_cidr", q.CIDR)
	}
	if q.SrcPort > 0 {
		where = append(where, "src_port = {src_port:UInt16}")
		vals.Set("param_src_port", strconv.Itoa(q.SrcPort))
	}
	if q.DstPort > 0 {
		where = append(where, "dst_port = {dst_port:UInt16}")
		vals.Set("param_dst_port", strconv.Itoa(q.DstPort))
	}
	if q.Port > 0 {
		where = append(where, "(src_port = {port:UInt16} OR dst_port = {port:UInt16})")
		vals.Set("param_port", strconv.Itoa(q.Port))
	}
	if q.Service != "" {
		selector, err := trafficSelectorForService(q.Service)
		if err == nil {
			if cond, err := selectorSQLCondition(selector, 91, vals); err == nil {
				where = append(where, cond)
			}
		}
	}
	if q.IPProtocolSet || q.IPProtocol > 0 {
		where = append(where, "ip_protocol = {ip_protocol:UInt8}")
		vals.Set("param_ip_protocol", strconv.Itoa(q.IPProtocol))
	}
	if q.VLAN > 0 {
		where = append(where, "vlan = {vlan:UInt16}")
		vals.Set("param_vlan", strconv.Itoa(q.VLAN))
	}
	if q.IngressIf > 0 {
		where = append(where, "ingress_if = {ingress_if:UInt32}")
		vals.Set("param_ingress_if", strconv.Itoa(q.IngressIf))
	}
	if q.EgressIf > 0 {
		where = append(where, "egress_if = {egress_if:UInt32}")
		vals.Set("param_egress_if", strconv.Itoa(q.EgressIf))
	}
	if q.SrcAS > 0 {
		where = append(where, "src_as = {src_as:UInt32}")
		vals.Set("param_src_as", strconv.FormatUint(uint64(q.SrcAS), 10))
	}
	if q.DstAS > 0 {
		where = append(where, "dst_as = {dst_as:UInt32}")
		vals.Set("param_dst_as", strconv.FormatUint(uint64(q.DstAS), 10))
	}
	if q.ASN > 0 {
		where = append(where, "(src_as = {asn:UInt32} OR dst_as = {asn:UInt32})")
		vals.Set("param_asn", strconv.FormatUint(uint64(q.ASN), 10))
	}
	if q.TCPFlags > 0 {
		where = append(where, "bitAnd(tcp_flags, {tcp_flags:UInt16}) = {tcp_flags:UInt16}")
		vals.Set("param_tcp_flags", strconv.FormatUint(uint64(q.TCPFlags), 10))
	}
	if q.MinBytes > 0 {
		where = append(where, "bytes >= {min_bytes:UInt64}")
		vals.Set("param_min_bytes", strconv.FormatUint(q.MinBytes, 10))
	}
	if q.MaxBytes > 0 {
		where = append(where, "bytes <= {max_bytes:UInt64}")
		vals.Set("param_max_bytes", strconv.FormatUint(q.MaxBytes, 10))
	}
	if q.MinPackets > 0 {
		where = append(where, "packets >= {min_packets:UInt64}")
		vals.Set("param_min_packets", strconv.FormatUint(q.MinPackets, 10))
	}
	if q.MaxPackets > 0 {
		where = append(where, "packets <= {max_packets:UInt64}")
		vals.Set("param_max_packets", strconv.FormatUint(q.MaxPackets, 10))
	}
	durationExpr := "if(isNull(start_time) OR isNull(end_time), 0, dateDiff('millisecond', start_time, end_time))"
	if q.MinDurationMS > 0 {
		where = append(where, durationExpr+" >= {min_duration:Int64}")
		vals.Set("param_min_duration", strconv.FormatInt(q.MinDurationMS, 10))
	}
	if q.MaxDurationMS > 0 {
		where = append(where, durationExpr+" <= {max_duration:Int64}")
		vals.Set("param_max_duration", strconv.FormatInt(q.MaxDurationMS, 10))
	}
	sql := fmt.Sprintf(`SELECT toUnixTimestamp64Milli(receive_time) receive_ms, ifNull(toUnixTimestamp64Milli(start_time),0) start_ms, ifNull(toUnixTimestamp64Milli(end_time),0) end_ms,
collector_node,tenant,exporter,listener,flow_protocol,observation_domain,src_ip,dst_ip,src_port,dst_port,ip_protocol,packets,bytes,tcp_flags,tos,dscp,ecn,ingress_if,egress_if,next_hop,src_as,dst_as,src_as_name,dst_as_name,src_country,dst_country,src_site,dst_site,src_prefix,dst_prefix,vlan,src_mac,dst_mac,nat_src_ip,nat_dst_ip,nat_src_port,nat_dst_port,direction,sampling_rate,sequence,application_id,application_name,vrf,custom_json
FROM %s.%s WHERE %s ORDER BY receive_time DESC LIMIT %d FORMAT JSONEachRow`, c.cfg.Database, c.cfg.Table, strings.Join(where, " AND "), q.Limit)
	resp, err := c.do(ctx, sql, nil, vals)
	if err != nil {
		c.setError(err)
		return nil, err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	out := make([]model.Flow, 0, q.Limit)
	for sc.Scan() {
		var r chQueryRow
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return out, err
		}
		out = append(out, r.flow())
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	c.healthy.Store(true)
	return out, nil
}

type chQueryRow struct {
	ReceiveMS     int64  `json:"receive_ms"`
	CollectorNode string `json:"collector_node"`
	Tenant        string `json:"tenant"`
	StartMS       int64  `json:"start_ms"`
	EndMS         int64  `json:"end_ms"`
	Exporter      string `json:"exporter"`
	Listener      string `json:"listener"`
	Protocol      string `json:"flow_protocol"`
	ObsDomain     uint32 `json:"observation_domain"`
	SrcIP         string `json:"src_ip"`
	DstIP         string `json:"dst_ip"`
	SrcPort       uint16 `json:"src_port"`
	DstPort       uint16 `json:"dst_port"`
	IPProtocol    uint8  `json:"ip_protocol"`
	Packets       uint64 `json:"packets"`
	Bytes         uint64 `json:"bytes"`
	TCPFlags      uint16 `json:"tcp_flags"`
	TOS           uint8  `json:"tos"`
	DSCP          uint8  `json:"dscp"`
	ECN           uint8  `json:"ecn"`
	IngressIf     uint32 `json:"ingress_if"`
	EgressIf      uint32 `json:"egress_if"`
	NextHop       string `json:"next_hop"`
	SrcAS         uint32 `json:"src_as"`
	DstAS         uint32 `json:"dst_as"`
	SrcASName     string `json:"src_as_name"`
	DstASName     string `json:"dst_as_name"`
	SrcCountry    string `json:"src_country"`
	DstCountry    string `json:"dst_country"`
	SrcSite       string `json:"src_site"`
	DstSite       string `json:"dst_site"`
	SrcPrefix     string `json:"src_prefix"`
	DstPrefix     string `json:"dst_prefix"`
	VLAN          uint16 `json:"vlan"`
	SrcMAC        string `json:"src_mac"`
	DstMAC        string `json:"dst_mac"`
	NATSrcIP      string `json:"nat_src_ip"`
	NATDstIP      string `json:"nat_dst_ip"`
	NATSrcPort    uint16 `json:"nat_src_port"`
	NATDstPort    uint16 `json:"nat_dst_port"`
	Direction     uint8  `json:"direction"`
	Sampling      uint32 `json:"sampling_rate"`
	Sequence      uint32 `json:"sequence"`
	AppID         string `json:"application_id"`
	AppName       string `json:"application_name"`
	VRF           string `json:"vrf"`
	CustomJSON    string `json:"custom_json"`
}

func (r chQueryRow) flow() model.Flow {
	f := model.Flow{ReceiveTime: time.UnixMilli(r.ReceiveMS).UTC(), CollectorNode: r.CollectorNode, Tenant: r.Tenant, Exporter: r.Exporter, Listener: r.Listener, Protocol: r.Protocol, ObsDomain: r.ObsDomain, SrcIP: r.SrcIP, DstIP: r.DstIP, SrcPort: r.SrcPort, DstPort: r.DstPort, IPProtocol: r.IPProtocol, Packets: r.Packets, Bytes: r.Bytes, TCPFlags: r.TCPFlags, TOS: r.TOS, DSCP: r.DSCP, ECN: r.ECN, IngressIf: r.IngressIf, EgressIf: r.EgressIf, NextHop: r.NextHop, SrcAS: r.SrcAS, DstAS: r.DstAS, SrcASName: r.SrcASName, DstASName: r.DstASName, SrcCountry: r.SrcCountry, DstCountry: r.DstCountry, SrcSite: r.SrcSite, DstSite: r.DstSite, SrcPrefix: r.SrcPrefix, DstPrefix: r.DstPrefix, VLAN: r.VLAN, SrcMAC: r.SrcMAC, DstMAC: r.DstMAC, NATSrcIP: r.NATSrcIP, NATDstIP: r.NATDstIP, NATSrcPort: r.NATSrcPort, NATDstPort: r.NATDstPort, Direction: r.Direction, Sampling: r.Sampling, Sequence: r.Sequence, AppID: r.AppID, AppName: r.AppName, VRF: r.VRF}
	if r.StartMS > 0 {
		f.StartTime = time.UnixMilli(r.StartMS).UTC()
	}
	if r.EndMS > 0 {
		f.EndTime = time.UnixMilli(r.EndMS).UTC()
	}
	if r.CustomJSON != "" && r.CustomJSON != "{}" {
		_ = json.Unmarshal([]byte(r.CustomJSON), &f.Custom)
	}
	return f
}

type chAssetRow struct {
	IP         string `json:"ip"`
	BytesIn    uint64 `json:"bytes_in"`
	BytesOut   uint64 `json:"bytes_out"`
	PacketsIn  uint64 `json:"packets_in"`
	PacketsOut uint64 `json:"packets_out"`
	Flows      uint64 `json:"flows"`
	Peers      uint64 `json:"peers"`
	FirstMS    int64  `json:"first_ms"`
	LastMS     int64  `json:"last_ms"`
	Protocols  []int  `json:"protocols"`
	Country    string `json:"country"`
	Site       string `json:"site"`
	ASN        uint32 `json:"asn"`
	ASName     string `json:"as_name"`
}

func (c *ClickHouse) Assets(ctx context.Context, q AggregateQuery) ([]AssetSummary, error) {
	var err error
	q, err = normalizeAgg(q)
	if err != nil {
		return nil, err
	}
	where, vals := chAnalysisWhere(q.Filters)
	vals.Set("max_execution_time", strconv.Itoa(c.cfg.MaxExecutionSeconds))
	vals.Set("max_result_rows", strconv.Itoa(maxInt(c.cfg.MaxResultRows, 100000)))
	vals.Set("result_overflow_mode", "throw")
	tenantCond := ""
	if q.Tenant != "" {
		tenantCond = " AND tenant = {tenant:String}"
		vals.Set("param_tenant", q.Tenant)
	}
	// Keep endpoint-specific exclusions outside the shared flow predicates.
	tenantCond += " AND " + where
	order := map[string]string{"bytes": "bytes_in + bytes_out", "packets": "packets_in + packets_out", "flows": "flows", "peers": "peers"}[q.Metric]
	sql := fmt.Sprintf(`SELECT ip,
 sum(bytes_in) AS bytes_in, sum(bytes_out) AS bytes_out,
 sum(packets_in) AS packets_in, sum(packets_out) AS packets_out,
 sum(flows) AS flows, uniqExact(peer) AS peers,
 toUnixTimestamp64Milli(min(first_seen)) AS first_ms,
 toUnixTimestamp64Milli(max(last_seen)) AS last_ms,
 groupUniqArray(protocol) AS protocols,
 argMax(country,last_seen) AS country, argMax(site,last_seen) AS site, argMax(asn,last_seen) AS asn, argMax(as_name,last_seen) AS as_name
FROM (
 SELECT src_ip AS ip, dst_ip AS peer, 0 AS bytes_in, bytes AS bytes_out, 0 AS packets_in, packets AS packets_out, 1 AS flows, receive_time AS first_seen, receive_time AS last_seen, ip_protocol AS protocol, src_country AS country, src_site AS site, src_as AS asn, src_as_name AS as_name
 FROM %s.%s WHERE receive_time >= {from:DateTime64(3)} AND receive_time <= {to:DateTime64(3)} AND src_ip != ''%s
 UNION ALL
 SELECT dst_ip AS ip, src_ip AS peer, bytes AS bytes_in, 0 AS bytes_out, packets AS packets_in, 0 AS packets_out, 1 AS flows, receive_time AS first_seen, receive_time AS last_seen, ip_protocol AS protocol, dst_country AS country, dst_site AS site, dst_as AS asn, dst_as_name AS as_name
 FROM %s.%s WHERE receive_time >= {from:DateTime64(3)} AND receive_time <= {to:DateTime64(3)} AND dst_ip != ''%s
)
GROUP BY ip
ORDER BY %s DESC, ip ASC
LIMIT %d FORMAT JSONEachRow`, c.cfg.Database, c.cfg.Table, tenantCond, c.cfg.Database, c.cfg.Table, tenantCond, order, q.Limit)
	resp, err := c.do(ctx, sql, nil, vals)
	if err != nil {
		c.setError(err)
		return nil, err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	out := make([]AssetSummary, 0, q.Limit)
	for sc.Scan() {
		var r chAssetRow
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return out, err
		}
		a := AssetSummary{IP: r.IP, BytesIn: r.BytesIn, BytesOut: r.BytesOut, PacketsIn: r.PacketsIn, PacketsOut: r.PacketsOut, Flows: r.Flows, Peers: r.Peers, Protocols: r.Protocols, Country: r.Country, Site: r.Site, ASN: r.ASN, ASName: r.ASName}
		if r.FirstMS > 0 {
			a.FirstSeen = time.UnixMilli(r.FirstMS).UTC()
		}
		if r.LastMS > 0 {
			a.LastSeen = time.UnixMilli(r.LastMS).UTC()
		}
		out = append(out, a)
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	c.healthy.Store(true)
	return out, nil
}

type chConversationRow struct {
	AIP       string `json:"a_ip"`
	APort     uint16 `json:"a_port"`
	BIP       string `json:"b_ip"`
	BPort     uint16 `json:"b_port"`
	Protocol  uint8  `json:"protocol"`
	BytesAB   uint64 `json:"bytes_a_to_b"`
	BytesBA   uint64 `json:"bytes_b_to_a"`
	PacketsAB uint64 `json:"packets_a_to_b"`
	PacketsBA uint64 `json:"packets_b_to_a"`
	Flows     uint64 `json:"flows"`
	FirstMS   int64  `json:"first_ms"`
	LastMS    int64  `json:"last_ms"`
}

func (c *ClickHouse) Conversations(ctx context.Context, q AggregateQuery) ([]ConversationSummary, error) {
	var err error
	q, err = normalizeAgg(q)
	if err != nil {
		return nil, err
	}
	if q.Metric == "peers" {
		return nil, errors.New("conversation metric must be bytes, packets or flows")
	}
	where, vals := chAnalysisWhere(q.Filters)
	vals.Set("max_execution_time", strconv.Itoa(c.cfg.MaxExecutionSeconds))
	vals.Set("max_result_rows", strconv.Itoa(maxInt(c.cfg.MaxResultRows, 100000)))
	vals.Set("result_overflow_mode", "throw")
	tenantCond := ""
	if q.Tenant != "" {
		tenantCond = " AND tenant = {tenant:String}"
		vals.Set("param_tenant", q.Tenant)
	}
	tenantCond += " AND " + where
	order := map[string]string{"bytes": "bytes_a_to_b + bytes_b_to_a", "packets": "packets_a_to_b + packets_b_to_a", "flows": "flows"}[q.Metric]
	sql := fmt.Sprintf(`SELECT a_ip,a_port,b_ip,b_port,protocol,
 sumIf(bytes, forward) AS bytes_a_to_b, sumIf(bytes, NOT forward) AS bytes_b_to_a,
 sumIf(packets, forward) AS packets_a_to_b, sumIf(packets, NOT forward) AS packets_b_to_a,
 count() AS flows, toUnixTimestamp64Milli(min(receive_time)) AS first_ms, toUnixTimestamp64Milli(max(receive_time)) AS last_ms
FROM (
 SELECT
  if(tuple(src_ip,src_port) <= tuple(dst_ip,dst_port), src_ip, dst_ip) AS a_ip,
  if(tuple(src_ip,src_port) <= tuple(dst_ip,dst_port), src_port, dst_port) AS a_port,
  if(tuple(src_ip,src_port) <= tuple(dst_ip,dst_port), dst_ip, src_ip) AS b_ip,
  if(tuple(src_ip,src_port) <= tuple(dst_ip,dst_port), dst_port, src_port) AS b_port,
  ip_protocol AS protocol, bytes, packets, receive_time,
  tuple(src_ip,src_port) <= tuple(dst_ip,dst_port) AS forward
 FROM %s.%s
 WHERE receive_time >= {from:DateTime64(3)} AND receive_time <= {to:DateTime64(3)} AND src_ip != '' AND dst_ip != ''%s
)
GROUP BY a_ip,a_port,b_ip,b_port,protocol
ORDER BY %s DESC, a_ip ASC, a_port ASC, b_ip ASC, b_port ASC, protocol ASC
LIMIT %d FORMAT JSONEachRow`, c.cfg.Database, c.cfg.Table, tenantCond, order, q.Limit)
	resp, err := c.do(ctx, sql, nil, vals)
	if err != nil {
		c.setError(err)
		return nil, err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	out := make([]ConversationSummary, 0, q.Limit)
	for sc.Scan() {
		var r chConversationRow
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			return out, err
		}
		x := ConversationSummary{AIP: r.AIP, APort: r.APort, BIP: r.BIP, BPort: r.BPort, Protocol: r.Protocol, BytesAB: r.BytesAB, BytesBA: r.BytesBA, PacketsAB: r.PacketsAB, PacketsBA: r.PacketsBA, Flows: r.Flows}
		if r.FirstMS > 0 {
			x.FirstSeen = time.UnixMilli(r.FirstMS).UTC()
		}
		if r.LastMS > 0 {
			x.LastSeen = time.UnixMilli(r.LastMS).UTC()
		}
		out = append(out, x)
	}
	if err := sc.Err(); err != nil {
		return out, err
	}
	c.healthy.Store(true)
	return out, nil
}

// InvestigateHost performs bounded, server-side aggregation. It deliberately
// avoids downloading raw flow rows for investigation charts.
func (c *ClickHouse) InvestigateHost(ctx context.Context, q HostQuery) (HostInvestigation, error) {
	q, err := normalizeHostQuery(q)
	if err != nil {
		return HostInvestigation{}, err
	}
	out := HostInvestigation{IP: q.IP, From: q.From, To: q.To}
	// A host filter in the lens can refer to the peer. It must not replace the
	// profile IP parameter used by sent/received aggregates.
	lens := q.Filters
	peerHost := lens.Host
	lens.Host = ""
	where, vals := chAnalysisWhere(lens)
	vals.Set("param_host", q.IP)
	if peerHost != "" {
		where += " AND (src_ip={lens_host:String} OR dst_ip={lens_host:String})"
		vals.Set("param_lens_host", peerHost)
	}
	tenantCond := ""
	if q.Tenant != "" {
		tenantCond = " AND tenant = {tenant:String}"
		vals.Set("param_tenant", q.Tenant)
	}
	tenantCond += " AND " + where

	var summary struct {
		BytesIn    uint64 `json:"bytes_in"`
		BytesOut   uint64 `json:"bytes_out"`
		PacketsIn  uint64 `json:"packets_in"`
		PacketsOut uint64 `json:"packets_out"`
		Flows      uint64 `json:"flows"`
		FirstMS    int64  `json:"first_ms"`
		LastMS     int64  `json:"last_ms"`
	}
	sql := fmt.Sprintf(`SELECT
 sumIf(bytes,dst_ip={host:String}) bytes_in, sumIf(bytes,src_ip={host:String}) bytes_out,
 sumIf(packets,dst_ip={host:String}) packets_in, sumIf(packets,src_ip={host:String}) packets_out,
 count() flows, if(count()=0,0,toUnixTimestamp64Milli(min(receive_time))) first_ms,
 if(count()=0,0,toUnixTimestamp64Milli(max(receive_time))) last_ms
FROM %s.%s WHERE receive_time >= {from:DateTime64(3)} AND receive_time <= {to:DateTime64(3)}
 AND (src_ip={host:String} OR dst_ip={host:String})%s FORMAT JSONEachRow`, c.cfg.Database, c.cfg.Table, tenantCond)
	resp, err := c.do(ctx, sql, nil, vals)
	if err != nil {
		return out, err
	}
	dec := json.NewDecoder(resp.Body)
	err = dec.Decode(&summary)
	resp.Body.Close()
	if err != nil && !errors.Is(err, io.EOF) {
		return out, err
	}
	out.BytesIn, out.BytesOut, out.PacketsIn, out.PacketsOut, out.Flows = summary.BytesIn, summary.BytesOut, summary.PacketsIn, summary.PacketsOut, summary.Flows
	if summary.FirstMS > 0 {
		out.FirstSeen = time.UnixMilli(summary.FirstMS).UTC()
	}
	if summary.LastMS > 0 {
		out.LastSeen = time.UnixMilli(summary.LastMS).UTC()
	}

	peerSQL := fmt.Sprintf(`SELECT peer AS key,sum(bytes) bytes,sum(packets) packets,count() flows FROM (
 SELECT if(src_ip={host:String},dst_ip,src_ip) peer,bytes,packets FROM %s.%s
 WHERE receive_time >= {from:DateTime64(3)} AND receive_time <= {to:DateTime64(3)} AND (src_ip={host:String} OR dst_ip={host:String})%s
) WHERE peer != '' GROUP BY peer ORDER BY bytes DESC LIMIT %d FORMAT JSONEachRow`, c.cfg.Database, c.cfg.Table, tenantCond, q.Limit)
	out.TopPeers, err = c.queryRanked(ctx, peerSQL, vals)
	if err != nil {
		return out, err
	}

	countrySQL := fmt.Sprintf(`SELECT country AS key,sum(bytes) bytes,sum(packets) packets,count() flows FROM (
 SELECT if(src_ip={host:String},dst_country,src_country) country,bytes,packets FROM %s.%s
 WHERE receive_time >= {from:DateTime64(3)} AND receive_time <= {to:DateTime64(3)} AND (src_ip={host:String} OR dst_ip={host:String})%s
) WHERE country != '' GROUP BY country ORDER BY bytes DESC LIMIT %d FORMAT JSONEachRow`, c.cfg.Database, c.cfg.Table, tenantCond, q.Limit)
	out.Countries, err = c.queryRanked(ctx, countrySQL, vals)
	if err != nil {
		return out, err
	}

	siteSQL := fmt.Sprintf(`SELECT site AS key,sum(bytes) bytes,sum(packets) packets,count() flows FROM (
 SELECT if(src_ip={host:String},dst_site,src_site) site,bytes,packets FROM %s.%s
 WHERE receive_time >= {from:DateTime64(3)} AND receive_time <= {to:DateTime64(3)} AND (src_ip={host:String} OR dst_ip={host:String})%s
) WHERE site != '' GROUP BY site ORDER BY bytes DESC LIMIT %d FORMAT JSONEachRow`, c.cfg.Database, c.cfg.Table, tenantCond, q.Limit)
	out.Sites, err = c.queryRanked(ctx, siteSQL, vals)
	if err != nil {
		return out, err
	}

	portSQL := fmt.Sprintf(`SELECT dst_port port,ip_protocol protocol,sum(bytes) bytes,sum(packets) packets,count() flows
 FROM %s.%s WHERE receive_time >= {from:DateTime64(3)} AND receive_time <= {to:DateTime64(3)}
 AND src_ip={host:String} AND dst_port != 0%s GROUP BY dst_port,ip_protocol ORDER BY bytes DESC LIMIT %d FORMAT JSONEachRow`, c.cfg.Database, c.cfg.Table, tenantCond, q.Limit)
	resp, err = c.do(ctx, portSQL, nil, vals)
	if err != nil {
		return out, err
	}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		var x PortMetric
		if err := json.Unmarshal(sc.Bytes(), &x); err != nil {
			resp.Body.Close()
			return out, err
		}
		out.TopPorts = append(out.TopPorts, x)
	}
	err = sc.Err()
	resp.Body.Close()
	if err != nil {
		return out, err
	}

	timelineSQL := fmt.Sprintf(`SELECT toUnixTimestamp(toStartOfFiveMinute(receive_time)) ts,
 sumIf(bytes,dst_ip={host:String}) bytes_in,sumIf(bytes,src_ip={host:String}) bytes_out,
 sumIf(packets,dst_ip={host:String}) packets_in,sumIf(packets,src_ip={host:String}) packets_out,count() flows
 FROM %s.%s WHERE receive_time >= {from:DateTime64(3)} AND receive_time <= {to:DateTime64(3)}
 AND (src_ip={host:String} OR dst_ip={host:String})%s GROUP BY ts ORDER BY ts FORMAT JSONEachRow`, c.cfg.Database, c.cfg.Table, tenantCond)
	resp, err = c.do(ctx, timelineSQL, nil, vals)
	if err != nil {
		return out, err
	}
	sc = bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for sc.Scan() {
		var r struct {
			TS         int64  `json:"ts"`
			BytesIn    uint64 `json:"bytes_in"`
			BytesOut   uint64 `json:"bytes_out"`
			PacketsIn  uint64 `json:"packets_in"`
			PacketsOut uint64 `json:"packets_out"`
			Flows      uint64 `json:"flows"`
		}
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			resp.Body.Close()
			return out, err
		}
		out.Timeline = append(out.Timeline, TimelineBucket{Timestamp: time.Unix(r.TS, 0).UTC(), BytesIn: r.BytesIn, BytesOut: r.BytesOut, PacketsIn: r.PacketsIn, PacketsOut: r.PacketsOut, Flows: r.Flows})
	}
	err = sc.Err()
	resp.Body.Close()
	if err != nil {
		return out, err
	}
	c.healthy.Store(true)
	return out, nil
}

func (c *ClickHouse) queryRanked(ctx context.Context, sql string, vals url.Values) ([]RankedMetric, error) {
	resp, err := c.do(ctx, sql, nil, vals)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
	var out []RankedMetric
	for sc.Scan() {
		var x RankedMetric
		if err := json.Unmarshal(sc.Bytes(), &x); err != nil {
			return out, err
		}
		out = append(out, x)
	}
	return out, sc.Err()
}

// Optimize requests a final part merge. It is an administrative maintenance
// operation and is never called from the ingestion path.
func (c *ClickHouse) Optimize(ctx context.Context) error {
	suffix := ""
	if c.cfg.Cluster != "" {
		suffix = fmt.Sprintf(" ON CLUSTER `%s`", c.cfg.Cluster)
	}
	return c.exec(ctx, fmt.Sprintf("OPTIMIZE TABLE `%s`.`%s`%s FINAL", c.cfg.Database, c.localTable, suffix))
}

// CheckTable asks ClickHouse to validate the currently configured local table.
func (c *ClickHouse) CheckTable(ctx context.Context) (string, error) {
	resp, err := c.do(ctx, fmt.Sprintf("CHECK TABLE `%s`.`%s` FORMAT TabSeparatedRaw", c.cfg.Database, c.localTable), nil, nil)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}
