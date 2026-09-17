package storage

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"central-flow-collector/internal/model"
)

type DimensionMetric struct {
	Dimension string `json:"dimension"`
	Key       string `json:"key"`
	Bytes     uint64 `json:"bytes"`
	Packets   uint64 `json:"packets"`
	Flows     uint64 `json:"flows"`
}

type AnalysisTotals struct {
	Flows               uint64 `json:"flows"`
	Packets             uint64 `json:"packets"`
	Bytes               uint64 `json:"bytes"`
	UniqueSources       uint64 `json:"unique_sources"`
	UniqueDestinations  uint64 `json:"unique_destinations"`
	UniqueConversations uint64 `json:"unique_conversations"`
	UniqueASNs          uint64 `json:"unique_asns"`
	UniqueCountries     uint64 `json:"unique_countries"`
	UniqueExporters     uint64 `json:"unique_exporters"`
	UniqueInterfaces    uint64 `json:"unique_interfaces"`
}

type AnalysisPoint struct {
	Timestamp time.Time `json:"timestamp"`
	Bytes     uint64    `json:"bytes"`
	Packets   uint64    `json:"packets"`
	Flows     uint64    `json:"flows"`
}

type AnalysisResult struct {
	From       time.Time                    `json:"from"`
	To         time.Time                    `json:"to"`
	Bucket     string                       `json:"bucket"`
	Totals     AnalysisTotals               `json:"totals"`
	Dimensions map[string][]DimensionMetric `json:"dimensions"`
	Timeline   []AnalysisPoint              `json:"timeline"`
}

type MatrixCell struct {
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Bytes       uint64 `json:"bytes"`
	Packets     uint64 `json:"packets"`
	Flows       uint64 `json:"flows"`
}

type CapacityInfo struct {
	Backend                string  `json:"backend"`
	BytesOnDisk            int64   `json:"bytes_on_disk"`
	FreeBytes              int64   `json:"free_bytes,omitempty"`
	TotalBytes             int64   `json:"total_bytes,omitempty"`
	DailyGrowthBytes       int64   `json:"daily_growth_bytes,omitempty"`
	RetentionDays          int     `json:"retention_days"`
	EstimatedRemainingDays float64 `json:"estimated_remaining_days,omitempty"`
}

var analysisDimensions = []string{"src_ip", "dst_ip", "application", "protocol", "src_port", "dst_port", "asn", "country", "exporter", "interface", "direction"}

func normalizeAnalysisQuery(q Query) (Query, time.Duration, error) {
	if q.To.IsZero() {
		q.To = time.Now().UTC()
	}
	if q.From.IsZero() {
		q.From = q.To.Add(-24 * time.Hour)
	}
	if q.To.Before(q.From) {
		return q, 0, errors.New("invalid time range")
	}
	if q.To.Sub(q.From) > 3660*24*time.Hour {
		return q, 0, errors.New("analysis range exceeds 10 years")
	}
	d := q.To.Sub(q.From)
	bucket := time.Minute
	switch {
	case d <= 6*time.Hour:
		bucket = time.Minute
	case d <= 48*time.Hour:
		bucket = 5 * time.Minute
	case d <= 14*24*time.Hour:
		bucket = 15 * time.Minute
	case d <= 120*24*time.Hour:
		bucket = time.Hour
	default:
		bucket = 24 * time.Hour
	}
	return q, bucket, nil
}

func bucketLabel(d time.Duration) string {
	switch d {
	case time.Minute:
		return "1m"
	case 5 * time.Minute:
		return "5m"
	case 15 * time.Minute:
		return "15m"
	case time.Hour:
		return "1h"
	case 24 * time.Hour:
		return "1d"
	}
	return d.String()
}

func flowConversationKey(f model.Flow) string {
	a := fmt.Sprintf("%s:%d", f.SrcIP, f.SrcPort)
	b := fmt.Sprintf("%s:%d", f.DstIP, f.DstPort)
	if a > b {
		a, b = b, a
	}
	return fmt.Sprintf("%s|%s|%d", a, b, f.IPProtocol)
}

func directionName(v uint8) string {
	switch v {
	case 1:
		return "inbound"
	case 2:
		return "outbound"
	case 3:
		return "internal"
	case 4:
		return "external"
	case 5:
		return "transit"
	default:
		return "unknown"
	}
}

func protocolName(v uint8) string {
	switch v {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 41:
		return "IPv6"
	case 47:
		return "GRE"
	case 50:
		return "ESP"
	case 58:
		return "ICMPv6"
	case 89:
		return "OSPF"
	case 132:
		return "SCTP"
	}
	if v == 0 {
		return "unknown"
	}
	return strconv.Itoa(int(v))
}

func matrixPrefix(ip string) string {
	p := net.ParseIP(ip)
	if p == nil {
		return "unknown"
	}
	if v4 := p.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
	}
	p = p.To16()
	if p == nil {
		return "unknown"
	}
	return fmt.Sprintf("%x:%x:%x:%x::/64", uint16(p[0])<<8|uint16(p[1]), uint16(p[2])<<8|uint16(p[3]), uint16(p[4])<<8|uint16(p[5]), uint16(p[6])<<8|uint16(p[7]))
}

func addDim(m map[string]map[string]*DimensionMetric, dim, key string, f model.Flow) {
	key = strings.TrimSpace(key)
	if key == "" {
		return
	}
	d := m[dim]
	if d == nil {
		d = map[string]*DimensionMetric{}
		m[dim] = d
	}
	x := d[key]
	if x == nil {
		x = &DimensionMetric{Dimension: dim, Key: key}
		d[key] = x
	}
	x.Bytes += f.Bytes
	x.Packets += f.Packets
	x.Flows++
}

func topDims(m map[string]map[string]*DimensionMetric, n int) map[string][]DimensionMetric {
	if n < 1 {
		n = 10
	}
	if n > 50 {
		n = 50
	}
	out := map[string][]DimensionMetric{}
	for _, dim := range analysisDimensions {
		mm := m[dim]
		arr := make([]DimensionMetric, 0, len(mm))
		for _, x := range mm {
			arr = append(arr, *x)
		}
		sort.Slice(arr, func(i, j int) bool {
			if arr[i].Bytes == arr[j].Bytes {
				return arr[i].Key < arr[j].Key
			}
			return arr[i].Bytes > arr[j].Bytes
		})
		if len(arr) > n {
			arr = arr[:n]
		}
		out[dim] = arr
	}
	return out
}

func (l *Local) scanAnalysis(ctx context.Context, q Query, fn func(model.Flow) error) error {
	if err := l.syncWrites(ctx); err != nil {
		return err
	}
	var files []string
	for d := dateOnly(q.From.UTC()); !d.After(dateOnly(q.To.UTC())); d = d.AddDate(0, 0, 1) {
		files = append(files, filepath.Join(l.dir, "flows", d.Format("2006-01-02")+".jsonl"))
	}
	for _, p := range files {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		f, e := os.Open(p)
		if os.IsNotExist(e) {
			continue
		}
		if e != nil {
			return e
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 2*1024*1024)
		var scanned uint64
		for sc.Scan() {
			scanned++
			if scanned%256 == 0 {
				if err := ctx.Err(); err != nil {
					_ = f.Close()
					return err
				}
			}
			var x model.Flow
			if json.Unmarshal(sc.Bytes(), &x) != nil || !match(x, q) {
				continue
			}
			if e := fn(x); e != nil {
				_ = f.Close()
				return e
			}
		}
		e = sc.Err()
		_ = f.Close()
		if e != nil {
			return e
		}
	}
	return nil
}

func (l *Local) Analyze(ctx context.Context, q Query, topN int) (AnalysisResult, error) {
	q, bucket, err := normalizeAnalysisQuery(q)
	if err != nil {
		return AnalysisResult{}, err
	}
	out := AnalysisResult{From: q.From, To: q.To, Bucket: bucketLabel(bucket), Dimensions: map[string][]DimensionMetric{}}
	dims := map[string]map[string]*DimensionMetric{}
	timeline := map[int64]*AnalysisPoint{}
	srcs, dsts, convs, asns, countries, exporters, ifs := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[uint32]struct{}{}, map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	err = l.scanAnalysis(ctx, q, func(f model.Flow) error {
		out.Totals.Flows++
		out.Totals.Bytes += f.Bytes
		out.Totals.Packets += f.Packets
		if f.SrcIP != "" {
			srcs[f.SrcIP] = struct{}{}
		}
		if f.DstIP != "" {
			dsts[f.DstIP] = struct{}{}
		}
		if f.SrcIP != "" && f.DstIP != "" {
			convs[flowConversationKey(f)] = struct{}{}
		}
		if f.SrcAS != 0 {
			asns[f.SrcAS] = struct{}{}
		}
		if f.DstAS != 0 {
			asns[f.DstAS] = struct{}{}
		}
		if f.SrcCountry != "" {
			countries[f.SrcCountry] = struct{}{}
		}
		if f.DstCountry != "" {
			countries[f.DstCountry] = struct{}{}
		}
		if f.Exporter != "" {
			exporters[f.Exporter] = struct{}{}
		}
		if f.IngressIf != 0 {
			ifs["in:"+strconv.FormatUint(uint64(f.IngressIf), 10)] = struct{}{}
		}
		if f.EgressIf != 0 {
			ifs["out:"+strconv.FormatUint(uint64(f.EgressIf), 10)] = struct{}{}
		}
		addDim(dims, "src_ip", f.SrcIP, f)
		addDim(dims, "dst_ip", f.DstIP, f)
		app := model.ApplicationName(f)
		addDim(dims, "application", app, f)
		addDim(dims, "protocol", protocolName(f.IPProtocol), f)
		if f.SrcPort != 0 {
			addDim(dims, "src_port", strconv.Itoa(int(f.SrcPort)), f)
		}
		if f.DstPort != 0 {
			addDim(dims, "dst_port", strconv.Itoa(int(f.DstPort)), f)
		}
		if f.SrcAS != 0 {
			k := fmt.Sprintf("AS%d", f.SrcAS)
			if f.SrcASName != "" {
				k += " " + f.SrcASName
			}
			addDim(dims, "asn", k, f)
		}
		if f.DstAS != 0 {
			k := fmt.Sprintf("AS%d", f.DstAS)
			if f.DstASName != "" {
				k += " " + f.DstASName
			}
			addDim(dims, "asn", k, f)
		}
		country := f.DstCountry
		if country == "" {
			country = f.SrcCountry
		}
		if country == "" {
			country = "Unknown"
		}
		addDim(dims, "country", country, f)
		addDim(dims, "exporter", f.Exporter, f)
		if f.IngressIf != 0 {
			addDim(dims, "interface", "Ingress "+strconv.FormatUint(uint64(f.IngressIf), 10), f)
		}
		if f.EgressIf != 0 {
			addDim(dims, "interface", "Egress "+strconv.FormatUint(uint64(f.EgressIf), 10), f)
		}
		addDim(dims, "direction", directionName(f.Direction), f)
		ts := f.ReceiveTime.UTC().Truncate(bucket).Unix()
		p := timeline[ts]
		if p == nil {
			p = &AnalysisPoint{Timestamp: time.Unix(ts, 0).UTC()}
			timeline[ts] = p
		}
		p.Bytes += f.Bytes
		p.Packets += f.Packets
		p.Flows++
		return nil
	})
	if err != nil {
		return AnalysisResult{}, err
	}
	out.Totals.UniqueSources = uint64(len(srcs))
	out.Totals.UniqueDestinations = uint64(len(dsts))
	out.Totals.UniqueConversations = uint64(len(convs))
	out.Totals.UniqueASNs = uint64(len(asns))
	out.Totals.UniqueCountries = uint64(len(countries))
	out.Totals.UniqueExporters = uint64(len(exporters))
	out.Totals.UniqueInterfaces = uint64(len(ifs))
	out.Dimensions = topDims(dims, topN)
	for _, p := range timeline {
		out.Timeline = append(out.Timeline, *p)
	}
	sort.Slice(out.Timeline, func(i, j int) bool { return out.Timeline[i].Timestamp.Before(out.Timeline[j].Timestamp) })
	return out, nil
}

func (l *Local) TrafficMatrix(ctx context.Context, q Query, limit int) ([]MatrixCell, error) {
	q, _, err := normalizeAnalysisQuery(q)
	if err != nil {
		return nil, err
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}
	m := map[string]*MatrixCell{}
	err = l.scanAnalysis(ctx, q, func(f model.Flow) error {
		s, d := f.SrcPrefix, f.DstPrefix
		if s == "" {
			s = matrixPrefix(f.SrcIP)
		}
		if d == "" {
			d = matrixPrefix(f.DstIP)
		}
		if s == "unknown" || d == "unknown" {
			return nil
		}
		k := s + "|" + d
		x := m[k]
		if x == nil {
			x = &MatrixCell{Source: s, Destination: d}
			m[k] = x
		}
		x.Bytes += f.Bytes
		x.Packets += f.Packets
		x.Flows++
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]MatrixCell, 0, len(m))
	for _, x := range m {
		out = append(out, *x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bytes > out[j].Bytes })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (l *Local) Capacity(ctx context.Context) (CapacityInfo, error) {
	_ = ctx
	info := CapacityInfo{Backend: "local", BytesOnDisk: dirSize(filepath.Join(l.dir, "flows")), RetentionDays: l.Retention()}
	info.FreeBytes, info.TotalBytes = filesystemCapacity(l.dir)
	// Estimate growth from the newest two flow files, without walking raw records.
	ents, _ := os.ReadDir(filepath.Join(l.dir, "flows"))
	type fi struct {
		n string
		s int64
	}
	var xs []fi
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		if x, er := e.Info(); er == nil {
			xs = append(xs, fi{e.Name(), x.Size()})
		}
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].n > xs[j].n })
	if len(xs) > 0 {
		n := len(xs)
		if n > 7 {
			n = 7
		}
		var sum int64
		for i := 0; i < n; i++ {
			sum += xs[i].s
		}
		info.DailyGrowthBytes = sum / int64(n)
	}
	if info.DailyGrowthBytes > 0 && info.FreeBytes > 0 {
		info.EstimatedRemainingDays = float64(info.FreeBytes) / float64(info.DailyGrowthBytes)
	}
	return info, nil
}

func chAnalysisWhere(q Query) (string, url.Values) {
	where := []string{"receive_time >= {from:DateTime64(3)}", "receive_time <= {to:DateTime64(3)}"}
	vals := url.Values{"param_from": {chTime(q.From)}, "param_to": {chTime(q.To)}}
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
	addS("exporter", "exporter", q.Exporter)
	addS("collector_node", "collector_node", q.CollectorNode)
	addS("listener", "listener", q.Listener)
	addS("flow_protocol", "protocol", q.Protocol)
	if q.Host != "" {
		where = append(where, "(src_ip = {host:String} OR dst_ip = {host:String})")
		vals.Set("param_host", q.Host)
	}
	if q.Country != "" {
		where = append(where, "(src_country = {country:String} OR dst_country = {country:String})")
		vals.Set("param_country", q.Country)
	}
	if q.Site != "" {
		where = append(where, "(src_site = {site:String} OR dst_site = {site:String})")
		vals.Set("param_site", q.Site)
	}
	if q.App != "" {
		where = append(where, "(application_name = {app:String} OR application_id = {app:String})")
		vals.Set("param_app", q.App)
	}
	if q.SrcCIDR != "" {
		where = append(where, "isIPAddressInRange(src_ip,{src_cidr:String})")
		vals.Set("param_src_cidr", q.SrcCIDR)
	}
	if q.DstCIDR != "" {
		where = append(where, "isIPAddressInRange(dst_ip,{dst_cidr:String})")
		vals.Set("param_dst_cidr", q.DstCIDR)
	}
	if q.CIDR != "" {
		where = append(where, "(isIPAddressInRange(src_ip,{cidr:String}) OR isIPAddressInRange(dst_ip,{cidr:String}))")
		vals.Set("param_cidr", q.CIDR)
	}
	if q.SrcPort > 0 {
		where = append(where, "src_port={src_port:UInt16}")
		vals.Set("param_src_port", strconv.Itoa(q.SrcPort))
	}
	if q.DstPort > 0 {
		where = append(where, "dst_port={dst_port:UInt16}")
		vals.Set("param_dst_port", strconv.Itoa(q.DstPort))
	}
	if q.Port > 0 {
		where = append(where, "(src_port={port:UInt16} OR dst_port={port:UInt16})")
		vals.Set("param_port", strconv.Itoa(q.Port))
	}
	if q.Service != "" {
		selector, err := trafficSelectorForService(q.Service)
		if err == nil {
			if cond, err := selectorSQLCondition(selector, 90, vals); err == nil {
				where = append(where, cond)
			}
		}
	}
	if q.IPProtocolSet || q.IPProtocol > 0 {
		where = append(where, "ip_protocol={ip_protocol:UInt8}")
		vals.Set("param_ip_protocol", strconv.Itoa(q.IPProtocol))
	}
	if q.VLAN > 0 {
		where = append(where, "vlan={vlan:UInt16}")
		vals.Set("param_vlan", strconv.Itoa(q.VLAN))
	}
	if q.IngressIf > 0 {
		where = append(where, "ingress_if={ingress_if:UInt32}")
		vals.Set("param_ingress_if", strconv.Itoa(q.IngressIf))
	}
	if q.EgressIf > 0 {
		where = append(where, "egress_if={egress_if:UInt32}")
		vals.Set("param_egress_if", strconv.Itoa(q.EgressIf))
	}
	if q.SrcAS > 0 {
		where = append(where, "src_as={src_as:UInt32}")
		vals.Set("param_src_as", strconv.FormatUint(uint64(q.SrcAS), 10))
	}
	if q.DstAS > 0 {
		where = append(where, "dst_as={dst_as:UInt32}")
		vals.Set("param_dst_as", strconv.FormatUint(uint64(q.DstAS), 10))
	}
	if q.ASN > 0 {
		where = append(where, "(src_as={asn:UInt32} OR dst_as={asn:UInt32})")
		vals.Set("param_asn", strconv.FormatUint(uint64(q.ASN), 10))
	}
	if q.TCPFlags > 0 {
		where = append(where, "bitAnd(tcp_flags,{tcp_flags:UInt16})={tcp_flags:UInt16}")
		vals.Set("param_tcp_flags", strconv.FormatUint(uint64(q.TCPFlags), 10))
	}
	if q.MinBytes > 0 {
		where = append(where, "bytes>={min_bytes:UInt64}")
		vals.Set("param_min_bytes", strconv.FormatUint(q.MinBytes, 10))
	}
	if q.MaxBytes > 0 {
		where = append(where, "bytes<={max_bytes:UInt64}")
		vals.Set("param_max_bytes", strconv.FormatUint(q.MaxBytes, 10))
	}
	if q.MinPackets > 0 {
		where = append(where, "packets>={min_packets:UInt64}")
		vals.Set("param_min_packets", strconv.FormatUint(q.MinPackets, 10))
	}
	if q.MaxPackets > 0 {
		where = append(where, "packets<={max_packets:UInt64}")
		vals.Set("param_max_packets", strconv.FormatUint(q.MaxPackets, 10))
	}
	durationExpr := "if(isNull(start_time) OR isNull(end_time), 0, greatest(0, dateDiff('millisecond', start_time, end_time)))"
	if q.MinDurationMS > 0 {
		where = append(where, durationExpr+" >= {min_duration:Int64}")
		vals.Set("param_min_duration", strconv.FormatInt(q.MinDurationMS, 10))
	}
	if q.MaxDurationMS > 0 {
		where = append(where, durationExpr+" <= {max_duration:Int64}")
		vals.Set("param_max_duration", strconv.FormatInt(q.MaxDurationMS, 10))
	}
	return strings.Join(where, " AND "), vals
}

type chTotals struct{ Flows, Packets, Bytes, UniqueSources, UniqueDestinations, UniqueConversations, UniqueASNs, UniqueCountries, UniqueExporters, UniqueInterfaces uint64 }

func (c *ClickHouse) Analyze(ctx context.Context, q Query, topN int) (AnalysisResult, error) {
	q, bucket, err := normalizeAnalysisQuery(q)
	if err != nil {
		return AnalysisResult{}, err
	}
	if topN < 1 || topN > 50 {
		topN = 10
	}
	where, vals := chAnalysisWhere(q)
	vals.Set("max_execution_time", strconv.Itoa(c.cfg.MaxExecutionSeconds))
	vals.Set("max_result_rows", strconv.Itoa(maxInt(c.cfg.MaxResultRows, 100000)))
	vals.Set("result_overflow_mode", "throw")
	table := fmt.Sprintf("`%s`.`%s`", c.cfg.Database, c.cfg.Table)
	totalsSQL := fmt.Sprintf(`SELECT count() flows,sum(packets) packets,sum(bytes) bytes,uniqCombined64(src_ip) unique_sources,uniqCombined64(dst_ip) unique_destinations,uniqCombined64(tuple(src_ip,src_port,dst_ip,dst_port,ip_protocol)) unique_conversations,uniqCombined64(arrayJoin([src_as,dst_as])) unique_asns,uniqCombined64(arrayJoin([src_country,dst_country])) unique_countries,uniqCombined64(exporter) unique_exporters,uniqCombined64(arrayJoin([ingress_if,egress_if])) unique_interfaces FROM %s WHERE %s FORMAT JSONEachRow`, table, where)
	out := AnalysisResult{From: q.From, To: q.To, Bucket: bucketLabel(bucket), Dimensions: map[string][]DimensionMetric{}}
	resp, e := c.do(ctx, totalsSQL, nil, vals)
	if e != nil {
		return out, e
	}
	sc := bufio.NewScanner(resp.Body)
	if sc.Scan() {
		var r struct {
			Flows               uint64 `json:"flows"`
			Packets             uint64 `json:"packets"`
			Bytes               uint64 `json:"bytes"`
			UniqueSources       uint64 `json:"unique_sources"`
			UniqueDestinations  uint64 `json:"unique_destinations"`
			UniqueConversations uint64 `json:"unique_conversations"`
			UniqueASNs          uint64 `json:"unique_asns"`
			UniqueCountries     uint64 `json:"unique_countries"`
			UniqueExporters     uint64 `json:"unique_exporters"`
			UniqueInterfaces    uint64 `json:"unique_interfaces"`
		}
		if e = json.Unmarshal(sc.Bytes(), &r); e == nil {
			out.Totals = AnalysisTotals{r.Flows, r.Packets, r.Bytes, r.UniqueSources, r.UniqueDestinations, r.UniqueConversations, r.UniqueASNs, r.UniqueCountries, r.UniqueExporters, r.UniqueInterfaces}
		}
	}
	e = sc.Err()
	resp.Body.Close()
	if e != nil {
		return out, e
	}
	dimSQL := fmt.Sprintf(`SELECT dimension,key,sum(bytes) bytes,sum(packets) packets,count() flows FROM (SELECT bytes,packets,arrayJoin([tuple('src_ip',src_ip),tuple('dst_ip',dst_ip),tuple('application',if(application_name!='',application_name,application_id)),tuple('protocol',toString(ip_protocol)),tuple('src_port',toString(src_port)),tuple('dst_port',toString(dst_port)),tuple('asn',if(dst_as>0,concat('AS',toString(dst_as),if(dst_as_name!='',concat(' ',dst_as_name),'')),if(src_as>0,concat('AS',toString(src_as),if(src_as_name!='',concat(' ',src_as_name),'')),''))),tuple('country',if(dst_country!='',dst_country,src_country)),tuple('exporter',exporter),tuple('interface',if(ingress_if>0,concat('Ingress ',toString(ingress_if)),if(egress_if>0,concat('Egress ',toString(egress_if)),''))),tuple('direction',toString(direction))]) d FROM %s WHERE %s) ARRAY JOIN [tupleElement(d,1)] AS dimension,[tupleElement(d,2)] AS key WHERE key!='' AND key!='0' GROUP BY dimension,key ORDER BY dimension,bytes DESC LIMIT %d BY dimension FORMAT JSONEachRow`, table, where, topN)
	resp, e = c.do(ctx, dimSQL, nil, vals)
	if e != nil {
		return out, e
	}
	sc = bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var x DimensionMetric
		if e = json.Unmarshal(sc.Bytes(), &x); e != nil {
			resp.Body.Close()
			return out, e
		}
		if x.Dimension == "protocol" {
			if n, er := strconv.Atoi(x.Key); er == nil {
				x.Key = protocolName(uint8(n))
			}
		}
		if x.Dimension == "direction" {
			if n, er := strconv.Atoi(x.Key); er == nil {
				x.Key = directionName(uint8(n))
			}
		}
		out.Dimensions[x.Dimension] = append(out.Dimensions[x.Dimension], x)
	}
	e = sc.Err()
	resp.Body.Close()
	if e != nil {
		return out, e
	}
	unit, num := "MINUTE", 1
	switch bucket {
	case 5 * time.Minute:
		num = 5
	case 15 * time.Minute:
		num = 15
	case time.Hour:
		unit = "HOUR"
	case 24 * time.Hour:
		unit = "DAY"
	}
	timelineSQL := fmt.Sprintf(`SELECT toUnixTimestamp(toStartOfInterval(receive_time,INTERVAL %d %s)) ts,sum(bytes) bytes,sum(packets) packets,count() flows FROM %s WHERE %s GROUP BY ts ORDER BY ts FORMAT JSONEachRow`, num, unit, table, where)
	resp, e = c.do(ctx, timelineSQL, nil, vals)
	if e != nil {
		return out, e
	}
	sc = bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var r struct {
			TS      int64  `json:"ts"`
			Bytes   uint64 `json:"bytes"`
			Packets uint64 `json:"packets"`
			Flows   uint64 `json:"flows"`
		}
		if e = json.Unmarshal(sc.Bytes(), &r); e != nil {
			resp.Body.Close()
			return out, e
		}
		out.Timeline = append(out.Timeline, AnalysisPoint{Timestamp: time.Unix(r.TS, 0).UTC(), Bytes: r.Bytes, Packets: r.Packets, Flows: r.Flows})
	}
	e = sc.Err()
	resp.Body.Close()
	if e != nil {
		return out, e
	}
	return out, nil
}

func (c *ClickHouse) TrafficMatrix(ctx context.Context, q Query, limit int) ([]MatrixCell, error) {
	q, _, err := normalizeAnalysisQuery(q)
	if err != nil {
		return nil, err
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}
	where, vals := chAnalysisWhere(q)
	vals.Set("max_execution_time", strconv.Itoa(c.cfg.MaxExecutionSeconds))
	table := fmt.Sprintf("`%s`.`%s`", c.cfg.Database, c.cfg.Table)
	sql := fmt.Sprintf(`SELECT if(src_prefix!='',src_prefix,if(isIPv4String(src_ip),concat(arrayStringConcat(arraySlice(splitByChar('.',src_ip),1,3),'.'),'.0/24'),src_ip)) source,if(dst_prefix!='',dst_prefix,if(isIPv4String(dst_ip),concat(arrayStringConcat(arraySlice(splitByChar('.',dst_ip),1,3),'.'),'.0/24'),dst_ip)) destination,sum(bytes) bytes,sum(packets) packets,count() flows FROM %s WHERE %s GROUP BY source,destination ORDER BY bytes DESC LIMIT %d FORMAT JSONEachRow`, table, where, limit)
	resp, e := c.do(ctx, sql, nil, vals)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	sc := bufio.NewScanner(resp.Body)
	out := []MatrixCell{}
	for sc.Scan() {
		var x MatrixCell
		if e = json.Unmarshal(sc.Bytes(), &x); e != nil {
			return out, e
		}
		out = append(out, x)
	}
	return out, sc.Err()
}

func (c *ClickHouse) Capacity(ctx context.Context) (CapacityInfo, error) {
	vals := url.Values{"max_execution_time": {"5"}}
	sql := fmt.Sprintf(`SELECT sum(bytes_on_disk) bytes_on_disk FROM system.parts WHERE active AND database=%s AND table IN (%s,%s) FORMAT JSONEachRow`, quoteCH(c.cfg.Database), quoteCH(c.localTable), quoteCH(c.localTable+"_5m"))
	resp, e := c.do(ctx, sql, nil, vals)
	if e != nil {
		return CapacityInfo{}, e
	}
	defer resp.Body.Close()
	var r struct {
		Bytes int64 `json:"bytes_on_disk"`
	}
	sc := bufio.NewScanner(resp.Body)
	if sc.Scan() {
		_ = json.Unmarshal(sc.Bytes(), &r)
	}
	return CapacityInfo{Backend: "clickhouse", BytesOnDisk: r.Bytes, RetentionDays: c.Retention()}, sc.Err()
}

func quoteCH(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }
