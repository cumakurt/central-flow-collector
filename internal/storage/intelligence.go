package storage

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"central-flow-collector/internal/intelligence"
	"central-flow-collector/internal/model"
)

type IntelligenceBackend interface {
	IntelligenceGroups(context.Context, Query, intelligence.Spec) ([]intelligence.Group, error)
}

func intelligenceNetwork(ip string) string {
	address, err := netip.ParseAddr(ip)
	if err != nil {
		return "unknown"
	}
	bits := 64
	if address.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(address, bits).Masked().String()
}

func intelligenceWindow(q Query, s intelligence.Spec) (Query, time.Time, error) {
	if err := s.Validate(); err != nil {
		return q, time.Time{}, err
	}
	if q.From.IsZero() || q.To.IsZero() || !q.To.After(q.From) || q.To.Sub(q.From) > 31*24*time.Hour {
		return q, time.Time{}, errors.New("advanced raw analysis requires a positive time range of at most 31 days")
	}
	if (s.Kind == "temporal" || s.Kind == "relationships" || s.Kind == "diversity" || s.Kind == "quality" || s.Kind == "persistence" || s.Kind == "anomalies") && int64(math.Ceil(float64(q.To.UnixMilli())/float64(s.Bucket*1000))-math.Floor(float64(q.From.UnixMilli())/float64(s.Bucket*1000))) > 2000 {
		return q, time.Time{}, errors.New("more than 2,000 time buckets; choose a larger bucket")
	}
	split := q.From
	if s.Kind == "changes" {
		q.From = q.From.Add(-q.To.Sub(q.From))
	}
	return q, split, nil
}
func intelligenceKey(f model.Flow, dim string) string {
	switch dim {
	case "src_site":
		return f.SrcSite
	case "dst_site":
		return f.DstSite
	case "src_ip":
		return f.SrcIP
	case "dst_ip":
		return f.DstIP
	case "src_network":
		return intelligenceNetwork(f.SrcIP)
	case "dst_network":
		return intelligenceNetwork(f.DstIP)
	case "application":
		if f.AppName != "" {
			return f.AppName
		}
		return f.AppID
	case "protocol":
		return strconv.Itoa(int(f.IPProtocol))
	case "src_as":
		return strconv.FormatUint(uint64(f.SrcAS), 10)
	case "dst_as":
		return strconv.FormatUint(uint64(f.DstAS), 10)
	case "src_country":
		return f.SrcCountry
	case "dst_country":
		return f.DstCountry
	case "exporter":
		return f.Exporter
	case "ingress_if":
		return f.Exporter + " / " + strconv.FormatUint(uint64(f.IngressIf), 10)
	case "egress_if":
		return f.Exporter + " / " + strconv.FormatUint(uint64(f.EgressIf), 10)
	case "dst_port":
		return strconv.Itoa(int(f.DstPort))
	}
	return ""
}
func distributionValue(f model.Flow, dim string) (float64, bool) {
	switch dim {
	case "bytes":
		return float64(f.Bytes), true
	case "packets":
		return float64(f.Packets), true
	case "bytes_per_packet":
		if f.Packets > 0 {
			return float64(f.Bytes) / float64(f.Packets), true
		}
	case "duration_ms":
		if !f.StartTime.IsZero() && !f.EndTime.IsZero() && !f.EndTime.Before(f.StartTime) {
			return float64(f.EndTime.UnixMilli() - f.StartTime.UnixMilli()), true
		}
	}
	return 0, false
}
func (l *Local) IntelligenceGroups(ctx context.Context, q Query, s intelligence.Spec) ([]intelligence.Group, error) {
	q, split, err := intelligenceWindow(q, s)
	if err != nil {
		return nil, err
	}
	type key struct {
		entity, peer string
		period       int
		bucket       int64
		value        float64
		invalid      bool
	}
	groups := map[key]*intelligence.Group{}
	err = l.scanAnalysis(ctx, q, func(f model.Flow) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !f.ReceiveTime.Before(q.To) {
			return nil
		}
		k := key{entity: intelligenceKey(f, s.Dimension), period: 1}
		if f.ReceiveTime.Before(split) {
			k.period = 0
		}
		switch s.Kind {
		case "distribution":
			v, ok := distributionValue(f, s.Dimension)
			k.entity = ""
			k.value = v
			k.invalid = !ok
		case "relationships", "diversity":
			k.peer = intelligenceKey(f, s.Peer)
			k.bucket = f.ReceiveTime.Unix() / int64(s.Bucket) * int64(s.Bucket)
		case "temporal":
			k.entity = ""
			k.bucket = f.ReceiveTime.Unix() / int64(s.Bucket) * int64(s.Bucket)
		case "persistence", "anomalies":
			k.bucket = f.ReceiveTime.Unix() / int64(s.Bucket) * int64(s.Bucket)
		case "quality":
			k.entity = f.Exporter
			k.bucket = f.ReceiveTime.Unix() / int64(s.Bucket) * int64(s.Bucket)
		}
		if len(k.entity) > 512 || len(k.peer) > 512 {
			return errors.New("analysis entity label exceeds 512 bytes")
		}
		g := groups[k]
		if g == nil {
			if len(groups) >= intelligence.MaxGroups {
				return intelligence.ErrCardinality
			}
			g = &intelligence.Group{Key: k.entity, Peer: k.peer, Period: k.period, Bucket: k.bucket, Value: k.value, First: f.ReceiveTime.UnixMilli()}
			groups[k] = g
		}
		g.Bytes += f.Bytes
		g.Packets += f.Packets
		g.Flows++
		if f.Sampling > 1 {
			g.Sampled++
		}
		if f.Sampling == 0 {
			g.SamplingUnknown++
		}
		if k.invalid {
			g.Invalid++
		}
		g.First = min(g.First, f.ReceiveTime.UnixMilli())
		g.Last = max(g.Last, f.ReceiveTime.UnixMilli())
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := make([]intelligence.Group, 0, len(groups))
	for _, g := range groups {
		out = append(out, *g)
	}
	return out, nil
}

func intelligenceSQLKey(dim string) string {
	if dim == "src_network" || dim == "dst_network" {
		col := strings.TrimSuffix(dim, "network") + "ip"
		return fmt.Sprintf("if(isIPv4String(%s),concat(IPv4NumToString(tupleElement(IPv4CIDRToRange(toIPv4OrDefault(%s),24),1)),'/24'),if(isIPv6String(%s),concat(IPv6NumToString(tupleElement(IPv6CIDRToRange(toIPv6OrDefault(%s),64),1)),'/64'),'unknown'))", col, col, col, col)
	}
	switch dim {
	case "src_ip", "dst_ip", "exporter", "src_country", "dst_country", "src_site", "dst_site":
		return dim
	case "src_as", "dst_as", "dst_port":
		return "toString(" + dim + ")"
	case "application":
		return "if(application_name!='',application_name,application_id)"
	case "protocol":
		return "toString(ip_protocol)"
	case "ingress_if", "egress_if":
		return "concat(exporter,' / ',toString(" + dim + "))"
	}
	return "''"
}
func buildIntelligenceSQL(q Query, s intelligence.Spec, table string, split time.Time) (string, map[string][]string) {
	where, vals := chAnalysisWhere(q)
	where = strings.Replace(where, "receive_time <=", "receive_time <", 1)
	key, peer, bucket, value, invalid := intelligenceSQLKey(s.Dimension), "''", "toInt64(0)", "toFloat64(0)", "0"
	period := "1"
	if s.Kind == "changes" {
		period = "if(receive_time >= {split:DateTime64(3)},1,0)"
		vals.Set("param_split", chTime(split))
	}
	switch s.Kind {
	case "distribution":
		key = "''"
		switch s.Dimension {
		case "bytes", "packets":
			value = "toFloat64(" + s.Dimension + ")"
		case "bytes_per_packet":
			value = "if(packets=0,0,toFloat64(bytes)/packets)"
			invalid = "packets=0"
		case "duration_ms":
			invalid = "isNull(start_time) OR isNull(end_time) OR end_time<start_time"
			value = "toFloat64(ifNull(greatest(0,dateDiff('millisecond',start_time,end_time)),0))"
		}
	case "relationships", "diversity":
		peer = intelligenceSQLKey(s.Peer)
		bucket = fmt.Sprintf("toInt64(intDiv(toUnixTimestamp(receive_time),%d)*%d)", s.Bucket, s.Bucket)
	case "quality", "temporal", "persistence", "anomalies":
		key = "''"
		if s.Kind == "quality" {
			key = "exporter"
		}
		if s.Kind == "persistence" || s.Kind == "anomalies" {
			key = intelligenceSQLKey(s.Dimension)
		}
		bucket = fmt.Sprintf("toInt64(intDiv(toUnixTimestamp(receive_time),%d)*%d)", s.Bucket, s.Bucket)
	}
	sql := fmt.Sprintf(`SELECT %s AS key,%s AS peer,%s AS period,%s AS bucket,%s AS value,
 sum(bytes) AS bytes,sum(packets) AS packets,count() AS flows,countIf(sampling_rate>1) AS sampled,countIf(sampling_rate=0) AS sampling_unknown,
 countIf(%s) AS invalid,min(toUnixTimestamp64Milli(receive_time)) AS first,max(toUnixTimestamp64Milli(receive_time)) AS last
 FROM %s WHERE %s GROUP BY key,peer,period,bucket,value,toUInt8(%s) FORMAT JSONEachRow`, key, peer, period, bucket, value, invalid, table, where, invalid)
	return sql, vals
}
func (c *ClickHouse) IntelligenceGroups(ctx context.Context, q Query, s intelligence.Spec) ([]intelligence.Group, error) {
	q, split, err := intelligenceWindow(q, s)
	if err != nil {
		return nil, err
	}
	sql, params := buildIntelligenceSQL(q, s, fmt.Sprintf("`%s`.`%s`", c.cfg.Database, c.cfg.Table), split)
	// Throw instead of returning partial groups: population statistics require completeness.
	params["max_rows_to_group_by"] = []string{strconv.Itoa(intelligence.MaxGroups)}
	params["group_by_overflow_mode"] = []string{"throw"}
	params["max_result_rows"] = []string{strconv.Itoa(intelligence.MaxGroups)}
	params["result_overflow_mode"] = []string{"throw"}
	params["max_memory_usage"] = []string{"268435456"}
	params["max_threads"] = []string{"2"}
	params["max_execution_time"] = []string{strconv.Itoa(min(20, max(1, c.cfg.MaxExecutionSeconds)))}
	params["prefer_column_name_to_alias"] = []string{"1"}
	params["output_format_json_quote_64bit_integers"] = []string{"0"}
	resp, err := c.do(ctx, sql, nil, params)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out := []intelligence.Group{}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 4096), 8192)
	for sc.Scan() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if len(out) >= intelligence.MaxGroups {
			return nil, intelligence.ErrCardinality
		}
		var g intelligence.Group
		if err := json.Unmarshal(sc.Bytes(), &g); err != nil {
			return nil, errors.New("invalid analytical aggregate response")
		}
		if len(g.Key) > 512 || len(g.Peer) > 512 {
			return nil, errors.New("analysis entity label exceeds 512 bytes")
		}
		out = append(out, g)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
