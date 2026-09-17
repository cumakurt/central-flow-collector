package storage

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"central-flow-collector/internal/model"
	"central-flow-collector/internal/notification"
)

type AlertRuleBackend interface {
	EvaluateAlertRule(context.Context, notification.RuleDefinition, time.Time) ([]notification.Observation, error)
}

func ruleRate(v float64, r notification.RuleDefinition) float64 {
	switch r.Metric {
	case "bps":
		return v * 8 / float64(r.WindowSeconds)
	case "bytes_per_sec", "packets_per_sec", "flows_per_sec":
		return v / float64(r.WindowSeconds)
	}
	return v
}
func ruleDimension(f model.Flow, g string) string {
	if g == "src_network" {
		return intelligenceNetwork(f.SrcIP)
	}
	if g == "dst_network" {
		return intelligenceNetwork(f.DstIP)
	}
	return notification.FlowValue(f, g)
}
func ruleEntity(values []string) string {
	if len(values) == 0 {
		return "scope"
	}
	b, _ := json.Marshal(values)
	return string(b)
}

func (l *Local) EvaluateAlertRule(ctx context.Context, r notification.RuleDefinition, at time.Time) ([]notification.Observation, error) {
	if r.Kind == "seasonal" {
		return nil, errors.New("seasonal rules require the seasonal evaluator")
	}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	from := at.Add(-time.Duration(r.WindowSeconds) * time.Second)
	split := from
	if r.Kind == "comparison" {
		from = from.Add(-time.Duration(r.WindowSeconds) * time.Second)
	}
	type group struct {
		o      notification.Observation
		unique [2]map[string]bool
	}
	groups := map[string]*group{}
	uniqueTotal := 0
	err := l.scanAnalysis(ctx, Query{From: from, To: at}, func(f model.Flow) error {
		if !f.ReceiveTime.Before(at) || !r.Condition.Match(f) {
			return nil
		}
		values := []string{}
		dims := map[string]string{}
		for _, g := range r.GroupBy {
			v := ruleDimension(f, g)
			values = append(values, v)
			dims[g] = v
		}
		key := ruleEntity(values)
		g := groups[key]
		if g == nil {
			if len(groups) >= notification.MaxGroups {
				return errors.New("rule exceeds 1000 groups; narrow the scope")
			}
			g = &group{o: notification.Observation{Entity: key, Dimensions: dims}}
			groups[key] = g
		}
		period := 1
		g.o.Records++
		if f.Sampling != 1 {
			g.o.SamplingUnavailable++
		}
		if f.ReceiveTime.Before(split) {
			period = 0
		}
		v := float64(1)
		switch r.Metric {
		case "bytes", "bps", "bytes_per_sec":
			v = float64(f.Bytes)
		case "packets", "packets_per_sec":
			v = float64(f.Packets)
		case "unique_sources", "unique_destinations":
			ip := f.SrcIP
			if r.Metric == "unique_destinations" {
				ip = f.DstIP
			}
			if g.unique[period] == nil {
				g.unique[period] = map[string]bool{}
			}
			v = 0
			if !g.unique[period][ip] {
				if uniqueTotal >= 100000 {
					return errors.New("exact distinct state limit reached")
				}
				g.unique[period][ip] = true
				uniqueTotal++
				v = 1
			}
		}
		if period == 1 {
			g.o.Value += v
		} else {
			g.o.Previous += v
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	out := []notification.Observation{}
	for _, g := range groups {
		g.o.Value = ruleRate(g.o.Value, r)
		g.o.Previous = ruleRate(g.o.Previous, r)
		out = append(out, g.o)
	}
	return out, nil
}

func ruleColumn(field string) string {
	switch field {
	case "protocol":
		return "ip_protocol"
	case "src_network":
		return "src_ip"
	case "dst_network":
		return "dst_ip"
	case "duration_ms":
		return "ifNull(dateDiff('millisecond',start_time,end_time),-1)"
	case "application":
		return "if(application_name!='',application_name,if(application_id!='',application_id,multiIf(dst_port IN (20,21),'FTP',dst_port=22,'SSH',dst_port IN (25,465,587),'SMTP',dst_port=53,'DNS',dst_port IN (80,8080),'HTTP',dst_port=123,'NTP',dst_port IN (143,993),'IMAP',dst_port IN (443,8443),'HTTPS',dst_port=445,'SMB',dst_port=3306,'MySQL',dst_port=3389,'RDP',dst_port=5432,'PostgreSQL',dst_port IN (8123,9000),'ClickHouse','Other')))"
	}
	return field
}
func ruleConditionSQL(c notification.Condition, params url.Values, n *int) string {
	if len(c.Children) > 0 {
		a := []string{}
		for _, child := range c.Children {
			a = append(a, ruleConditionSQL(child, params, n))
		}
		if c.Op == "not" {
			return "NOT (" + a[0] + ")"
		}
		return "(" + strings.Join(a, " "+strings.ToUpper(c.Op)+" ") + ")"
	}
	col := ruleColumn(c.Field)
	values := []string{}
	for _, v := range c.Values {
		key := fmt.Sprintf("condition_%d", *n)
		*n++
		params.Set("param_"+key, v)
		kind := "String"
		if c.Field == "src_port" || c.Field == "dst_port" || c.Field == "protocol" || c.Field == "bytes" || c.Field == "packets" || c.Field == "duration_ms" || c.Field == "direction" || strings.HasSuffix(c.Field, "_if") || strings.HasSuffix(c.Field, "_as") {
			kind = "Float64"
		}
		values = append(values, "{"+key+":"+kind+"}")
	}
	if c.Field == "src_network" || c.Field == "dst_network" {
		parts := []string{}
		for _, v := range values {
			parts = append(parts, "isIPAddressInRange("+col+","+v+")")
		}
		expr := "(" + strings.Join(parts, " OR ") + ")"
		if c.Op == "ne" || c.Op == "not_in" {
			expr = "NOT " + expr
		}
		return expr
	}
	switch c.Op {
	case "in":
		return col + " IN (" + strings.Join(values, ",") + ")"
	case "not_in":
		return col + " NOT IN (" + strings.Join(values, ",") + ")"
	case "range":
		return "(" + col + ">=" + values[0] + " AND " + col + "<=" + values[1] + ")"
	}
	op := map[string]string{"eq": "=", "ne": "!=", "gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[c.Op]
	return col + op + values[0]
}
func buildRuleSQL(r notification.RuleDefinition, at time.Time, table string) (string, url.Values) {
	from := at.Add(-time.Duration(r.WindowSeconds) * time.Second)
	split := from
	if r.Kind == "comparison" {
		from = from.Add(-time.Duration(r.WindowSeconds) * time.Second)
	}
	p := url.Values{"param_from": {chTime(from)}, "param_to": {chTime(at)}, "param_split": {chTime(split)}, "max_rows_to_group_by": {"1000"}, "group_by_overflow_mode": {"throw"}, "max_result_rows": {"1000"}, "result_overflow_mode": {"throw"}, "max_memory_usage": {"134217728"}, "max_execution_time": {"15"}, "max_threads": {"2"}, "output_format_json_quote_64bit_integers": {"0"}}
	n := 0
	condition := ruleConditionSQL(r.Condition, p, &n)
	keys := []string{}
	for _, g := range r.GroupBy {
		expr := "toString(" + ruleColumn(g) + ")"
		if g == "src_network" || g == "dst_network" {
			expr = intelligenceSQLKey(g)
		}
		keys = append(keys, expr)
	}
	key := "CAST([], 'Array(String)')"
	if len(keys) > 0 {
		key = "[" + strings.Join(keys, ",") + "]"
	}
	metric := func(period string) string {
		predicate := "receive_time " + period + " {split:DateTime64(3)}"
		switch r.Metric {
		case "bytes", "bps", "bytes_per_sec":
			return "sumIf(bytes," + predicate + ")"
		case "packets", "packets_per_sec":
			return "sumIf(packets," + predicate + ")"
		case "unique_sources":
			return "uniqExactIf(src_ip," + predicate + ")"
		case "unique_destinations":
			return "uniqExactIf(dst_ip," + predicate + ")"
		}
		return "countIf(" + predicate + ")"
	}
	sql := fmt.Sprintf("SELECT %s AS dimensions,toFloat64(%s) AS value,toFloat64(%s) AS previous,count() AS records,countIf(sampling_rate!=1) AS sampling_unavailable FROM %s WHERE receive_time >= {from:DateTime64(3)} AND receive_time < {to:DateTime64(3)} AND (%s) GROUP BY dimensions FORMAT JSONEachRow", key, metric(">="), metric("<"), table, condition)
	return sql, p
}
func (c *ClickHouse) EvaluateAlertRule(ctx context.Context, r notification.RuleDefinition, at time.Time) ([]notification.Observation, error) {
	if r.Kind == "seasonal" {
		return nil, errors.New("seasonal rules require the seasonal evaluator")
	}
	if e := r.Validate(); e != nil {
		return nil, e
	}
	sql, p := buildRuleSQL(r, at, fmt.Sprintf("`%s`.`%s`", c.cfg.Database, c.cfg.Table))
	resp, err := c.do(ctx, sql, nil, p)
	if err != nil {
		return nil, errors.New("rule aggregation unavailable")
	}
	defer resp.Body.Close()
	out := []notification.Observation{}
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 4096), 8192)
	for sc.Scan() {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if len(out) >= notification.MaxGroups {
			return nil, errors.New("rule group limit exceeded")
		}
		var row struct {
			Records             uint64   `json:"records"`
			SamplingUnavailable uint64   `json:"sampling_unavailable"`
			Dimensions          []string `json:"dimensions"`
			Value               float64  `json:"value"`
			Previous            float64  `json:"previous"`
		}
		if err = json.Unmarshal(sc.Bytes(), &row); err != nil {
			return nil, errors.New("invalid rule aggregation response")
		}
		if len(row.Dimensions) != len(r.GroupBy) {
			return nil, errors.New("invalid rule dimensions")
		}
		dims := map[string]string{}
		for i, d := range row.Dimensions {
			dims[r.GroupBy[i]] = d
		}
		out = append(out, notification.Observation{Entity: ruleEntity(row.Dimensions), Value: ruleRate(row.Value, r), Previous: ruleRate(row.Previous, r), Dimensions: dims, Records: row.Records, SamplingUnavailable: row.SamplingUnavailable})
	}
	return out, sc.Err()
}
