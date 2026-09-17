package storage

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"central-flow-collector/internal/model"
)

// ServicePortRule describes one standard service port and the IP protocols
// that are valid for it. An empty protocol list means any IP protocol.
type ServicePortRule struct {
	Port      uint16   `json:"port"`
	Protocols []uint16 `json:"protocols,omitempty"`
}

// ServiceDefinition is a curated, protocol-aware service preset. It is used by
// both the service timeline and Flow Explorer service drill-down filters.
type ServiceDefinition struct {
	ID          string            `json:"id"`
	Label       string            `json:"label"`
	Description string            `json:"description,omitempty"`
	Rules       []ServicePortRule `json:"rules"`
}

var standardServices = []ServiceDefinition{
	{ID: "smtp", Label: "SMTP", Description: "Mail transfer and submission", Rules: []ServicePortRule{{25, []uint16{6}}, {465, []uint16{6}}, {587, []uint16{6}}}},
	{ID: "http", Label: "HTTP", Description: "Web traffic", Rules: []ServicePortRule{{80, []uint16{6}}}},
	{ID: "https", Label: "HTTPS", Description: "TLS web traffic", Rules: []ServicePortRule{{443, []uint16{6}}}},
	{ID: "dns", Label: "DNS", Description: "Domain Name System", Rules: []ServicePortRule{{53, []uint16{6, 17}}}},
	{ID: "pop3", Label: "POP3", Description: "POP3 and POP3S", Rules: []ServicePortRule{{110, []uint16{6}}, {995, []uint16{6}}}},
	{ID: "imap", Label: "IMAP", Description: "IMAP and IMAPS", Rules: []ServicePortRule{{143, []uint16{6}}, {993, []uint16{6}}}},
	{ID: "ssh", Label: "SSH / SFTP", Description: "Secure Shell and SFTP", Rules: []ServicePortRule{{22, []uint16{6}}}},
	{ID: "rdp", Label: "RDP", Description: "Remote Desktop Protocol", Rules: []ServicePortRule{{3389, []uint16{6, 17}}}},
	{ID: "ftp", Label: "FTP", Description: "FTP control and data", Rules: []ServicePortRule{{20, []uint16{6}}, {21, []uint16{6}}}},
	{ID: "dhcp", Label: "DHCP", Description: "Dynamic Host Configuration Protocol", Rules: []ServicePortRule{{67, []uint16{17}}, {68, []uint16{17}}}},
	{ID: "ntp", Label: "NTP", Description: "Network Time Protocol", Rules: []ServicePortRule{{123, []uint16{17}}}},
	{ID: "snmp", Label: "SNMP", Description: "SNMP queries and traps", Rules: []ServicePortRule{{161, []uint16{17}}, {162, []uint16{17}}}},
	{ID: "ldap", Label: "LDAP / LDAPS", Description: "Directory services", Rules: []ServicePortRule{{389, []uint16{6, 17}}, {636, []uint16{6}}}},
	{ID: "smb", Label: "SMB", Description: "Server Message Block", Rules: []ServicePortRule{{445, []uint16{6}}}},
	{ID: "kerberos", Label: "Kerberos", Description: "Kerberos authentication", Rules: []ServicePortRule{{88, []uint16{6, 17}}}},
	{ID: "syslog", Label: "Syslog", Description: "Syslog and syslog over TLS", Rules: []ServicePortRule{{514, []uint16{6, 17}}, {6514, []uint16{6}}}},
	{ID: "mysql", Label: "MySQL", Description: "MySQL database", Rules: []ServicePortRule{{3306, []uint16{6}}}},
	{ID: "postgresql", Label: "PostgreSQL", Description: "PostgreSQL database", Rules: []ServicePortRule{{5432, []uint16{6}}}},
	{ID: "mssql", Label: "MS SQL", Description: "Microsoft SQL Server", Rules: []ServicePortRule{{1433, []uint16{6}}, {1434, []uint16{17}}}},
	{ID: "redis", Label: "Redis", Description: "Redis database", Rules: []ServicePortRule{{6379, []uint16{6}}}},
	{ID: "mongodb", Label: "MongoDB", Description: "MongoDB database", Rules: []ServicePortRule{{27017, []uint16{6}}}},
	{ID: "winrm", Label: "WinRM", Description: "Windows Remote Management", Rules: []ServicePortRule{{5985, []uint16{6}}, {5986, []uint16{6}}}},
	{ID: "telnet", Label: "Telnet", Description: "Telnet remote terminal", Rules: []ServicePortRule{{23, []uint16{6}}}},
	{ID: "sip", Label: "SIP", Description: "Session Initiation Protocol", Rules: []ServicePortRule{{5060, []uint16{6, 17}}, {5061, []uint16{6}}}},
}

func ServiceCatalog() []ServiceDefinition {
	out := make([]ServiceDefinition, len(standardServices))
	for i, s := range standardServices {
		out[i] = s
		out[i].Rules = append([]ServicePortRule(nil), s.Rules...)
		for j := range out[i].Rules {
			out[i].Rules[j].Protocols = append([]uint16(nil), s.Rules[j].Protocols...)
		}
	}
	return out
}

func ServiceByID(id string) (ServiceDefinition, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, s := range standardServices {
		if s.ID == id {
			return s, true
		}
	}
	return ServiceDefinition{}, false
}

// TrafficSelector represents one line on the multi-service timeline.
type TrafficSelector struct {
	Key       string            `json:"key"`
	Label     string            `json:"label"`
	Kind      string            `json:"kind"`
	ServiceID string            `json:"service,omitempty"`
	Port      uint16            `json:"port,omitempty"`
	Protocols []uint16          `json:"protocols,omitempty"`
	App       string            `json:"app,omitempty"`
	Rules     []ServicePortRule `json:"-"`
}

type TrafficSeries struct {
	Selector TrafficSelector `json:"selector"`
	Totals   AnalysisTotals  `json:"totals"`
	Timeline []AnalysisPoint `json:"timeline"`
}

type TrafficSeriesResult struct {
	From   time.Time       `json:"from"`
	To     time.Time       `json:"to"`
	Bucket string          `json:"bucket"`
	Series []TrafficSeries `json:"series"`
}

func trafficSelectorForService(id string) (TrafficSelector, error) {
	s, ok := ServiceByID(id)
	if !ok {
		return TrafficSelector{}, fmt.Errorf("unknown service %q", id)
	}
	return TrafficSelector{Key: "service:" + s.ID, Label: s.Label, Kind: "service", ServiceID: s.ID, Rules: s.Rules}, nil
}

func protocolAllowed(v uint8, allowed []uint16) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, p := range allowed {
		if p == uint16(v) {
			return true
		}
	}
	return false
}

func matchTrafficSelector(f model.Flow, s TrafficSelector) bool {
	if s.App != "" {
		return strings.EqualFold(f.AppName, s.App) || strings.EqualFold(f.AppID, s.App)
	}
	if len(s.Rules) > 0 {
		for _, rule := range s.Rules {
			if f.SrcPort != rule.Port && f.DstPort != rule.Port {
				continue
			}
			// Some NetFlow v9/IPFIX exporters omit protocolIdentifier while still
			// exporting L4 ports. In that case keep port-backed service visibility
			// rather than silently turning the entire service timeline into zero.
			// A known, conflicting transport (for example UDP/25 for SMTP) is
			// still rejected. Protocol-only series remain strict below.
			if f.IPProtocol == 0 || protocolAllowed(f.IPProtocol, rule.Protocols) {
				return true
			}
		}
		return false
	}
	if s.Port > 0 {
		if f.SrcPort != s.Port && f.DstPort != s.Port {
			return false
		}
		if len(s.Protocols) == 0 || f.IPProtocol == 0 {
			return true
		}
		return protocolAllowed(f.IPProtocol, s.Protocols)
	}
	return len(s.Protocols) == 0 || protocolAllowed(f.IPProtocol, s.Protocols)
}

func (l *Local) AnalyzeTrafficSeries(ctx context.Context, q Query, selectors []TrafficSelector) (TrafficSeriesResult, error) {
	q, bucket, err := normalizeAnalysisQuery(q)
	if err != nil {
		return TrafficSeriesResult{}, err
	}
	if len(selectors) == 0 || len(selectors) > 32 {
		return TrafficSeriesResult{}, errors.New("traffic series count must be 1..32")
	}
	out := TrafficSeriesResult{From: q.From, To: q.To, Bucket: bucketLabel(bucket), Series: make([]TrafficSeries, len(selectors))}
	timelines := make([]map[int64]*AnalysisPoint, len(selectors))
	for i, s := range selectors {
		out.Series[i].Selector = s
		out.Series[i].Selector.Rules = nil
		timelines[i] = map[int64]*AnalysisPoint{}
	}
	err = l.scanAnalysis(ctx, q, func(f model.Flow) error {
		for i, s := range selectors {
			if !matchTrafficSelector(f, s) {
				continue
			}
			series := &out.Series[i]
			series.Totals.Flows++
			series.Totals.Bytes += f.Bytes
			series.Totals.Packets += f.Packets
			ts := f.ReceiveTime.UTC().Truncate(bucket).Unix()
			p := timelines[i][ts]
			if p == nil {
				p = &AnalysisPoint{Timestamp: time.Unix(ts, 0).UTC()}
				timelines[i][ts] = p
			}
			p.Bytes += f.Bytes
			p.Packets += f.Packets
			p.Flows++
		}
		return nil
	})
	if err != nil {
		return TrafficSeriesResult{}, err
	}
	for i := range out.Series {
		for _, p := range timelines[i] {
			out.Series[i].Timeline = append(out.Series[i].Timeline, *p)
		}
		sort.Slice(out.Series[i].Timeline, func(a, b int) bool {
			return out.Series[i].Timeline[a].Timestamp.Before(out.Series[i].Timeline[b].Timestamp)
		})
	}
	return out, nil
}

func selectorSQLCondition(s TrafficSelector, idx int, vals url.Values) (string, error) {
	if s.App != "" {
		name := fmt.Sprintf("series_app_%d", idx)
		vals.Set("param_"+name, s.App)
		return fmt.Sprintf("(application_name={%s:String} OR application_id={%s:String})", name, name), nil
	}
	if len(s.Rules) > 0 {
		parts := make([]string, 0, len(s.Rules))
		for _, rule := range s.Rules {
			cond := fmt.Sprintf("(src_port=%d OR dst_port=%d)", rule.Port, rule.Port)
			if len(rule.Protocols) > 0 {
				ps := make([]string, len(rule.Protocols))
				for i, p := range rule.Protocols {
					ps[i] = strconv.Itoa(int(p))
				}
				cond = "(" + cond + " AND (ip_protocol=0 OR ip_protocol IN (" + strings.Join(ps, ",") + ")))"
			}
			parts = append(parts, cond)
		}
		return "(" + strings.Join(parts, " OR ") + ")", nil
	}
	parts := []string{}
	if s.Port > 0 {
		parts = append(parts, fmt.Sprintf("(src_port=%d OR dst_port=%d)", s.Port, s.Port))
	}
	if len(s.Protocols) > 0 {
		ps := make([]string, len(s.Protocols))
		for i, p := range s.Protocols {
			ps[i] = strconv.Itoa(int(p))
		}
		protoCond := "ip_protocol IN (" + strings.Join(ps, ",") + ")"
		if s.Port > 0 {
			protoCond = "(ip_protocol=0 OR " + protoCond + ")"
		}
		parts = append(parts, protoCond)
	}
	if len(parts) == 0 {
		return "", errors.New("empty traffic selector")
	}
	return "(" + strings.Join(parts, " AND ") + ")", nil
}

func (c *ClickHouse) AnalyzeTrafficSeries(ctx context.Context, q Query, selectors []TrafficSelector) (TrafficSeriesResult, error) {
	q, bucket, err := normalizeAnalysisQuery(q)
	if err != nil {
		return TrafficSeriesResult{}, err
	}
	if len(selectors) == 0 || len(selectors) > 32 {
		return TrafficSeriesResult{}, errors.New("traffic series count must be 1..32")
	}
	where, vals := chAnalysisWhere(q)
	vals.Set("max_execution_time", strconv.Itoa(c.cfg.MaxExecutionSeconds))
	vals.Set("max_result_rows", strconv.Itoa(maxInt(c.cfg.MaxResultRows, 100000)))
	vals.Set("result_overflow_mode", "throw")
	conditions := make([]string, len(selectors))
	arrayParts := make([]string, len(selectors))
	for i, s := range selectors {
		cond, e := selectorSQLCondition(s, i, vals)
		if e != nil {
			return TrafficSeriesResult{}, e
		}
		conditions[i] = cond
		arrayParts[i] = fmt.Sprintf("if(%s,['s%d'],CAST([], 'Array(String)'))", cond, i)
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
	table := fmt.Sprintf("`%s`.`%s`", c.cfg.Database, c.cfg.Table)
	sql := fmt.Sprintf(`SELECT series,toUnixTimestamp(ts) ts,sum(bytes) bytes,sum(packets) packets,count() flows FROM (SELECT arrayJoin(arrayConcat(%s)) series,toStartOfInterval(receive_time,INTERVAL %d %s) ts,bytes,packets FROM %s WHERE %s AND (%s)) GROUP BY series,ts ORDER BY ts,series FORMAT JSONEachRow`, strings.Join(arrayParts, ","), num, unit, table, where, strings.Join(conditions, " OR "))
	resp, err := c.do(ctx, sql, nil, vals)
	if err != nil {
		return TrafficSeriesResult{}, err
	}
	defer resp.Body.Close()
	out := TrafficSeriesResult{From: q.From, To: q.To, Bucket: bucketLabel(bucket), Series: make([]TrafficSeries, len(selectors))}
	for i, s := range selectors {
		out.Series[i].Selector = s
		out.Series[i].Selector.Rules = nil
	}
	sc := bufio.NewScanner(resp.Body)
	for sc.Scan() {
		var row struct {
			Series  string `json:"series"`
			TS      int64  `json:"ts"`
			Bytes   uint64 `json:"bytes"`
			Packets uint64 `json:"packets"`
			Flows   uint64 `json:"flows"`
		}
		if err := json.Unmarshal(sc.Bytes(), &row); err != nil {
			return TrafficSeriesResult{}, err
		}
		i, err := strconv.Atoi(strings.TrimPrefix(row.Series, "s"))
		if err != nil || i < 0 || i >= len(out.Series) {
			return TrafficSeriesResult{}, errors.New("invalid traffic series response")
		}
		p := AnalysisPoint{Timestamp: time.Unix(row.TS, 0).UTC(), Bytes: row.Bytes, Packets: row.Packets, Flows: row.Flows}
		out.Series[i].Timeline = append(out.Series[i].Timeline, p)
		out.Series[i].Totals.Bytes += row.Bytes
		out.Series[i].Totals.Packets += row.Packets
		out.Series[i].Totals.Flows += row.Flows
	}
	return out, sc.Err()
}
