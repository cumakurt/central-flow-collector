package api

import (
	"central-flow-collector/internal/auth"
	"central-flow-collector/internal/reporting"
	"central-flow-collector/internal/storage"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type periodChange struct {
	Current  uint64  `json:"current"`
	Previous uint64  `json:"previous"`
	Change   float64 `json:"change_percent"`
}

type periodCompare struct {
	Current  storage.AnalysisResult  `json:"current"`
	Previous storage.AnalysisResult  `json:"previous"`
	Changes  map[string]periodChange `json:"changes"`
}

func change(cur, prev uint64) periodChange {
	p := periodChange{Current: cur, Previous: prev}
	if prev == 0 {
		if cur > 0 {
			p.Change = 100
		}
		return p
	}
	p.Change = (float64(cur) - float64(prev)) * 100 / float64(prev)
	return p
}

func queryWithoutTenant(r *http.Request) (storage.Query, error) {
	q, err := storage.ParseQuery(r.URL.Query())
	if err != nil {
		return q, err
	}
	// v4 is deliberately a single-organization product. The legacy storage
	// column is retained for upgrade compatibility, but it is never a public
	// query/security boundary.
	q.Tenant = ""
	return q, nil
}

func analysisLimit(r *http.Request) int {
	n := 10
	if v := strings.TrimSpace(r.URL.Query().Get("top")); v != "" {
		if x, err := strconv.Atoi(v); err == nil && x >= 1 && x <= 50 {
			n = x
		}
	}
	return n
}

func (s *Server) baselineStatus(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	writeJSON(w, http.StatusOK, s.Analytics.BaselineStatus())
}

func (s *Server) flowAnalytics(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	q, err := queryWithoutTenant(r)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	out, err := s.Store.Analyze(ctx, q, analysisLimit(r))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) periodComparison(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	q, err := queryWithoutTenant(r)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if q.To.IsZero() {
		q.To = time.Now().UTC()
	}
	if q.From.IsZero() {
		q.From = q.To.Add(-24 * time.Hour)
	}
	if !q.To.After(q.From) {
		writeErr(w, 400, "invalid time range")
		return
	}
	d := q.To.Sub(q.From)
	pq := q
	pq.To = q.From
	pq.From = q.From.Add(-d)
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	cur, err := s.Store.Analyze(ctx, q, analysisLimit(r))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	prev, err := s.Store.Analyze(ctx, pq, analysisLimit(r))
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	c, p := cur.Totals, prev.Totals
	changes := map[string]periodChange{
		"flows": change(c.Flows, p.Flows), "packets": change(c.Packets, p.Packets), "bytes": change(c.Bytes, p.Bytes),
		"unique_sources": change(c.UniqueSources, p.UniqueSources), "unique_destinations": change(c.UniqueDestinations, p.UniqueDestinations),
		"unique_conversations": change(c.UniqueConversations, p.UniqueConversations), "unique_asns": change(c.UniqueASNs, p.UniqueASNs),
		"unique_countries": change(c.UniqueCountries, p.UniqueCountries), "unique_exporters": change(c.UniqueExporters, p.UniqueExporters),
	}
	writeJSON(w, 200, periodCompare{Current: cur, Previous: prev, Changes: changes})
}

func (s *Server) trafficMatrixV4(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	q, err := queryWithoutTenant(r)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	n := 100
	if v := strings.TrimSpace(r.URL.Query().Get("limit")); v != "" {
		if x, e := strconv.Atoi(v); e == nil && x >= 1 && x <= 500 {
			n = x
		} else {
			writeErr(w, 400, "invalid limit")
			return
		}
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	out, err := s.Store.TrafficMatrix(ctx, q, n)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) capacityV4(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	out, err := s.Store.Capacity(ctx)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, out)
}

type flowCursor struct {
	Before time.Time `json:"before"`
}

func encodeCursor(t time.Time) string {
	b, _ := json.Marshal(flowCursor{Before: t.UTC()})
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCursor(v string) (time.Time, error) {
	b, err := base64.RawURLEncoding.DecodeString(v)
	if err != nil {
		return time.Time{}, err
	}
	var c flowCursor
	if err := json.Unmarshal(b, &c); err != nil || c.Before.IsZero() {
		return time.Time{}, fmt.Errorf("invalid cursor")
	}
	return c.Before, nil
}

func (s *Server) flowsPage(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	q, err := queryWithoutTenant(r)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if c := strings.TrimSpace(r.URL.Query().Get("cursor")); c != "" {
		before, e := decodeCursor(c)
		if e != nil {
			writeErr(w, 400, "invalid cursor")
			return
		}
		// Query is inclusive on To, so move one nanosecond back to prevent a
		// boundary row from appearing on consecutive pages.
		q.To = before.Add(-time.Nanosecond)
	}
	if q.Limit < 1 || q.Limit > 500 {
		q.Limit = 200
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	rows, err := s.Store.Query(ctx, q)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	next := ""
	if len(rows) == q.Limit {
		next = encodeCursor(rows[len(rows)-1].ReceiveTime)
	}
	if s.Workspace != nil {
		s.Workspace.RecordHistory(ss.Username, queryMap(r), len(rows))
	}
	writeJSON(w, 200, map[string]any{"rows": rows, "next_cursor": next, "limit": q.Limit})
}

type reportExportRequest struct {
	Name    string            `json:"name"`
	Format  string            `json:"format"`
	Filters map[string]string `json:"filters"`
	From    time.Time         `json:"from"`
	To      time.Time         `json:"to"`
}

func (s *Server) reportExportV4(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.Reports == nil {
		writeErr(w, 503, "reporting unavailable")
		return
	}
	var in reportExportRequest
	if !decode(w, r, &in) {
		return
	}
	format := strings.ToLower(strings.TrimSpace(in.Format))
	if format == "" {
		format = "pdf"
	}
	qv := make(map[string][]string, len(in.Filters)+2)
	for k, v := range in.Filters {
		if strings.TrimSpace(v) != "" {
			qv[k] = []string{v}
		}
	}
	if !in.From.IsZero() {
		qv["from"] = []string{in.From.UTC().Format(time.RFC3339)}
	}
	if !in.To.IsZero() {
		qv["to"] = []string{in.To.UTC().Format(time.RFC3339)}
	}
	q, err := storage.ParseQuery(qv)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	q.Tenant = ""
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	_, data, err := s.Reports.Build(ctx, in.Name, format, q, in.Filters)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	ct := map[string]string{"pdf": "application/pdf", "xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "csv": "text/csv; charset=utf-8", "json": "application/json"}[format]
	if ct == "" {
		writeErr(w, 400, "format must be pdf, xlsx, csv or json")
		return
	}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "network-flow-analysis"
	}
	name = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			return r
		}
		if r == ' ' {
			return '-'
		}
		return -1
	}, name)
	if name == "" {
		name = "network-flow-analysis"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name+"."+format))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
	if s.Audit != nil {
		s.writeCompatAudit(reportingAuditEvent(ss.Username, remoteIP(r), format, len(data)))
	}
}

// Small adapter keeps v4 report export independent from reporting internals.
func reportingAuditEvent(user, source, format string, bytes int) auditEventCompat {
	return auditEventCompat{User: user, Action: "report_export", Source: source, Success: true, Detail: fmt.Sprintf("format=%s bytes=%d", format, bytes)}
}

// auditEventCompat is converted by the helper in v4_audit_compat.go. Keeping
// the construction here explicit makes report metadata easy to regression-test.
type auditEventCompat struct {
	User, Action, Source, Detail string
	Success                      bool
}

var _ = reporting.Job{}

func (s *Server) serviceCatalog(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	writeJSON(w, http.StatusOK, map[string]any{"services": storage.ServiceCatalog(), "max_series": 8})
}

func parseSeriesProtocol(v string) (uint8, string, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "icmp":
		return 1, "ICMP", nil
	case "6", "tcp":
		return 6, "TCP", nil
	case "17", "udp":
		return 17, "UDP", nil
	case "47", "gre":
		return 47, "GRE", nil
	case "50", "esp":
		return 50, "ESP", nil
	case "58", "icmpv6", "icmp6":
		return 58, "ICMPv6", nil
	case "89", "ospf":
		return 89, "OSPF", nil
	case "132", "sctp":
		return 132, "SCTP", nil
	default:
		return 0, "", errors.New("invalid series_protocol")
	}
}

func serviceSeriesSelectors(values map[string][]string) ([]storage.TrafficSelector, error) {
	selectors := make([]storage.TrafficSelector, 0, 8)
	seen := map[string]struct{}{}
	add := func(x storage.TrafficSelector) error {
		if _, ok := seen[x.Key]; ok {
			return nil
		}
		if len(selectors) >= 8 {
			return errors.New("select at most 8 traffic series")
		}
		seen[x.Key] = struct{}{}
		selectors = append(selectors, x)
		return nil
	}
	for _, raw := range values["series_service"] {
		id := strings.ToLower(strings.TrimSpace(raw))
		d, ok := storage.ServiceByID(id)
		if !ok {
			return nil, fmt.Errorf("unknown service %q", raw)
		}
		if err := add(storage.TrafficSelector{Key: "service:" + d.ID, Label: d.Label, Kind: "service", ServiceID: d.ID, Rules: d.Rules}); err != nil {
			return nil, err
		}
	}
	for _, raw := range values["series_port"] {
		raw = strings.ToLower(strings.TrimSpace(raw))
		proto, portText := "any", raw
		if a, b, ok := strings.Cut(raw, ":"); ok {
			proto, portText = a, b
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return nil, fmt.Errorf("invalid series_port %q", raw)
		}
		var protocols []uint16
		labelPrefix := "Port"
		switch proto {
		case "any", "ip":
		case "tcp":
			protocols, labelPrefix = []uint16{6}, "TCP"
		case "udp":
			protocols, labelPrefix = []uint16{17}, "UDP"
		case "sctp":
			protocols, labelPrefix = []uint16{132}, "SCTP"
		default:
			return nil, fmt.Errorf("invalid series_port protocol %q", proto)
		}
		key := fmt.Sprintf("port:%s:%d", proto, port)
		if err := add(storage.TrafficSelector{Key: key, Label: fmt.Sprintf("%s %d", labelPrefix, port), Kind: "port", Port: uint16(port), Protocols: protocols}); err != nil {
			return nil, err
		}
	}
	for _, raw := range values["series_protocol"] {
		code, label, err := parseSeriesProtocol(raw)
		if err != nil {
			return nil, err
		}
		if err := add(storage.TrafficSelector{Key: "protocol:" + strconv.Itoa(int(code)), Label: label, Kind: "protocol", Protocols: []uint16{uint16(code)}}); err != nil {
			return nil, err
		}
	}
	for _, raw := range values["series_app"] {
		app := strings.TrimSpace(raw)
		if app == "" || len(app) > 128 || strings.ContainsAny(app, "\r\n\x00") {
			return nil, errors.New("invalid series_app")
		}
		key := "app:" + strings.ToLower(app)
		if err := add(storage.TrafficSelector{Key: key, Label: app, Kind: "application", App: app}); err != nil {
			return nil, err
		}
	}
	if len(selectors) == 0 {
		for _, id := range []string{"smtp", "dns", "https", "ssh"} {
			d, _ := storage.ServiceByID(id)
			_ = add(storage.TrafficSelector{Key: "service:" + d.ID, Label: d.Label, Kind: "service", ServiceID: d.ID, Rules: d.Rules})
		}
	}
	return selectors, nil
}

func (s *Server) serviceSeries(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	q, err := queryWithoutTenant(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var selectors []storage.TrafficSelector
	if r.URL.Query().Get("catalog") == "1" {
		for _, d := range storage.ServiceCatalog() {
			selectors = append(selectors, storage.TrafficSelector{Key: "service:" + d.ID, Label: d.Label, Kind: "service", ServiceID: d.ID, Rules: d.Rules})
		}
	} else {
		selectors, err = serviceSeriesSelectors(r.URL.Query())
	}
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	out, err := s.Store.AnalyzeTrafficSeries(ctx, q, selectors)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, out)
}
