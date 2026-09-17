package api

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"central-flow-collector/internal/auth"
	"central-flow-collector/internal/intelligence"
	"central-flow-collector/internal/storage"
)

type intelligenceState struct {
	active                                 atomic.Int64
	queries, failures, rejected, cancelled atomic.Uint64
}

func parseIntelligence(r *http.Request) (intelligence.Spec, error) {
	v := r.URL.Query()
	s := intelligence.Spec{Kind: "changes", Dimension: "application", Metric: "bytes", Peer: "dst_ip", Bucket: 3600, Top: 25, Bins: 24, Strategy: "logarithmic", Threshold: 99}
	for key, dst := range map[string]*string{"kind": &s.Kind, "dimension": &s.Dimension, "metric": &s.Metric, "peer": &s.Peer, "strategy": &s.Strategy, "event_state": &s.EventState} {
		if v.Has(key) {
			*dst = v.Get(key)
		}
	}
	for key, dst := range map[string]*int{"bucket": &s.Bucket, "top": &s.Top, "bins": &s.Bins} {
		if v.Has(key) {
			n, e := strconv.Atoi(v.Get(key))
			if e != nil {
				return s, fmt.Errorf("invalid %s", key)
			}
			*dst = n
		}
	}
	if v.Has("threshold") {
		n, e := strconv.ParseFloat(v.Get("threshold"), 64)
		if e != nil || n != n {
			return s, errors.New("invalid threshold")
		}
		s.Threshold = n
	}
	if v.Has("capacity_bps") {
		n, e := strconv.ParseFloat(v.Get("capacity_bps"), 64)
		if e != nil {
			return s, errors.New("invalid capacity_bps")
		}
		s.CapacityBPS = n
	}
	return s, s.Validate()
}
func (s *Server) intelligenceQuery(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	spec, err := parseIntelligence(r)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
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
	format := r.URL.Query().Get("format")
	if format != "" && format != "json" && format != "csv" {
		writeErr(w, 400, "format must be csv or json")
		return
	}
	if format != "" && (!auth.HasPermission(ss.Role, "flows.export") || (strings.HasPrefix(strings.ToLower(r.Header.Get("Authorization")), "bearer ") && !auth.ScopeAllows(ss.Scopes, "flows.export"))) {
		writeErr(w, 403, "export permission required")
		return
	}
	backend, ok := s.Store.(storage.IntelligenceBackend)
	if !ok {
		writeErr(w, 503, "advanced aggregation unavailable for this backend")
		return
	}
	if s.intelligenceState.active.Add(1) > 2 {
		s.intelligenceState.active.Add(-1)
		s.intelligenceState.rejected.Add(1)
		w.Header().Set("Retry-After", "2")
		writeErr(w, 429, "two advanced queries are running; retry shortly")
		return
	}
	defer s.intelligenceState.active.Add(-1)
	s.intelligenceState.queries.Add(1)
	started := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
	defer cancel()
	groups, err := backend.IntelligenceGroups(ctx, q, spec)
	if err != nil {
		s.intelligenceState.failures.Add(1)
		if ctx.Err() != nil {
			s.intelligenceState.cancelled.Add(1)
			writeErr(w, 408, "analysis cancelled or timed out; narrow the range")
			return
		}
		if errors.Is(err, intelligence.ErrCardinality) {
			s.intelligenceState.rejected.Add(1)
			writeErr(w, 422, err.Error())
			return
		}
		writeErr(w, 422, "analysis unavailable: check time range (maximum 31 days), bucket count (maximum 2,000), storage health and cardinality; narrow the range or add filters")
		return
	}
	out := intelligence.Calculate(spec, groups, q.From, q.To)
	out.Summary["query_duration_ms"] = float64(time.Since(started).Microseconds()) / 1000
	payload := struct {
		intelligence.Result
		Filters map[string]string `json:"filters"`
	}{out, map[string]string{}}
	for key, values := range r.URL.Query() {
		if len(values) > 0 && key != "format" {
			payload.Filters[key] = values[0]
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	if format == "" {
		writeJSON(w, 200, payload)
		return
	}
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=cfc-%s.%s", spec.Kind, format))
	if format == "json" {
		writeJSON(w, 200, payload)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	cw := csv.NewWriter(w)
	// Long-form CSV keeps nested metadata and all result types in one stable schema.
	_ = cw.Write([]string{"field", "value"})
	meta, _ := json.Marshal(payload)
	var tree any
	_ = json.Unmarshal(meta, &tree)
	writeAnalysisCSV(cw, "", tree)
	cw.Flush()
}

func writeAnalysisCSV(w *csv.Writer, path string, value any) {
	switch x := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			next := k
			if path != "" {
				next = path + "." + k
			}
			writeAnalysisCSV(w, next, x[k])
		}
	case []any:
		for i, v := range x {
			writeAnalysisCSV(w, fmt.Sprintf("%s[%d]", path, i), v)
		}
	default:
		cell := fmt.Sprint(value)
		if value == nil {
			cell = ""
		}
		trimmed := strings.TrimSpace(cell)
		if strings.HasPrefix(trimmed, "=") || strings.HasPrefix(trimmed, "+") || strings.HasPrefix(trimmed, "-") || strings.HasPrefix(trimmed, "@") || strings.HasPrefix(cell, "\t") || strings.HasPrefix(cell, "\r") {
			cell = "'" + cell
		}
		_ = w.Write([]string{path, cell})
	}
}
