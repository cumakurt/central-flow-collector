package api

import (
	"central-flow-collector/internal/auth"
	"central-flow-collector/internal/engineering"
	"central-flow-collector/internal/storage"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func (s *Server) engineeringRoutes() {
	s.mux.HandleFunc("GET /api/v1/engineering/{resource}", s.withAuth("analytics.read", s.engineeringRead))
	s.mux.HandleFunc("POST /api/v1/engineering/routes", s.withAuth("system.manage", s.engineeringRoutesSave))
	s.mux.HandleFunc("POST /api/v1/capacity/simulate", s.withAuth("analytics.read", s.capacitySimulate))
}
func (s *Server) engineeringRead(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.EngineeringRoutes == nil {
		writeErr(w, 503, "Routing context is unavailable")
		return
	}
	resource := r.PathValue("resource")
	if resource == "routes" {
		version, updated, count := s.EngineeringRoutes.Snapshot()
		limit, offset := 100, 0
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 1000 {
				limit = n
			}
		}
		if v := r.URL.Query().Get("offset"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 && n <= count {
				offset = n
			}
		}
		routes := s.EngineeringRoutes.Routes()
		end := offset + limit
		if end > len(routes) {
			end = len(routes)
		}
		if offset > end {
			offset = end
		}
		writeJSON(w, 200, map[string]any{"version": version, "last_updated": updated, "prefixes": count, "offset": offset, "limit": limit, "truncated": end < count, "routes": routes[offset:end]})
		return
	}
	from, to, e := engineeringRange(r)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	b, ok := s.Store.(storage.EngineeringBackend)
	if !ok {
		writeErr(w, 503, "Engineering aggregation is unavailable for this storage backend")
		return
	}
	summary, e := b.EngineeringSummary(r.Context(), from, to, s.EngineeringRoutes)
	if e != nil {
		writeErr(w, 422, "Engineering aggregation unavailable; narrow the range or check storage health")
		return
	}
	writeJSON(w, 200, summary)
}
func engineeringRange(r *http.Request) (time.Time, time.Time, error) {
	q := r.URL.Query()
	to := time.Now().UTC()
	from := to.Add(-24 * time.Hour)
	if v := q.Get("from"); v != "" {
		x, e := time.Parse(time.RFC3339, v)
		if e != nil {
			return time.Time{}, time.Time{}, errors.New("from must be RFC3339")
		}
		from = x
	}
	if v := q.Get("to"); v != "" {
		x, e := time.Parse(time.RFC3339, v)
		if e != nil {
			return time.Time{}, time.Time{}, errors.New("to must be RFC3339")
		}
		to = x
	}
	if !to.After(from) || to.Sub(from) > 31*24*time.Hour {
		return time.Time{}, time.Time{}, errors.New("range must be positive and at most 31 days")
	}
	return from, to, nil
}
func (s *Server) engineeringRoutesSave(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.EngineeringRoutes == nil {
		writeErr(w, 503, "Routing context unavailable")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<20)
	var routes []engineering.PrefixRoute
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(&routes); e != nil {
		writeErr(w, 400, "Invalid routing table JSON")
		return
	}
	if e := s.EngineeringRoutes.Replace(routes); e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	if s.EngineeringRoutesPath != "" {
		b, _ := json.Marshal(routes)
		tmp := s.EngineeringRoutesPath + ".tmp"
		if e := os.MkdirAll(filepath.Dir(s.EngineeringRoutesPath), 0700); e != nil || os.WriteFile(tmp, b, 0600) != nil || os.Rename(tmp, s.EngineeringRoutesPath) != nil {
			_ = os.Remove(tmp)
			writeErr(w, 500, "Routing table could not be persisted")
			return
		}
	}
	writeJSON(w, 200, map[string]any{"ok": true, "prefixes": len(routes), "version": func() string { v, _, _ := s.EngineeringRoutes.Snapshot(); return v }()})
}
func (s *Server) capacitySimulate(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var in engineering.SimulationInput
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(&in); e != nil {
		writeErr(w, 400, "Invalid simulator input")
		return
	}
	if in.CurrentDailyBytes == 0 {
		st := s.Store.Stats()
		days := s.Store.Retention()
		if days < 1 {
			days = 1
		}
		in.CurrentDailyBytes = float64(st.BytesOnDisk) / float64(days)
		in.CurrentRawDays = days
		in.CurrentAggregateDays = days
	}
	if in.FreeBytes == 0 {
		if cap, e := s.Store.Capacity(r.Context()); e == nil {
			in.FreeBytes = float64(cap.FreeBytes)
		}
	}
	out, e := engineering.Simulate(in)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, out)
}
