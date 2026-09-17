package api

import (
	product "central-flow-collector"
	"central-flow-collector/internal/buildinfo"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

func (s *Server) about(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"product":    json.RawMessage(product.Metadata),
		"version":    buildinfo.Version,
		"commit":     buildinfo.Commit,
		"build_time": buildinfo.BuildTime,
	})
}

func (s *Server) license(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	http.ServeContent(w, r, "LICENSE", time.Time{}, strings.NewReader(product.LicenseText))
}
