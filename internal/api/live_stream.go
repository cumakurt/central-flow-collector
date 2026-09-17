package api

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"central-flow-collector/internal/auth"
	"central-flow-collector/internal/collector"
	"central-flow-collector/internal/model"
)

func matchesAddress(ip, filter string) bool {
	if filter == "" {
		return true
	}
	if strings.Contains(filter, "/") {
		_, network, err := net.ParseCIDR(filter)
		return err == nil && network.Contains(net.ParseIP(ip))
	}
	return ip == filter
}

func (s *Server) liveStream(w http.ResponseWriter, r *http.Request, _ auth.Session) {
	v := r.URL.Query()
	limit := 100
	if raw := v.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 200 {
			writeErr(w, 400, "limit must be 1..200")
			return
		}
		limit = n
	}
	for _, key := range []string{"src_ip", "dst_ip", "exporter"} {
		f := v.Get(key)
		if f == "" {
			continue
		}
		if strings.Contains(f, "/") {
			if _, _, err := net.ParseCIDR(f); err != nil {
				writeErr(w, 400, "invalid "+key)
				return
			}
		} else if net.ParseIP(f) == nil {
			writeErr(w, 400, "invalid "+key)
			return
		}
	}
	allFlows, allPackets := s.Collector.LiveSnapshot()
	flows := make([]model.Flow, 0, limit)
	packets := make([]collector.LivePacket, 0, limit)
	for _, f := range allFlows {
		if len(flows) >= limit {
			break
		}
		if !matchesAddress(f.SrcIP, v.Get("src_ip")) || !matchesAddress(f.DstIP, v.Get("dst_ip")) || !matchesAddress(f.Exporter, v.Get("exporter")) {
			continue
		}
		if p := v.Get("flow_protocol"); p != "" && !strings.EqualFold(f.Protocol, p) {
			continue
		}
		if p := v.Get("port"); p != "" && strconv.Itoa(int(f.DstPort)) != p {
			continue
		}
		if country := v.Get("country"); country != "" && !strings.EqualFold(f.SrcCountry, country) && !strings.EqualFold(f.DstCountry, country) {
			continue
		}
		flows = append(flows, f)
	}
	for _, p := range allPackets {
		if len(packets) >= limit {
			break
		}
		if !matchesAddress(p.Exporter, v.Get("exporter")) {
			continue
		}
		if proto := v.Get("flow_protocol"); proto != "" && !strings.EqualFold(p.Protocol, proto) {
			continue
		}
		packets = append(packets, p)
	}
	writeJSON(w, 200, map[string]any{"timeline": s.Collector.ProtocolTimeline(), "timeline_bucket_seconds": 5, "flows": flows, "packets": packets, "as_of": time.Now().UTC(), "flow_buffer": len(allFlows), "packet_buffer": len(allPackets)})
}
