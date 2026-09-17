package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"central-flow-collector/internal/audit"
	"central-flow-collector/internal/auth"
	"central-flow-collector/internal/notification"
	"central-flow-collector/internal/storage"
)

func (s *Server) notificationRoutes() {
	s.mux.HandleFunc("GET /api/v1/notifications/{resource}", s.withAuth("view", s.notificationRead))
	s.mux.HandleFunc("POST /api/v1/notifications/{resource}", s.withAuth("system.manage", s.notificationSave))
	s.mux.HandleFunc("DELETE /api/v1/notifications/{resource}/{id}", s.withAuth("system.manage", s.notificationDelete))
	s.mux.HandleFunc("POST /api/v1/notifications/channels/{id}/test", s.withAuth("system.manage", s.notificationTest))
	s.mux.HandleFunc("POST /api/v1/notifications/simulate", s.withAuth("system.manage", s.notificationSimulate))
	s.mux.HandleFunc("POST /api/v1/notifications/preview", s.withAuth("view", s.notificationPreview))
	s.mux.HandleFunc("POST /api/v1/notifications/history/{id}/retry", s.withAuth("system.manage", s.notificationRetry))
	s.mux.HandleFunc("POST /api/v1/notifications/alerts/{id}/ack", s.withAuth("system.manage", s.notificationAck))
	s.mux.HandleFunc("GET /api/v1/notifications/rules/{id}/revisions", s.withAuth("view", s.notificationRevisions))
}
func (s *Server) notificationReady(w http.ResponseWriter) bool {
	if s.Notifications == nil {
		writeErr(w, 503, "Notification subsystem unavailable; check protected state directory")
		return false
	}
	return true
}
func (s *Server) notificationRead(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.notificationReady(w) {
		return
	}
	resource := r.PathValue("resource")
	switch resource {
	case "channels":
		writeJSON(w, 200, s.Notifications.Channels())
	case "policies":
		writeJSON(w, 200, s.Notifications.Policies())
	case "rules":
		writeJSON(w, 200, s.Notifications.Rules())
	case "settings":
		writeJSON(w, 200, s.Notifications.Settings())
	case "health":
		writeJSON(w, 200, s.Notifications.Health())
	case "alerts", "events", "history", "silences":
		limit := 100
		offset := 0
		var err error
		if v := r.URL.Query().Get("limit"); v != "" {
			limit, err = strconv.Atoi(v)
		}
		if err != nil || limit < 1 || limit > 200 {
			writeErr(w, 400, "limit must be 1..200")
			return
		}
		if v := r.URL.Query().Get("offset"); v != "" {
			offset, err = strconv.Atoi(v)
		}
		if err != nil || offset < 0 || offset > 20000 {
			writeErr(w, 400, "offset must be 0..20000")
			return
		}
		writeJSON(w, 200, s.Notifications.Snapshot(resource, offset, limit))
	case "templates":
		writeJSON(w, 200, notification.RuleTemplates())
	default:
		writeErr(w, 404, "Notification resource not found")
	}
}
func (s *Server) notificationSave(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.notificationReady(w) {
		return
	}
	var result any
	var err error
	id := ""
	kind := r.PathValue("resource")
	switch kind {
	case "validate":
		var x notification.RuleDefinition
		if !notificationDecode(w, r, &x) {
			return
		}
		if e := x.Validate(); e != nil {
			writeErr(w, 400, e.Error())
			return
		}
		writeJSON(w, 200, map[string]string{"summary": x.Summary(), "cost": x.Cost()})
		return
	case "channels":
		var x notification.ChannelInput
		if !notificationDecode(w, r, &x) {
			return
		}
		v, e := s.Notifications.SaveChannel(x)
		result, err, id = v, e, v.ID
	case "policies":
		var x notification.NotificationPolicy
		if !notificationDecode(w, r, &x) {
			return
		}
		v, e := s.Notifications.SavePolicy(x)
		result, err, id = v, e, v.ID
	case "rules":
		var x notification.RuleDefinition
		if !notificationDecode(w, r, &x) {
			return
		}
		v, e := s.Notifications.SaveRule(x, ss.Username)
		result, err, id = v, e, v.ID
	case "silences":
		var x notification.Silence
		if !notificationDecode(w, r, &x) {
			return
		}
		v, e := s.Notifications.SaveSilence(x)
		result, err, id = v, e, v.ID
	case "settings":
		var x notification.PlatformSettings
		if !notificationDecode(w, r, &x) {
			return
		}
		err = s.Notifications.SaveSettings(x)
		result = x
	default:
		writeErr(w, 404, "Notification resource not found")
		return
	}
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.notificationAudit(r, ss, "notification_"+kind+"_saved", id, true)
	writeJSON(w, 200, result)
}

// Decoder errors are intentionally generic: malformed input may contain secrets.
func notificationDecode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		writeErr(w, 400, "Invalid notification request JSON")
		return false
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		writeErr(w, 400, "Unexpected trailing request data")
		return false
	}
	return true
}
func (s *Server) notificationDelete(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.notificationReady(w) {
		return
	}
	if e := s.Notifications.Delete(r.PathValue("resource"), r.PathValue("id")); e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	s.notificationAudit(r, ss, "notification_"+r.PathValue("resource")+"_deleted", r.PathValue("id"), true)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) notificationTest(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.notificationReady(w) {
		return
	}
	var req notification.ChannelTestRequest
	if !notificationDecode(w, r, &req) {
		return
	}
	out, e := s.Notifications.TestChannel(r.Context(), r.PathValue("id"), req)
	s.notificationAudit(r, ss, "notification_channel_test", r.PathValue("id"), e == nil && out.Success)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) notificationSimulate(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.notificationReady(w) {
		return
	}
	var req struct {
		Rule notification.RuleDefinition `json:"rule"`
		From time.Time                   `json:"from"`
		To   time.Time                   `json:"to"`
	}
	if !notificationDecode(w, r, &req) {
		return
	}
	out, e := s.Notifications.Simulate(r.Context(), req.Rule, req.From, req.To)
	if e != nil {
		writeErr(w, 422, e.Error())
		return
	}
	writeJSON(w, 200, out)
}
func (s *Server) notificationPreview(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.notificationReady(w) {
		return
	}
	var req struct {
		Rule  notification.RuleDefinition `json:"rule"`
		State string                      `json:"state"`
	}
	if !notificationDecode(w, r, &req) {
		return
	}
	if e := req.Rule.Validate(); e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	if req.State != "FIRING" && req.State != "RECOVERED" {
		writeErr(w, 400, "preview state must be FIRING or RECOVERED")
		return
	}
	if req.Rule.Kind == "seasonal" {
		writeErr(w, 422, "Seasonal bounds require historical data. Run a simulation, then preview its latest email and Telegram message.")
		return
	}
	now := time.Now().UTC()
	m, e := notification.RenderMessage(notification.MessageContext{NotificationID: "preview", RuleID: req.Rule.ID, RuleName: req.Rule.Name, Summary: req.Rule.Summary(), Entity: "Preview — no delivery", State: req.State, Priority: req.Rule.Priority, Threshold: req.Rule.Threshold, Metric: req.Rule.Metric, WindowSeconds: req.Rule.WindowSeconds, At: now, From: now.Add(-time.Duration(req.Rule.WindowSeconds) * time.Second)}, s.Notifications.Settings().PortalURL)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, m)
}
func (s *Server) notificationRetry(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.notificationReady(w) {
		return
	}
	if e := s.Notifications.Retry(r.PathValue("id")); e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	s.notificationAudit(r, ss, "notification_retry", r.PathValue("id"), true)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) notificationAck(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.notificationReady(w) {
		return
	}
	if e := s.Notifications.Acknowledge(r.PathValue("id")); e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	s.notificationAudit(r, ss, "notification_ack", r.PathValue("id"), true)
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) notificationRevisions(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.notificationReady(w) {
		return
	}
	writeJSON(w, 200, s.Notifications.Snapshot(r.PathValue("id"), 0, 20))
}
func (s *Server) notificationAudit(r *http.Request, ss auth.Session, action, id string, success bool) {
	if s.Audit != nil {
		s.Audit.Write(audit.Event{User: ss.Username, Action: action, Source: remoteIP(r), Object: id, Success: success})
	}
}

func (s *Server) EvaluateNotificationRule(ctx context.Context, r notification.RuleDefinition, at time.Time) ([]notification.Observation, error) {
	if r.Kind == "system" {
		var value float64
		switch r.Metric {
		case "storage_unhealthy":
			if !s.Store.Stats().Healthy {
				value = 1
			}
		case "queue_percent":
			for _, l := range s.Collector.ListenerStates() {
				if l.QueueCapacity > 0 {
					v := float64(l.QueueDepth) * 100 / float64(l.QueueCapacity)
					if v > value {
						value = v
					}
				}
			}
		case "disk_percent":
			cap, e := s.Store.Capacity(ctx)
			if e != nil {
				return nil, e
			}
			if cap.TotalBytes <= 0 {
				return nil, errors.New("storage capacity unavailable")
			}
			value = 100 * (1 - float64(cap.FreeBytes)/float64(cap.TotalBytes))
		default:
			return nil, errors.New("unsupported system metric")
		}
		return []notification.Observation{{Entity: "collector", Value: value}}, nil
	}
	b, ok := s.Store.(storage.AlertRuleBackend)
	if !ok {
		return nil, errors.New("storage does not support rule aggregation")
	}
	if r.Kind == "seasonal" {
		return notification.EvaluateSeasonal(ctx, r, at, b.EvaluateAlertRule)
	}
	return b.EvaluateAlertRule(ctx, r, at)
}
