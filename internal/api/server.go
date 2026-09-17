package api

import (
	"central-flow-collector/internal/adminops"
	"central-flow-collector/internal/analytics"
	"central-flow-collector/internal/audit"
	"central-flow-collector/internal/auth"
	"central-flow-collector/internal/buildinfo"
	"central-flow-collector/internal/cluster"
	"central-flow-collector/internal/collector"
	"central-flow-collector/internal/engineering"
	"central-flow-collector/internal/enrichment"
	"central-flow-collector/internal/ldapauth"
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/notification"
	"central-flow-collector/internal/oidc"
	"central-flow-collector/internal/policy"
	"central-flow-collector/internal/reporting"
	"central-flow-collector/internal/storage"
	"central-flow-collector/internal/workspace"
	"context"
	"embed"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/pprof"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

//go:embed static/*
var webFS embed.FS

type Server struct {
	Notifications         *notification.Platform
	EngineeringRoutes     *engineering.RouteProvider
	EngineeringRoutesPath string
	Auth                  *auth.Manager
	Policies              *policy.Engine
	Collector             *collector.Collector
	Store                 storage.Backend
	Analytics             *analytics.Engine
	Audit                 *audit.Log
	Enrichment            *enrichment.Engine
	Workspace             *workspace.Manager
	OIDC                  *oidc.Manager
	Cluster               *cluster.Registry
	LDAP                  *ldapauth.Manager
	Reports               *reporting.Manager
	AdminOps              *adminops.Manager
	Restart               func()
	NodeID                string
	NodeRegion            string
	RequireMFA            bool
	DiagnosticsEnabled    bool
	ClusterRequireMTLS    bool
	mux                   *http.ServeMux
	intelligenceState     intelligenceState
}
type userView struct {
	Username   string `json:"username"`
	Role       string `json:"role"`
	MustChange bool   `json:"must_change"`
	Disabled   bool   `json:"disabled"`
}

// v4 represents one organization per deployment. These helpers remain only as
// compatibility shims for code paths that read legacy records.

func New(a *auth.Manager, p *policy.Engine, c *collector.Collector, s storage.Backend, an *analytics.Engine, au *audit.Log, en *enrichment.Engine, ws *workspace.Manager) *Server {
	x := &Server{Auth: a, Policies: p, Collector: c, Store: s, Analytics: an, Audit: au, Enrichment: en, Workspace: ws, mux: http.NewServeMux()}
	x.routes()
	return x
}
func (s *Server) Handler() http.Handler           { return s.securityHeaders(s.mux) }
func (s *Server) SetOIDC(m *oidc.Manager)         { s.OIDC = m }
func (s *Server) SetCluster(r *cluster.Registry)  { s.Cluster = r }
func (s *Server) SetLDAP(m *ldapauth.Manager)     { s.LDAP = m }
func (s *Server) SetReports(m *reporting.Manager) { s.Reports = m }
func (s *Server) SetAdminOps(m *adminops.Manager) { s.AdminOps = m }
func (s *Server) SetRestart(fn func())            { s.Restart = fn }
func (s *Server) SetNodeInfo(id, region string)   { s.NodeID = id; s.NodeRegion = region }
func (s *Server) SetRequireMFA(v bool)            { s.RequireMFA = v }
func (s *Server) SetDiagnosticsEnabled(v bool)    { s.DiagnosticsEnabled = v }
func (s *Server) SetClusterRequireMTLS(v bool)    { s.ClusterRequireMTLS = v }
func (s *Server) routes() {
	s.notificationRoutes()
	s.engineeringRoutes()
	s.mux.HandleFunc("GET /api/v1/about", s.about)
	s.mux.HandleFunc("GET /LICENSE", s.license)
	s.mux.HandleFunc("POST /api/v1/auth/login", s.login)
	s.mux.HandleFunc("GET /api/v1/auth/oidc/status", s.oidcStatus)
	s.mux.HandleFunc("GET /api/v1/auth/oidc/start", s.oidcStart)
	s.mux.HandleFunc("GET /api/v1/auth/oidc/callback", s.oidcCallback)
	s.mux.HandleFunc("GET /api/v1/auth/me", s.withAuth("view", s.me))
	s.mux.HandleFunc("GET /api/v1/auth/permissions", s.withAuth("view", s.permissions))
	s.mux.HandleFunc("POST /api/v1/auth/logout", s.withAuth("view", s.logout))
	s.mux.HandleFunc("POST /api/v1/auth/change-password", s.withAuth("view", s.changePassword))
	s.mux.HandleFunc("GET /api/v1/auth/ldap/status", s.ldapStatus)
	s.mux.HandleFunc("POST /api/v1/auth/ldap/login", s.ldapLogin)
	s.mux.HandleFunc("GET /api/v1/auth/mfa/status", s.withAuth("view", s.mfaStatus))
	s.mux.HandleFunc("POST /api/v1/auth/mfa/totp/begin", s.withAuth("view", s.mfaTOTPBegin))
	s.mux.HandleFunc("POST /api/v1/auth/mfa/totp/confirm", s.withAuth("view", s.mfaTOTPConfirm))
	s.mux.HandleFunc("POST /api/v1/auth/mfa/totp/disable", s.withAuth("view", s.mfaTOTPDisable))
	s.mux.HandleFunc("POST /api/v1/auth/webauthn/register/options", s.withAuth("view", s.webauthnRegisterOptions))
	s.mux.HandleFunc("POST /api/v1/auth/webauthn/register/finish", s.withAuth("view", s.webauthnRegisterFinish))
	s.mux.HandleFunc("POST /api/v1/auth/webauthn/assert/options", s.webauthnAssertOptions)
	s.mux.HandleFunc("POST /api/v1/auth/webauthn/assert/finish", s.webauthnAssertFinish)
	s.mux.HandleFunc("GET /api/v1/dashboard", s.withAuth("flows.read", s.dashboard))
	s.mux.HandleFunc("GET /api/v1/analytics", s.withAuth("analytics.read", s.flowAnalytics))
	s.mux.HandleFunc("GET /api/v1/analytics/service-catalog", s.withAuth("analytics.read", s.serviceCatalog))
	s.mux.HandleFunc("GET /api/v1/analytics/service-series", s.withAuth("analytics.read", s.serviceSeries))
	s.mux.HandleFunc("GET /api/v1/analytics/query", s.withAuth("analytics.read", s.intelligenceQuery))
	s.mux.HandleFunc("GET /api/v1/analytics/baseline", s.withAuth("analytics.read", s.baselineStatus))
	s.mux.HandleFunc("GET /api/v1/ip/{ip}", s.withAuth("analytics.read", s.investigateHost))
	s.mux.HandleFunc("GET /api/v1/analytics/compare", s.withAuth("analytics.read", s.periodComparison))
	s.mux.HandleFunc("GET /api/v1/analytics/matrix", s.withAuth("analytics.read", s.trafficMatrixV4))
	s.mux.HandleFunc("GET /api/v1/storage/capacity", s.withAuth("storage.read", s.capacityV4))
	s.mux.HandleFunc("GET /api/v1/flows/page", s.withAuth("flows.read", s.flowsPage))
	s.mux.HandleFunc("POST /api/v1/reports/export", s.withAuth("reports.read", s.reportExportV4))
	s.mux.HandleFunc("GET /api/v1/topology", s.withAuth("topology.read", s.topology))
	s.mux.HandleFunc("GET /api/v1/cluster", s.withAuth("cluster.read", s.clusterStatus))
	s.mux.HandleFunc("GET /api/v1/cluster/assignment", s.withAuth("cluster.read", s.clusterAssignment))
	s.mux.HandleFunc("POST /api/v1/cluster/heartbeat", s.clusterHeartbeat)
	s.mux.HandleFunc("POST /api/v1/cluster/dedup", s.clusterDedup)
	s.mux.HandleFunc("GET /api/v1/cluster/commands", s.withAuth("cluster.manage", s.clusterCommands))
	s.mux.HandleFunc("POST /api/v1/cluster/commands", s.withAuth("cluster.manage", s.clusterCommandQueue))
	s.mux.HandleFunc("GET /api/v1/flows", s.withAuth("flows.read", s.flows))
	s.mux.HandleFunc("GET /api/v1/flows/export", s.withAuth("flows.export", s.flowExport))
	s.mux.HandleFunc("GET /api/v1/searches", s.withAuth("view", s.savedSearches))
	s.mux.HandleFunc("POST /api/v1/searches", s.withAuth("view", s.savedSearchUpsert))
	s.mux.HandleFunc("DELETE /api/v1/searches/{id}", s.withAuth("view", s.savedSearchDelete))
	s.mux.HandleFunc("GET /api/v1/search-history", s.withAuth("view", s.searchHistory))
	s.mux.HandleFunc("GET /api/v1/assets", s.withAuth("view", s.assets))
	s.mux.HandleFunc("GET /api/v1/conversations", s.withAuth("view", s.conversations))
	s.mux.HandleFunc("GET /api/v1/exporters", s.withAuth("collectors.read", s.exporters))
	s.mux.HandleFunc("GET /api/v1/exporters/health", s.withAuth("collectors.read", s.exporterHealth))
	s.mux.HandleFunc("GET /api/v1/exporters/templates", s.withAuth("collectors.read", s.exporterTemplates))
	s.mux.HandleFunc("GET /api/v1/onboarding/vendors", s.withAuth("view", s.onboardingVendors))
	s.mux.HandleFunc("POST /api/v1/onboarding/render", s.withAuth("view", s.onboardingRender))
	s.mux.HandleFunc("GET /api/v1/onboarding/check", s.withAuth("view", s.onboardingCheck))
	s.mux.HandleFunc("GET /api/v1/live/events", s.withAuth("view", s.liveEvents))
	s.mux.HandleFunc("GET /api/v1/live/stream", s.withAuth("flows.read", s.liveStream))
	s.mux.HandleFunc("GET /api/v1/rejections", s.withAuth("view", s.rejections))
	s.mux.HandleFunc("GET /api/v1/policies", s.withAuth("view", s.policies))
	s.mux.HandleFunc("GET /api/v1/policies/traffic", s.withAuth("view", s.policyTraffic))
	s.mux.HandleFunc("POST /api/v1/policies", s.withAuth("policies.manage", s.policyUpsert))
	s.mux.HandleFunc("DELETE /api/v1/policies/{id}", s.withAuth("policies.manage", s.policyDelete))
	s.mux.HandleFunc("POST /api/v1/policies/simulate", s.withAuth("view", s.policySimulate))
	s.mux.HandleFunc("GET /api/v1/listeners", s.withAuth("collectors.read", s.listeners))
	s.mux.HandleFunc("GET /api/v1/alerts", s.withAuth("analytics.read", s.alerts))
	s.mux.HandleFunc("POST /api/v1/alerts/{id}/ack", s.withAuth("analytics.manage", s.alertAck))
	s.mux.HandleFunc("GET /api/v1/alert-rules", s.withAuth("analytics.read", s.alertRules))
	s.mux.HandleFunc("POST /api/v1/alert-rules", s.withAuth("system.manage", s.alertRuleUpsert))
	s.mux.HandleFunc("DELETE /api/v1/alert-rules/{type}", s.withAuth("system.manage", s.alertRuleDelete))
	s.mux.HandleFunc("GET /api/v1/enrichment/status", s.withAuth("view", s.enrichmentStatus))
	s.mux.HandleFunc("GET /api/v1/geoip", s.withAuth("view", s.geoIPLookup))
	s.mux.HandleFunc("POST /api/v1/enrichment/reload", s.withAuth("enrichment.manage", s.enrichmentReload))
	s.mux.HandleFunc("GET /api/v1/sites", s.withAuth("view", s.sites))
	s.mux.HandleFunc("POST /api/v1/sites", s.withAuth("enrichment.manage", s.siteUpsert))
	s.mux.HandleFunc("DELETE /api/v1/sites/{id}", s.withAuth("enrichment.manage", s.siteDelete))
	s.mux.HandleFunc("GET /api/v1/users", s.withAuth("users.manage", s.users))
	s.mux.HandleFunc("GET /api/v1/api-tokens", s.withAuth("tokens.manage", s.apiTokens))
	s.mux.HandleFunc("POST /api/v1/api-tokens", s.withAuth("tokens.manage", s.apiTokenCreate))
	s.mux.HandleFunc("DELETE /api/v1/api-tokens/{id}", s.withAuth("tokens.manage", s.apiTokenDelete))
	s.mux.HandleFunc("GET /api/v1/storage", s.withAuth("view", s.storageInfo))
	s.mux.HandleFunc("POST /api/v1/storage/retention", s.withAuth("storage.manage", s.storageRetention))
	s.mux.HandleFunc("POST /api/v1/storage/purge", s.withAuth("storage.manage", s.storagePurge))
	s.mux.HandleFunc("POST /api/v1/users", s.withAuth("users.manage", s.userAdd))
	s.mux.HandleFunc("POST /api/v1/users/{username}/password", s.withAuth("users.manage", s.userPasswordReset))
	s.mux.HandleFunc("GET /api/v1/audit", s.withAuth("audit.read", s.auditLog))
	s.mux.HandleFunc("GET /api/v1/audit/verify", s.withAuth("audit.read", s.auditVerify))
	s.mux.HandleFunc("GET /api/v1/reports", s.withAuth("reports.read", s.reportJobs))
	s.mux.HandleFunc("POST /api/v1/reports", s.withAuth("reports.manage", s.reportUpsert))
	s.mux.HandleFunc("POST /api/v1/reports/{id}/run", s.withAuth("reports.manage", s.reportRun))
	s.mux.HandleFunc("DELETE /api/v1/reports/{id}", s.withAuth("reports.manage", s.reportDelete))
	s.mux.HandleFunc("GET /api/v1/cluster/rollouts", s.withAuth("cluster.manage", s.clusterRollouts))
	s.mux.HandleFunc("POST /api/v1/cluster/rollouts", s.withAuth("cluster.manage", s.clusterRolloutStart))
	s.mux.HandleFunc("POST /api/v1/cluster/rollouts/{id}/advance", s.withAuth("cluster.manage", s.clusterRolloutAdvance))
	s.mux.HandleFunc("GET /api/v1/admin/overview", s.withAuth("settings", s.adminOverview))
	s.mux.HandleFunc("GET /api/v1/admin/settings", s.withAuth("settings", s.adminSettings))
	s.mux.HandleFunc("POST /api/v1/admin/settings/validate", s.withAuth("settings", s.adminSettingsValidate))
	s.mux.HandleFunc("POST /api/v1/admin/settings/apply", s.withAuth("settings", s.adminSettingsApply))
	s.mux.HandleFunc("GET /api/v1/admin/config/versions", s.withAuth("settings", s.adminConfigVersions))
	s.mux.HandleFunc("POST /api/v1/admin/config/rollback", s.withAuth("settings", s.adminConfigRollback))
	s.mux.HandleFunc("POST /api/v1/admin/restart", s.withAuth("settings", s.adminRestart))
	s.mux.HandleFunc("POST /api/v1/admin/database/test", s.withAuth("settings", s.adminDatabaseTest))
	s.mux.HandleFunc("GET /api/v1/admin/database/health", s.withAuth("settings", s.adminDatabaseHealth))
	s.mux.HandleFunc("POST /api/v1/admin/ingestion/{action}", s.withAuth("settings", s.adminIngestion))
	s.mux.HandleFunc("POST /api/v1/admin/maintenance/{action}", s.withAuth("settings", s.adminMaintenance))
	s.mux.HandleFunc("GET /api/v1/admin/backups", s.withAuth("settings", s.adminBackups))
	s.mux.HandleFunc("POST /api/v1/admin/backups/create", s.withAuth("settings", s.adminBackupCreate))
	s.mux.HandleFunc("POST /api/v1/admin/backups/verify", s.withAuth("settings", s.adminBackupVerify))
	s.mux.HandleFunc("POST /api/v1/admin/backups/restore", s.withAuth("settings", s.adminBackupRestore))
	s.mux.HandleFunc("POST /api/v1/admin/notifications/test", s.withAuth("settings", s.adminNotificationTest))
	s.mux.HandleFunc("GET /api/v1/admin/upgrade/preflight", s.withAuth("settings", s.adminUpgradePreflight))
	s.mux.HandleFunc("GET /api/v1/health", s.withAuth("view", s.health))
	s.mux.HandleFunc("GET /debug/pprof/", s.withDiagnosticsAuth(s.pprofIndex))
	s.mux.HandleFunc("GET /debug/pprof/{profile}", s.withDiagnosticsAuth(s.pprofIndex))
	s.mux.HandleFunc("GET /debug/pprof/profile", s.withDiagnosticsAuth(s.pprofProfile))
	s.mux.HandleFunc("GET /debug/pprof/trace", s.withDiagnosticsAuth(s.pprofTrace))
	s.mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"status": "ok"}) })
	s.mux.HandleFunc("GET /ready", s.ready)
	s.mux.HandleFunc("GET /metrics", s.metrics)
	sub, _ := fs.Sub(webFS, "static")
	fh := http.FileServer(http.FS(sub))
	s.mux.Handle("GET /", spaHandler(fh))
}
func (s *Server) oidcStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"enabled": s.OIDC != nil})
}
func (s *Server) oidcStart(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		writeErr(w, 404, "OIDC is not configured")
		return
	}
	u, err := s.OIDC.Start()
	if err != nil {
		writeErr(w, 500, "unable to start OIDC login")
		return
	}
	http.Redirect(w, r, u, http.StatusFound)
}
func (s *Server) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if s.OIDC == nil {
		writeErr(w, 404, "OIDC is not configured")
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		writeErr(w, 401, "OIDC provider rejected login")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	id, err := s.OIDC.Callback(ctx, r.URL.Query().Get("state"), r.URL.Query().Get("code"))
	if err != nil {
		s.Audit.Write(audit.Event{User: "oidc", Action: "oidc_login_failure", Source: remoteIP(r), Success: false, Detail: err.Error()})
		writeErr(w, 401, "OIDC login validation failed")
		return
	}
	sess, err := s.Auth.CreateExternalSessionScoped(id.Username, id.Role, "", "oidc")
	if err != nil {
		writeErr(w, 403, "OIDC identity is not permitted")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "fc_session", Value: sess.ID, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode, Expires: sess.Expires})
	s.Audit.Write(audit.Event{User: id.Username, Action: "oidc_login", Source: remoteIP(r), Success: true, Detail: id.Subject})
	http.Redirect(w, r, "/", http.StatusFound)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Username, Password string
		MFACode            string `json:"mfa_code"`
	}
	if !decode(w, r, &in) {
		return
	}
	remote := remoteIP(r)
	sess, e := s.Auth.LoginWithMFA(in.Username, in.Password, in.MFACode, remote)
	if e != nil {
		s.Audit.Write(audit.Event{User: in.Username, Action: "login_failure", Source: remote, Success: false, Detail: e.Error()})
		if e == auth.ErrMFARequired {
			writeJSON(w, 401, map[string]any{"error": "mfa required", "mfa_required": true})
			return
		}
		writeErr(w, 401, "invalid credentials, MFA code, or temporarily throttled")
		return
	}
	u, _ := s.Auth.User(in.Username)
	http.SetCookie(w, &http.Cookie{Name: "fc_session", Value: sess.ID, Path: "/", HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, Expires: sess.Expires})
	s.Audit.Write(audit.Event{User: u.Username, Action: "login", Source: remote, Success: true})
	writeJSON(w, 200, map[string]any{"csrf": sess.CSRF, "user": view(u)})
}
func (s *Server) me(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	u, _ := s.Auth.User(ss.Username)
	writeJSON(w, 200, map[string]any{"csrf": ss.CSRF, "user": view(u), "version": buildinfo.Version})
}
func (s *Server) permissions(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	writeJSON(w, 200, map[string]any{"role": ss.Role, "permissions": auth.Permissions(ss.Role), "token_scopes": ss.Scopes})
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	s.Auth.Logout(ss.ID)
	http.SetCookie(w, &http.Cookie{Name: "fc_session", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	s.Audit.Write(audit.Event{User: ss.Username, Action: "logout", Source: remoteIP(r), Success: true})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	var in struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if !decode(w, r, &in) {
		return
	}
	e := s.Auth.ChangePassword(ss.Username, in.OldPassword, in.NewPassword)
	s.Audit.Write(audit.Event{User: ss.Username, Action: "password_change", Source: remoteIP(r), Success: e == nil})
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	exp := s.Collector.Exporters()
	active := 0
	cut := time.Now().Add(-5 * time.Minute)
	for _, e := range exp {
		if e.Allowed && e.LastSeen.After(cut) {
			active++
		}
	}
	payload := map[string]any{
		"storage":          s.Store.Stats(),
		"active_exporters": active,
		"analytics":        s.Analytics.Snapshot(),
		"rejected_sources": len(s.Collector.Rejections()),
	}
	if s.Notifications != nil {
		payload["notifications"] = s.Notifications.Health()
	}
	if s.Enrichment != nil {
		payload["enrichment"] = s.Enrichment.Status()
	}
	writeJSON(w, 200, payload)
}
func (s *Server) flows(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	q, e := storage.ParseQuery(r.URL.Query())
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	q.Tenant = ""
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	rows, e := s.Store.Query(ctx, q)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	if s.Workspace != nil {
		s.Workspace.RecordHistory(ss.Username, queryMap(r), len(rows))
	}
	writeJSON(w, 200, rows)
}
func queryMap(r *http.Request) map[string]string {
	out := map[string]string{}
	for k, vv := range r.URL.Query() {
		if len(vv) > 0 && strings.TrimSpace(vv[0]) != "" {
			out[k] = vv[0]
		}
	}
	return out
}
func (s *Server) savedSearches(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.Workspace == nil {
		writeJSON(w, 200, []workspace.SavedSearch{})
		return
	}
	writeJSON(w, 200, s.Workspace.Saved(ss.Username))
}
func (s *Server) savedSearchUpsert(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.Workspace == nil {
		writeErr(w, 500, "workspace unavailable")
		return
	}
	var x workspace.SavedSearch
	if !decode(w, r, &x) {
		return
	}
	y, e := s.Workspace.UpsertSaved(ss.Username, x)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "saved_search_upsert", Source: remoteIP(r), Object: y.ID, Success: true, Detail: y.Name})
	writeJSON(w, 200, y)
}
func (s *Server) savedSearchDelete(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.Workspace == nil {
		writeErr(w, 500, "workspace unavailable")
		return
	}
	id := r.PathValue("id")
	if e := s.Workspace.DeleteSaved(ss.Username, id); e != nil {
		writeErr(w, 404, e.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "saved_search_delete", Source: remoteIP(r), Object: id, Success: true})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) searchHistory(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.Workspace == nil {
		writeJSON(w, 200, []workspace.SearchHistory{})
		return
	}
	writeJSON(w, 200, s.Workspace.History(ss.Username, 50))
}
func (s *Server) flowExport(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	q, e := storage.ParseExportQuery(r.URL.Query())
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	q.Tenant = ""
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	rows, e := s.Store.Query(ctx, q)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	format := strings.ToLower(r.URL.Query().Get("format"))
	if format == "json" {
		w.Header().Set("Content-Disposition", "attachment; filename=flows.json")
		writeJSON(w, 200, rows)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=flows.csv")
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"receive_time", "collector_node", "exporter", "listener", "flow_protocol", "src_ip", "src_port", "dst_ip", "dst_port", "ip_protocol", "packets", "bytes", "src_as", "dst_as", "src_country", "dst_country", "src_site", "dst_site", "vlan", "tcp_flags"})
	for _, f := range rows {
		_ = cw.Write([]string{f.ReceiveTime.UTC().Format(time.RFC3339Nano), f.CollectorNode, f.Exporter, f.Listener, f.Protocol, f.SrcIP, strconv.Itoa(int(f.SrcPort)), f.DstIP, strconv.Itoa(int(f.DstPort)), strconv.Itoa(int(f.IPProtocol)), strconv.FormatUint(f.Packets, 10), strconv.FormatUint(f.Bytes, 10), strconv.FormatUint(uint64(f.SrcAS), 10), strconv.FormatUint(uint64(f.DstAS), 10), f.SrcCountry, f.DstCountry, f.SrcSite, f.DstSite, strconv.Itoa(int(f.VLAN)), fmt.Sprintf("0x%02x", f.TCPFlags)})
	}
	cw.Flush()
}

func (s *Server) assets(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	q, e := storage.ParseAggregateQuery(r.URL.Query())
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	q.Tenant = ""
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	rows, e := s.Store.Assets(ctx, q)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, rows)
}
func (s *Server) conversations(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	q, e := storage.ParseAggregateQuery(r.URL.Query())
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	q.Tenant = ""
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	rows, e := s.Store.Conversations(ctx, q)
	if e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, rows)
}
func (s *Server) investigateHost(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	filters, filterErr := queryWithoutTenant(r)
	if filterErr != nil {
		writeErr(w, 400, filterErr.Error())
		return
	}
	from, to := time.Time{}, time.Time{}
	var err error
	if v := r.URL.Query().Get("from"); v != "" {
		from, err = time.Parse(time.RFC3339, v)
		if err != nil {
			writeErr(w, 400, "invalid from")
			return
		}
	}
	if v := r.URL.Query().Get("to"); v != "" {
		to, err = time.Parse(time.RFC3339, v)
		if err != nil {
			writeErr(w, 400, "invalid to")
			return
		}
	}
	limit := 20
	if v := r.URL.Query().Get("limit"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 1 || n > 100 {
			writeErr(w, 400, "invalid limit")
			return
		}
		limit = n
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	out, err := s.Store.InvestigateHost(ctx, storage.HostQuery{IP: r.PathValue("ip"), From: from, To: to, Limit: limit, Filters: filters})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, out)
}

func (s *Server) alertRules(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	writeJSON(w, 200, s.Analytics.Rules())
}
func (s *Server) alertRuleUpsert(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	var x analytics.Rule
	if !decode(w, r, &x) {
		return
	}
	if err := s.Analytics.UpsertRule(x); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "alert_rule_upsert", Source: remoteIP(r), Object: x.Type, Success: true, Detail: fmt.Sprintf("enabled=%v threshold=%g severity=%s", x.Enabled, x.Threshold, x.Severity)})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) alertRuleDelete(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	t := r.PathValue("type")
	if err := s.Analytics.DeleteRule(t); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "alert_rule_disable", Source: remoteIP(r), Object: t, Success: true})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) enrichmentStatus(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.Enrichment == nil {
		writeJSON(w, 200, map[string]any{"enabled": false})
		return
	}
	writeJSON(w, 200, s.Enrichment.Status())
}
func (s *Server) enrichmentReload(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.Enrichment == nil {
		writeErr(w, 400, "enrichment unavailable")
		return
	}
	if err := s.Enrichment.Reload(); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "enrichment_reload", Source: remoteIP(r), Success: true})
	writeJSON(w, 200, s.Enrichment.Status())
}
func (s *Server) sites(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.Enrichment == nil {
		writeJSON(w, 200, []enrichment.Site{})
		return
	}
	writeJSON(w, 200, s.Enrichment.Sites())
}
func (s *Server) siteUpsert(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.Enrichment == nil {
		writeErr(w, 400, "enrichment unavailable")
		return
	}
	var x enrichment.Site
	if !decode(w, r, &x) {
		return
	}
	if err := s.Enrichment.UpsertSite(x); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "site_upsert", Source: remoteIP(r), Object: x.ID, Success: true, Detail: x.CIDR})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) siteDelete(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.Enrichment == nil {
		writeErr(w, 400, "enrichment unavailable")
		return
	}
	id := r.PathValue("id")
	if err := s.Enrichment.DeleteSite(id); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "site_delete", Source: remoteIP(r), Object: id, Success: true})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) exporters(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	writeJSON(w, 200, s.Collector.Exporters())
}
func (s *Server) exporterHealth(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	writeJSON(w, 200, s.Collector.ExporterHealth())
}
func (s *Server) exporterTemplates(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	writeJSON(w, 200, s.Collector.Templates())
}

type onboardingVendor struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Protocol    string `json:"protocol"`
	DefaultPort int    `json:"default_port"`
	Notes       string `json:"notes"`
}

func vendors() []onboardingVendor {
	return []onboardingVendor{
		{ID: "cisco-iosxe-netflow9", Name: "Cisco IOS XE · NetFlow v9", Protocol: "netflow", DefaultPort: 2055, Notes: "Standards-compatible NetFlow v9 template/data export."},
		{ID: "cisco-iosxe-ipfix", Name: "Cisco IOS XE · IPFIX", Protocol: "ipfix", DefaultPort: 4739, Notes: "Standards-compatible IPFIX export."},
		{ID: "juniper-jflow", Name: "Juniper · J-Flow (NetFlow v9)", Protocol: "netflow", DefaultPort: 2055, Notes: "Use standards-compatible v9 export."},
		{ID: "mikrotik-traffic-flow", Name: "MikroTik · Traffic Flow", Protocol: "netflow", DefaultPort: 2055, Notes: "NetFlow v9 mode recommended."},
		{ID: "cisco-asa-nsel", Name: "Cisco Secure Firewall / ASA · NSEL", Protocol: "netflow", DefaultPort: 2055, Notes: "NetFlow v9 security events, standard NAT and byte fields; private event fields retained."},
		{ID: "juniper-ipfix", Name: "Juniper · Inline J-Flow / IPFIX", Protocol: "ipfix", DefaultPort: 4739, Notes: "IPv4/IPv6 flow templates and scoped options over UDP."},
		{ID: "huawei-netstream", Name: "Huawei · NetStream v9", Protocol: "netflow", DefaultPort: 2055, Notes: "Select version 9, not legacy version 8 aggregation."},
		{ID: "h3c-netstream", Name: "H3C · NetStream / IPFIX", Protocol: "ipfix", DefaultPort: 4739, Notes: "Select NetStream version 10 (IPFIX); version 9 uses the NetFlow listener."},
		{ID: "fortinet-netflow", Name: "Fortinet FortiGate · NetFlow", Protocol: "netflow", DefaultPort: 2055, Notes: "NetFlow v9 IPv4/IPv6/NAT and application/sampler options; post counters retained as metadata."},
		{ID: "paloalto-netflow", Name: "Palo Alto Networks · NetFlow", Protocol: "netflow", DefaultPort: 2055, Notes: "PAN-OS standard/enterprise IPv4/IPv6/NAT templates, App-ID and User-ID."},
		{ID: "checkpoint-ipfix", Name: "Check Point Gaia · IPFIX", Protocol: "ipfix", DefaultPort: 4739, Notes: "Select IPFIX export format; v5/v9 also work on the NetFlow listener."},
		{ID: "sonicwall-ipfix", Name: "SonicWall · IPFIX", Protocol: "ipfix", DefaultPort: 4739, Notes: "External flow reporting in standard IPFIX mode; private extension fields are retained."},
		{ID: "arista-sflow", Name: "Arista EOS · sFlow", Protocol: "sflow", DefaultPort: 6343, Notes: "sFlow v5 packet sampling; select sampled packet headers."},
		{ID: "aruba-sflow", Name: "Aruba / HPE · sFlow", Protocol: "sflow", DefaultPort: 6343, Notes: "AOS-CX/AOS-S sFlow v5 packet sampling on supported switches."},
		{ID: "dell-sflow", Name: "Dell PowerSwitch · sFlow", Protocol: "sflow", DefaultPort: 6343, Notes: "OS10 sFlow v5 packet sampling."},
		{ID: "extreme-sflow", Name: "Extreme Networks · sFlow", Protocol: "sflow", DefaultPort: 6343, Notes: "ExtremeXOS / Switch Engine / SLX sFlow v5 packet sampling."},
		{ID: "nvidia-sflow", Name: "NVIDIA / Mellanox · sFlow", Protocol: "sflow", DefaultPort: 6343, Notes: "Cumulus Linux / Onyx sFlow packet sampling."},
		{ID: "ruijie-sflow", Name: "Ruijie · sFlow", Protocol: "sflow", DefaultPort: 6343, Notes: "sFlow v5 packet sampling on supported switches."},
		{ID: "nokia-cflowd", Name: "Nokia SR OS / SAR · cflowd", Protocol: "ipfix", DefaultPort: 4739, Notes: "Select cflowd version 10; version 9 uses the NetFlow listener."},
		{ID: "vmware-ipfix", Name: "VMware / Broadcom · IPFIX", Protocol: "ipfix", DefaultPort: 4739, Notes: "vSphere Distributed Switch / NSX IPFIX traffic export over UDP."},
		{ID: "netscaler-appflow", Name: "NetScaler / Citrix · AppFlow", Protocol: "ipfix", DefaultPort: 4739, Notes: "Select IPFIX transport; application transaction extensions are retained as raw metadata."},
		{ID: "f5-sflow", Name: "F5 BIG-IP · sFlow", Protocol: "sflow", DefaultPort: 6343, Notes: "sFlow packet records; HTTP-only and counter-only samples are not traffic flows."},
		{ID: "f5-ipfix", Name: "F5 BIG-IP · IPFIX", Protocol: "ipfix", DefaultPort: 4739, Notes: "Standard IPFIX traffic and CGNAT event fields over UDP; private IEs retained."},
		{ID: "ubiquiti-ipfix", Name: "Ubiquiti UniFi · IPFIX", Protocol: "ipfix", DefaultPort: 4739, Notes: "Enable NetFlow (IPFIX) traffic logging on supported gateways."},
		{ID: "generic-ipfix", Name: "Generic IPFIX exporter", Protocol: "ipfix", DefaultPort: 4739, Notes: "RFC-compatible IPFIX over UDP."},
		{ID: "generic-sflow", Name: "Generic sFlow v5 agent", Protocol: "sflow", DefaultPort: 6343, Notes: "sFlow v5 datagrams."},
	}
}
func (s *Server) onboardingVendors(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	writeJSON(w, 200, vendors())
}
func (s *Server) onboardingRender(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	var in struct {
		Vendor      string `json:"vendor"`
		CollectorIP string `json:"collector_ip"`
		SourceIP    string `json:"source_ip"`
		Port        int    `json:"port"`
	}
	if !decode(w, r, &in) {
		return
	}
	var v *onboardingVendor
	for _, x := range vendors() {
		if x.ID == in.Vendor {
			xx := x
			v = &xx
			break
		}
	}
	if v == nil {
		writeErr(w, 400, "unsupported onboarding vendor")
		return
	}
	if net.ParseIP(in.CollectorIP) == nil {
		writeErr(w, 400, "collector_ip must be an IP address")
		return
	}
	if in.Port == 0 {
		in.Port = v.DefaultPort
	}
	if in.Port < 1 || in.Port > 65535 {
		writeErr(w, 400, "invalid destination port")
		return
	}
	var snippet string
	switch v.ID {
	case "cisco-iosxe-netflow9":
		snippet = fmt.Sprintf("flow exporter FLOWCOLLECTOR\n destination %s\n transport udp %d\n export-protocol netflow-v9\n!\n! Attach FLOWCOLLECTOR to your existing flow monitor exporter list.", in.CollectorIP, in.Port)
	case "cisco-iosxe-ipfix":
		snippet = fmt.Sprintf("flow exporter FLOWCOLLECTOR\n destination %s\n transport udp %d\n export-protocol ipfix\n!\n! Attach FLOWCOLLECTOR to your Flexible NetFlow monitor.", in.CollectorIP, in.Port)
	case "juniper-jflow":
		snippet = fmt.Sprintf("set forwarding-options sampling family inet output flow-server %s port %d\nset forwarding-options sampling family inet output flow-server %s version9 template refresh-rate packets 20", in.CollectorIP, in.Port, in.CollectorIP)
	case "mikrotik-traffic-flow":
		snippet = fmt.Sprintf("/ip traffic-flow set enabled=yes\n/ip traffic-flow target add dst-address=%s port=%d version=9", in.CollectorIP, in.Port)
	case "generic-sflow":
		snippet = fmt.Sprintf("Configure the agent collector/receiver address as %s and UDP port %d; export sFlow v5 datagrams.", in.CollectorIP, in.Port)
	default:
		switch v.Protocol {
		case "sflow":
			snippet = fmt.Sprintf("Configure %s to send sFlow v5 packet samples to %s UDP/%d. Enable packet sampling on the monitored interfaces and configure an agent/source address. %s", v.Name, in.CollectorIP, in.Port, v.Notes)
		case "netflow":
			snippet = fmt.Sprintf("Configure %s to export NetFlow v9 to %s UDP/%d. Enable template and options-template refresh, and attach export to the monitored interfaces or flow monitor. %s", v.Name, in.CollectorIP, in.Port, v.Notes)
		default:
			snippet = fmt.Sprintf("Configure %s to export IPFIX to %s UDP/%d. Enable template and options-template refresh. %s", v.Name, in.CollectorIP, in.Port, v.Notes)
		}
	}
	policyHint := "Exporter source IP is not supplied. Add a DEFAULT-DENY allow policy before sending production telemetry."
	if net.ParseIP(in.SourceIP) != nil {
		policyHint = fmt.Sprintf("Create an ALLOW rule for source %s, protocol %s, destination port %d before testing.", in.SourceIP, v.Protocol, in.Port)
	}
	writeJSON(w, 200, map[string]any{"vendor": v, "snippet": snippet, "policy_hint": policyHint})
}
func (s *Server) onboardingCheck(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	source := r.URL.Query().Get("source")
	proto := strings.ToLower(r.URL.Query().Get("protocol"))
	listener := r.URL.Query().Get("listener")
	port, _ := strconv.Atoi(r.URL.Query().Get("port"))
	if net.ParseIP(source) == nil {
		writeErr(w, 400, "valid source is required")
		return
	}
	if port == 0 {
		switch proto {
		case "ipfix":
			port = 4739
		case "sflow":
			port = 6343
		default:
			port = 2055
		}
	}
	d := s.Policies.Decide(source, proto, listener, port)
	var found any
	for _, e := range s.Collector.Exporters() {
		if e.Address == source && (proto == "" || strings.EqualFold(e.Protocol, proto)) {
			found = e
			break
		}
	}
	next := "Exporter is observed. Review exporter health for templates, decode errors and sequence gaps."
	if !d.Allowed {
		next = "Add/adjust an ALLOW policy first."
	} else if found == nil {
		next = "Policy allows this source, but no telemetry has been observed yet."
	}
	writeJSON(w, 200, map[string]any{"source": source, "policy": d, "exporter": found, "observed": found != nil, "next_step": next})
}
func topFromMap(m map[string]uint64, limit int) []analytics.Top {
	out := make([]analytics.Top, 0, len(m))
	for k, v := range m {
		out = append(out, analytics.Top{Key: k, Value: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value == out[j].Value {
			return out[i].Key < out[j].Key
		}
		return out[i].Value > out[j].Value
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *Server) liveEvents(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	fl, ok := w.(http.Flusher)
	if !ok {
		writeErr(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	t := time.NewTicker(time.Second)
	defer t.Stop()
	send := func() bool {
		states := map[string]int{}
		for _, h := range s.Collector.ExporterHealth() {
			states[h.State]++
		}
		payload := map[string]any{"timestamp": time.Now().UTC(), "analytics": s.Analytics.Snapshot(), "storage": s.Store.Stats(), "exporter_states": states, "listeners": s.Collector.ListenerStates()}
		b, err := json.Marshal(payload)
		if err != nil {
			return false
		}
		if _, err = fmt.Fprintf(w, "event: snapshot\\ndata: %s\\n\\n", b); err != nil {
			return false
		}
		fl.Flush()
		return true
	}
	if !send() {
		return
	}
	for {
		select {
		case <-t.C:
			if !send() {
				return
			}
		case <-r.Context().Done():
			return
		}
	}
}
func (s *Server) rejections(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if ss.Role != "administrator" {
		writeJSON(w, 200, []model.RejectionStat{})
		return
	}
	writeJSON(w, 200, s.Collector.Rejections())
}
func (s *Server) policies(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	writeJSON(w, 200, s.Policies.Rules())
}
func (s *Server) policyTraffic(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	writeJSON(w, 200, s.Collector.PolicyTraffic())
}
func (s *Server) geoIPLookup(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.Enrichment == nil {
		writeErr(w, 503, "GeoIP unavailable")
		return
	}
	parts := strings.Split(r.URL.Query().Get("ips"), ",")
	if len(parts) > 50 {
		writeErr(w, 400, "at most 50 IPs are allowed")
		return
	}
	out := map[string]enrichment.GeoInfo{}
	for _, raw := range parts {
		ip := strings.TrimSpace(raw)
		if ip == "" {
			continue
		}
		if net.ParseIP(ip) == nil {
			writeErr(w, 400, "invalid IP address")
			return
		}
		out[ip] = s.Enrichment.LookupIP(ip)
	}
	writeJSON(w, 200, out)
}
func (s *Server) policyUpsert(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	var x policy.Rule
	if !decode(w, r, &x) {
		return
	}
	if e := s.Policies.Upsert(x); e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "policy_upsert", Source: remoteIP(r), Object: x.ID, Success: true, Detail: x.Action + " " + x.Source})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) policyDelete(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	id := r.PathValue("id")
	if e := s.Policies.Delete(id); e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "policy_delete", Source: remoteIP(r), Object: id, Success: true})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) policySimulate(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	var in struct {
		Source, Protocol, Listener string
		DestPort                   int `json:"dest_port"`
	}
	if !decode(w, r, &in) {
		return
	}
	writeJSON(w, 200, s.Policies.Simulate(in.Source, in.Protocol, in.Listener, in.DestPort))
}
func (s *Server) listeners(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	writeJSON(w, 200, s.Collector.ListenerStates())
}
func (s *Server) alerts(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	writeJSON(w, 200, s.Analytics.Alerts())
}
func (s *Server) alertAck(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	id := r.PathValue("id")
	if !s.Analytics.Ack(id) {
		writeErr(w, 404, "alert not found")
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "alert_ack", Source: remoteIP(r), Object: id, Success: true})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) users(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	us := s.Auth.Users()
	out := make([]userView, 0, len(us))
	for _, u := range us {
		out = append(out, view(u))
	}
	writeJSON(w, 200, out)
}
func (s *Server) userAdd(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	var in struct{ Username, Password, Role string }
	if !decode(w, r, &in) {
		return
	}
	if e := s.Auth.AddUser(in.Username, in.Password, in.Role); e != nil {
		writeErr(w, 400, e.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "user_create", Source: remoteIP(r), Object: in.Username, Success: true, Detail: "role=" + in.Role})
	writeJSON(w, 201, map[string]bool{"ok": true})
}
func (s *Server) userPasswordReset(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	var in struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	username := r.PathValue("username")
	err := s.Auth.ResetPassword(username, in.Password)
	s.Audit.Write(audit.Event{User: ss.Username, Action: "user_password_reset", Source: remoteIP(r), Object: username, Success: err == nil})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) auditLog(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	writeJSON(w, 200, s.Audit.Read(500))
}
func (s *Server) requireClusterTransport(w http.ResponseWriter, r *http.Request) bool {
	if !s.ClusterRequireMTLS {
		return true
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		writeErr(w, 401, "verified cluster client certificate required")
		return false
	}
	return true
}

func (s *Server) clusterHeartbeat(w http.ResponseWriter, r *http.Request) {
	if !s.requireClusterTransport(w, r) {
		return
	}
	if s.Cluster == nil || !s.Cluster.Enabled() {
		writeErr(w, 404, "cluster heartbeat endpoint is not enabled")
		return
	}
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(authz, "Bearer ") || !s.Cluster.Authenticate(strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))) {
		writeErr(w, 401, "invalid cluster heartbeat token")
		return
	}
	var hb cluster.Heartbeat
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&hb); err != nil {
		writeErr(w, 400, "invalid heartbeat payload")
		return
	}
	if err := s.Cluster.Heartbeat(hb, remoteIP(r)); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, cluster.HeartbeatResponse{OK: true, ServerTime: time.Now().UTC(), Command: s.Cluster.NextCommand(hb.NodeID)})
}

func (s *Server) clusterCommands(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if ss.Role != "administrator" || s.Cluster == nil {
		writeErr(w, 403, "cluster fleet commands are administrator-only")
		return
	}
	writeJSON(w, 200, s.Cluster.Commands())
}

func (s *Server) clusterCommandQueue(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if ss.Role != "administrator" || s.Cluster == nil {
		writeErr(w, 403, "cluster fleet commands are administrator-only")
		return
	}
	var in struct{ NodeID, Action string }
	if !decode(w, r, &in) {
		return
	}
	c, err := s.Cluster.QueueCommand(strings.TrimSpace(in.NodeID), strings.TrimSpace(in.Action), ss.Username)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "fleet_command_queue", Source: remoteIP(r), Object: c.NodeID, Success: true, Detail: c.Action + " id=" + c.ID})
	writeJSON(w, 201, c)
}

func (s *Server) clusterDedup(w http.ResponseWriter, r *http.Request) {
	if !s.requireClusterTransport(w, r) {
		return
	}
	if s.Cluster == nil || !s.Cluster.Enabled() || !s.Cluster.DedupStats().Enabled {
		writeErr(w, 404, "cluster dedup endpoint is not enabled")
		return
	}
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(authz, "Bearer ") || !s.Cluster.Authenticate(strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))) {
		writeErr(w, 401, "invalid cluster token")
		return
	}
	var in struct {
		Fingerprint string `json:"fingerprint"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || len(strings.TrimSpace(in.Fingerprint)) < 16 {
		writeErr(w, 400, "invalid fingerprint")
		return
	}
	accepted := s.Cluster.AcceptFingerprint(in.Fingerprint, time.Now().UTC())
	writeJSON(w, 200, cluster.DedupResponse{Accepted: accepted, Stats: s.Cluster.DedupStats()})
}

func (s *Server) clusterStatus(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if ss.Role != "administrator" {
		writeErr(w, 403, "cluster fleet status is administrator-only")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	q := storage.Query{From: time.Now().Add(-5 * time.Minute), To: time.Now(), Limit: 5000}
	flows, _ := s.Store.Query(ctx, q)
	type nodeSeen struct {
		ID       string    `json:"id"`
		Region   string    `json:"region,omitempty"`
		Flows    int       `json:"flows_sampled"`
		LastSeen time.Time `json:"last_seen"`
		Local    bool      `json:"local"`
	}
	m := map[string]*nodeSeen{}
	for _, f := range flows {
		id := f.CollectorNode
		if id == "" {
			id = "legacy/unassigned"
		}
		n := m[id]
		if n == nil {
			n = &nodeSeen{ID: id}
			m[id] = n
		}
		n.Flows++
		if f.ReceiveTime.After(n.LastSeen) {
			n.LastSeen = f.ReceiveTime
		}
	}
	if m[s.NodeID] == nil {
		m[s.NodeID] = &nodeSeen{ID: s.NodeID, Region: s.NodeRegion, Local: true}
	} else {
		m[s.NodeID].Region = s.NodeRegion
		m[s.NodeID].Local = true
	}
	out := make([]*nodeSeen, 0, len(m))
	for _, n := range m {
		out = append(out, n)
	}
	registered := []cluster.Node{}
	if s.Cluster != nil {
		registered = s.Cluster.Nodes()
	}
	topology := cluster.TopologyStatus{}
	if s.Cluster != nil {
		topology = s.Cluster.TopologyStatus()
	}
	writeJSON(w, 200, map[string]any{"local_node": s.NodeID, "region": s.NodeRegion, "storage_backend": s.Store.Stats().Backend, "shared_storage_ready": s.Store.Stats().Backend == "clickhouse", "nodes": out, "registered_nodes": registered, "heartbeat_enabled": s.Cluster != nil && s.Cluster.Enabled(), "dedup": s.Collector.DedupStats(), "global_dedup": s.Collector.GlobalDedupStats(), "coordinator_dedup": func() any {
		if s.Cluster != nil {
			return s.Cluster.DedupStats()
		}
		return nil
	}(), "topology": topology, "bounded": true, "cluster_mtls_required": s.ClusterRequireMTLS, "note": "Heartbeat registry quorum, deterministic coordinator selection and rendezvous exporter assignment are active. Shared ClickHouse remains the durable shared data plane."})
}

func (s *Server) clusterAssignment(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.Cluster == nil {
		writeErr(w, 404, "cluster registry unavailable")
		return
	}
	key := strings.TrimSpace(r.URL.Query().Get("exporter"))
	if key == "" || len(key) > 512 {
		writeErr(w, 400, "exporter key required")
		return
	}
	node, ok := s.Cluster.AssignExporter(key)
	if !ok {
		writeErr(w, 503, "no reachable cluster nodes")
		return
	}
	writeJSON(w, 200, map[string]any{"exporter": key, "assigned_node": node, "topology": s.Cluster.TopologyStatus()})
}

func (s *Server) topology(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	q, err := storage.ParseQuery(r.URL.Query())
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	q.Tenant = ""
	if q.To.IsZero() {
		q.To = time.Now()
	}
	if q.From.IsZero() {
		q.From = q.To.Add(-time.Hour)
	}
	if q.To.Sub(q.From) > 24*time.Hour {
		writeErr(w, 400, "topology time range exceeds 24 hours")
		return
	}
	q.Limit = 5000
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	flows, err := s.Store.Query(ctx, q)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	mode := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("mode")))
	if mode == "" {
		mode = strings.ToLower(strings.TrimSpace(r.URL.Query().Get("level"))) // UI/API compatibility alias
	}
	maxNodes := 40
	minBytes := uint64(0)
	if v := r.URL.Query().Get("max_nodes"); v != "" {
		n, e := strconv.Atoi(v)
		if e != nil || n < 10 || n > 200 {
			writeErr(w, 400, "max_nodes must be 10..200")
			return
		}
		maxNodes = n
	}
	if v := r.URL.Query().Get("min_bytes"); v != "" {
		n, e := strconv.ParseUint(v, 10, 64)
		if e != nil {
			writeErr(w, 400, "invalid min_bytes")
			return
		}
		minBytes = n
	}
	writeJSON(w, 200, buildTopology(flows, mode, maxNodes, minBytes))
}
func (s *Server) apiTokens(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	writeJSON(w, 200, s.Auth.APITokens(ss.Username))
}
func (s *Server) apiTokenCreate(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	var in struct {
		Name         string   `json:"name"`
		Days         int      `json:"days"`
		Scopes       []string `json:"scopes"`
		AllowedCIDRs []string `json:"allowed_cidrs"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Days == 0 {
		in.Days = 90
	}
	t, secret, err := s.Auth.CreateAPITokenAdvanced(ss.Username, in.Name, in.Days, in.Scopes, in.AllowedCIDRs)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "api_token_create", Source: remoteIP(r), Object: t.ID, Success: true, Detail: t.Name})
	writeJSON(w, 201, map[string]any{"token": t, "secret": secret, "warning": "This secret is shown once. Store it securely."})
}
func (s *Server) apiTokenDelete(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	id := r.PathValue("id")
	if err := s.Auth.RevokeAPIToken(ss.Username, id); err != nil {
		writeErr(w, 404, err.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "api_token_revoke", Source: remoteIP(r), Object: id, Success: true})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) storageInfo(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	writeJSON(w, 200, map[string]any{"stats": s.Store.Stats(), "retention_days": s.Store.Retention()})
}
func (s *Server) storageRetention(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	var in struct {
		Days int `json:"days"`
	}
	if !decode(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.Store.SetRetention(ctx, in.Days); err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "storage_retention_change", Source: remoteIP(r), Success: true, Detail: fmt.Sprintf("days=%d", in.Days)})
	writeJSON(w, 200, map[string]any{"ok": true, "retention_days": s.Store.Retention()})
}
func (s *Server) storagePurge(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	out, err := s.Store.Purge(ctx)
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "storage_purge", Source: remoteIP(r), Success: true, Detail: out.Action})
	writeJSON(w, 200, out)
}

func (s *Server) health(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	payload := map[string]any{"runtime": map[string]any{"goroutines": runtime.NumGoroutine(), "heap_bytes": m.HeapAlloc, "gc_cycles": m.NumGC}, "storage": s.Store.Stats(), "listeners": s.Collector.ListenerStates(), "analytics_capacity": s.Analytics.CapacityStatus()}
	if s.Notifications != nil {
		payload["notifications"] = s.Notifications.Health()
	}
	if s.Enrichment != nil {
		payload["enrichment"] = s.Enrichment.Status()
	}
	writeJSON(w, 200, payload)
}
func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	st := s.Store.Stats()
	listeners := s.Collector.ListenerStates()
	running := 0
	for _, l := range listeners {
		if l.Running {
			running++
		}
	}
	if !st.Healthy || running == 0 {
		writeJSON(w, 503, map[string]any{"ready": false, "storage": st, "running_listeners": running})
		return
	}
	writeJSON(w, 200, map[string]any{"ready": true, "storage_backend": st.Backend, "running_listeners": running})
}

func (s *Server) metrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	if s.Notifications != nil {
		_, _ = fmt.Fprint(w, s.Notifications.Metrics())
	}
	a := s.Analytics.Snapshot()
	st := s.Store.Stats()
	ds := s.Collector.DedupStats()
	fmt.Fprintf(w, "flowcollector_advanced_queries_total %d\nflowcollector_advanced_query_failures_total %d\nflowcollector_advanced_query_rejections_total %d\nflowcollector_advanced_query_cancellations_total %d\nflowcollector_advanced_queries_active %d\n", s.intelligenceState.queries.Load(), s.intelligenceState.failures.Load(), s.intelligenceState.rejected.Load(), s.intelligenceState.cancelled.Load(), s.intelligenceState.active.Load())
	cs := s.Analytics.CapacityStatus()
	fmt.Fprintf(w, "flowcollector_flows_total %d\nflowcollector_packets_total %d\nflowcollector_bytes_total %d\nflowcollector_flows_per_second %d\nflowcollector_storage_written_total %d\nflowcollector_storage_write_errors_total %d\nflowcollector_storage_dropped_total %d\nflowcollector_storage_queue_depth %d\nflowcollector_storage_queue_capacity %d\nflowcollector_dedup_accepted_total %d\nflowcollector_dedup_duplicates_total %d\nflowcollector_dedup_entries %d\nflowcollector_analytics_state_dropped_total %d\nflowcollector_analytics_baseline_hosts %d\nflowcollector_analytics_source_keys %d\nflowcollector_analytics_destination_keys %d\n", a.TotalFlows, a.TotalPackets, a.TotalBytes, a.FlowsPerSec, st.Written, st.WriteErrors, st.Dropped, st.QueueDepth, st.QueueCapacity, ds.Accepted, ds.Duplicates, ds.Entries, cs.StateDrops, cs.BaselineHosts, cs.SourceKeys, cs.DestinationKeys)
	for _, l := range s.Collector.ListenerStates() {
		fmt.Fprintf(w, "flowcollector_listener_packets_total{listener=%q,protocol=%q} %d\n", l.Name, l.Protocol, l.Packets)
		fmt.Fprintf(w, "flowcollector_listener_bytes_total{listener=%q,protocol=%q} %d\n", l.Name, l.Protocol, l.Bytes)
		fmt.Fprintf(w, "flowcollector_listener_drops_total{listener=%q,protocol=%q} %d\n", l.Name, l.Protocol, l.Drops)
		fmt.Fprintf(w, "flowcollector_listener_queue_depth{listener=%q,protocol=%q} %d\n", l.Name, l.Protocol, l.QueueDepth)
		fmt.Fprintf(w, "flowcollector_listener_queue_capacity{listener=%q,protocol=%q} %d\n", l.Name, l.Protocol, l.QueueCapacity)
	}
}

type authed func(http.ResponseWriter, *http.Request, auth.Session)

func (s *Server) withAuth(perm string, next authed) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var ss auth.Session
		var ok bool
		bearer := false
		if h := r.Header.Get("Authorization"); strings.HasPrefix(strings.ToLower(h), "bearer ") {
			ss, ok = s.Auth.AuthenticateBearerFrom(strings.TrimSpace(h[7:]), remoteIP(r))
			bearer = true
		} else if c, e := r.Cookie("fc_session"); e == nil {
			ss, ok = s.Auth.Session(c.Value)
		}
		if !ok {
			writeErr(w, 401, "authentication required or token expired")
			return
		}
		if !bearer && r.Method != "GET" && r.Method != "HEAD" && r.Header.Get("X-CSRF-Token") != ss.CSRF {
			writeErr(w, 403, "csrf validation failed")
			return
		}
		if !auth.HasPermission(ss.Role, perm) {
			writeErr(w, 403, "permission denied")
			return
		}
		if bearer && !auth.ScopeAllows(ss.Scopes, perm) {
			writeErr(w, 403, "api token scope denied")
			return
		}
		// Mandatory MFA applies to the built-in local password login. A password
		// session is fully trusted only when TOTP/recovery verification occurred
		// during that login (session+mfa) or the user authenticated with a passkey.
		// API tokens and external OIDC/LDAP sessions retain their own authentication
		// policy; upstream MFA for external IdPs is deliberately not guessed here.
		if s.RequireMFA && ss.AuthType == "session" {
			st := s.Auth.MFAStatus(ss.Username)
			allowedEnroll := strings.HasPrefix(r.URL.Path, "/api/v1/auth/mfa/") || strings.HasPrefix(r.URL.Path, "/api/v1/auth/webauthn/register/") || r.URL.Path == "/api/v1/auth/me" || r.URL.Path == "/api/v1/auth/change-password" || r.URL.Path == "/api/v1/auth/logout"
			if !allowedEnroll {
				msg := "MFA enrollment required"
				if st.Passkeys > 0 {
					msg = "MFA required: sign in with a passkey or enroll TOTP"
				}
				writeJSON(w, 403, map[string]any{"error": msg, "mfa_enrollment_required": !st.TOTPEnabled && st.Passkeys == 0})
				return
			}
		}
		next(w, r, ss)
	}
}
func (s *Server) withDiagnosticsAuth(next authed) http.HandlerFunc {
	guarded := s.withAuth("diagnostics.read", next)
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.DiagnosticsEnabled {
			http.NotFound(w, r)
			return
		}
		guarded(w, r)
	}
}

func (s *Server) diagnosticsAllowed(w http.ResponseWriter) bool {
	if !s.DiagnosticsEnabled {
		writeErr(w, 404, "diagnostics endpoint disabled")
		return false
	}
	return true
}
func (s *Server) pprofIndex(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.diagnosticsAllowed(w) {
		pprof.Index(w, r)
	}
}
func (s *Server) pprofProfile(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.diagnosticsAllowed(w) {
		pprof.Profile(w, r)
	}
}
func (s *Server) pprofTrace(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.diagnosticsAllowed(w) {
		pprof.Trace(w, r)
	}
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=(), usb=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; connect-src 'self'")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
func spaHandler(fh http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/health" || r.URL.Path == "/ready" || r.URL.Path == "/metrics" {
			http.NotFound(w, r)
			return
		}
		// Do not rewrite "/" to "/index.html" here. net/http.FileServer
		// canonicalizes explicit index.html requests back to "./". Rewriting the
		// root request therefore creates a browser-visible redirect loop:
		//     / -> /index.html -> ./ -> / -> ...
		// FileServer already serves index.html automatically for a directory
		// request ending in "/", so pass the original request through unchanged.
		fh.ServeHTTP(w, r)
	})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if e := d.Decode(v); e != nil {
		writeErr(w, 400, "invalid JSON: "+e.Error())
		return false
	}
	// Reject concatenated/trailing JSON values instead of silently accepting the
	// first object and ignoring the remainder.
	var extra any
	if e := d.Decode(&extra); e == nil {
		writeErr(w, 400, "invalid JSON: multiple values are not allowed")
		return false
	} else if !errors.Is(e, io.EOF) {
		writeErr(w, 400, "invalid JSON: "+e.Error())
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
func remoteIP(r *http.Request) string {
	h, _, e := net.SplitHostPort(r.RemoteAddr)
	if e == nil {
		return h
	}
	return r.RemoteAddr
}
func view(u auth.User) userView {
	return userView{Username: u.Username, Role: u.Role, MustChange: u.MustChange, Disabled: u.Disabled}
}

var _ = log.Printf
var _ = strconv.Itoa
var _ = model.Flow{}
