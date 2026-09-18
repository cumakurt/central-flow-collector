package api

import (
	"central-flow-collector/internal/accesspolicy"
	"central-flow-collector/internal/adminops"
	"central-flow-collector/internal/audit"
	"central-flow-collector/internal/auth"
	"central-flow-collector/internal/buildinfo"
	"central-flow-collector/internal/dr"
	"central-flow-collector/internal/notification"
	"central-flow-collector/internal/storage"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func (s *Server) accessPolicyGet(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.AccessPolicy == nil {
		writeErr(w, 503, "access policy is unavailable")
		return
	}
	writeJSON(w, http.StatusOK, s.AccessPolicy.Snapshot())
}

func (s *Server) accessPolicyApply(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if s.AccessPolicy == nil {
		writeErr(w, 503, "access policy is unavailable")
		return
	}
	var in accesspolicy.Document
	if !decode(w, r, &in) {
		return
	}
	if err := s.AccessPolicy.Replace(in); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if s.Audit != nil {
		s.Audit.Write(audit.Event{User: ss.Username, Action: "access_policy_update", Source: remoteIP(r), Success: true})
	}
	writeJSON(w, http.StatusOK, s.AccessPolicy.Snapshot())
}

type adminApplyRequest struct {
	Settings adminops.Settings `json:"settings"`
	Reason   string            `json:"reason"`
}

type adminBackupItem struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	Kind       string    `json:"kind"`
	Size       int64     `json:"size"`
	ModifiedAt time.Time `json:"modified_at"`
	Verified   *bool     `json:"verified,omitempty"`
}

func (s *Server) adminReady(w http.ResponseWriter) bool {
	if s.AdminOps == nil {
		writeErr(w, 503, "administration control plane unavailable")
		return false
	}
	return true
}

func (s *Server) adminOverview(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.adminReady(w) {
		return
	}
	st := s.Store.Stats()
	listeners := s.Collector.ListenerStates()
	au := s.Audit.Verify()
	settings := s.AdminOps.Current()
	versions := s.AdminOps.Versions()
	backups := s.listAdminBackups()
	nodes := 0
	online := 0
	if s.Cluster != nil {
		ns := s.Cluster.Nodes()
		nodes = len(ns)
		for _, n := range ns {
			if n.State == "online" {
				online++
			}
		}
	}
	writeJSON(w, 200, map[string]any{
		"version":          buildinfo.Version,
		"storage":          st,
		"retention_days":   s.Store.Retention(),
		"listeners":        listeners,
		"ingestion_paused": s.Collector.Paused(),
		"audit_integrity":  au,
		"config_versions":  len(versions),
		"latest_config": func() any {
			if len(versions) > 0 {
				return versions[0]
			}
			return nil
		}(),
		"backups":  backups,
		"cluster":  map[string]any{"nodes": nodes, "online": online},
		"web":      map[string]any{"bind": settings.Web.Bind, "port": settings.Web.Port, "tls": settings.Web.TLS},
		"database": map[string]any{"backend": settings.Storage.Backend, "url": settings.Storage.ClickHouseURL, "database": settings.Storage.ClickHouseDatabase, "table": settings.Storage.ClickHouseTable, "cluster": settings.Storage.ClickHouseCluster},
		"data_dir": settings.Storage.DataDir,
	})
}

func (s *Server) adminSettings(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.adminReady(w) {
		return
	}
	writeJSON(w, 200, s.AdminOps.Current())
}
func (s *Server) adminSettingsValidate(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.adminReady(w) {
		return
	}
	var in adminApplyRequest
	if !decode(w, r, &in) {
		return
	}
	v := s.AdminOps.Validate(in.Settings)
	code := 200
	if !v.Valid {
		code = 400
	}
	writeJSON(w, code, v)
}
func (s *Server) adminSettingsApply(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.adminReady(w) {
		return
	}
	var in adminApplyRequest
	if !decode(w, r, &in) {
		return
	}
	v := s.AdminOps.Validate(in.Settings)
	if !v.Valid {
		writeJSON(w, 400, v)
		return
	}
	res, err := s.AdminOps.Apply(in.Settings, ss.Username, in.Reason)
	if err != nil {
		s.Audit.Write(audit.Event{User: ss.Username, Action: "admin_config_apply", Source: remoteIP(r), Success: false, Detail: err.Error()})
		writeErr(w, 400, err.Error())
		return
	}
	// Retention is safe to activate without restarting. Everything else is
	// persisted by the control-plane overlay and flagged as restart-required.
	if err = s.Store.SetRetention(r.Context(), in.Settings.Storage.RetentionDays); err != nil {
		res.Validation.Warnings = append(res.Validation.Warnings, "retention live-apply failed: "+err.Error())
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "admin_config_apply", Source: remoteIP(r), Object: res.Version.ID, Success: true, Detail: fmt.Sprintf("reason=%s changes=%d restart_required=%v", in.Reason, len(res.Validation.Changes), res.Validation.RestartRequired)})
	writeJSON(w, 200, res)
}
func (s *Server) adminConfigVersions(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.adminReady(w) {
		return
	}
	writeJSON(w, 200, s.AdminOps.Versions())
}
func (s *Server) adminConfigRollback(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.adminReady(w) {
		return
	}
	var in struct {
		ID      string `json:"id"`
		Reason  string `json:"reason"`
		Confirm string `json:"confirm"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Confirm != "ROLLBACK" {
		writeErr(w, 400, "rollback requires confirm=ROLLBACK")
		return
	}
	v, err := s.AdminOps.Rollback(in.ID, ss.Username, in.Reason)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "admin_config_rollback", Source: remoteIP(r), Object: v.ID, Success: true, Detail: "target=" + in.ID})
	writeJSON(w, 200, map[string]any{"ok": true, "version": v, "restart_required": true})
}
func (s *Server) adminRestart(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.adminReady(w) {
		return
	}
	var in struct {
		Confirm string `json:"confirm"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Confirm != "RESTART" {
		writeErr(w, 400, "restart requires confirm=RESTART")
		return
	}
	if s.Restart == nil {
		writeErr(w, 503, "graceful restart controller unavailable")
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "admin_restart", Source: remoteIP(r), Success: true})
	writeJSON(w, 202, map[string]any{"accepted": true, "message": "service restart requested"})
	go func() { time.Sleep(250 * time.Millisecond); s.Restart() }()
}

func (s *Server) adminDatabaseTest(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.adminReady(w) {
		return
	}
	var in adminops.Settings
	if !decode(w, r, &in) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	p := s.AdminOps.ProbeClickHouse(ctx, in)
	s.Audit.Write(audit.Event{User: ss.Username, Action: "admin_database_test", Source: remoteIP(r), Success: p.OK, Detail: p.Error})
	code := 200
	if !p.OK {
		code = 400
	}
	writeJSON(w, code, p)
}

func (s *Server) adminDatabaseHealth(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.adminReady(w) {
		return
	}
	settings := s.AdminOps.Current()
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	local := dr.Check(s.AdminOps.DataDir())
	stats := s.Store.Stats()
	clickhouse := s.AdminOps.ProbeClickHouse(ctx, settings)
	disks := []storage.DiskUsage{storage.DiskSpace("/"), storage.DiskSpace(s.AdminOps.DataDir())}
	if info, err := os.Stat(filepath.Join(s.AdminOps.DataDir(), "clickhouse")); err == nil && info.IsDir() {
		disks = append(disks, storage.DiskSpace(filepath.Join(s.AdminOps.DataDir(), "clickhouse")))
	}
	writeJSON(w, 200, map[string]any{
		"host":           hostResources(),
		"checked_at":     time.Now().UTC(),
		"disks":          disks,
		"active_backend": settings.Storage.Backend,
		"active_storage": stats,
		"local":          local,
		"clickhouse":     clickhouse,
	})
}

func (s *Server) adminIngestion(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	action := r.PathValue("action")
	if action != "start" && action != "stop" {
		writeErr(w, 400, "action must be start or stop")
		return
	}
	s.Collector.SetPaused(action == "stop")
	s.Audit.Write(audit.Event{User: ss.Username, Action: "ingestion_" + action, Source: remoteIP(r), Success: true})
	writeJSON(w, 200, map[string]any{"ok": true, "paused": s.Collector.Paused(), "listeners": s.Collector.ListenerStates()})
}

func (s *Server) adminMaintenance(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.adminReady(w) {
		return
	}
	action := strings.ToLower(r.PathValue("action"))
	started := time.Now()
	var out any
	var err error
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	switch action {
	case "purge":
		out, err = s.Store.Purge(ctx)
	case "optimize":
		if ch, ok := s.Store.(*storage.ClickHouse); ok {
			err = ch.Optimize(ctx)
			out = map[string]any{"action": "ClickHouse OPTIMIZE FINAL", "ok": err == nil}
		} else {
			err = errors.New("optimize is only available for ClickHouse")
		}
	case "check_database":
		if ch, ok := s.Store.(*storage.ClickHouse); ok {
			var x string
			x, err = ch.CheckTable(ctx)
			out = map[string]any{"result": x, "ok": err == nil}
		} else {
			out = dr.Check(s.AdminOps.DataDir())
		}
	case "audit_verify":
		out = s.Audit.Verify()
	case "cleanup_sessions":
		out = map[string]any{"removed": s.Auth.CleanupExpiredSessions(time.Now().UTC())}
	case "reload_enrichment":
		if s.Enrichment == nil {
			err = errors.New("enrichment unavailable")
		} else {
			err = s.Enrichment.Reload()
			out = s.Enrichment.Status()
		}
	default:
		err = fmt.Errorf("unsupported maintenance action %q", action)
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "maintenance_" + action, Source: remoteIP(r), Success: err == nil, Detail: func() string {
		if err != nil {
			return err.Error()
		}
		return "completed"
	}()})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "action": action, "result": out, "duration_ms": time.Since(started).Milliseconds(), "completed_at": time.Now().UTC()})
}

func (s *Server) adminUpgradePreflight(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.adminReady(w) {
		return
	}
	settings := s.AdminOps.Current()
	validation := s.AdminOps.Validate(settings)
	st := s.Store.Stats()
	backs := s.listAdminBackups()
	var latest any
	if len(backs) > 0 {
		latest = backs[0]
	}
	ready := validation.Valid && st.Healthy
	out := map[string]any{
		"ok": ready, "version": buildinfo.Version, "config_valid": validation.Valid,
		"config_error": validation.Error, "storage_healthy": st.Healthy, "storage_error": st.LastError,
		"listener_count": len(s.Collector.ListenerStates()), "latest_backup": latest,
		"recommendation": "Create and verify a fresh backup, then use install.sh --upgrade so binary checksums, permissions, service health and rollback snapshots remain enforced.",
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "upgrade_preflight", Source: remoteIP(r), Success: ready})
	writeJSON(w, 200, out)
}

func (s *Server) backupDir() string {
	if s.AdminOps == nil {
		return ""
	}
	return filepath.Join(s.AdminOps.DataDir(), "backups")
}
func safeBackupName(n string) bool {
	return n != "" && filepath.Base(n) == n && !strings.Contains(n, "..") && (strings.HasSuffix(n, ".tar.gz") || strings.HasSuffix(n, ".jsonl.gz"))
}
func (s *Server) listAdminBackups() []adminBackupItem {
	dir := s.backupDir()
	es, _ := os.ReadDir(dir)
	out := []adminBackupItem{}
	for _, e := range es {
		if e.IsDir() || !safeBackupName(e.Name()) {
			continue
		}
		i, er := e.Info()
		if er != nil {
			continue
		}
		kind := "metadata"
		if strings.HasSuffix(e.Name(), ".jsonl.gz") {
			kind = "clickhouse"
		}
		out = append(out, adminBackupItem{Name: e.Name(), Path: filepath.Join(dir, e.Name()), Kind: kind, Size: i.Size(), ModifiedAt: i.ModTime()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ModifiedAt.After(out[j].ModifiedAt) })
	return out
}
func (s *Server) adminBackups(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.adminReady(w) {
		return
	}
	writeJSON(w, 200, s.listAdminBackups())
}
func (s *Server) adminBackupCreate(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.adminReady(w) {
		return
	}
	var in struct {
		Kind         string `json:"kind"`
		IncludeFlows bool   `json:"include_flows"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Kind == "" {
		in.Kind = "metadata"
	}
	dir := s.backupDir()
	if err := os.MkdirAll(dir, 0750); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	var result any
	var err error
	switch in.Kind {
	case "metadata":
		p := filepath.Join(dir, "metadata-"+stamp+".tar.gz")
		var m dr.Manifest
		m, err = dr.Create(s.AdminOps.ConfigPath(), s.AdminOps.DataDir(), p, in.IncludeFlows)
		result = map[string]any{"path": p, "manifest": m}
	case "clickhouse":
		ch, ok := s.Store.(*storage.ClickHouse)
		if !ok {
			err = errors.New("ClickHouse backup requires the ClickHouse backend")
			break
		}
		p := filepath.Join(dir, "clickhouse-"+stamp+".jsonl.gz")
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
		defer cancel()
		var m storage.ClickHouseBackupManifest
		m, err = ch.LogicalBackup(ctx, p, time.Time{}, time.Time{})
		result = m
	default:
		err = errors.New("kind must be metadata or clickhouse")
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "backup_create", Source: remoteIP(r), Success: err == nil, Detail: "kind=" + in.Kind})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "result": result})
}
func (s *Server) adminBackupVerify(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.adminReady(w) {
		return
	}
	var in struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !safeBackupName(in.Name) {
		writeErr(w, 400, "invalid backup name")
		return
	}
	p := filepath.Join(s.backupDir(), in.Name)
	var out any
	var err error
	if strings.HasSuffix(in.Name, ".jsonl.gz") {
		out, err = storage.VerifyClickHouseBackup(p)
	} else {
		out, err = dr.Verify(p)
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "backup_verify", Source: remoteIP(r), Object: in.Name, Success: err == nil})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "result": out})
}
func (s *Server) adminBackupRestore(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.adminReady(w) {
		return
	}
	var in struct {
		Name    string `json:"name"`
		Confirm string `json:"confirm"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Confirm != "RESTORE" {
		writeErr(w, 400, "restore requires confirm=RESTORE")
		return
	}
	if !safeBackupName(in.Name) {
		writeErr(w, 400, "invalid backup name")
		return
	}
	p := filepath.Join(s.backupDir(), in.Name)
	if strings.HasSuffix(in.Name, ".jsonl.gz") {
		ch, ok := s.Store.(*storage.ClickHouse)
		if !ok {
			writeErr(w, 400, "ClickHouse restore requires ClickHouse backend")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Minute)
		defer cancel()
		m, err := ch.LogicalRestore(ctx, p, true)
		if err != nil {
			writeErr(w, 400, err.Error())
			return
		}
		s.Audit.Write(audit.Event{User: ss.Username, Action: "clickhouse_restore", Source: remoteIP(r), Object: in.Name, Success: true})
		writeJSON(w, 200, map[string]any{"ok": true, "result": m})
		return
	}
	if _, err := dr.Verify(p); err != nil {
		writeErr(w, 400, "backup verification failed: "+err.Error())
		return
	}
	if s.Restart == nil {
		writeErr(w, 503, "restart controller unavailable")
		return
	}
	if err := adminops.ScheduleRestore(s.AdminOps.DataDir(), p, ss.Username); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	s.Audit.Write(audit.Event{User: ss.Username, Action: "restore_schedule", Source: remoteIP(r), Object: in.Name, Success: true})
	writeJSON(w, 202, map[string]any{"accepted": true, "message": "verified restore scheduled; service will restart and restore before opening listeners"})
	go func() { time.Sleep(250 * time.Millisecond); s.Restart() }()
}

func (s *Server) adminNotificationTest(w http.ResponseWriter, r *http.Request, ss auth.Session) {
	if !s.adminReady(w) {
		return
	}
	var in struct {
		Provider string             `json:"provider"`
		Settings *adminops.Settings `json:"settings,omitempty"`
	}
	if !decode(w, r, &in) {
		return
	}
	cfg := s.AdminOps.EffectiveConfig()
	if in.Settings != nil {
		st := *in.Settings
		if st.Notifications.WebhookURL != "" {
			cfg.Notifications.WebhookURL = st.Notifications.WebhookURL
		}
		if st.Notifications.TelegramChatID != "" {
			cfg.Notifications.TelegramChatID = st.Notifications.TelegramChatID
		}
		if st.Notifications.NewTelegramBotToken != "" {
			cfg.Notifications.TelegramBotToken = st.Notifications.NewTelegramBotToken
		}
		if st.Notifications.SMTPAddr != "" {
			cfg.Notifications.SMTPAddr = st.Notifications.SMTPAddr
		}
		if st.Notifications.SMTPFrom != "" {
			cfg.Notifications.SMTPFrom = st.Notifications.SMTPFrom
		}
		if st.Notifications.SMTPTo != "" {
			cfg.Notifications.SMTPTo = st.Notifications.SMTPTo
		}
		if st.Notifications.SMTPUsername != "" {
			cfg.Notifications.SMTPUsername = st.Notifications.SMTPUsername
		}
		if st.Notifications.NewSMTPPassword != "" {
			cfg.Notifications.SMTPPassword = st.Notifications.NewSMTPPassword
		}
		if st.Notifications.SyslogAddr != "" {
			cfg.Notifications.SyslogAddr = st.Notifications.SyslogAddr
		}
	}
	nc := notification.Config{WebhookURL: cfg.Notifications.WebhookURL, TelegramBotToken: cfg.Notifications.TelegramBotToken, TelegramChatID: cfg.Notifications.TelegramChatID, SMTPAddr: cfg.Notifications.SMTPAddr, SMTPFrom: cfg.Notifications.SMTPFrom, SMTPTo: cfg.Notifications.SMTPTo, SMTPUsername: cfg.Notifications.SMTPUsername, SMTPPassword: cfg.Notifications.SMTPPassword, SyslogAddr: cfg.Notifications.SyslogAddr}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	err := notification.TestConfig(ctx, nc, in.Provider)
	s.Audit.Write(audit.Event{User: ss.Username, Action: "notification_test", Source: remoteIP(r), Object: in.Provider, Success: err == nil})
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "provider": in.Provider})
}

// Keep encoding/json referenced for backwards-compatible generated API clients
// that inspect the source build tags; this also documents JSON-only control-plane payloads.
var _ = json.Valid
