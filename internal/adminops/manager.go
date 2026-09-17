package adminops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"central-flow-collector/internal/config"
)

type Settings struct {
	Web struct {
		Bind     string `json:"bind"`
		Port     int    `json:"port"`
		TLS      bool   `json:"tls"`
		CertFile string `json:"cert_file"`
		KeyFile  string `json:"key_file"`
	} `json:"web"`
	Storage struct {
		Backend                    string `json:"backend"`
		DataDir                    string `json:"data_dir"`
		RetentionDays              int    `json:"retention_days"`
		ClickHouseURL              string `json:"clickhouse_url"`
		ClickHouseDatabase         string `json:"clickhouse_database"`
		ClickHouseTable            string `json:"clickhouse_table"`
		ClickHouseUser             string `json:"clickhouse_user"`
		ClickHousePasswordSet      bool   `json:"clickhouse_password_set"`
		NewClickHousePassword      string `json:"new_clickhouse_password,omitempty"`
		ClickHouseBatchSize        int    `json:"clickhouse_batch_size"`
		ClickHouseFlushMS          int    `json:"clickhouse_flush_ms"`
		ClickHouseQueueSize        int    `json:"clickhouse_queue_size"`
		ClickHouseCluster          string `json:"clickhouse_cluster"`
		ClickHouseDistributedTable string `json:"clickhouse_distributed_table"`
		ClickHouseReplicaPath      string `json:"clickhouse_replica_path"`
		ClickHouseReplicaName      string `json:"clickhouse_replica_name"`
	} `json:"storage"`
	Security struct {
		DefaultPolicy string `json:"default_policy"`
		SessionHours  int    `json:"session_hours"`
		RequireMFA    bool   `json:"require_mfa"`
	} `json:"security"`
	Logging struct {
		JSON  bool   `json:"json"`
		Level string `json:"level"`
	} `json:"logging"`
	Analytics struct {
		BaselineEnabled     bool `json:"baseline_enabled"`
		BaselineMinSamples  int  `json:"baseline_min_samples"`
		BaselineSaveSeconds int  `json:"baseline_save_seconds"`
		DedupEnabled        bool `json:"dedup_enabled"`
		DedupWindowSeconds  int  `json:"dedup_window_seconds"`
		DedupMaxEntries     int  `json:"dedup_max_entries"`
	} `json:"analytics"`
	Enrichment struct {
		Enabled       bool   `json:"enabled"`
		PrefixFile    string `json:"prefix_file"`
		RemoteEnabled bool   `json:"remote_enabled"`
		RemoteURL     string `json:"remote_url"`
	} `json:"enrichment"`
	Cluster struct {
		HeartbeatURL          string `json:"heartbeat_url"`
		SharedTokenFile       string `json:"shared_token_file"`
		HeartbeatSeconds      int    `json:"heartbeat_seconds"`
		NodeTimeoutSeconds    int    `json:"node_timeout_seconds"`
		AllowInsecureHTTP     bool   `json:"allow_insecure_http"`
		GlobalDedupEnabled    bool   `json:"global_dedup_enabled"`
		GlobalDedupURL        string `json:"global_dedup_url"`
		GlobalDedupTimeoutMS  int    `json:"global_dedup_timeout_ms"`
		GlobalDedupMaxEntries int    `json:"global_dedup_max_entries"`
	} `json:"cluster"`
	Notifications struct {
		WebhookURL          string `json:"webhook_url"`
		TelegramChatID      string `json:"telegram_chat_id"`
		TelegramTokenSet    bool   `json:"telegram_token_set"`
		NewTelegramBotToken string `json:"new_telegram_bot_token,omitempty"`
		SMTPAddr            string `json:"smtp_addr"`
		SMTPFrom            string `json:"smtp_from"`
		SMTPTo              string `json:"smtp_to"`
		SMTPUsername        string `json:"smtp_username"`
		SMTPPasswordSet     bool   `json:"smtp_password_set"`
		NewSMTPPassword     string `json:"new_smtp_password,omitempty"`
		SyslogAddr          string `json:"syslog_addr"`
	} `json:"notifications"`
	OIDC struct {
		Enabled         bool   `json:"enabled"`
		Issuer          string `json:"issuer"`
		ClientID        string `json:"client_id"`
		ClientSecretSet bool   `json:"client_secret_set"`
		NewClientSecret string `json:"new_client_secret,omitempty"`
		RedirectURL     string `json:"redirect_url"`
		DefaultRole     string `json:"default_role"`
		GroupRoleMap    string `json:"group_role_map"`
	} `json:"oidc"`
	LDAP struct {
		Enabled         bool   `json:"enabled"`
		URL             string `json:"url"`
		BindDN          string `json:"bind_dn"`
		BindPasswordSet bool   `json:"bind_password_set"`
		NewBindPassword string `json:"new_bind_password,omitempty"`
		BaseDN          string `json:"base_dn"`
		UserAttribute   string `json:"user_attribute"`
		UserDNTemplate  string `json:"user_dn_template"`
		GroupAttribute  string `json:"group_attribute"`
		GroupRoleMap    string `json:"group_role_map"`
		DefaultRole     string `json:"default_role"`
		AllowInsecure   bool   `json:"allow_insecure"`
	} `json:"ldap"`
	Listeners []config.Listener `json:"listeners"`
}

type Change struct {
	Path   string `json:"path"`
	Before string `json:"before"`
	After  string `json:"after"`
	Risk   string `json:"risk"`
}
type Version struct {
	ID              string               `json:"id"`
	CreatedAt       time.Time            `json:"created_at"`
	User            string               `json:"user"`
	Reason          string               `json:"reason"`
	Status          string               `json:"status"`
	RestartRequired bool                 `json:"restart_required"`
	Changes         []Change             `json:"changes"`
	Before          config.AdminOverride `json:"before"`
	After           config.AdminOverride `json:"after"`
}
type Validation struct {
	Valid           bool     `json:"valid"`
	RestartRequired bool     `json:"restart_required"`
	Changes         []Change `json:"changes"`
	Warnings        []string `json:"warnings,omitempty"`
	Error           string   `json:"error,omitempty"`
}
type ApplyResult struct {
	Version    Version    `json:"version"`
	Validation Validation `json:"validation"`
}
type ClickHouseProbe struct {
	OK             bool   `json:"ok"`
	LatencyMS      int64  `json:"latency_ms"`
	ServerVersion  string `json:"server_version,omitempty"`
	DatabaseExists bool   `json:"database_exists"`
	TableExists    bool   `json:"table_exists"`
	WriteProbe     bool   `json:"write_probe"`
	Error          string `json:"error,omitempty"`
}

type Manager struct {
	mu                               sync.RWMutex
	configPath, dataDir, historyPath string
	cfg                              config.Config
	override                         config.AdminOverride
	versions                         []Version
}

func New(configPath string, cfg config.Config) (*Manager, error) {
	o, err := config.LoadAdminOverride(cfg.Storage.DataDir)
	if err != nil {
		return nil, err
	}
	m := &Manager{configPath: configPath, dataDir: cfg.Storage.DataDir, historyPath: filepath.Join(cfg.Storage.DataDir, "admin-config-history.json"), cfg: cfg, override: o}
	if b, e := os.ReadFile(m.historyPath); e == nil {
		if e = json.Unmarshal(b, &m.versions); e != nil {
			return nil, e
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return nil, e
	}
	return m, nil
}
func (m *Manager) ConfigPath() string { return m.configPath }
func (m *Manager) DataDir() string    { return m.dataDir }
func (m *Manager) Current() Settings  { m.mu.RLock(); defer m.mu.RUnlock(); return fromConfig(m.cfg) }
func (m *Manager) Versions() []Version {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := append([]Version(nil), m.versions...)
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	for i := range out {
		out[i].Before = config.AdminOverride{}
		out[i].After = config.AdminOverride{}
	}
	return out
}

func fromConfig(c config.Config) Settings {
	var s Settings
	s.Web.Bind = c.Web.Bind
	s.Web.Port = c.Web.Port
	s.Web.TLS = c.Web.TLS
	s.Web.CertFile = c.Web.CertFile
	s.Web.KeyFile = c.Web.KeyFile
	x := &s.Storage
	x.Backend = c.Storage.Backend
	x.DataDir = c.Storage.DataDir
	x.RetentionDays = c.Storage.RetentionDays
	x.ClickHouseURL = c.Storage.ClickHouseURL
	x.ClickHouseDatabase = c.Storage.ClickHouseDatabase
	x.ClickHouseTable = c.Storage.ClickHouseTable
	x.ClickHouseUser = c.Storage.ClickHouseUser
	x.ClickHousePasswordSet = c.Storage.ClickHousePassword != ""
	x.ClickHouseBatchSize = c.Storage.ClickHouseBatchSize
	x.ClickHouseFlushMS = c.Storage.ClickHouseFlushMS
	x.ClickHouseQueueSize = c.Storage.ClickHouseQueueSize
	x.ClickHouseCluster = c.Storage.ClickHouseCluster
	x.ClickHouseDistributedTable = c.Storage.ClickHouseDistributedTable
	x.ClickHouseReplicaPath = c.Storage.ClickHouseReplicaPath
	x.ClickHouseReplicaName = c.Storage.ClickHouseReplicaName
	s.Security.DefaultPolicy = c.Security.DefaultPolicy
	s.Security.SessionHours = c.Security.SessionHours
	s.Security.RequireMFA = c.Security.RequireMFA
	s.Logging.JSON = c.Logging.JSON
	s.Logging.Level = c.Logging.Level
	s.Analytics.BaselineEnabled = c.Analytics.BaselineEnabled
	s.Analytics.BaselineMinSamples = c.Analytics.BaselineMinSamples
	s.Analytics.BaselineSaveSeconds = c.Analytics.BaselineSaveSeconds
	s.Analytics.DedupEnabled = c.Analytics.DedupEnabled
	s.Analytics.DedupWindowSeconds = c.Analytics.DedupWindowSeconds
	s.Analytics.DedupMaxEntries = c.Analytics.DedupMaxEntries
	s.Enrichment.Enabled = c.Enrichment.Enabled
	s.Enrichment.PrefixFile = c.Enrichment.PrefixFile
	s.Enrichment.RemoteEnabled = c.Enrichment.RemoteEnabled
	s.Enrichment.RemoteURL = c.Enrichment.RemoteURL
	s.Cluster.HeartbeatURL = c.Cluster.HeartbeatURL
	s.Cluster.SharedTokenFile = c.Cluster.SharedTokenFile
	s.Cluster.HeartbeatSeconds = c.Cluster.HeartbeatSeconds
	s.Cluster.NodeTimeoutSeconds = c.Cluster.NodeTimeoutSeconds
	s.Cluster.AllowInsecureHTTP = c.Cluster.AllowInsecureHTTP
	s.Cluster.GlobalDedupEnabled = c.Cluster.GlobalDedupEnabled
	s.Cluster.GlobalDedupURL = c.Cluster.GlobalDedupURL
	s.Cluster.GlobalDedupTimeoutMS = c.Cluster.GlobalDedupTimeoutMS
	s.Cluster.GlobalDedupMaxEntries = c.Cluster.GlobalDedupMaxEntries
	s.Notifications.WebhookURL = c.Notifications.WebhookURL
	s.Notifications.TelegramChatID = c.Notifications.TelegramChatID
	s.Notifications.TelegramTokenSet = c.Notifications.TelegramBotToken != ""
	s.Notifications.SMTPAddr = c.Notifications.SMTPAddr
	s.Notifications.SMTPFrom = c.Notifications.SMTPFrom
	s.Notifications.SMTPTo = c.Notifications.SMTPTo
	s.Notifications.SMTPUsername = c.Notifications.SMTPUsername
	s.Notifications.SMTPPasswordSet = c.Notifications.SMTPPassword != ""
	s.Notifications.SyslogAddr = c.Notifications.SyslogAddr
	s.OIDC.Enabled = c.OIDC.Enabled
	s.OIDC.Issuer = c.OIDC.Issuer
	s.OIDC.ClientID = c.OIDC.ClientID
	s.OIDC.ClientSecretSet = c.OIDC.ClientSecret != ""
	s.OIDC.RedirectURL = c.OIDC.RedirectURL
	s.OIDC.DefaultRole = c.OIDC.DefaultRole
	s.OIDC.GroupRoleMap = c.OIDC.GroupRoleMap
	s.LDAP.Enabled = c.LDAP.Enabled
	s.LDAP.URL = c.LDAP.URL
	s.LDAP.BindDN = c.LDAP.BindDN
	s.LDAP.BindPasswordSet = c.LDAP.BindPassword != ""
	s.LDAP.BaseDN = c.LDAP.BaseDN
	s.LDAP.UserAttribute = c.LDAP.UserAttribute
	s.LDAP.UserDNTemplate = c.LDAP.UserDNTemplate
	s.LDAP.GroupAttribute = c.LDAP.GroupAttribute
	s.LDAP.GroupRoleMap = c.LDAP.GroupRoleMap
	s.LDAP.DefaultRole = c.LDAP.DefaultRole
	s.LDAP.AllowInsecure = c.LDAP.AllowInsecure
	s.Listeners = append([]config.Listener(nil), c.Listeners...)
	return s
}

func (m *Manager) candidate(in Settings) (config.Config, config.AdminOverride) {
	c := m.cfg
	o := m.override
	// data_dir is deliberately immutable from the portal because moving the live
	// state tree requires an offline migration. It remains visible in Settings.
	c.Web.Bind = in.Web.Bind
	c.Web.Port = in.Web.Port
	c.Web.TLS = in.Web.TLS
	c.Web.CertFile = in.Web.CertFile
	c.Web.KeyFile = in.Web.KeyFile
	c.Storage.Backend = in.Storage.Backend
	c.Storage.RetentionDays = in.Storage.RetentionDays
	c.Storage.ClickHouseURL = in.Storage.ClickHouseURL
	c.Storage.ClickHouseDatabase = in.Storage.ClickHouseDatabase
	c.Storage.ClickHouseTable = in.Storage.ClickHouseTable
	c.Storage.ClickHouseUser = in.Storage.ClickHouseUser
	c.Storage.ClickHouseBatchSize = in.Storage.ClickHouseBatchSize
	c.Storage.ClickHouseFlushMS = in.Storage.ClickHouseFlushMS
	c.Storage.ClickHouseQueueSize = in.Storage.ClickHouseQueueSize
	c.Storage.ClickHouseCluster = in.Storage.ClickHouseCluster
	c.Storage.ClickHouseDistributedTable = in.Storage.ClickHouseDistributedTable
	c.Storage.ClickHouseReplicaPath = in.Storage.ClickHouseReplicaPath
	c.Storage.ClickHouseReplicaName = in.Storage.ClickHouseReplicaName
	if in.Storage.NewClickHousePassword != "" {
		c.Storage.ClickHousePassword = in.Storage.NewClickHousePassword
	}
	c.Security.DefaultPolicy = in.Security.DefaultPolicy
	c.Security.SessionHours = in.Security.SessionHours
	c.Security.RequireMFA = in.Security.RequireMFA
	c.Logging.JSON = in.Logging.JSON
	c.Logging.Level = in.Logging.Level
	c.Analytics.BaselineEnabled = in.Analytics.BaselineEnabled
	c.Analytics.BaselineMinSamples = in.Analytics.BaselineMinSamples
	c.Analytics.BaselineSaveSeconds = in.Analytics.BaselineSaveSeconds
	c.Analytics.DedupEnabled = in.Analytics.DedupEnabled
	c.Analytics.DedupWindowSeconds = in.Analytics.DedupWindowSeconds
	c.Analytics.DedupMaxEntries = in.Analytics.DedupMaxEntries
	c.Enrichment.Enabled = in.Enrichment.Enabled
	c.Enrichment.PrefixFile = in.Enrichment.PrefixFile
	c.Enrichment.RemoteEnabled = in.Enrichment.RemoteEnabled
	c.Enrichment.RemoteURL = in.Enrichment.RemoteURL
	c.Cluster.HeartbeatURL = in.Cluster.HeartbeatURL
	c.Cluster.SharedTokenFile = in.Cluster.SharedTokenFile
	c.Cluster.HeartbeatSeconds = in.Cluster.HeartbeatSeconds
	c.Cluster.NodeTimeoutSeconds = in.Cluster.NodeTimeoutSeconds
	c.Cluster.AllowInsecureHTTP = in.Cluster.AllowInsecureHTTP
	c.Cluster.GlobalDedupEnabled = in.Cluster.GlobalDedupEnabled
	c.Cluster.GlobalDedupURL = in.Cluster.GlobalDedupURL
	c.Cluster.GlobalDedupTimeoutMS = in.Cluster.GlobalDedupTimeoutMS
	c.Cluster.GlobalDedupMaxEntries = in.Cluster.GlobalDedupMaxEntries
	c.Notifications.WebhookURL = in.Notifications.WebhookURL
	c.Notifications.TelegramChatID = in.Notifications.TelegramChatID
	c.Notifications.SMTPAddr = in.Notifications.SMTPAddr
	c.Notifications.SMTPFrom = in.Notifications.SMTPFrom
	c.Notifications.SMTPTo = in.Notifications.SMTPTo
	c.Notifications.SMTPUsername = in.Notifications.SMTPUsername
	c.Notifications.SyslogAddr = in.Notifications.SyslogAddr
	if in.Notifications.NewTelegramBotToken != "" {
		c.Notifications.TelegramBotToken = in.Notifications.NewTelegramBotToken
	}
	if in.Notifications.NewSMTPPassword != "" {
		c.Notifications.SMTPPassword = in.Notifications.NewSMTPPassword
	}
	c.OIDC.Enabled = in.OIDC.Enabled
	c.OIDC.Issuer = in.OIDC.Issuer
	c.OIDC.ClientID = in.OIDC.ClientID
	c.OIDC.RedirectURL = in.OIDC.RedirectURL
	c.OIDC.DefaultRole = in.OIDC.DefaultRole
	c.OIDC.GroupRoleMap = in.OIDC.GroupRoleMap
	if in.OIDC.NewClientSecret != "" {
		c.OIDC.ClientSecret = in.OIDC.NewClientSecret
	}
	c.LDAP.Enabled = in.LDAP.Enabled
	c.LDAP.URL = in.LDAP.URL
	c.LDAP.BindDN = in.LDAP.BindDN
	c.LDAP.BaseDN = in.LDAP.BaseDN
	c.LDAP.UserAttribute = in.LDAP.UserAttribute
	c.LDAP.UserDNTemplate = in.LDAP.UserDNTemplate
	c.LDAP.GroupAttribute = in.LDAP.GroupAttribute
	c.LDAP.GroupRoleMap = in.LDAP.GroupRoleMap
	c.LDAP.DefaultRole = in.LDAP.DefaultRole
	c.LDAP.AllowInsecure = in.LDAP.AllowInsecure
	if in.LDAP.NewBindPassword != "" {
		c.LDAP.BindPassword = in.LDAP.NewBindPassword
	}
	c.Listeners = append([]config.Listener(nil), in.Listeners...)
	// Build a complete portal-owned overlay for non-secret sections.
	o = overrideFrom(c, o, in)
	return c, o
}

func overrideFrom(c config.Config, old config.AdminOverride, in Settings) config.AdminOverride {
	var o config.AdminOverride
	o.Web = &struct {
		Bind     string `json:"bind"`
		Port     int    `json:"port"`
		TLS      bool   `json:"tls"`
		CertFile string `json:"cert_file"`
		KeyFile  string `json:"key_file"`
	}{c.Web.Bind, c.Web.Port, c.Web.TLS, c.Web.CertFile, c.Web.KeyFile}
	pass := (*string)(nil)
	if in.Storage.NewClickHousePassword != "" {
		v := in.Storage.NewClickHousePassword
		pass = &v
	} else if old.Storage != nil {
		pass = old.Storage.ClickHousePassword
	}
	o.Storage = &struct {
		Backend                    string  `json:"backend"`
		RetentionDays              int     `json:"retention_days"`
		ClickHouseURL              string  `json:"clickhouse_url"`
		ClickHouseDatabase         string  `json:"clickhouse_database"`
		ClickHouseTable            string  `json:"clickhouse_table"`
		ClickHouseUser             string  `json:"clickhouse_user"`
		ClickHousePassword         *string `json:"clickhouse_password,omitempty"`
		ClickHouseBatchSize        int     `json:"clickhouse_batch_size"`
		ClickHouseFlushMS          int     `json:"clickhouse_flush_ms"`
		ClickHouseQueueSize        int     `json:"clickhouse_queue_size"`
		ClickHouseCluster          string  `json:"clickhouse_cluster"`
		ClickHouseDistributedTable string  `json:"clickhouse_distributed_table"`
		ClickHouseReplicaPath      string  `json:"clickhouse_replica_path"`
		ClickHouseReplicaName      string  `json:"clickhouse_replica_name"`
	}{c.Storage.Backend, c.Storage.RetentionDays, c.Storage.ClickHouseURL, c.Storage.ClickHouseDatabase, c.Storage.ClickHouseTable, c.Storage.ClickHouseUser, pass, c.Storage.ClickHouseBatchSize, c.Storage.ClickHouseFlushMS, c.Storage.ClickHouseQueueSize, c.Storage.ClickHouseCluster, c.Storage.ClickHouseDistributedTable, c.Storage.ClickHouseReplicaPath, c.Storage.ClickHouseReplicaName}
	o.Security = &struct {
		DefaultPolicy string `json:"default_policy"`
		SessionHours  int    `json:"session_hours"`
		RequireMFA    bool   `json:"require_mfa"`
	}{c.Security.DefaultPolicy, c.Security.SessionHours, c.Security.RequireMFA}
	o.Logging = &struct {
		JSON  bool   `json:"json"`
		Level string `json:"level"`
	}{c.Logging.JSON, c.Logging.Level}
	o.Analytics = &struct {
		BaselineEnabled     bool `json:"baseline_enabled"`
		BaselineMinSamples  int  `json:"baseline_min_samples"`
		BaselineSaveSeconds int  `json:"baseline_save_seconds"`
		DedupEnabled        bool `json:"dedup_enabled"`
		DedupWindowSeconds  int  `json:"dedup_window_seconds"`
		DedupMaxEntries     int  `json:"dedup_max_entries"`
	}{c.Analytics.BaselineEnabled, c.Analytics.BaselineMinSamples, c.Analytics.BaselineSaveSeconds, c.Analytics.DedupEnabled, c.Analytics.DedupWindowSeconds, c.Analytics.DedupMaxEntries}
	o.Enrichment = &struct {
		Enabled       bool   `json:"enabled"`
		PrefixFile    string `json:"prefix_file"`
		RemoteEnabled bool   `json:"remote_enabled"`
		RemoteURL     string `json:"remote_url"`
	}{c.Enrichment.Enabled, c.Enrichment.PrefixFile, c.Enrichment.RemoteEnabled, c.Enrichment.RemoteURL}
	o.Cluster = &struct {
		HeartbeatURL          string `json:"heartbeat_url"`
		SharedTokenFile       string `json:"shared_token_file"`
		HeartbeatSeconds      int    `json:"heartbeat_seconds"`
		NodeTimeoutSeconds    int    `json:"node_timeout_seconds"`
		AllowInsecureHTTP     bool   `json:"allow_insecure_http"`
		GlobalDedupEnabled    bool   `json:"global_dedup_enabled"`
		GlobalDedupURL        string `json:"global_dedup_url"`
		GlobalDedupTimeoutMS  int    `json:"global_dedup_timeout_ms"`
		GlobalDedupMaxEntries int    `json:"global_dedup_max_entries"`
	}{c.Cluster.HeartbeatURL, c.Cluster.SharedTokenFile, c.Cluster.HeartbeatSeconds, c.Cluster.NodeTimeoutSeconds, c.Cluster.AllowInsecureHTTP, c.Cluster.GlobalDedupEnabled, c.Cluster.GlobalDedupURL, c.Cluster.GlobalDedupTimeoutMS, c.Cluster.GlobalDedupMaxEntries}
	tg := (*string)(nil)
	smtp := (*string)(nil)
	if in.Notifications.NewTelegramBotToken != "" {
		v := in.Notifications.NewTelegramBotToken
		tg = &v
	} else if old.Notifications != nil {
		tg = old.Notifications.TelegramBotToken
	}
	if in.Notifications.NewSMTPPassword != "" {
		v := in.Notifications.NewSMTPPassword
		smtp = &v
	} else if old.Notifications != nil {
		smtp = old.Notifications.SMTPPassword
	}
	o.Notifications = &struct {
		WebhookURL       string  `json:"webhook_url"`
		TelegramChatID   string  `json:"telegram_chat_id"`
		TelegramBotToken *string `json:"telegram_bot_token,omitempty"`
		SMTPAddr         string  `json:"smtp_addr"`
		SMTPFrom         string  `json:"smtp_from"`
		SMTPTo           string  `json:"smtp_to"`
		SMTPUsername     string  `json:"smtp_username"`
		SMTPPassword     *string `json:"smtp_password,omitempty"`
		SyslogAddr       string  `json:"syslog_addr"`
	}{c.Notifications.WebhookURL, c.Notifications.TelegramChatID, tg, c.Notifications.SMTPAddr, c.Notifications.SMTPFrom, c.Notifications.SMTPTo, c.Notifications.SMTPUsername, smtp, c.Notifications.SyslogAddr}
	oidcSecret := (*string)(nil)
	if in.OIDC.NewClientSecret != "" {
		v := in.OIDC.NewClientSecret
		oidcSecret = &v
	} else if old.OIDC != nil {
		oidcSecret = old.OIDC.ClientSecret
	}
	o.OIDC = &struct {
		Enabled      bool    `json:"enabled"`
		Issuer       string  `json:"issuer"`
		ClientID     string  `json:"client_id"`
		ClientSecret *string `json:"client_secret,omitempty"`
		RedirectURL  string  `json:"redirect_url"`
		DefaultRole  string  `json:"default_role"`
		GroupRoleMap string  `json:"group_role_map"`
	}{c.OIDC.Enabled, c.OIDC.Issuer, c.OIDC.ClientID, oidcSecret, c.OIDC.RedirectURL, c.OIDC.DefaultRole, c.OIDC.GroupRoleMap}
	ldapSecret := (*string)(nil)
	if in.LDAP.NewBindPassword != "" {
		v := in.LDAP.NewBindPassword
		ldapSecret = &v
	} else if old.LDAP != nil {
		ldapSecret = old.LDAP.BindPassword
	}
	o.LDAP = &struct {
		Enabled        bool    `json:"enabled"`
		URL            string  `json:"url"`
		BindDN         string  `json:"bind_dn"`
		BindPassword   *string `json:"bind_password,omitempty"`
		BaseDN         string  `json:"base_dn"`
		UserAttribute  string  `json:"user_attribute"`
		UserDNTemplate string  `json:"user_dn_template"`
		GroupAttribute string  `json:"group_attribute"`
		GroupRoleMap   string  `json:"group_role_map"`
		DefaultRole    string  `json:"default_role"`
		AllowInsecure  bool    `json:"allow_insecure"`
	}{c.LDAP.Enabled, c.LDAP.URL, c.LDAP.BindDN, ldapSecret, c.LDAP.BaseDN, c.LDAP.UserAttribute, c.LDAP.UserDNTemplate, c.LDAP.GroupAttribute, c.LDAP.GroupRoleMap, c.LDAP.DefaultRole, c.LDAP.AllowInsecure}
	ls := append([]config.Listener(nil), c.Listeners...)
	o.Listeners = &ls
	return o
}

func riskFor(path string) string {
	switch {
	case strings.HasPrefix(path, "storage.backend"), strings.HasPrefix(path, "storage.clickhouse"), strings.HasPrefix(path, "web."), strings.HasPrefix(path, "oidc."), strings.HasPrefix(path, "ldap."), strings.HasPrefix(path, "cluster."):
		return "critical"
	case strings.HasPrefix(path, "listeners"), strings.HasPrefix(path, "security."), strings.HasPrefix(path, "analytics."):
		return "operational"
	default:
		return "safe"
	}
}
func diffSettings(a, b Settings) []Change {
	ma := flatten(a)
	mb := flatten(b)
	keys := map[string]bool{}
	for k := range ma {
		keys[k] = true
	}
	for k := range mb {
		keys[k] = true
	}
	var out []Change
	for k := range keys {
		if strings.Contains(k, "new_") || strings.HasSuffix(k, "_set") {
			continue
		}
		if ma[k] != mb[k] {
			out = append(out, Change{Path: k, Before: ma[k], After: mb[k], Risk: riskFor(k)})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}
func flatten(v any) map[string]string {
	out := map[string]string{}
	var walk func(string, reflect.Value)
	walk = func(p string, x reflect.Value) {
		if x.Kind() == reflect.Pointer {
			if x.IsNil() {
				return
			}
			x = x.Elem()
		}
		switch x.Kind() {
		case reflect.Struct:
			for i := 0; i < x.NumField(); i++ {
				f := x.Type().Field(i)
				n := strings.Split(f.Tag.Get("json"), ",")[0]
				if n == "" || n == "-" {
					n = f.Name
				}
				q := n
				if p != "" {
					q = p + "." + n
				}
				walk(q, x.Field(i))
			}
		case reflect.Slice:
			b, _ := json.Marshal(x.Interface())
			out[p] = string(b)
		default:
			out[p] = fmt.Sprint(x.Interface())
		}
	}
	walk("", reflect.ValueOf(v))
	return out
}
func needsRestart(changes []Change) bool {
	for _, c := range changes {
		if c.Path != "storage.retention_days" {
			return true
		}
	}
	return false
}

func (m *Manager) Validate(in Settings) Validation {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cand, _ := m.candidate(in)
	ch := diffSettings(fromConfig(m.cfg), in)
	v := Validation{Valid: true, Changes: ch, RestartRequired: needsRestart(ch)}
	if in.Storage.DataDir != "" && filepath.Clean(in.Storage.DataDir) != filepath.Clean(m.dataDir) {
		v.Valid = false
		v.Error = "storage.data_dir cannot be moved online; use the installer/offline migration"
		return v
	}
	if err := config.Validate(cand); err != nil {
		v.Valid = false
		v.Error = err.Error()
		return v
	}
	if cand.Web.TLS && (strings.TrimSpace(cand.Web.CertFile) == "" || strings.TrimSpace(cand.Web.KeyFile) == "") {
		v.Valid = false
		v.Error = "TLS requires cert_file and key_file"
	}
	if v.RestartRequired {
		v.Warnings = append(v.Warnings, "One or more changes require a graceful service restart before they become active.")
	}
	return v
}

func (m *Manager) Apply(in Settings, user, reason string) (ApplyResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cand, after := m.candidate(in)
	ch := diffSettings(fromConfig(m.cfg), in)
	v := Validation{Valid: true, Changes: ch, RestartRequired: needsRestart(ch)}
	if in.Storage.DataDir != "" && filepath.Clean(in.Storage.DataDir) != filepath.Clean(m.dataDir) {
		v.Valid = false
		v.Error = "storage.data_dir cannot be moved online"
		return ApplyResult{Validation: v}, errors.New(v.Error)
	}
	if err := config.Validate(cand); err != nil {
		v.Valid = false
		v.Error = err.Error()
		return ApplyResult{Validation: v}, err
	}
	if len(ch) == 0 {
		return ApplyResult{Validation: v}, errors.New("no configuration changes")
	}
	critical := false
	for _, change := range ch {
		if change.Risk == "critical" {
			critical = true
			break
		}
	}
	if critical && strings.TrimSpace(reason) == "" {
		return ApplyResult{Validation: v}, errors.New("a change reason is required for critical configuration changes")
	}
	before := m.override
	if err := config.SaveAdminOverride(m.dataDir, after); err != nil {
		return ApplyResult{Validation: v}, err
	}
	now := time.Now().UTC()
	ver := Version{ID: fmt.Sprintf("cfg-%d", now.UnixNano()), CreatedAt: now, User: user, Reason: strings.TrimSpace(reason), Status: "active", RestartRequired: v.RestartRequired, Changes: ch, Before: before, After: after}
	for i := range m.versions {
		if m.versions[i].Status == "active" {
			m.versions[i].Status = "superseded"
		}
	}
	m.versions = append(m.versions, ver)
	m.override = after
	m.cfg = cand
	if err := m.saveHistoryLocked(); err != nil {
		return ApplyResult{Validation: v}, err
	}
	if v.RestartRequired {
		v.Warnings = append(v.Warnings, "Configuration is persisted. Restart the service to activate restart-required fields.")
	}
	return ApplyResult{Version: publicVersion(ver), Validation: v}, nil
}
func publicVersion(v Version) Version {
	v.Before = config.AdminOverride{}
	v.After = config.AdminOverride{}
	return v
}
func (m *Manager) Rollback(id, user, reason string) (Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var target *Version
	for i := range m.versions {
		if m.versions[i].ID == id {
			x := m.versions[i]
			target = &x
			break
		}
	}
	if target == nil {
		return Version{}, errors.New("configuration version not found")
	}
	before := m.override
	after := target.Before
	if err := config.SaveAdminOverride(m.dataDir, after); err != nil {
		return Version{}, err
	}
	cfg, err := config.Load(m.configPath)
	if err != nil {
		_ = config.SaveAdminOverride(m.dataDir, before)
		return Version{}, fmt.Errorf("rollback validation failed: %w", err)
	}
	now := time.Now().UTC()
	ver := Version{ID: fmt.Sprintf("cfg-%d", now.UnixNano()), CreatedAt: now, User: user, Reason: "rollback: " + strings.TrimSpace(reason), Status: "active", RestartRequired: true, Changes: diffSettings(fromConfig(m.cfg), fromConfig(cfg)), Before: before, After: after}
	for i := range m.versions {
		if m.versions[i].Status == "active" {
			m.versions[i].Status = "superseded"
		}
	}
	m.versions = append(m.versions, ver)
	m.override = after
	m.cfg = cfg
	if err = m.saveHistoryLocked(); err != nil {
		return Version{}, err
	}
	return publicVersion(ver), nil
}
func (m *Manager) saveHistoryLocked() error {
	if err := os.MkdirAll(m.dataDir, 0750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m.versions, "", "  ")
	if err != nil {
		return err
	}
	p := m.historyPath
	tmp := p + ".tmp"
	if err = os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (m *Manager) ProbeClickHouse(ctx context.Context, in Settings) ClickHouseProbe {
	m.mu.RLock()
	cur := m.cfg
	m.mu.RUnlock()
	pw := cur.Storage.ClickHousePassword
	if in.Storage.NewClickHousePassword != "" {
		pw = in.Storage.NewClickHousePassword
	}
	base := strings.TrimRight(in.Storage.ClickHouseURL, "/")
	if base == "" {
		return ClickHouseProbe{Error: "ClickHouse URL is required"}
	}
	start := time.Now()
	do := func(q string) (string, error) {
		u, err := url.Parse(base)
		if err != nil {
			return "", err
		}
		vv := u.Query()
		vv.Set("query", q)
		u.RawQuery = vv.Encode()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), nil)
		if err != nil {
			return "", err
		}
		if in.Storage.ClickHouseUser != "" {
			req.SetBasicAuth(in.Storage.ClickHouseUser, pw)
		}
		resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
		if err != nil {
			return "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		if resp.StatusCode/100 != 2 {
			return "", fmt.Errorf("HTTP %s: %s", resp.Status, strings.TrimSpace(string(b)))
		}
		return strings.TrimSpace(string(b)), nil
	}
	ver, err := do("SELECT version() FORMAT TabSeparatedRaw")
	p := ClickHouseProbe{LatencyMS: time.Since(start).Milliseconds(), ServerVersion: ver}
	if err != nil {
		p.Error = err.Error()
		return p
	}
	db := strings.ReplaceAll(in.Storage.ClickHouseDatabase, "'", "''")
	tbl := strings.ReplaceAll(in.Storage.ClickHouseTable, "'", "''")
	x, err := do(fmt.Sprintf("SELECT count() FROM system.databases WHERE name='%s' FORMAT TabSeparatedRaw", db))
	p.DatabaseExists = err == nil && strings.TrimSpace(x) == "1"
	if p.DatabaseExists {
		y, e := do(fmt.Sprintf("SELECT count() FROM system.tables WHERE database='%s' AND name='%s' FORMAT TabSeparatedRaw", db, tbl))
		p.TableExists = e == nil && strings.TrimSpace(y) == "1"
	}
	if _, err = do("SELECT 1 FORMAT TabSeparatedRaw"); err != nil {
		p.Error = err.Error()
		return p
	}
	if p.TableExists {
		identDB := "`" + strings.ReplaceAll(in.Storage.ClickHouseDatabase, "`", "``") + "`"
		identTable := "`" + strings.ReplaceAll(in.Storage.ClickHouseTable, "`", "``") + "`"
		if _, e := do("CHECK GRANT INSERT ON " + identDB + "." + identTable); e == nil {
			p.WriteProbe = true
		}
	}
	p.OK = true
	return p
}

type PendingRestore struct {
	Archive     string    `json:"archive"`
	RequestedBy string    `json:"requested_by"`
	CreatedAt   time.Time `json:"created_at"`
}

func PendingRestorePath(dataDir string) string { return filepath.Join(dataDir, "pending-restore.json") }
func ScheduleRestore(dataDir, archive, user string) error {
	r := PendingRestore{Archive: archive, RequestedBy: user, CreatedAt: time.Now().UTC()}
	b, _ := json.MarshalIndent(r, "", "  ")
	p := PendingRestorePath(dataDir)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
func LoadPendingRestore(dataDir string) (PendingRestore, error) {
	var r PendingRestore
	b, err := os.ReadFile(PendingRestorePath(dataDir))
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	return r, nil
}

// EffectiveConfig returns a copy for in-process control-plane operations. API
// responses must never serialize this value because it may contain secrets.
func (m *Manager) EffectiveConfig() config.Config { m.mu.RLock(); defer m.mu.RUnlock(); return m.cfg }
