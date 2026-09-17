package config

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// AdminOverride is the persisted control-plane overlay written by the web
// administration center. Sections are pointers so an absent section preserves
// the corresponding value from config.yaml/environment. Secrets are only
// persisted when an administrator explicitly changes them.
type AdminOverride struct {
	Web *struct {
		Bind     string `json:"bind"`
		Port     int    `json:"port"`
		TLS      bool   `json:"tls"`
		CertFile string `json:"cert_file"`
		KeyFile  string `json:"key_file"`
	} `json:"web,omitempty"`
	Storage *struct {
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
	} `json:"storage,omitempty"`
	Security *struct {
		DefaultPolicy string `json:"default_policy"`
		SessionHours  int    `json:"session_hours"`
		RequireMFA    bool   `json:"require_mfa"`
	} `json:"security,omitempty"`
	Logging *struct {
		JSON  bool   `json:"json"`
		Level string `json:"level"`
	} `json:"logging,omitempty"`
	Analytics *struct {
		BaselineEnabled     bool `json:"baseline_enabled"`
		BaselineMinSamples  int  `json:"baseline_min_samples"`
		BaselineSaveSeconds int  `json:"baseline_save_seconds"`
		DedupEnabled        bool `json:"dedup_enabled"`
		DedupWindowSeconds  int  `json:"dedup_window_seconds"`
		DedupMaxEntries     int  `json:"dedup_max_entries"`
	} `json:"analytics,omitempty"`
	Enrichment *struct {
		Enabled       bool   `json:"enabled"`
		PrefixFile    string `json:"prefix_file"`
		RemoteEnabled bool   `json:"remote_enabled"`
		RemoteURL     string `json:"remote_url"`
	} `json:"enrichment,omitempty"`
	Cluster *struct {
		HeartbeatURL          string `json:"heartbeat_url"`
		SharedTokenFile       string `json:"shared_token_file"`
		HeartbeatSeconds      int    `json:"heartbeat_seconds"`
		NodeTimeoutSeconds    int    `json:"node_timeout_seconds"`
		AllowInsecureHTTP     bool   `json:"allow_insecure_http"`
		GlobalDedupEnabled    bool   `json:"global_dedup_enabled"`
		GlobalDedupURL        string `json:"global_dedup_url"`
		GlobalDedupTimeoutMS  int    `json:"global_dedup_timeout_ms"`
		GlobalDedupMaxEntries int    `json:"global_dedup_max_entries"`
	} `json:"cluster,omitempty"`
	Notifications *struct {
		WebhookURL       string  `json:"webhook_url"`
		TelegramChatID   string  `json:"telegram_chat_id"`
		TelegramBotToken *string `json:"telegram_bot_token,omitempty"`
		SMTPAddr         string  `json:"smtp_addr"`
		SMTPFrom         string  `json:"smtp_from"`
		SMTPTo           string  `json:"smtp_to"`
		SMTPUsername     string  `json:"smtp_username"`
		SMTPPassword     *string `json:"smtp_password,omitempty"`
		SyslogAddr       string  `json:"syslog_addr"`
	} `json:"notifications,omitempty"`
	OIDC *struct {
		Enabled      bool    `json:"enabled"`
		Issuer       string  `json:"issuer"`
		ClientID     string  `json:"client_id"`
		ClientSecret *string `json:"client_secret,omitempty"`
		RedirectURL  string  `json:"redirect_url"`
		DefaultRole  string  `json:"default_role"`
		GroupRoleMap string  `json:"group_role_map"`
	} `json:"oidc,omitempty"`
	LDAP *struct {
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
	} `json:"ldap,omitempty"`
	Listeners *[]Listener `json:"listeners,omitempty"`
}

func AdminOverridePath(dataDir string) string { return filepath.Join(dataDir, "admin-settings.json") }

func LoadAdminOverride(dataDir string) (AdminOverride, error) {
	var o AdminOverride
	b, err := os.ReadFile(AdminOverridePath(dataDir))
	if errors.Is(err, os.ErrNotExist) {
		return o, nil
	}
	if err != nil {
		return o, err
	}
	if err = json.Unmarshal(b, &o); err != nil {
		return o, err
	}
	return o, nil
}

func SaveAdminOverride(dataDir string, o AdminOverride) error {
	if strings.TrimSpace(dataDir) == "" {
		return errors.New("data directory is required")
	}
	if err := os.MkdirAll(dataDir, 0750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	p := AdminOverridePath(dataDir)
	tmp := p + ".tmp"
	if err = os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	if err = os.Chmod(tmp, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func ApplyAdminOverride(c *Config, o AdminOverride) {
	if o.Web != nil {
		c.Web.Bind = o.Web.Bind
		c.Web.Port = o.Web.Port
		c.Web.TLS = o.Web.TLS
		c.Web.CertFile = o.Web.CertFile
		c.Web.KeyFile = o.Web.KeyFile
	}
	if o.Storage != nil {
		x := o.Storage
		c.Storage.Backend = x.Backend
		c.Storage.RetentionDays = x.RetentionDays
		c.Storage.ClickHouseURL = x.ClickHouseURL
		c.Storage.ClickHouseDatabase = x.ClickHouseDatabase
		c.Storage.ClickHouseTable = x.ClickHouseTable
		c.Storage.ClickHouseUser = x.ClickHouseUser
		if x.ClickHousePassword != nil {
			c.Storage.ClickHousePassword = *x.ClickHousePassword
		}
		c.Storage.ClickHouseBatchSize = x.ClickHouseBatchSize
		c.Storage.ClickHouseFlushMS = x.ClickHouseFlushMS
		c.Storage.ClickHouseQueueSize = x.ClickHouseQueueSize
		c.Storage.ClickHouseCluster = x.ClickHouseCluster
		c.Storage.ClickHouseDistributedTable = x.ClickHouseDistributedTable
		c.Storage.ClickHouseReplicaPath = x.ClickHouseReplicaPath
		c.Storage.ClickHouseReplicaName = x.ClickHouseReplicaName
	}
	if o.Security != nil {
		c.Security.DefaultPolicy = o.Security.DefaultPolicy
		c.Security.SessionHours = o.Security.SessionHours
		c.Security.RequireMFA = o.Security.RequireMFA
	}
	if o.Logging != nil {
		c.Logging.JSON = o.Logging.JSON
		c.Logging.Level = o.Logging.Level
	}
	if o.Analytics != nil {
		c.Analytics.BaselineEnabled = o.Analytics.BaselineEnabled
		c.Analytics.BaselineMinSamples = o.Analytics.BaselineMinSamples
		c.Analytics.BaselineSaveSeconds = o.Analytics.BaselineSaveSeconds
		c.Analytics.DedupEnabled = o.Analytics.DedupEnabled
		c.Analytics.DedupWindowSeconds = o.Analytics.DedupWindowSeconds
		c.Analytics.DedupMaxEntries = o.Analytics.DedupMaxEntries
	}
	if o.Enrichment != nil {
		c.Enrichment.Enabled = o.Enrichment.Enabled
		c.Enrichment.PrefixFile = o.Enrichment.PrefixFile
		if o.Enrichment.RemoteURL != "" {
			c.Enrichment.RemoteEnabled = o.Enrichment.RemoteEnabled
			c.Enrichment.RemoteURL = o.Enrichment.RemoteURL
		}
	}
	if o.Cluster != nil {
		x := o.Cluster
		c.Cluster.HeartbeatURL = x.HeartbeatURL
		c.Cluster.SharedTokenFile = x.SharedTokenFile
		c.Cluster.HeartbeatSeconds = x.HeartbeatSeconds
		c.Cluster.NodeTimeoutSeconds = x.NodeTimeoutSeconds
		c.Cluster.AllowInsecureHTTP = x.AllowInsecureHTTP
		c.Cluster.GlobalDedupEnabled = x.GlobalDedupEnabled
		c.Cluster.GlobalDedupURL = x.GlobalDedupURL
		c.Cluster.GlobalDedupTimeoutMS = x.GlobalDedupTimeoutMS
		c.Cluster.GlobalDedupMaxEntries = x.GlobalDedupMaxEntries
	}
	if o.Notifications != nil {
		x := o.Notifications
		c.Notifications.WebhookURL = x.WebhookURL
		c.Notifications.TelegramChatID = x.TelegramChatID
		if x.TelegramBotToken != nil {
			c.Notifications.TelegramBotToken = *x.TelegramBotToken
		}
		c.Notifications.SMTPAddr = x.SMTPAddr
		c.Notifications.SMTPFrom = x.SMTPFrom
		c.Notifications.SMTPTo = x.SMTPTo
		c.Notifications.SMTPUsername = x.SMTPUsername
		if x.SMTPPassword != nil {
			c.Notifications.SMTPPassword = *x.SMTPPassword
		}
		c.Notifications.SyslogAddr = x.SyslogAddr
	}
	if o.OIDC != nil {
		x := o.OIDC
		c.OIDC.Enabled = x.Enabled
		c.OIDC.Issuer = x.Issuer
		c.OIDC.ClientID = x.ClientID
		if x.ClientSecret != nil {
			c.OIDC.ClientSecret = *x.ClientSecret
		}
		c.OIDC.RedirectURL = x.RedirectURL
		c.OIDC.DefaultRole = x.DefaultRole
		c.OIDC.GroupRoleMap = x.GroupRoleMap
	}
	if o.LDAP != nil {
		x := o.LDAP
		c.LDAP.Enabled = x.Enabled
		c.LDAP.URL = x.URL
		c.LDAP.BindDN = x.BindDN
		if x.BindPassword != nil {
			c.LDAP.BindPassword = *x.BindPassword
		}
		c.LDAP.BaseDN = x.BaseDN
		c.LDAP.UserAttribute = x.UserAttribute
		c.LDAP.UserDNTemplate = x.UserDNTemplate
		c.LDAP.GroupAttribute = x.GroupAttribute
		c.LDAP.GroupRoleMap = x.GroupRoleMap
		c.LDAP.DefaultRole = x.DefaultRole
		c.LDAP.AllowInsecure = x.AllowInsecure
	}
	if o.Listeners != nil {
		c.Listeners = append([]Listener(nil), (*o.Listeners)...)
	}
}
