package config

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type Listener struct {
	Name       string `json:"name"`
	Bind       string `json:"bind"`
	Port       int    `json:"port"`
	Protocol   string `json:"protocol"`
	Workers    int    `json:"workers"`
	QueueSize  int    `json:"queue_size"`
	ReadBuffer int    `json:"read_buffer"`
	BatchSize  int    `json:"batch_size"`
	Enabled    bool   `json:"enabled"`
	Transport  string `json:"transport"`
}

type Config struct {
	Node struct {
		ID     string `json:"id"`
		Region string `json:"region"`
	} `json:"node"`
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
		RequireMTLS           bool   `json:"require_mtls"`
		CAFile                string `json:"ca_file"`
		CertFile              string `json:"cert_file"`
		KeyFile               string `json:"key_file"`
		ServerName            string `json:"server_name"`
		ExpectedNodes         int    `json:"expected_nodes"`
	} `json:"cluster"`
	Web struct {
		Bind     string `json:"bind"`
		Port     int    `json:"port"`
		TLS      bool   `json:"tls"`
		CertFile string `json:"cert_file"`
		KeyFile  string `json:"key_file"`
	} `json:"web"`
	Storage struct {
		Backend                     string `json:"backend"`
		DataDir                     string `json:"data_dir"`
		RetentionDays               int    `json:"retention_days"`
		ClickHouseURL               string `json:"clickhouse_url"`
		ClickHouseDatabase          string `json:"clickhouse_database"`
		ClickHouseTable             string `json:"clickhouse_table"`
		ClickHouseUser              string `json:"clickhouse_user"`
		ClickHousePassword          string `json:"clickhouse_password"`
		ClickHouseBatchSize         int    `json:"clickhouse_batch_size"`
		ClickHouseFlushMS           int    `json:"clickhouse_flush_ms"`
		ClickHouseQueueSize         int    `json:"clickhouse_queue_size"`
		ClickHouseCluster           string `json:"clickhouse_cluster"`
		ClickHouseDistributedTable  string `json:"clickhouse_distributed_table"`
		ClickHouseReplicaPath       string `json:"clickhouse_replica_path"`
		ClickHouseReplicaName       string `json:"clickhouse_replica_name"`
		ClickHouseSpoolEnabled      bool   `json:"clickhouse_spool_enabled"`
		ClickHouseSpoolMaxBytes     int64  `json:"clickhouse_spool_max_bytes"`
		ClickHouseSpoolReplaySecs   int    `json:"clickhouse_spool_replay_seconds"`
		ClickHouseSpoolSegmentBytes int64  `json:"clickhouse_spool_segment_bytes"`
		ClickHouseSpoolFsync        bool   `json:"clickhouse_spool_fsync"`
		ClickHouseQueryTimeoutMS    int    `json:"clickhouse_query_timeout_ms"`
		ClickHouseMaxResultRows     int    `json:"clickhouse_max_result_rows"`
		ClickHouseMaxExecutionSecs  int    `json:"clickhouse_max_execution_seconds"`
		ClickHouseStoragePolicy     string `json:"clickhouse_storage_policy"`
		ClickHouseColdVolume        string `json:"clickhouse_cold_volume"`
		ClickHouseColdAfterDays     int    `json:"clickhouse_cold_after_days"`
	} `json:"storage"`
	Security struct {
		DefaultPolicy         string `json:"default_policy"`
		SessionHours          int    `json:"session_hours"`
		BootstrapFile         string `json:"bootstrap_file"`
		RequireMFA            bool   `json:"require_mfa"`
		ExporterPacketsPerSec int    `json:"exporter_packets_per_second"`
		ExporterBurst         int    `json:"exporter_burst"`
		DiagnosticsEnabled    bool   `json:"diagnostics_enabled"`
	} `json:"security"`
	OIDC struct {
		Enabled      bool   `json:"enabled"`
		Issuer       string `json:"issuer"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		RedirectURL  string `json:"redirect_url"`
		DefaultRole  string `json:"default_role"`
		GroupRoleMap string `json:"group_role_map"`
	} `json:"oidc"`
	LDAP struct {
		Enabled        bool   `json:"enabled"`
		URL            string `json:"url"`
		BindDN         string `json:"bind_dn"`
		BindPassword   string `json:"bind_password"`
		BaseDN         string `json:"base_dn"`
		UserAttribute  string `json:"user_attribute"`
		UserDNTemplate string `json:"user_dn_template"`
		GroupAttribute string `json:"group_attribute"`
		GroupRoleMap   string `json:"group_role_map"`
		DefaultRole    string `json:"default_role"`
		AllowInsecure  bool   `json:"allow_insecure"`
	} `json:"ldap"`
	Logging struct {
		JSON  bool   `json:"json"`
		Level string `json:"level"`
	} `json:"logging"`
	Enrichment struct {
		Enabled       bool   `json:"enabled"`
		PrefixFile    string `json:"prefix_file"`
		RemoteEnabled bool   `json:"remote_enabled"`
		RemoteURL     string `json:"remote_url"`
	} `json:"enrichment"`
	Analytics struct {
		BaselineEnabled     bool   `json:"baseline_enabled"`
		BaselineMinSamples  int    `json:"baseline_min_samples"`
		BaselineStateFile   string `json:"baseline_state_file"`
		BaselineSaveSeconds int    `json:"baseline_save_seconds"`
		DedupEnabled        bool   `json:"dedup_enabled"`
		DedupWindowSeconds  int    `json:"dedup_window_seconds"`
		DedupMaxEntries     int    `json:"dedup_max_entries"`
		MaxTrackedHosts     int    `json:"max_tracked_hosts"`
		MaxDimensionKeys    int    `json:"max_dimension_keys"`
	} `json:"analytics"`
	Notifications struct {
		WebhookURL       string `json:"webhook_url"`
		WebhookSecret    string `json:"webhook_secret"`
		TelegramBotToken string `json:"telegram_bot_token"`
		TelegramChatID   string `json:"telegram_chat_id"`
		SMTPAddr         string `json:"smtp_addr"`
		SMTPFrom         string `json:"smtp_from"`
		SMTPTo           string `json:"smtp_to"`
		SMTPUsername     string `json:"smtp_username"`
		SMTPPassword     string `json:"smtp_password"`
		SyslogAddr       string `json:"syslog_addr"`
	} `json:"notifications"`
	Listeners []Listener `json:"listeners"`
}

func Default() Config {
	var c Config
	c.Cluster.SharedTokenFile = "/etc/flowcollector/cluster.token"
	c.Cluster.HeartbeatSeconds = 30
	c.Cluster.NodeTimeoutSeconds = 90
	c.Cluster.GlobalDedupTimeoutMS = 300
	c.Cluster.GlobalDedupMaxEntries = 500000
	c.Cluster.ExpectedNodes = 1
	// The portal is intended to be reachable from the management network by
	// default. Access is constrained by the management IP policy and TLS can be
	// enabled for untrusted networks.
	c.Web.Bind = "0.0.0.0"
	c.Web.Port = 8080
	c.Web.TLS = false
	c.Storage.Backend = "local"
	c.Storage.DataDir = "/var/lib/flowcollector"
	c.Storage.RetentionDays = 7
	c.Storage.ClickHouseURL = "http://127.0.0.1:8123"
	c.Storage.ClickHouseDatabase = "flowcollector"
	c.Storage.ClickHouseTable = "flows"
	c.Storage.ClickHouseUser = "default"
	c.Storage.ClickHouseBatchSize = 2000
	c.Storage.ClickHouseFlushMS = 1000
	c.Storage.ClickHouseQueueSize = 65536
	c.Storage.ClickHouseDistributedTable = "flows_distributed"
	c.Storage.ClickHouseReplicaPath = "/clickhouse/tables/{shard}/flowcollector/flows"
	c.Storage.ClickHouseReplicaName = "{replica}"
	c.Storage.ClickHouseSpoolEnabled = true
	c.Storage.ClickHouseSpoolMaxBytes = 2 << 30
	c.Storage.ClickHouseSpoolReplaySecs = 5
	c.Storage.ClickHouseSpoolSegmentBytes = 64 << 20
	c.Storage.ClickHouseSpoolFsync = true
	c.Storage.ClickHouseQueryTimeoutMS = 12000
	c.Storage.ClickHouseMaxResultRows = 100000
	c.Storage.ClickHouseMaxExecutionSecs = 12
	c.Storage.ClickHouseColdAfterDays = 0
	c.Security.DefaultPolicy = "deny"
	c.Security.SessionHours = 8
	c.Security.ExporterPacketsPerSec = 50000
	c.Security.ExporterBurst = 100000
	c.Security.DiagnosticsEnabled = false
	c.Security.BootstrapFile = "/var/lib/flowcollector/bootstrap-admin.txt"
	c.OIDC.DefaultRole = "read_only"
	c.LDAP.UserAttribute = "sAMAccountName"
	c.LDAP.GroupAttribute = "memberOf"
	c.LDAP.DefaultRole = "read_only"
	c.Logging.Level = "info"
	c.Enrichment.Enabled = true
	c.Enrichment.PrefixFile = "/var/lib/flowcollector/enrichment/geoasn.csv"
	c.Enrichment.RemoteEnabled = true
	c.Enrichment.RemoteURL = "https://ipwho.is"
	c.Analytics.BaselineEnabled = true
	c.Analytics.BaselineMinSamples = 20
	c.Analytics.BaselineSaveSeconds = 60
	c.Analytics.DedupEnabled = true
	c.Analytics.DedupWindowSeconds = 30
	c.Analytics.DedupMaxEntries = 200000
	c.Analytics.MaxTrackedHosts = 20000
	c.Analytics.MaxDimensionKeys = 100000
	c.Listeners = []Listener{
		{Name: "netflow", Bind: "0.0.0.0", Port: 2055, Protocol: "netflow", Transport: "udp", Workers: 4, QueueSize: 8192, ReadBuffer: 4 << 20, BatchSize: 16, Enabled: true},
		{Name: "ipfix", Bind: "0.0.0.0", Port: 4739, Protocol: "ipfix", Transport: "udp", Workers: 4, QueueSize: 8192, ReadBuffer: 4 << 20, BatchSize: 16, Enabled: true},
		{Name: "sflow", Bind: "0.0.0.0", Port: 6343, Protocol: "sflow", Transport: "udp", Workers: 4, QueueSize: 8192, ReadBuffer: 4 << 20, BatchSize: 16, Enabled: true},
	}
	return c
}

func Load(path string) (Config, error) {
	c := Default()
	b, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := parseYAMLSubset(string(b), &c); err != nil {
		return c, err
	}
	// Portal-managed settings are stored as a separate, permission-restricted
	// overlay. Environment variables intentionally remain highest precedence.
	if o, oe := LoadAdminOverride(c.Storage.DataDir); oe != nil {
		return c, fmt.Errorf("admin settings: %w", oe)
	} else {
		ApplyAdminOverride(&c, o)
	}
	applyEnv(&c)
	if c.Security.BootstrapFile == "" {
		c.Security.BootstrapFile = filepath.Join(c.Storage.DataDir, "bootstrap-admin.txt")
	}
	if c.Analytics.BaselineStateFile == "" {
		c.Analytics.BaselineStateFile = filepath.Join(c.Storage.DataDir, "baseline-state.json")
	}
	return c, Validate(c)
}

func Validate(c Config) error {
	if len(c.Node.ID) > 64 {
		return errors.New("node.id must be at most 64 characters")
	}
	for _, r := range c.Node.ID {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._-", r)) {
			return errors.New("node.id may contain only letters, digits, dot, underscore and dash")
		}
	}
	if c.Cluster.HeartbeatSeconds < 5 || c.Cluster.HeartbeatSeconds > 3600 {
		return errors.New("cluster.heartbeat_seconds must be 5..3600")
	}
	if c.Cluster.NodeTimeoutSeconds < c.Cluster.HeartbeatSeconds*2 || c.Cluster.NodeTimeoutSeconds > 86400 {
		return errors.New("cluster.node_timeout_seconds must be at least 2x heartbeat_seconds and <=86400")
	}
	if c.Cluster.HeartbeatURL != "" {
		u, err := url.Parse(c.Cluster.HeartbeatURL)
		if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			return errors.New("cluster.heartbeat_url must be an absolute http(s) URL")
		}
		if u.Scheme == "http" && !c.Cluster.AllowInsecureHTTP {
			h := u.Hostname()
			if h != "127.0.0.1" && h != "localhost" && h != "::1" {
				return errors.New("cluster.heartbeat_url must use https for non-loopback destinations unless allow_insecure_http=true")
			}
		}
		if strings.TrimSpace(c.Cluster.SharedTokenFile) == "" {
			return errors.New("cluster.shared_token_file is required when heartbeat_url is configured")
		}
	}
	if c.Cluster.GlobalDedupEnabled {
		if c.Cluster.GlobalDedupTimeoutMS < 50 || c.Cluster.GlobalDedupTimeoutMS > 5000 {
			return errors.New("cluster.global_dedup_timeout_ms must be 50..5000")
		}
		if c.Cluster.GlobalDedupMaxEntries < 1000 || c.Cluster.GlobalDedupMaxEntries > 5000000 {
			return errors.New("cluster.global_dedup_max_entries must be 1000..5000000")
		}
		if strings.TrimSpace(c.Cluster.SharedTokenFile) == "" {
			return errors.New("cluster.shared_token_file is required for global dedup")
		}
		if c.Cluster.GlobalDedupURL != "" {
			u, err := url.Parse(c.Cluster.GlobalDedupURL)
			if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
				return errors.New("cluster.global_dedup_url must be an absolute http(s) URL")
			}
			if u.Scheme == "http" && !c.Cluster.AllowInsecureHTTP {
				h := u.Hostname()
				if h != "127.0.0.1" && h != "localhost" && h != "::1" {
					return errors.New("cluster.global_dedup_url must use https for non-loopback destinations unless allow_insecure_http=true")
				}
			}
		}
	}
	if c.Web.Port < 1 || c.Web.Port > 65535 {
		return errors.New("web.port must be 1..65535")
	}
	if strings.TrimSpace(c.Web.Bind) == "" {
		return errors.New("web.bind is required")
	}
	if c.Web.TLS {
		if strings.TrimSpace(c.Web.CertFile) == "" || strings.TrimSpace(c.Web.KeyFile) == "" {
			return errors.New("web.tls=true requires explicit web.cert_file and web.key_file; automatic self-signed certificates are intentionally disabled")
		}
	}
	if c.Storage.Backend != "local" && c.Storage.Backend != "clickhouse" {
		return fmt.Errorf("storage.backend must be local or clickhouse, got %q", c.Storage.Backend)
	}
	if c.Storage.Backend == "clickhouse" {
		if !strings.HasPrefix(c.Storage.ClickHouseURL, "http://") && !strings.HasPrefix(c.Storage.ClickHouseURL, "https://") {
			return errors.New("storage.clickhouse_url must start with http:// or https://")
		}
		if c.Storage.ClickHouseDatabase == "" || c.Storage.ClickHouseTable == "" {
			return errors.New("storage.clickhouse_database and storage.clickhouse_table are required")
		}
		for name, val := range map[string]string{"database": c.Storage.ClickHouseDatabase, "table": c.Storage.ClickHouseTable, "cluster": c.Storage.ClickHouseCluster, "distributed_table": c.Storage.ClickHouseDistributedTable} {
			if val != "" {
				for i, r := range val {
					if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || (i > 0 && r >= '0' && r <= '9')) {
						return fmt.Errorf("storage.clickhouse_%s contains invalid identifier characters", name)
					}
				}
			}
		}
		if c.Storage.ClickHouseCluster != "" {
			if c.Storage.ClickHouseDistributedTable == "" || c.Storage.ClickHouseReplicaPath == "" || c.Storage.ClickHouseReplicaName == "" {
				return errors.New("clustered ClickHouse requires distributed_table, replica_path and replica_name")
			}
		}
		if c.Storage.ClickHouseBatchSize < 1 || c.Storage.ClickHouseBatchSize > 100000 {
			return errors.New("storage.clickhouse_batch_size must be 1..100000")
		}
		if c.Storage.ClickHouseFlushMS < 50 || c.Storage.ClickHouseFlushMS > 60000 {
			return errors.New("storage.clickhouse_flush_ms must be 50..60000")
		}
		if c.Storage.ClickHouseQueueSize < 64 || c.Storage.ClickHouseQueueSize > 2000000 {
			return errors.New("storage.clickhouse_queue_size must be 64..2000000")
		}
	}
	if c.Enrichment.Enabled && strings.TrimSpace(c.Enrichment.PrefixFile) == "" {
		return errors.New("enrichment.prefix_file is required when enrichment.enabled=true")
	}
	if c.Storage.RetentionDays < 1 || c.Storage.RetentionDays > 3650 {
		return errors.New("storage.retention_days must be 1..3650")
	}
	if (c.Notifications.TelegramBotToken == "") != (c.Notifications.TelegramChatID == "") {
		return errors.New("notifications.telegram_bot_token and telegram_chat_id must be configured together")
	}
	if c.Notifications.SMTPAddr != "" && (c.Notifications.SMTPFrom == "" || c.Notifications.SMTPTo == "") {
		return errors.New("notifications.smtp_addr requires smtp_from and smtp_to")
	}
	if c.Notifications.WebhookURL != "" && !strings.HasPrefix(c.Notifications.WebhookURL, "http://") && !strings.HasPrefix(c.Notifications.WebhookURL, "https://") {
		return errors.New("notifications.webhook_url must use http:// or https://")
	}
	if c.Analytics.BaselineMinSamples < 5 || c.Analytics.BaselineMinSamples > 10000 {
		return errors.New("analytics.baseline_min_samples must be 5..10000")
	}
	if c.Analytics.BaselineSaveSeconds < 10 || c.Analytics.BaselineSaveSeconds > 3600 {
		return errors.New("analytics.baseline_save_seconds must be 10..3600")
	}
	if c.Analytics.DedupWindowSeconds < 1 || c.Analytics.DedupWindowSeconds > 3600 {
		return errors.New("analytics.dedup_window_seconds must be 1..3600")
	}
	if c.Analytics.DedupMaxEntries < 1000 || c.Analytics.DedupMaxEntries > 5000000 {
		return errors.New("analytics.dedup_max_entries must be 1000..5000000")
	}
	if c.LDAP.Enabled {
		u, err := url.Parse(c.LDAP.URL)
		if err != nil || (u.Scheme != "ldap" && u.Scheme != "ldaps") {
			return errors.New("ldap.url must use ldap:// or ldaps://")
		}
		if u.Scheme == "ldap" && !c.LDAP.AllowInsecure {
			return errors.New("ldap:// requires ldap.allow_insecure=true; prefer ldaps://")
		}
		if strings.TrimSpace(c.LDAP.BaseDN) == "" && strings.TrimSpace(c.LDAP.UserDNTemplate) == "" {
			return errors.New("ldap.base_dn or ldap.user_dn_template is required")
		}
	}
	if c.OIDC.Enabled {
		if strings.TrimSpace(c.OIDC.Issuer) == "" || strings.TrimSpace(c.OIDC.ClientID) == "" || strings.TrimSpace(c.OIDC.RedirectURL) == "" {
			return errors.New("oidc.enabled=true requires issuer, client_id and redirect_url")
		}
		if c.OIDC.DefaultRole != "read_only" && c.OIDC.DefaultRole != "analyst" {
			return errors.New("oidc.default_role must be read_only or analyst")
		}
		for name, raw := range map[string]string{"issuer": c.OIDC.Issuer, "redirect_url": c.OIDC.RedirectURL} {
			u, e := url.Parse(raw)
			if e != nil || u.Scheme == "" || u.Host == "" {
				return fmt.Errorf("oidc.%s is invalid", name)
			}
			if u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "localhost" || u.Hostname() == "::1")) {
				return fmt.Errorf("oidc.%s must use https except loopback development URLs", name)
			}
		}
	}
	if c.Security.DefaultPolicy != "deny" && c.Security.DefaultPolicy != "allow" {
		return errors.New("security.default_policy must be deny or allow")
	}
	if c.Security.ExporterPacketsPerSec < 0 || c.Security.ExporterPacketsPerSec > 10_000_000 {
		return errors.New("security.exporter_packets_per_second must be 0..10000000")
	}
	if c.Security.ExporterBurst < 0 || c.Security.ExporterBurst > 20_000_000 {
		return errors.New("security.exporter_burst must be 0..20000000")
	}
	if c.Storage.ClickHouseSpoolMaxBytes < 0 || c.Storage.ClickHouseSpoolMaxBytes > 1<<40 {
		return errors.New("storage.clickhouse_spool_max_bytes must be 0..1TiB")
	}
	if c.Storage.ClickHouseSpoolReplaySecs < 1 || c.Storage.ClickHouseSpoolReplaySecs > 3600 {
		return errors.New("storage.clickhouse_spool_replay_seconds must be 1..3600")
	}
	if c.Storage.ClickHouseSpoolSegmentBytes < 1<<20 || c.Storage.ClickHouseSpoolSegmentBytes > 1<<30 {
		return errors.New("storage.clickhouse_spool_segment_bytes must be 1MiB..1GiB")
	}
	if c.Storage.ClickHouseQueryTimeoutMS < 100 || c.Storage.ClickHouseQueryTimeoutMS > 120000 {
		return errors.New("storage.clickhouse_query_timeout_ms must be 100..120000")
	}
	if c.Storage.ClickHouseMaxResultRows < 100 || c.Storage.ClickHouseMaxResultRows > 1000000 {
		return errors.New("storage.clickhouse_max_result_rows must be 100..1000000")
	}
	if c.Storage.ClickHouseMaxExecutionSecs < 1 || c.Storage.ClickHouseMaxExecutionSecs > 300 {
		return errors.New("storage.clickhouse_max_execution_seconds must be 1..300")
	}
	for name, val := range map[string]string{"storage_policy": c.Storage.ClickHouseStoragePolicy, "cold_volume": c.Storage.ClickHouseColdVolume} {
		for i, r := range val {
			if !(r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || (i > 0 && r >= '0' && r <= '9')) {
				return fmt.Errorf("storage.clickhouse_%s contains invalid identifier characters", name)
			}
		}
	}
	if c.Storage.ClickHouseColdAfterDays < 0 || c.Storage.ClickHouseColdAfterDays >= c.Storage.RetentionDays {
		if c.Storage.ClickHouseColdAfterDays != 0 {
			return errors.New("storage.clickhouse_cold_after_days must be 0 or less than retention_days")
		}
	}
	if (c.Storage.ClickHouseColdAfterDays > 0) != (strings.TrimSpace(c.Storage.ClickHouseColdVolume) != "") {
		return errors.New("storage.clickhouse_cold_after_days and clickhouse_cold_volume must be configured together")
	}
	if c.Storage.ClickHouseColdVolume != "" && c.Storage.ClickHouseStoragePolicy == "" {
		return errors.New("clickhouse cold volume tiering requires clickhouse_storage_policy")
	}
	if c.Cluster.ExpectedNodes < 1 || c.Cluster.ExpectedNodes > 1000 {
		return errors.New("cluster.expected_nodes must be 1..1000")
	}
	if c.Cluster.RequireMTLS {
		if !c.Web.TLS {
			return errors.New("cluster.require_mtls=true requires web.tls=true")
		}
		if strings.TrimSpace(c.Cluster.CAFile) == "" || strings.TrimSpace(c.Cluster.CertFile) == "" || strings.TrimSpace(c.Cluster.KeyFile) == "" {
			return errors.New("cluster.require_mtls=true requires cluster.ca_file, cert_file and key_file")
		}
	}
	if c.Analytics.MaxTrackedHosts < 1000 || c.Analytics.MaxTrackedHosts > 500000 {
		return errors.New("analytics.max_tracked_hosts must be 1000..500000")
	}
	if c.Analytics.MaxDimensionKeys < 1000 || c.Analytics.MaxDimensionKeys > 2000000 {
		return errors.New("analytics.max_dimension_keys must be 1000..2000000")
	}
	seen := map[string]bool{}
	type boundListener struct {
		name, bind string
		port       int
		transport  string
	}
	var bound []boundListener
	for _, l := range c.Listeners {
		if l.Name == "" {
			return errors.New("listener name required")
		}
		if seen[l.Name] {
			return fmt.Errorf("duplicate listener name %q", l.Name)
		}
		seen[l.Name] = true
		if l.Port < 1 || l.Port > 65535 {
			return fmt.Errorf("listener %s invalid port", l.Name)
		}
		p := strings.ToLower(l.Protocol)
		if p != "netflow" && p != "ipfix" && p != "sflow" {
			return fmt.Errorf("listener %s invalid protocol %q", l.Name, l.Protocol)
		}
		transport := strings.ToLower(strings.TrimSpace(l.Transport))
		if transport == "" {
			transport = "udp"
		}
		if transport != "udp" && transport != "tcp" && transport != "sctp" {
			return fmt.Errorf("listener %s invalid transport %q", l.Name, l.Transport)
		}
		if transport != "udp" && strings.ToLower(strings.TrimSpace(l.Protocol)) != "ipfix" {
			return fmt.Errorf("listener %s: %s transport is only supported for ipfix", l.Name, transport)
		}
		if l.Workers < 1 || l.Workers > 256 {
			return fmt.Errorf("listener %s workers must be 1..256", l.Name)
		}
		if l.QueueSize < 64 || l.QueueSize > 1_000_000 {
			return fmt.Errorf("listener %s queue_size out of range", l.Name)
		}
		if l.BatchSize < 1 || l.BatchSize > 64 {
			return fmt.Errorf("listener %s batch_size must be 1..64", l.Name)
		}
		if l.Enabled {
			b := strings.TrimSpace(l.Bind)
			if b == "" {
				b = "0.0.0.0"
			}
			for _, prev := range bound {
				overlap := b == prev.bind || b == "0.0.0.0" || prev.bind == "0.0.0.0" || b == "::" || prev.bind == "::"
				if overlap && l.Port == prev.port && transport == prev.transport {
					return fmt.Errorf("listeners %s and %s conflict on port %d (%s vs %s)", prev.name, l.Name, l.Port, prev.bind, b)
				}
			}
			bound = append(bound, boundListener{name: l.Name, bind: b, port: l.Port, transport: transport})
		}
	}
	return nil
}

func parseYAMLSubset(s string, c *Config) error {
	sc := bufio.NewScanner(strings.NewReader(s))
	section := ""
	var cur *Listener
	lineNo := 0
	for sc.Scan() {
		lineNo++
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(raw) - len(strings.TrimLeft(raw, " \t"))
		if indent == 0 && strings.HasSuffix(trimmed, ":") {
			section = strings.TrimSuffix(trimmed, ":")
			cur = nil
			continue
		}
		if section == "listeners" && strings.HasPrefix(trimmed, "-") {
			c.Listeners = append(c.Listeners[:0], c.Listeners...)
			// first list item replaces defaults once.
			if cur == nil && len(c.Listeners) > 0 && c.Listeners[0].Name == "netflow" {
				c.Listeners = nil
			}
			l := Listener{Bind: "0.0.0.0", Workers: 4, QueueSize: 8192, ReadBuffer: 4 << 20, BatchSize: 16, Enabled: true}
			c.Listeners = append(c.Listeners, l)
			cur = &c.Listeners[len(c.Listeners)-1]
			kv := strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
			if kv != "" {
				if err := setListener(cur, kv); err != nil {
					return fmt.Errorf("line %d: %w", lineNo, err)
				}
			}
			continue
		}
		if section == "listeners" && cur != nil {
			if err := setListener(cur, trimmed); err != nil {
				return fmt.Errorf("line %d: %w", lineNo, err)
			}
			continue
		}
		if !strings.Contains(trimmed, ":") {
			return fmt.Errorf("line %d: expected key: value", lineNo)
		}
		parts := strings.SplitN(trimmed, ":", 2)
		key := strings.TrimSpace(parts[0])
		val := unquote(strings.TrimSpace(parts[1]))
		var err error
		switch section {
		case "node":
			switch key {
			case "id":
				c.Node.ID = val
			case "region":
				c.Node.Region = val
			}
		case "cluster":
			switch key {
			case "heartbeat_url":
				c.Cluster.HeartbeatURL = val
			case "shared_token_file":
				c.Cluster.SharedTokenFile = val
			case "heartbeat_seconds":
				c.Cluster.HeartbeatSeconds, err = strconv.Atoi(val)
			case "node_timeout_seconds":
				c.Cluster.NodeTimeoutSeconds, err = strconv.Atoi(val)
			case "allow_insecure_http":
				c.Cluster.AllowInsecureHTTP, err = strconv.ParseBool(val)
			case "global_dedup_enabled":
				c.Cluster.GlobalDedupEnabled, err = strconv.ParseBool(val)
			case "global_dedup_url":
				c.Cluster.GlobalDedupURL = val
			case "global_dedup_timeout_ms":
				c.Cluster.GlobalDedupTimeoutMS, err = strconv.Atoi(val)
			case "global_dedup_max_entries":
				c.Cluster.GlobalDedupMaxEntries, err = strconv.Atoi(val)
			case "require_mtls":
				c.Cluster.RequireMTLS, err = strconv.ParseBool(val)
			case "ca_file":
				c.Cluster.CAFile = val
			case "cert_file":
				c.Cluster.CertFile = val
			case "key_file":
				c.Cluster.KeyFile = val
			case "server_name":
				c.Cluster.ServerName = val
			case "expected_nodes":
				c.Cluster.ExpectedNodes, err = strconv.Atoi(val)
			}
		case "web":
			switch key {
			case "bind":
				c.Web.Bind = val
			case "port":
				c.Web.Port, err = strconv.Atoi(val)
			case "tls":
				c.Web.TLS, err = strconv.ParseBool(val)
			case "cert_file":
				c.Web.CertFile = val
			case "key_file":
				c.Web.KeyFile = val
			}
		case "storage":
			switch key {
			case "backend":
				c.Storage.Backend = strings.ToLower(val)
			case "data_dir":
				c.Storage.DataDir = val
			case "retention_days":
				c.Storage.RetentionDays, err = strconv.Atoi(val)
			case "clickhouse_url":
				c.Storage.ClickHouseURL = val
			case "clickhouse_database":
				c.Storage.ClickHouseDatabase = val
			case "clickhouse_table":
				c.Storage.ClickHouseTable = val
			case "clickhouse_user":
				c.Storage.ClickHouseUser = val
			case "clickhouse_password":
				c.Storage.ClickHousePassword = val
			case "clickhouse_batch_size":
				c.Storage.ClickHouseBatchSize, err = strconv.Atoi(val)
			case "clickhouse_flush_ms":
				c.Storage.ClickHouseFlushMS, err = strconv.Atoi(val)
			case "clickhouse_queue_size":
				c.Storage.ClickHouseQueueSize, err = strconv.Atoi(val)
			case "clickhouse_cluster":
				c.Storage.ClickHouseCluster = val
			case "clickhouse_distributed_table":
				c.Storage.ClickHouseDistributedTable = val
			case "clickhouse_replica_path":
				c.Storage.ClickHouseReplicaPath = val
			case "clickhouse_replica_name":
				c.Storage.ClickHouseReplicaName = val
			case "clickhouse_spool_enabled":
				c.Storage.ClickHouseSpoolEnabled, err = strconv.ParseBool(val)
			case "clickhouse_spool_max_bytes":
				c.Storage.ClickHouseSpoolMaxBytes, err = strconv.ParseInt(val, 10, 64)
			case "clickhouse_spool_replay_seconds":
				c.Storage.ClickHouseSpoolReplaySecs, err = strconv.Atoi(val)
			case "clickhouse_spool_segment_bytes":
				c.Storage.ClickHouseSpoolSegmentBytes, err = strconv.ParseInt(val, 10, 64)
			case "clickhouse_spool_fsync":
				c.Storage.ClickHouseSpoolFsync, err = strconv.ParseBool(val)
			case "clickhouse_query_timeout_ms":
				c.Storage.ClickHouseQueryTimeoutMS, err = strconv.Atoi(val)
			case "clickhouse_max_result_rows":
				c.Storage.ClickHouseMaxResultRows, err = strconv.Atoi(val)
			case "clickhouse_max_execution_seconds":
				c.Storage.ClickHouseMaxExecutionSecs, err = strconv.Atoi(val)
			case "clickhouse_storage_policy":
				c.Storage.ClickHouseStoragePolicy = val
			case "clickhouse_cold_volume":
				c.Storage.ClickHouseColdVolume = val
			case "clickhouse_cold_after_days":
				c.Storage.ClickHouseColdAfterDays, err = strconv.Atoi(val)
			}
		case "security":
			switch key {
			case "default_policy":
				c.Security.DefaultPolicy = strings.ToLower(val)
			case "session_hours":
				c.Security.SessionHours, err = strconv.Atoi(val)
			case "bootstrap_file":
				c.Security.BootstrapFile = val
			case "require_mfa":
				c.Security.RequireMFA, err = strconv.ParseBool(val)
			case "exporter_packets_per_second":
				c.Security.ExporterPacketsPerSec, err = strconv.Atoi(val)
			case "exporter_burst":
				c.Security.ExporterBurst, err = strconv.Atoi(val)
			case "diagnostics_enabled":
				c.Security.DiagnosticsEnabled, err = strconv.ParseBool(val)
			}
		case "oidc":
			switch key {
			case "enabled":
				c.OIDC.Enabled, err = strconv.ParseBool(val)
			case "issuer":
				c.OIDC.Issuer = val
			case "client_id":
				c.OIDC.ClientID = val
			case "client_secret":
				c.OIDC.ClientSecret = val
			case "redirect_url":
				c.OIDC.RedirectURL = val
			case "default_role":
				c.OIDC.DefaultRole = strings.ToLower(val)
			case "default_tenant": // v3 compatibility: ignored in single-organization v4
			case "group_role_map":
				c.OIDC.GroupRoleMap = val
			case "group_tenant_map": // v3 compatibility: ignored in single-organization v4
			}
		case "ldap":
			switch key {
			case "enabled":
				c.LDAP.Enabled, err = strconv.ParseBool(val)
			case "url":
				c.LDAP.URL = val
			case "bind_dn":
				c.LDAP.BindDN = val
			case "bind_password":
				c.LDAP.BindPassword = val
			case "base_dn":
				c.LDAP.BaseDN = val
			case "user_attribute":
				c.LDAP.UserAttribute = val
			case "user_dn_template":
				c.LDAP.UserDNTemplate = val
			case "group_attribute":
				c.LDAP.GroupAttribute = val
			case "group_role_map":
				c.LDAP.GroupRoleMap = val
			case "group_tenant_map": // v3 compatibility: ignored in single-organization v4
			case "default_role":
				c.LDAP.DefaultRole = strings.ToLower(val)
			case "default_tenant": // v3 compatibility: ignored in single-organization v4
			case "allow_insecure":
				c.LDAP.AllowInsecure, err = strconv.ParseBool(val)
			}
		case "logging":
			switch key {
			case "json":
				c.Logging.JSON, err = strconv.ParseBool(val)
			case "level":
				c.Logging.Level = val
			}
		case "enrichment":
			switch key {
			case "enabled":
				c.Enrichment.Enabled, err = strconv.ParseBool(val)
			case "prefix_file":
				c.Enrichment.PrefixFile = val
			case "remote_enabled":
				c.Enrichment.RemoteEnabled, err = strconv.ParseBool(val)
			case "remote_url":
				c.Enrichment.RemoteURL = val
			}
		case "threat_intel": // v3 compatibility: feature removed in v4
		case "analytics":
			switch key {
			case "baseline_enabled":
				c.Analytics.BaselineEnabled, err = strconv.ParseBool(val)
			case "baseline_min_samples":
				c.Analytics.BaselineMinSamples, err = strconv.Atoi(val)
			case "baseline_state_file":
				c.Analytics.BaselineStateFile = val
			case "baseline_save_seconds":
				c.Analytics.BaselineSaveSeconds, err = strconv.Atoi(val)
			case "dedup_enabled":
				c.Analytics.DedupEnabled, err = strconv.ParseBool(val)
			case "dedup_window_seconds":
				c.Analytics.DedupWindowSeconds, err = strconv.Atoi(val)
			case "dedup_max_entries":
				c.Analytics.DedupMaxEntries, err = strconv.Atoi(val)
			case "behavior_enabled": // v3 compatibility: behavior/NDR analytics removed in v4
			case "behavior_min_samples": // v3 compatibility: behavior/NDR analytics removed in v4
			case "behavior_state_file": // v3 compatibility: behavior/NDR analytics removed in v4
			case "behavior_save_seconds": // v3 compatibility: behavior/NDR analytics removed in v4
			case "max_tracked_hosts":
				c.Analytics.MaxTrackedHosts, err = strconv.Atoi(val)
			case "max_dimension_keys", "max_transient_states":
				c.Analytics.MaxDimensionKeys, err = strconv.Atoi(val)
			}
		case "pcap": // v3 compatibility: packet-capture pivot removed in v4
		case "notifications":
			switch key {
			case "webhook_url":
				c.Notifications.WebhookURL = val
			case "webhook_secret":
				c.Notifications.WebhookSecret = val
			case "telegram_bot_token":
				c.Notifications.TelegramBotToken = val
			case "telegram_chat_id":
				c.Notifications.TelegramChatID = val
			case "smtp_addr":
				c.Notifications.SMTPAddr = val
			case "smtp_from":
				c.Notifications.SMTPFrom = val
			case "smtp_to":
				c.Notifications.SMTPTo = val
			case "smtp_username":
				c.Notifications.SMTPUsername = val
			case "smtp_password":
				c.Notifications.SMTPPassword = val
			case "syslog_addr":
				c.Notifications.SyslogAddr = val
			}
		}
		if err != nil {
			return fmt.Errorf("line %d: %w", lineNo, err)
		}
	}
	return sc.Err()
}

func setListener(l *Listener, kv string) error {
	p := strings.SplitN(kv, ":", 2)
	if len(p) != 2 {
		return fmt.Errorf("invalid listener field %q", kv)
	}
	k, v := strings.TrimSpace(p[0]), unquote(strings.TrimSpace(p[1]))
	var err error
	switch k {
	case "name":
		l.Name = v
	case "bind":
		l.Bind = v
	case "port":
		l.Port, err = strconv.Atoi(v)
	case "protocol":
		l.Protocol = strings.ToLower(v)
	case "transport":
		l.Transport = strings.ToLower(v)
	case "workers":
		l.Workers, err = strconv.Atoi(v)
	case "queue_size":
		l.QueueSize, err = strconv.Atoi(v)
	case "read_buffer":
		l.ReadBuffer, err = strconv.Atoi(v)
	case "batch_size":
		l.BatchSize, err = strconv.Atoi(v)
	case "enabled":
		l.Enabled, err = strconv.ParseBool(v)
	}
	return err
}
func unquote(s string) string { return strings.Trim(s, "\"'") }
func applyEnv(c *Config) {
	if v := os.Getenv("FLOWCOLLECTOR_NODE_ID"); v != "" {
		c.Node.ID = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_NODE_REGION"); v != "" {
		c.Node.Region = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLUSTER_HEARTBEAT_URL"); v != "" {
		c.Cluster.HeartbeatURL = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLUSTER_TOKEN_FILE"); v != "" {
		c.Cluster.SharedTokenFile = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLUSTER_HEARTBEAT_SECONDS"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			c.Cluster.HeartbeatSeconds = n
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLUSTER_NODE_TIMEOUT_SECONDS"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			c.Cluster.NodeTimeoutSeconds = n
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLUSTER_ALLOW_INSECURE_HTTP"); v != "" {
		if b, e := strconv.ParseBool(v); e == nil {
			c.Cluster.AllowInsecureHTTP = b
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLUSTER_GLOBAL_DEDUP_ENABLED"); v != "" {
		if b, e := strconv.ParseBool(v); e == nil {
			c.Cluster.GlobalDedupEnabled = b
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLUSTER_GLOBAL_DEDUP_URL"); v != "" {
		c.Cluster.GlobalDedupURL = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLUSTER_GLOBAL_DEDUP_TIMEOUT_MS"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			c.Cluster.GlobalDedupTimeoutMS = n
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLUSTER_REQUIRE_MTLS"); v != "" {
		if b, e := strconv.ParseBool(v); e == nil {
			c.Cluster.RequireMTLS = b
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLUSTER_CA_FILE"); v != "" {
		c.Cluster.CAFile = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLUSTER_CERT_FILE"); v != "" {
		c.Cluster.CertFile = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLUSTER_KEY_FILE"); v != "" {
		c.Cluster.KeyFile = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLUSTER_SERVER_NAME"); v != "" {
		c.Cluster.ServerName = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLUSTER_EXPECTED_NODES"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			c.Cluster.ExpectedNodes = n
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_WEB_BIND"); v != "" {
		c.Web.Bind = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_WEB_PORT"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			c.Web.Port = n
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_WEB_TLS"); v != "" {
		if b, e := strconv.ParseBool(v); e == nil {
			c.Web.TLS = b
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_WEB_CERT_FILE"); v != "" {
		c.Web.CertFile = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_WEB_KEY_FILE"); v != "" {
		c.Web.KeyFile = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_DATA_DIR"); v != "" {
		c.Storage.DataDir = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_STORAGE_BACKEND"); v != "" {
		c.Storage.Backend = strings.ToLower(v)
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLICKHOUSE_URL"); v != "" {
		c.Storage.ClickHouseURL = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLICKHOUSE_DATABASE"); v != "" {
		c.Storage.ClickHouseDatabase = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLICKHOUSE_TABLE"); v != "" {
		c.Storage.ClickHouseTable = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLICKHOUSE_USER"); v != "" {
		c.Storage.ClickHouseUser = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLICKHOUSE_PASSWORD"); v != "" {
		c.Storage.ClickHousePassword = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLICKHOUSE_CLUSTER"); v != "" {
		c.Storage.ClickHouseCluster = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLICKHOUSE_DISTRIBUTED_TABLE"); v != "" {
		c.Storage.ClickHouseDistributedTable = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLICKHOUSE_REPLICA_PATH"); v != "" {
		c.Storage.ClickHouseReplicaPath = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLICKHOUSE_REPLICA_NAME"); v != "" {
		c.Storage.ClickHouseReplicaName = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLICKHOUSE_STORAGE_POLICY"); v != "" {
		c.Storage.ClickHouseStoragePolicy = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLICKHOUSE_COLD_VOLUME"); v != "" {
		c.Storage.ClickHouseColdVolume = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_CLICKHOUSE_COLD_AFTER_DAYS"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			c.Storage.ClickHouseColdAfterDays = n
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_ENRICHMENT_ENABLED"); v != "" {
		if b, e := strconv.ParseBool(v); e == nil {
			c.Enrichment.Enabled = b
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_ENRICHMENT_PREFIX_FILE"); v != "" {
		c.Enrichment.PrefixFile = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_BASELINE_ENABLED"); v != "" {
		if b, e := strconv.ParseBool(v); e == nil {
			c.Analytics.BaselineEnabled = b
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_BASELINE_MIN_SAMPLES"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			c.Analytics.BaselineMinSamples = n
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_BASELINE_STATE_FILE"); v != "" {
		c.Analytics.BaselineStateFile = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_BASELINE_SAVE_SECONDS"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			c.Analytics.BaselineSaveSeconds = n
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_ANALYTICS_MAX_TRACKED_HOSTS"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			c.Analytics.MaxTrackedHosts = n
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_ANALYTICS_MAX_DIMENSION_KEYS"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			c.Analytics.MaxDimensionKeys = n
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_DEDUP_ENABLED"); v != "" {
		if b, e := strconv.ParseBool(v); e == nil {
			c.Analytics.DedupEnabled = b
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_DEDUP_WINDOW_SECONDS"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			c.Analytics.DedupWindowSeconds = n
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_DEDUP_MAX_ENTRIES"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			c.Analytics.DedupMaxEntries = n
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_WEBHOOK_URL"); v != "" {
		c.Notifications.WebhookURL = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_TELEGRAM_BOT_TOKEN"); v != "" {
		c.Notifications.TelegramBotToken = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_TELEGRAM_CHAT_ID"); v != "" {
		c.Notifications.TelegramChatID = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_SMTP_ADDR"); v != "" {
		c.Notifications.SMTPAddr = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_SMTP_FROM"); v != "" {
		c.Notifications.SMTPFrom = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_SMTP_TO"); v != "" {
		c.Notifications.SMTPTo = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_SMTP_USERNAME"); v != "" {
		c.Notifications.SMTPUsername = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_SMTP_PASSWORD"); v != "" {
		c.Notifications.SMTPPassword = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_SYSLOG_ADDR"); v != "" {
		c.Notifications.SyslogAddr = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_OIDC_ENABLED"); v != "" {
		if b, e := strconv.ParseBool(v); e == nil {
			c.OIDC.Enabled = b
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_OIDC_ISSUER"); v != "" {
		c.OIDC.Issuer = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_OIDC_CLIENT_ID"); v != "" {
		c.OIDC.ClientID = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_OIDC_CLIENT_SECRET"); v != "" {
		c.OIDC.ClientSecret = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_OIDC_REDIRECT_URL"); v != "" {
		c.OIDC.RedirectURL = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_OIDC_DEFAULT_ROLE"); v != "" {
		c.OIDC.DefaultRole = strings.ToLower(v)
	}
	if v := os.Getenv("FLOWCOLLECTOR_OIDC_GROUP_ROLE_MAP"); v != "" {
		c.OIDC.GroupRoleMap = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_LDAP_ENABLED"); v != "" {
		if b, e := strconv.ParseBool(v); e == nil {
			c.LDAP.Enabled = b
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_LDAP_URL"); v != "" {
		c.LDAP.URL = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_LDAP_BIND_DN"); v != "" {
		c.LDAP.BindDN = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_LDAP_BIND_PASSWORD"); v != "" {
		c.LDAP.BindPassword = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_LDAP_BASE_DN"); v != "" {
		c.LDAP.BaseDN = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_LDAP_USER_ATTRIBUTE"); v != "" {
		c.LDAP.UserAttribute = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_LDAP_USER_DN_TEMPLATE"); v != "" {
		c.LDAP.UserDNTemplate = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_LDAP_GROUP_ATTRIBUTE"); v != "" {
		c.LDAP.GroupAttribute = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_LDAP_GROUP_ROLE_MAP"); v != "" {
		c.LDAP.GroupRoleMap = v
	}
	if v := os.Getenv("FLOWCOLLECTOR_LDAP_DEFAULT_ROLE"); v != "" {
		c.LDAP.DefaultRole = strings.ToLower(v)
	}
	if v := os.Getenv("FLOWCOLLECTOR_LDAP_ALLOW_INSECURE"); v != "" {
		if b, e := strconv.ParseBool(v); e == nil {
			c.LDAP.AllowInsecure = b
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_REQUIRE_MFA"); v != "" {
		if b, e := strconv.ParseBool(v); e == nil {
			c.Security.RequireMFA = b
		}
	}
	if v := os.Getenv("FLOWCOLLECTOR_DEFAULT_POLICY"); v != "" {
		c.Security.DefaultPolicy = strings.ToLower(v)
	}
}
