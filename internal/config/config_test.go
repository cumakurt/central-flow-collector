package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultWebTransportIsCertificateFreeAllInterfaceHTTP(t *testing.T) {
	c := Default()
	if c.Web.Bind != "0.0.0.0" {
		t.Fatalf("default web bind = %q, want 0.0.0.0", c.Web.Bind)
	}
	if c.Web.Port != 8080 {
		t.Fatalf("default web port = %d, want 8080", c.Web.Port)
	}
	if c.Web.TLS {
		t.Fatal("default web transport unexpectedly enables TLS")
	}
	if c.Web.CertFile != "" || c.Web.KeyFile != "" {
		t.Fatalf("default certificate paths must be empty, got cert=%q key=%q", c.Web.CertFile, c.Web.KeyFile)
	}
}

func TestTLSRequiresExplicitCertificateAndKey(t *testing.T) {
	c := Default()
	c.Web.TLS = true
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "requires explicit") {
		t.Fatalf("Validate() error = %v, want explicit cert/key error", err)
	}
	c.Web.CertFile = "/tmp/server.crt"
	if err := Validate(c); err == nil {
		t.Fatal("Validate() accepted TLS with certificate but no key")
	}
	c.Web.KeyFile = "/tmp/server.key"
	if err := Validate(c); err != nil {
		t.Fatalf("Validate() rejected structurally complete TLS config: %v", err)
	}
}

func TestLoadHTTPConfigDoesNotInventTLSPaths(t *testing.T) {
	d := t.TempDir()
	cfg := filepath.Join(d, "config.yaml")
	body := `web:
  bind: "127.0.0.1"
  port: 8080
  tls: false
  cert_file: ""
  key_file: ""
storage:
  backend: "local"
  data_dir: "` + d + `"
  retention_days: 7
security:
  default_policy: "deny"
  session_hours: 8
  bootstrap_file: ""
logging:
  json: false
  level: "info"
`
	if err := os.WriteFile(cfg, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c.Web.TLS || c.Web.CertFile != "" || c.Web.KeyFile != "" {
		t.Fatalf("Load invented TLS state: tls=%v cert=%q key=%q", c.Web.TLS, c.Web.CertFile, c.Web.KeyFile)
	}
	if c.Security.BootstrapFile != filepath.Join(d, "bootstrap-admin.txt") {
		t.Fatalf("bootstrap file = %q", c.Security.BootstrapFile)
	}
}

func TestEnrichmentConfig(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "config.yaml")
	cfg := `web:
  bind: "127.0.0.1"
  port: 8080
  tls: false
storage:
  backend: "local"
  data_dir: "` + d + `"
  retention_days: 7
security:
  default_policy: "deny"
  session_hours: 8
enrichment:
  enabled: true
  prefix_file: "` + filepath.Join(d, "geo.csv") + `"
listeners:
  - name: "nf"
    bind: "127.0.0.1"
    port: 22055
    protocol: "netflow"
    workers: 1
    queue_size: 64
    read_buffer: 65536
    enabled: true
`
	if err := os.WriteFile(p, []byte(cfg), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Enrichment.Enabled || c.Enrichment.PrefixFile == "" {
		t.Fatalf("enrichment not parsed: %+v", c.Enrichment)
	}
}

func TestClusterHeartbeatRequiresHTTPSForRemote(t *testing.T) {
	c := Default()
	c.Cluster.HeartbeatURL = "http://10.0.0.5:8080/api/v1/cluster/heartbeat"
	if err := Validate(c); err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("err=%v", err)
	}
	c.Cluster.AllowInsecureHTTP = true
	if err := Validate(c); err != nil {
		t.Fatalf("explicit trusted-LAN override rejected: %v", err)
	}
}

func TestClusterLoopbackHTTPAllowed(t *testing.T) {
	c := Default()
	c.Cluster.HeartbeatURL = "http://127.0.0.1:8080/api/v1/cluster/heartbeat"
	if err := Validate(c); err != nil {
		t.Fatal(err)
	}
}
func TestLDAPSecurityValidation(t *testing.T) {
	c := Default()
	c.LDAP.Enabled = true
	c.LDAP.URL = "ldap://dc.example:389"
	c.LDAP.BaseDN = "DC=example,DC=com"
	if e := Validate(c); e == nil {
		t.Fatal("plaintext LDAP unexpectedly accepted")
	}
	c.LDAP.AllowInsecure = true
	if e := Validate(c); e != nil {
		t.Fatal(e)
	}
	c.LDAP.URL = "ldaps://dc.example:636"
	c.LDAP.AllowInsecure = false
	if e := Validate(c); e != nil {
		t.Fatal(e)
	}
}

func TestValidateRejectsOverlappingEnabledListenerPorts(t *testing.T) {
	c := Default()
	c.Listeners[0].Port = 2055
	c.Listeners[0].Bind = "0.0.0.0"
	c.Listeners[1].Port = 2055
	c.Listeners[1].Bind = "127.0.0.1"
	if err := Validate(c); err == nil {
		t.Fatal("expected wildcard/specific UDP listener port conflict")
	}
	c.Listeners[1].Enabled = false
	if err := Validate(c); err != nil {
		t.Fatalf("disabled conflicting listener should validate: %v", err)
	}
}
