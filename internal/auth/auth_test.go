package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHashVerify(t *testing.T) {
	h, e := HashPassword("GoodPassword7!")
	if e != nil {
		t.Fatal(e)
	}
	if !verify(h, "GoodPassword7!") {
		t.Fatal("verify failed")
	}
	if verify(h, "wrong") {
		t.Fatal("bad password accepted")
	}
}

func TestAPITokenLifecycle(t *testing.T) {
	d := t.TempDir()
	m, _, err := New(d, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// bootstrap admin has administrator role
	tok, secret, err := m.CreateAPIToken("admin", "automation", 30)
	if err != nil {
		t.Fatal(err)
	}
	if secret == "" || tok.ID == "" {
		t.Fatal("missing token material")
	}
	b, err := os.ReadFile(filepath.Join(d, "api-tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), secret) {
		t.Fatal("plaintext API token was persisted")
	}
	ss, ok := m.AuthenticateBearer(secret)
	if !ok || ss.Username != "admin" || ss.Role != "administrator" || ss.AuthType != "api_token" {
		t.Fatalf("bad bearer auth: %#v %v", ss, ok)
	}
	if err := m.RevokeAPIToken("admin", tok.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.AuthenticateBearer(secret); ok {
		t.Fatal("revoked token still authenticates")
	}
}

func TestOIDCSessionCannotTakeOverLocalUser(t *testing.T) {
	m, _, err := New(t.TempDir(), "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.CreateExternalSession("admin", "viewer"); err == nil {
		t.Fatal("OIDC identity was allowed to inherit local admin account")
	}
	s, err := m.CreateExternalSession("alice@example.test", "viewer")
	if err != nil {
		t.Fatal(err)
	}
	if s.Role != "read_only" || s.AuthType != "oidc" {
		t.Fatalf("unexpected external session %#v", s)
	}
}

func TestSingleOrganizationUserSessionAndToken(t *testing.T) {
	d := t.TempDir()
	m, _, err := New(d, d+"/bootstrap.txt", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	// Legacy AddUserTenant calls are accepted during upgrades, but tenant is
	// deliberately discarded in the v4 single-organization product.
	if err := m.AddUserTenant("alice", "GoodPassw0rd!", "analyst", "tenant-a"); err != nil {
		t.Fatal(err)
	}
	s, err := m.Login("alice", "GoodPassw0rd!", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if s.Tenant != "" || s.Role != "analyst" {
		t.Fatalf("unexpected session: %+v", s)
	}
	tok, secret, err := m.CreateAPIToken("alice", "cli", 1)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Tenant != "" {
		t.Fatalf("token retained legacy tenant=%q", tok.Tenant)
	}
	bs, ok := m.AuthenticateBearer(secret)
	if !ok || bs.Tenant != "" {
		t.Fatalf("bearer=%+v ok=%v", bs, ok)
	}
}

func TestBearerAuthenticationDoesNotRewriteTokenFile(t *testing.T) {
	d := t.TempDir()
	m, _, err := New(d, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, secret, err := m.CreateAPIToken("admin", "hot-path", 30)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(d, "api-tokens.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 25; i++ {
		if _, ok := m.AuthenticateBearer(secret); !ok {
			t.Fatalf("bearer authentication failed at iteration %d", i)
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("bearer hot path rewrote persistent token state")
	}
}

func TestAPITokenScopesAndCIDRRestriction(t *testing.T) {
	d := t.TempDir()
	m, _, err := New(d, "", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tok, secret, err := m.CreateAPITokenAdvanced("admin", "scoped", 1, []string{"flows.read"}, []string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	if len(tok.Scopes) != 1 || tok.Scopes[0] != "flows.read" {
		t.Fatalf("unexpected scopes: %+v", tok.Scopes)
	}
	ss, ok := m.AuthenticateBearerFrom(secret, "127.0.0.1")
	if !ok || !ScopeAllows(ss.Scopes, "flows.read") || ScopeAllows(ss.Scopes, "users.manage") {
		t.Fatalf("scope authentication failed: %+v %v", ss, ok)
	}
	if _, ok := m.AuthenticateBearerFrom(secret, "192.0.2.10"); ok {
		t.Fatal("token should be rejected outside allowed CIDR")
	}
}

func TestSimpleFlowAnalyticsRoles(t *testing.T) {
	if !HasPermission("analyst", "analytics.read") || !HasPermission("analyst", "flows.export") || HasPermission("analyst", "users.manage") {
		t.Fatal("analyst permissions invalid")
	}
	if HasPermission("read_only", "flows.export") || !HasPermission("read_only", "flows.read") || !HasPermission("read_only", "analytics.read") {
		t.Fatal("read_only permissions invalid")
	}
	if !HasPermission("administrator", "system.manage") || !HasPermission("administrator", "users.manage") {
		t.Fatal("administrator must have full permissions")
	}
	// Legacy roles migrate to the closest v4 role instead of creating a fourth
	// public authorization tier.
	if !HasPermission("viewer", "flows.read") || !HasPermission("network_operator", "analytics.read") {
		t.Fatal("legacy role migration broken")
	}
}

func TestEnterprisePermissionMatrixLeastPrivilege(t *testing.T) {
	cases := []struct {
		role, perm string
		want       bool
	}{
		{"administrator", "cluster.manage", true},
		{"administrator", "users.manage", true},
		{"analyst", "analytics.read", true},
		{"analyst", "analytics.manage", true},
		{"analyst", "reports.manage", true},
		{"analyst", "users.manage", false},
		{"read_only", "flows.read", true},
		{"read_only", "analytics.read", true},
		{"read_only", "flows.export", false},
		{"read_only", "system.manage", false},
		{"read_only", "tokens.manage", false},
	}
	for _, tc := range cases {
		if got := HasPermission(tc.role, tc.perm); got != tc.want {
			t.Fatalf("role=%s perm=%s got=%v want=%v", tc.role, tc.perm, got, tc.want)
		}
	}
}

func TestScopedTokenCannotExpandRole(t *testing.T) {
	if !ScopeAllows([]string{"flows.read"}, "flows.read") || ScopeAllows([]string{"flows.read"}, "users.manage") {
		t.Fatal("token scope boundary broken")
	}
	if HasPermission("read_only", "users.manage") {
		t.Fatal("read-only role unexpectedly has user management")
	}
}
