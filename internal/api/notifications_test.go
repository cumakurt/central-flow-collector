package api

import (
	"central-flow-collector/internal/notification"
	"encoding/json"
	"strings"
	"testing"
)

func TestNotificationAPISecretsRBACAndValidation(t *testing.T) {
	f := newV17Fixture(t)
	p, e := notification.OpenPlatform(t.TempDir(), f.srv.EvaluateNotificationRule)
	if e != nil {
		t.Fatal(e)
	}
	defer p.Close()
	f.srv.Notifications = p
	h := f.srv.Handler()
	for _, rule := range notification.RuleTemplates() {
		if rule.Kind != "seasonal" {
			continue
		}
		payload, err := json.Marshal(map[string]any{"rule": rule, "state": "FIRING"})
		if err != nil {
			t.Fatal(err)
		}
		preview := doBearer(h, "POST", "/api/v1/notifications/preview", f.adminToken, string(payload))
		if preview.Code != 422 || !strings.Contains(preview.Body.String(), "simulation") {
			t.Fatalf("seasonal preview must require measured bounds: %d %s", preview.Code, preview.Body.String())
		}
	}
	for _, resource := range []string{"rules", "channels", "policies", "history", "alerts", "silences", "templates", "settings", "health"} {
		w := doBearer(h, "GET", "/api/v1/notifications/"+resource, f.aliceToken, "")
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", resource, w.Code, w.Body.String())
		}
	}
	body := `{"name":"SMTP","type":"email","enabled":true,"host":"127.0.0.1","port":587,"security":"starttls","from":"collector@example.test","recipients":["noc@example.test"],"username":"test","password":"test-password-only","timeout_seconds":2,"per_minute":20}`
	w := doBearer(h, "POST", "/api/v1/notifications/channels", f.aliceToken, body)
	if w.Code != 403 {
		t.Fatalf("analyst mutation allowed: %d", w.Code)
	}
	w = doBearer(h, "POST", "/api/v1/notifications/channels", f.adminToken, body)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "test-password-only") {
		t.Fatal("secret returned")
	}
	var channel notification.ChannelConfig
	if e = json.Unmarshal(w.Body.Bytes(), &channel); e != nil {
		t.Fatal(e)
	}
	if !channel.PasswordSet {
		t.Fatal("secret state missing")
	}
	w = doBearer(h, "GET", "/api/v1/notifications/channels", f.aliceToken, "")
	if strings.Contains(w.Body.String(), "test-password-only") {
		t.Fatal("read leaks secret")
	}
	for _, body := range []string{`{"password": {"test-password-only":1}}`, `{"bot_token":"test-password-only","unknown":1}`, `{} {"password":"test-password-only"}`} {
		w = doBearer(h, "POST", "/api/v1/notifications/channels", f.adminToken, body)
		if w.Code != 400 || strings.Contains(w.Body.String(), "test-password-only") {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	w = doBearer(h, "GET", "/api/v1/notifications/history?limit=1000000", f.adminToken, "")
	if w.Code != 400 {
		t.Fatal("unbounded history")
	}
}
