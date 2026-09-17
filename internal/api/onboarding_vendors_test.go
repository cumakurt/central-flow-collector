package api

import (
	"central-flow-collector/internal/auth"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVendorOnboardingUsesCorrectWireProtocol(t *testing.T) {
	seen := map[string]bool{}
	for _, v := range vendors() {
		t.Run(v.ID, func(t *testing.T) {
			if seen[v.ID] {
				t.Fatal("duplicate vendor ID")
			}
			seen[v.ID] = true
			body, _ := json.Marshal(map[string]any{"vendor": v.ID, "collector_ip": "192.0.2.10", "source_ip": "192.0.2.20"})
			r := httptest.NewRequest("POST", "/api/v1/onboarding/render", strings.NewReader(string(body)))
			w := httptest.NewRecorder()
			(&Server{}).onboardingRender(w, r, auth.Session{})
			if w.Code != 200 {
				t.Fatalf("status %d: %s", w.Code, w.Body.String())
			}
			var out struct {
				Snippet string           `json:"snippet"`
				Vendor  onboardingVendor `json:"vendor"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.Snippet, "192.0.2.10") || out.Vendor.Protocol != v.Protocol {
				t.Fatal("wrong collector or protocol")
			}
			if v.Protocol == "sflow" && !strings.Contains(out.Snippet, "sFlow") {
				t.Fatal("sFlow profile rendered IPFIX instructions")
			}
		})
	}
	for _, id := range []string{"fortinet-netflow", "paloalto-netflow", "huawei-netstream", "h3c-netstream", "arista-sflow", "aruba-sflow", "dell-sflow", "extreme-sflow", "nokia-cflowd", "vmware-ipfix", "netscaler-appflow", "f5-ipfix", "ubiquiti-ipfix", "checkpoint-ipfix", "sonicwall-ipfix"} {
		if !seen[id] {
			t.Errorf("missing vendor profile %s", id)
		}
	}
}
