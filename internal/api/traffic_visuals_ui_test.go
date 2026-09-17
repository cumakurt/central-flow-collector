package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestTrafficVisualsUIIsEmbedded(t *testing.T) {
	html := readStaticV4(t, "index.html")
	js := readStaticV4(t, "traffic-visuals.js")
	state := readStaticV4(t, "traffic-visuals-state.js")
	menu := readStaticV4(t, "insights.js")
	css := readStaticV4(t, "style.css")
	for _, want := range []string{"/traffic-visuals-state.js", "/traffic-visuals.js"} {
		if !strings.Contains(html, want) {
			t.Fatalf("index missing %q", want)
		}
	}
	for _, want := range []string{"serviceMixPage", "trafficTrendsPage", "trafficHeatmapPage", "connectionSignalsPage", "conversationBarChart", "exporterTrendPanel", "Flow rate vs traffic rate"} {
		if !strings.Contains(js, want) {
			t.Fatalf("traffic-visuals.js missing %q", want)
		}
	}
	for _, want := range []string{"topSeries", "heatmap", "bucketWindow"} {
		if !strings.Contains(state, want) {
			t.Fatalf("traffic-visuals-state.js missing %q", want)
		}
	}
	for _, want := range []string{"Service Mix", "Traffic Trends", "Heatmap", "Connection Signals"} {
		if !strings.Contains(menu, want) {
			t.Fatalf("traffic menu missing %q", want)
		}
	}
	if !strings.Contains(css, ".traffic-heatmap") || !strings.Contains(css, ".heat-cell") {
		t.Fatal("heatmap styles missing")
	}
}

func TestServiceMixCatalogEndpointReturnsAllStandardServices(t *testing.T) {
	f := newV17Fixture(t)
	w := doBearer(f.srv.Handler(), http.MethodGet, "/api/v1/analytics/service-series?catalog=1", f.aliceToken, "")
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var out struct {
		Series []struct {
			Selector struct {
				Service string `json:"service"`
			} `json:"selector"`
		} `json:"series"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Series) < 20 {
		t.Fatalf("expected full standard service catalog series, got %d", len(out.Series))
	}
	seen := map[string]bool{}
	for _, s := range out.Series {
		seen[s.Selector.Service] = true
	}
	for _, id := range []string{"smtp", "dns", "https", "ssh", "rdp", "postgresql"} {
		if !seen[id] {
			t.Fatalf("catalog series missing %s", id)
		}
	}
}
