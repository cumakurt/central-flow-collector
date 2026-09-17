package api

import (
	"strings"
	"testing"
)

func TestServiceTimelineUIIsEmbedded(t *testing.T) {
	html := readStaticV4(t, "index.html")
	js := readStaticV4(t, "services.js")
	css := readStaticV4(t, "style.css")
	for _, want := range []string{"/services.js", "/app.js"} {
		if !strings.Contains(html, want) {
			t.Fatalf("index missing %q", want)
		}
	}
	for _, want := range []string{"Service Timeline", "/api/v1/analytics/service-series", "series_service", "series_port", "series_protocol", "series_app", "openServiceFlows", "service-series-${s.index%8}"} {
		if !strings.Contains(js, want) {
			t.Fatalf("services.js missing %q", want)
		}
	}
	for _, want := range []string{".service-series-line", ".service-series-grid", "--series-8", ".service-plot-interaction"} {
		if !strings.Contains(css, want) {
			t.Fatalf("style.css missing %q", want)
		}
	}
}
