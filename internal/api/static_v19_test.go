package api

import (
	"io/fs"
	"strings"
	"testing"
)

func readStaticV4(t *testing.T, name string) string {
	t.Helper()
	b, err := fs.ReadFile(webFS, "static/"+name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestV4FocusedFlowAnalyticsPortal(t *testing.T) {
	html, js, css := readStaticV4(t, "index.html"), readStaticV4(t, "app.js"), readStaticV4(t, "style.css")
	for _, want := range []string{"sidebarToggle", "globalSearch", "themeBtn", "fullscreenBtn", "toastStack"} {
		if !strings.Contains(html, want) {
			t.Fatalf("index missing %q", want)
		}
	}
	for _, want := range []string{"Overview", "Executive", "Analytics", "Flow Explorer", "Traffic", "Exporters", "Reports", "System", "Top Sources", "Top Destinations", "Top Protocols", "Saved View", "Visual Query Builder", "/api/v1/analytics/compare", "/api/v1/flows/page", "/api/v1/reports/export"} {
		if !strings.Contains(js, want) {
			t.Fatalf("app.js missing %q", want)
		}
	}
	for _, forbidden := range []string{"Threat Intel", "MITRE ATT&CK", "Detection Rules v2", "Investigation Cases", "PCAP pivots", "tenant scope"} {
		if strings.Contains(js, forbidden) {
			t.Fatalf("focused portal still contains %q", forbidden)
		}
	}
	for _, want := range []string{"@media(max-width:1024px)", "@media(max-width:820px)", "@media(max-width:560px)", "[data-theme=\"dark\"]", ".loading-state", ".error-state"} {
		if !strings.Contains(css, want) {
			t.Fatalf("style.css missing %q", want)
		}
	}
}

func TestV4DoesNotEmbedDemoFlowData(t *testing.T) {
	js := readStaticV4(t, "app.js")
	for _, x := range []string{"fakeFlow", "dummyFlow", "demoTraffic", "Math.random()*1000000"} {
		if strings.Contains(js, x) {
			t.Fatalf("unexpected demo marker %q", x)
		}
	}
}

func TestV4RichTablesSanitizeCells(t *testing.T) {
	js := readStaticV4(t, "app.js")
	for _, x := range []string{"function safeTableHTML", "el.removeAttribute(a.name)", "rich?safeTableHTML(c):esc(c)"} {
		if !strings.Contains(js, x) {
			t.Fatalf("missing sanitizer marker %q", x)
		}
	}
}

func TestScheduledReportsPortalHasManagementControls(t *testing.T) {
	app, err := webFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	s := string(app)
	for _, want := range []string{
		"+ Add scheduled report",
		"reportJobModal",
		"report-delete",
		"report-toggle",
		"report-run",
		"/api/v1/reports/${encodeURIComponent(job.id)}",
		"Schedules use the collector host's local time",
		"Send report by email",
		"email_recipients",
		"Email delivery requires SMTP configuration",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("scheduled reports UI missing %q", want)
		}
	}
}

func TestServiceTimelineUsesDistinctColorsOnSingleChart(t *testing.T) {
	js, err := webFS.ReadFile("static/services.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := webFS.ReadFile("static/style.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"serviceScale", "Auto visibility", "Log Y-axis · actual values", "var(--series-${s.index%8+1})", "service-legend-item"} {
		if !strings.Contains(string(js), want) {
			t.Fatalf("service timeline missing %q", want)
		}
	}
	for _, want := range []string{"--series-1:", "--series-8:", ".service-chart-options", ".service-legend-item"} {
		if !strings.Contains(string(css), want) {
			t.Fatalf("service timeline CSS missing %q", want)
		}
	}
	if strings.Contains(string(js), "Per-service view") || strings.Contains(string(js), "serviceSeriesLanes") {
		t.Fatal("service timeline still renders per-service small multiples")
	}

}

func TestPortalPreservesBackendErrorDetail(t *testing.T) {
	app, err := webFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	text := string(app)
	if !strings.Contains(text, "Error(x?.error||") {
		t.Fatal("portal still masks detailed backend errors")
	}
}
