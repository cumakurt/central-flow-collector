package collector

import (
	"central-flow-collector/internal/analytics"
	"central-flow-collector/internal/config"
	"central-flow-collector/internal/model"
	"testing"
	"time"
)

func TestExporterHealthScoring(t *testing.T) {
	c := New(config.Default(), nil, nil, analytics.New(), nil)
	now := time.Now().UTC()
	c.exporters["x"] = &model.ExporterStat{Address: "10.0.0.1", Protocol: "ipfix", Listener: "ipfix", Allowed: true, FirstSeen: now.Add(-time.Minute), LastSeen: now, PacketsReceived: 100, Flows: 100, DecodeErrors: 2, MissingTemplates: 1, SequenceGaps: 3}
	h := c.ExporterHealth()
	if len(h) != 1 {
		t.Fatal(h)
	}
	if h[0].State != "degraded" || h[0].HealthScore >= 100 {
		t.Fatalf("health=%+v", h[0])
	}
	c.cancel()
}

func TestRejectedExporterUsesSingleOrganizationKey(t *testing.T) {
	c := &Collector{exporters: map[string]*model.ExporterStat{}, rejects: map[string]*model.RejectionStat{}}
	c.reject("10.0.0.5", "ipfix", "edge", 100, "deny")
	c.reject("10.0.0.5", "ipfix", "edge", 200, "deny")
	if got := len(c.Rejections()); got != 1 {
		t.Fatalf("rejections=%d, want 1", got)
	}
	if got := len(c.Exporters()); got != 1 {
		t.Fatalf("exporters=%d, want 1", got)
	}
}

func TestExporterRateLimiter(t *testing.T) {
	cfg := config.Default()
	cfg.Security.ExporterPacketsPerSec = 1
	cfg.Security.ExporterBurst = 2
	c := New(cfg, nil, nil, analytics.New(), nil)
	now := time.Now()
	if !c.allowExporterPacket("192.0.2.1", "nf", now) || !c.allowExporterPacket("192.0.2.1", "nf", now) {
		t.Fatal("initial burst should be allowed")
	}
	if c.allowExporterPacket("192.0.2.1", "nf", now) {
		t.Fatal("third packet in same instant should be rate limited")
	}
	if !c.allowExporterPacket("192.0.2.1", "nf", now.Add(time.Second)) {
		t.Fatal("token should refill")
	}
}
