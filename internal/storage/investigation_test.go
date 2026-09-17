package storage

import (
	"central-flow-collector/internal/model"
	"context"
	"testing"
	"time"
)

func TestLocalHostInvestigation(t *testing.T) {
	l, err := NewLocal(t.TempDir(), 64, 7)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	flows := []model.Flow{
		{ReceiveTime: now, SrcIP: "10.1.1.10", DstIP: "203.0.113.5", DstPort: 443, IPProtocol: 6, Bytes: 1000, Packets: 10, DstCountry: "TR", DstSite: "Internet"},
		{ReceiveTime: now.Add(time.Minute), SrcIP: "203.0.113.5", DstIP: "10.1.1.10", SrcPort: 443, IPProtocol: 6, Bytes: 400, Packets: 4, SrcCountry: "TR", SrcSite: "Internet"},
		{ReceiveTime: now.Add(6 * time.Minute), SrcIP: "10.1.1.10", DstIP: "198.51.100.2", DstPort: 53, IPProtocol: 17, Bytes: 200, Packets: 2, DstCountry: "DE"},
	}
	for _, f := range flows {
		if err := l.Write(f); err != nil {
			t.Fatal(err)
		}
	}
	defer l.Close()
	got, err := l.InvestigateHost(context.Background(), HostQuery{IP: "10.1.1.10", From: now.Add(-time.Second), To: now.Add(10 * time.Minute), Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if got.BytesOut != 1200 || got.BytesIn != 400 || got.Flows != 3 {
		t.Fatalf("unexpected totals: %+v", got)
	}
	if len(got.TopPeers) != 2 || got.TopPeers[0].Key != "203.0.113.5" {
		t.Fatalf("peers=%+v", got.TopPeers)
	}
	if len(got.TopPorts) != 2 || got.TopPorts[0].Port != 443 {
		t.Fatalf("ports=%+v", got.TopPorts)
	}
	if len(got.Timeline) < 2 {
		t.Fatalf("timeline=%+v", got.Timeline)
	}
	var tf uint64
	for _, b := range got.Timeline {
		tf += b.Flows
	}
	if tf != 3 {
		t.Fatalf("timeline flow total=%d buckets=%+v", tf, got.Timeline)
	}
}
