package api

import (
	"central-flow-collector/internal/model"
	"testing"
)

func TestBuildTopologyAggregatesAndBounds(t *testing.T) {
	fs := []model.Flow{{SrcIP: "10.0.0.1", DstIP: "10.0.1.2", SrcSite: "HQ", DstSite: "DC", Bytes: 100, Packets: 2}, {SrcIP: "10.0.0.2", DstIP: "10.0.1.3", SrcSite: "HQ", DstSite: "DC", Bytes: 300, Packets: 3}}
	x := buildTopology(fs, "site", 40, 0)
	if len(x.Nodes) != 2 || len(x.Edges) != 1 {
		t.Fatalf("nodes=%d edges=%d", len(x.Nodes), len(x.Edges))
	}
	if x.Edges[0].Bytes != 400 || x.Edges[0].Flows != 2 {
		t.Fatalf("bad edge %#v", x.Edges[0])
	}
	if !x.Bounded || x.FlowsExamined != 2 {
		t.Fatalf("bad metadata %#v", x)
	}
}
