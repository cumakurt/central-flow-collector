package engineering

import (
	"central-flow-collector/internal/model"
	"context"
	"strings"
	"testing"
	"time"
)

func TestRouteLongestPrefixMatchIPv4AndIPv6(t *testing.T) {
	p := NewRouteProvider()
	if e := p.Replace([]PrefixRoute{{Prefix: "0.0.0.0/0", OriginASN: 1}, {Prefix: "10.0.0.0/8", OriginASN: 2}, {Prefix: "10.20.0.0/16", OriginASN: 3}, {Prefix: "2001:db8::/32", OriginASN: 4}}); e != nil {
		t.Fatal(e)
	}
	for _, x := range []struct {
		ip     string
		asn    uint32
		prefix string
	}{{"10.20.1.1", 3, "10.20.0.0/16"}, {"10.2.1.1", 2, "10.0.0.0/8"}, {"192.0.2.1", 1, "0.0.0.0/0"}, {"2001:db8::1", 4, "2001:db8::/32"}} {
		r, ok := p.Lookup(x.ip)
		if !ok || r.OriginASN != x.asn || r.MatchedPrefix != x.prefix {
			t.Fatalf("%+v %+v %v", x, r, ok)
		}
	}
}
func TestSummaryUsesRouteProviderForMissingRoutingFields(t *testing.T) {
	p := NewRouteProvider()
	if err := p.Replace([]PrefixRoute{{Prefix: "203.0.113.0/24", OriginASN: 64501, RouteSource: "static"}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	s, err := Summarize(context.Background(), []model.Flow{{ReceiveTime: now, DstIP: "203.0.113.8", Bytes: 10, Packets: 1}}, now.Add(-time.Minute), now.Add(time.Minute), p)
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Prefixes) != 1 || s.Prefixes[0].Key != "203.0.113.0/24" {
		t.Fatalf("route prefix was not derived: %+v", s.Prefixes)
	}
	if len(s.OriginASNs) != 1 || s.OriginASNs[0].Key != "64501" {
		t.Fatalf("origin ASN was not derived: %+v", s.OriginASNs)
	}
}

func BenchmarkRouteLookup10KPrefixes(b *testing.B) {
	p := NewRouteProvider()
	routes := make([]PrefixRoute, 10000)
	for i := range routes {
		routes[i] = PrefixRoute{Prefix: "10." + itoa(i/256) + "." + itoa(i%256) + ".0/24", OriginASN: uint32(64512 + i%100)}
	}
	if err := p.Replace(routes); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = p.Lookup("10.20.30.1")
	}
}
func TestDSCPAndCoverage(t *testing.T) {
	if DSCPName(46) != "EF" || DSCPName(63) != "DSCP 63" {
		t.Fatal(DSCPName(46), DSCPName(63))
	}
	now := time.Now().UTC()
	rows := []model.Flow{{ReceiveTime: now.Add(-time.Minute), Bytes: 100, Packets: 2, DSCP: 46, TOS: 184, NATSrcIP: "10.0.0.1", NextHop: "192.0.2.1", SrcPrefix: "10.0.0.0/24", DstPrefix: "203.0.113.0/24", SrcAS: 64512, Sampling: 100, Custom: map[string]string{"dscp_present": "1", "nat_present": "1"}}, {ReceiveTime: now, Bytes: 300, Packets: 4, DSCP: 0, TOS: 0}}
	s, e := Summarize(context.Background(), rows, now.Add(-2*time.Minute), now.Add(time.Minute), nil)
	if e != nil {
		t.Fatal(e)
	}
	if s.ObservedFlows != 2 || s.ObservedBytes != 400 || s.Coverage[5].Ratio != 50 || s.Coverage[6].Ratio != 50 {
		t.Fatalf("%+v", s.Coverage)
	}
	translated := false
	for _, r := range s.NAT {
		translated = translated || strings.Contains(r.Key, "10.0.0.1")
	}
	if s.DSCP[1].Key != "EF" || !translated {
		t.Fatal(s.DSCP, s.NAT)
	}
}
func TestCapacitySimulationDeterministic(t *testing.T) {
	r, e := Simulate(SimulationInput{CurrentRawDays: 30, ProposedRawDays: 90, CurrentAggregateDays: 90, ProposedAggregateDays: 180, CurrentSampling: 100, ProposedSampling: 500, CurrentDailyBytes: 1e12, FreeBytes: 20e12, StorageCostPerTB: 10})
	if e != nil {
		t.Fatal(e)
	}
	if r.CurrentBytes != 39e12 || r.ProposedBytes != 20.7e12 || r.DeltaBytes != -18.3e12 || r.HeadroomBytes != -0.7e12 || r.Confidence != "High" {
		t.Fatalf("%+v", r)
	}
}
