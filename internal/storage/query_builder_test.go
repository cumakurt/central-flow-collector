package storage

import (
	"central-flow-collector/internal/model"
	"context"
	"net/url"
	"testing"
	"time"
)

func TestParseQueryBuilderAndLocalMatch(t *testing.T) {
	vals := url.Values{
		"src_cidr": {"10.0.0.0/8"}, "dst_port": {"443"}, "asn": {"64512"},
		"country": {"TR"}, "site": {"istanbul"}, "vlan": {"42"}, "tcp_flags": {"12"},
		"min_bytes": {"100"}, "max_bytes": {"1000"}, "limit": {"25"},
	}
	q, err := ParseQuery(vals)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	q.From = now.Add(-time.Minute)
	q.To = now.Add(time.Minute)
	f := model.Flow{ReceiveTime: now, SrcIP: "10.1.2.3", DstIP: "203.0.113.10", DstPort: 443, SrcAS: 64512, DstCountry: "TR", SrcSite: "istanbul", VLAN: 42, TCPFlags: 0x12, Bytes: 500}
	if !match(f, q) {
		t.Fatalf("expected flow to match advanced query: %+v", q)
	}
	f.Bytes = 50
	if match(f, q) {
		t.Fatal("min_bytes filter was not enforced")
	}
}

func TestLocalAdvancedQuery(t *testing.T) {
	d := t.TempDir()
	l, e := NewLocal(d, 64, 7)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	want := model.Flow{ReceiveTime: now, SrcIP: "10.2.3.4", DstIP: "198.51.100.9", DstPort: 443, IPProtocol: 6, Bytes: 900, Packets: 9, SrcAS: 64512, DstCountry: "US", SrcSite: "edge", VLAN: 12}
	other := model.Flow{ReceiveTime: now, SrcIP: "172.16.0.2", DstIP: "198.51.100.10", DstPort: 53, IPProtocol: 17, Bytes: 50, Packets: 1}
	_ = l.Write(want)
	_ = l.Write(other)
	defer l.Close()
	q := Query{From: now.Add(-time.Second), To: now.Add(time.Second), CIDR: "10.0.0.0/8", DstPort: 443, ASN: 64512, MinBytes: 100, Country: "US", Limit: 10}
	rows, e := l.Query(context.Background(), q)
	if e != nil {
		t.Fatal(e)
	}
	if len(rows) != 1 || rows[0].SrcIP != want.SrcIP {
		t.Fatalf("unexpected rows: %+v", rows)
	}
}

func TestTenantFilterLocal(t *testing.T) {
	d := t.TempDir()
	s, err := NewLocal(d, 128, 7)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := s.Write(model.Flow{ReceiveTime: now, Tenant: "alpha", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", Bytes: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.Write(model.Flow{ReceiveTime: now, Tenant: "beta", SrcIP: "10.0.0.3", DstIP: "10.0.0.4", Bytes: 1}); err != nil {
		t.Fatal(err)
	}
	if err := s.syncWrites(context.Background()); err != nil {
		t.Fatal(err)
	}
	rows, err := s.Query(context.Background(), Query{From: now.Add(-time.Minute), To: now.Add(time.Minute), Tenant: "alpha", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Tenant != "alpha" {
		t.Fatalf("rows=%+v", rows)
	}
	_ = s.Close()
}

func TestProtocolDrilldownNamesAndNumbers(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  int
	}{{"TCP", 6}, {"udp", 17}, {"ICMP", 1}, {"ICMPv6", 58}, {"IPv6", 41}, {"GRE", 47}, {"ESP", 50}, {"OSPF", 89}, {"SCTP", 132}, {"17", 17}, {"unknown", 0}} {
		q, err := ParseQuery(url.Values{"ip_protocol": {tc.input}})
		if err != nil || q.IPProtocol != tc.want || !q.IPProtocolSet {
			t.Fatalf("%s: %+v %v", tc.input, q, err)
		}
		if !match(model.Flow{IPProtocol: uint8(tc.want)}, q) {
			t.Fatalf("matching flow rejected: %s", tc.input)
		}
		if match(model.Flow{IPProtocol: uint8((tc.want + 1) % 256)}, q) {
			t.Fatalf("wrong protocol accepted: %s", tc.input)
		}
	}
	for _, input := range []string{"not-a-protocol", "256", "-1"} {
		if _, err := ParseQuery(url.Values{"ip_protocol": {input}}); err == nil {
			t.Fatalf("invalid protocol accepted: %s", input)
		}
	}
}
