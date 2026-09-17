package sflow

import (
	"central-flow-collector/internal/model"
	"encoding/binary"
	"testing"
	"time"
)

func u32s(values ...uint32) []byte {
	b := make([]byte, len(values)*4)
	for i, v := range values {
		binary.BigEndian.PutUint32(b[i*4:], v)
	}
	return b
}

func record(kind uint32, b []byte) []byte {
	out := append(u32s(kind, uint32(len(b))), b...)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}

func sample(expanded bool, records ...[]byte) []byte {
	b := u32s(1, 12, 100, 1000, 0, 12, 13, uint32(len(records)))
	if expanded {
		b = u32s(1, 0, 12, 100, 1000, 0, 0, 12, 0, 13, uint32(len(records)))
	}
	for _, r := range records {
		b = append(b, r...)
	}
	return b
}

func datagram(expanded bool, records ...[]byte) []byte {
	kind := uint32(1)
	if expanded {
		kind = 3
	}
	return append(u32s(5, 1, 0xc0000201, 4, 9, 10000, 1), record(kind, sample(expanded, records...))...)
}

func TestSampleMetadataAndSingleCounting(t *testing.T) {
	ip := u32s(1500, 6, 0xc0000201, 0xcb007101, 12345, 443, 18, 184)
	for _, expanded := range []bool{false, true} {
		packet := datagram(expanded, record(3, ip), record(1001, u32s(123, 5, 456, 6)), record(3, ip), record(32473<<12|7, []byte{1, 2, 3}))
		res, err := Decode(packet, model.PacketContext{Exporter: "192.0.2.1", Received: time.Unix(1700000000, 0)})
		if err != nil || len(res.Flows) != 1 {
			t.Fatalf("expanded=%v %+v %v", expanded, res, err)
		}
		f := res.Flows[0]
		if f.Packets != 1 || f.Bytes != 1500 || f.IngressIf != 12 || f.EgressIf != 13 || f.Sampling != 100 || f.VLAN != 123 || f.DSCP != 46 || f.ObsDomain != 4 || f.Custom["sflow_32473_7"] != "010203" {
			t.Fatalf("lost sample metadata: %+v", f)
		}
		for i := 0; i < len(packet); i++ {
			if _, err := Decode(packet[:i], model.PacketContext{}); err == nil {
				t.Fatalf("accepted truncated packet at %d", i)
			}
		}
	}
}

func raw(protocol uint32, h []byte) []byte {
	return append(u32s(protocol, 1500, 0, uint32(len(h))), h...)
}

func TestRawIPv4FragmentAndQinQ(t *testing.T) {
	ip := make([]byte, 40)
	ip[0], ip[1], ip[9] = 0x45, 184, 6
	copy(ip[12:20], []byte{192, 0, 2, 1, 203, 0, 113, 1})
	binary.BigEndian.PutUint16(ip[20:], 12345)
	binary.BigEndian.PutUint16(ip[22:], 443)
	ip[33] = 18
	f, ok := rawHeader(raw(11, ip))
	if !ok || f.DstPort != 443 || f.DSCP != 46 {
		t.Fatalf("direct IP: %+v", f)
	}
	ether := make([]byte, 22)
	binary.BigEndian.PutUint16(ether[12:], 0x88a8)
	binary.BigEndian.PutUint16(ether[14:], 200)
	binary.BigEndian.PutUint16(ether[16:], 0x8100)
	binary.BigEndian.PutUint16(ether[18:], 123)
	binary.BigEndian.PutUint16(ether[20:], 0x0800)
	f, ok = rawHeader(raw(1, append(ether, ip...)))
	if !ok || f.VLAN != 123 || f.DstPort != 443 {
		t.Fatalf("QinQ: %+v", f)
	}
	ip[7] = 1
	f, ok = rawHeader(raw(11, ip))
	if !ok || f.DstPort != 0 || f.SrcPort != 0 || f.TCPFlags != 0 {
		t.Fatalf("fragment treated as TCP: %+v", f)
	}
}

func TestRawIPv6ExtensionHeaders(t *testing.T) {
	ip := make([]byte, 68)
	ip[0], ip[1], ip[6] = 0x6b, 0x80, 0
	ip[8], ip[9], ip[24], ip[25] = 0x20, 1, 0x20, 1
	ip[40] = 6 // Hop-by-hop header points to TCP.
	binary.BigEndian.PutUint16(ip[48:], 12345)
	binary.BigEndian.PutUint16(ip[50:], 443)
	ip[61] = 18
	f, ok := rawHeader(raw(12, ip))
	if !ok || f.IPProtocol != 6 || f.DstPort != 443 || f.TOS != 184 || f.TCPFlags != 18 {
		t.Fatalf("IPv6 extensions: %+v", f)
	}
	ip[6] = 44
	binary.BigEndian.PutUint16(ip[42:], 8)
	f, ok = rawHeader(raw(12, ip))
	if !ok || f.DstPort != 0 || f.TCPFlags != 0 {
		t.Fatalf("IPv6 fragment treated as TCP: %+v", f)
	}
}

func FuzzValidDatagram(f *testing.F) {
	ip := u32s(1500, 6, 0xc0000201, 0xcb007101, 12345, 443, 18, 184)
	f.Add(datagram(false, record(3, ip)))
	f.Add(datagram(true, record(3, ip)))
	f.Add(datagram(false, record(3, ip), record(1003, u32s(1, 0xc00002fe, 64512, 64513, 64514, 1, 2, 2, 64515, 64516, 1, 0xfc000001, 100))))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Decode(b, model.PacketContext{}) })
}

func TestExtendedGatewayAndNAT(t *testing.T) {
	ip := u32s(1500, 6, 0xc0000201, 0xcb007101, 12345, 443, 18, 184)
	gateway := u32s(1, 0xc00002fe, 64512, 64513, 64514, 1, 2, 2, 64515, 64516, 1, 0xfc000001, 100)
	nat := u32s(1, 0xc0000202, 1, 0xcb007102)
	r, err := Decode(datagram(false, record(3, ip), record(1003, gateway), record(1007, nat)), model.PacketContext{})
	if err != nil || len(r.Flows) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	f := r.Flows[0]
	if f.SrcAS != 64513 || f.DstAS != 64516 || f.Custom["bgp_communities"] != "64512:1" || f.NATSrcIP != "192.0.2.2" {
		t.Fatalf("extended data lost: %+v", f)
	}
	for i := 0; i < len(gateway); i++ {
		if _, err := Decode(datagram(false, record(3, ip), record(1003, gateway[:i])), model.PacketContext{}); err == nil {
			t.Fatalf("accepted truncated gateway at %d", i)
		}
	}
}
