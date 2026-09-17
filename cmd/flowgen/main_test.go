package main

import (
	"net"
	"testing"
	"time"

	"central-flow-collector/internal/decoder/ipfix"
	"central-flow-collector/internal/decoder/netflow9"
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/templates"
)

func TestNetFlow9GeneratorExportsTransportAndPackets(t *testing.T) {
	d := netflow9.New(templates.New(time.Hour))
	ctx := model.PacketContext{Exporter: "192.0.2.10", Listener: "nf9", Received: time.Now().UTC()}
	if _, err := d.Decode(nf9Template(1), ctx); err != nil {
		t.Fatal(err)
	}
	out, err := d.Decode(nf9Data(net.ParseIP("10.0.0.1").To4(), net.ParseIP("203.0.113.1").To4(), 2), ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Flows) != 1 {
		t.Fatalf("flows=%d want 1", len(out.Flows))
	}
	f := out.Flows[0]
	if f.DstPort != 443 || f.IPProtocol != 6 || f.Packets == 0 || f.Bytes == 0 {
		t.Fatalf("generated flow missing service metadata: %+v", f)
	}
}

func TestIPFIXGeneratorExportsTransportAndPackets(t *testing.T) {
	d := ipfix.New(templates.New(time.Hour))
	ctx := model.PacketContext{Exporter: "192.0.2.11", Listener: "ipfix", Received: time.Now().UTC()}
	if _, err := d.Decode(ipfixTemplate(1), ctx); err != nil {
		t.Fatal(err)
	}
	out, err := d.Decode(ipfixData(net.ParseIP("10.0.0.2").To4(), net.ParseIP("8.8.8.8").To4(), 2), ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Flows) != 1 {
		t.Fatalf("flows=%d want 1", len(out.Flows))
	}
	f := out.Flows[0]
	if f.DstPort != 53 || f.IPProtocol != 17 || f.Packets != 8 || f.Bytes != 8000 {
		t.Fatalf("generated flow missing service metadata: %+v", f)
	}
}
