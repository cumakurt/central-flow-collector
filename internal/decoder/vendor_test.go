package decoder_test

import (
	"central-flow-collector/internal/decoder/ipfix"
	"central-flow-collector/internal/decoder/netflow9"
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/templates"
	"encoding/binary"
	"testing"
	"time"
)

// Fixtures follow the published vendor field layouts, not captured appliances.
func TestFortiGateApplicationAndSamplerOptions(t *testing.T) {
	d := netflow9.New(templates.New(time.Hour))
	ctx := model.PacketContext{Received: time.Now()}
	appTemplate := set(1, words(300, 4, 8, 1, 2, 95, 9, 96, 64))
	appID := []byte{1, 0, 0, 0, 0, 0, 0, 0, 42}
	appData := append([]byte{0, 0}, appID...)
	name := make([]byte, 64)
	copy(name, "Microsoft.Teams")
	appData = append(appData, name...)
	otherID := append([]byte(nil), appID...)
	otherID[8] = 43
	otherData := append([]byte{0, 0}, otherID...)
	otherName := make([]byte, 64)
	copy(otherName, "DNS")
	otherData = append(otherData, otherName...)
	samplerTemplate := set(1, words(301, 4, 8, 1, 2, 48, 1, 50, 4))
	_, err := d.Decode(message(9, appTemplate, set(300, append(appData, otherData...)), samplerTemplate, set(301, []byte{0, 0, 7, 0, 0, 0, 100})), ctx)
	if err != nil {
		t.Fatal(err)
	}
	template := templateSet(9, 95, 9, 48, 1, 8, 4, 12, 4, 1, 8, 2, 4)
	data := append(append([]byte(nil), appID...), 7, 192, 0, 2, 1, 203, 0, 113, 1)
	counts := make([]byte, 12)
	binary.BigEndian.PutUint64(counts, 1500)
	binary.BigEndian.PutUint32(counts[8:], 3)
	data = append(data, counts...)
	r, err := d.Decode(message(9, template, set(256, data)), ctx)
	if err != nil || len(r.Flows) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	f := r.Flows[0]
	if f.AppName != "Microsoft.Teams" || f.Sampling != 100 || f.Bytes != 1500 || f.Packets != 3 {
		t.Fatalf("FortiGate metadata: %+v", f)
	}
}

func TestPANOSPrivateNamespaceAndNAT64(t *testing.T) {
	d := netflow9.New(templates.New(time.Hour))
	// Put App-ID before the namespace IE to test template field-order independence.
	template := templateSet(9, 56701, 32, 346, 4, 27, 16, 281, 16, 282, 16, 233, 1)
	data := make([]byte, 85)
	copy(data, "ssl")
	binary.BigEndian.PutUint32(data[32:], 25461)
	for _, offset := range []int{36, 52, 68} {
		copy(data[offset:], []byte{0x20, 1, 0x0d, 0xb8})
		data[offset+15] = byte(offset)
	}
	data[84] = 2
	r, err := d.Decode(message(9, template, set(256, data)), model.PacketContext{})
	if err != nil || len(r.Flows) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	f := r.Flows[0]
	if f.AppName != "ssl" || f.NATSrcIP != "2001:db8::34" || f.NATDstIP != "2001:db8::44" || f.Custom["firewall_event"] != "2" {
		t.Fatalf("PAN-OS fields: %+v", f)
	}
	binary.BigEndian.PutUint32(data[32:], 32473)
	r, err = d.Decode(message(9, set(256, data)), model.PacketContext{})
	if err != nil || r.Flows[0].AppName != "" {
		t.Fatal("private field namespace collision")
	}
}

func TestIPFIXReverseCounters(t *testing.T) {
	d := ipfix.New(templates.New(time.Hour))
	template := words(256, 6, 8, 4, 12, 4, 1, 8, 2, 4, 0x8001, 8)
	template = append(template, []byte{0, 0, 0x72, 0x79}...) // RFC 5103 PEN 29305
	template = append(template, words(0x8002, 4)...)
	template = append(template, []byte{0, 0, 0x72, 0x79}...)
	data := make([]byte, 32)
	copy(data, []byte{192, 0, 2, 1, 203, 0, 113, 1})
	binary.BigEndian.PutUint64(data[8:], 1000)
	binary.BigEndian.PutUint32(data[16:], 10)
	binary.BigEndian.PutUint64(data[20:], 2000)
	binary.BigEndian.PutUint32(data[28:], 20)
	r, err := d.Decode(message(10, set(2, template), set(256, data)), model.PacketContext{})
	if err != nil || len(r.Flows) != 2 || r.DataRecords != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	if r.Flows[0].Bytes != 1000 || r.Flows[1].Bytes != 2000 || r.Flows[1].Packets != 20 || r.Flows[1].SrcIP != "203.0.113.1" || r.Flows[1].DstIP != "192.0.2.1" {
		t.Fatalf("reverse flow: %+v", r.Flows)
	}
}
