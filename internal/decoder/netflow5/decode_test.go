package netflow5

import (
	"central-flow-collector/internal/model"
	"encoding/binary"
	"testing"
	"time"
)

func TestDecodeV5(t *testing.T) {
	b := make([]byte, 72)
	binary.BigEndian.PutUint16(b[0:2], 5)
	binary.BigEndian.PutUint16(b[2:4], 1)
	binary.BigEndian.PutUint32(b[4:8], 10000)
	binary.BigEndian.PutUint32(b[8:12], 1700000000)
	copy(b[24:28], []byte{10, 0, 0, 1})
	copy(b[28:32], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint32(b[40:44], 5)
	binary.BigEndian.PutUint32(b[44:48], 1000)
	binary.BigEndian.PutUint16(b[56:58], 1234)
	binary.BigEndian.PutUint16(b[58:60], 443)
	b[62] = 6
	r, e := Decode(b, model.PacketContext{Exporter: "1.2.3.4", Listener: "n", Received: time.Now()})
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Flows) != 1 || r.Flows[0].SrcIP != "10.0.0.1" || r.Flows[0].DstPort != 443 {
		t.Fatalf("bad flow %+v", r.Flows)
	}
}
func FuzzDecode(f *testing.F) {
	f.Add([]byte{0, 5})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Decode(b, model.PacketContext{Received: time.Now()}) })
}
