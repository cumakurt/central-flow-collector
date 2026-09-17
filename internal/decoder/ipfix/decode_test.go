package ipfix

import (
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/templates"
	"encoding/binary"
	"testing"
	"time"
)

func TestIPFIXTemplate(t *testing.T) {
	d := New(templates.New(time.Hour))
	ctx := model.PacketContext{Exporter: "2.2.2.2", Listener: "ipfix", Received: time.Now()}
	p := make([]byte, 16)
	binary.BigEndian.PutUint16(p[:2], 10)
	binary.BigEndian.PutUint32(p[12:16], 1)
	set := []byte{0, 2, 0, 16, 1, 0, 0, 2, 0, 8, 0, 4, 0, 12, 0, 4}
	p = append(p, set...)
	binary.BigEndian.PutUint16(p[2:4], uint16(len(p)))
	if _, e := d.Decode(p, ctx); e != nil {
		t.Fatal(e)
	}
	q := make([]byte, 16)
	binary.BigEndian.PutUint16(q[:2], 10)
	binary.BigEndian.PutUint32(q[12:16], 1)
	q = append(q, []byte{1, 0, 0, 12, 10, 1, 1, 1, 10, 2, 2, 2}...)
	binary.BigEndian.PutUint16(q[2:4], uint16(len(q)))
	r, e := d.Decode(q, ctx)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Flows) != 1 || r.Flows[0].SrcIP != "10.1.1.1" {
		t.Fatalf("bad %+v", r)
	}
}
func FuzzDecode(f *testing.F) {
	f.Add([]byte{0, 10})
	d := New(templates.New(time.Minute))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = d.Decode(b, model.PacketContext{Received: time.Now()}) })
}
