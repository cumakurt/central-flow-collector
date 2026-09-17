package netflow9

import (
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/templates"
	"encoding/binary"
	"testing"
	"time"
)

func TestTemplateAndData(t *testing.T) {
	d := New(templates.New(time.Hour))
	p := make([]byte, 20)
	binary.BigEndian.PutUint16(p[:2], 9)
	binary.BigEndian.PutUint32(p[8:12], 1700000000)
	binary.BigEndian.PutUint32(p[16:20], 7)
	tmpl := make([]byte, 4+4+8)
	binary.BigEndian.PutUint16(tmpl[0:2], 0)
	binary.BigEndian.PutUint16(tmpl[2:4], uint16(len(tmpl)))
	binary.BigEndian.PutUint16(tmpl[4:6], 256)
	binary.BigEndian.PutUint16(tmpl[6:8], 2)
	binary.BigEndian.PutUint16(tmpl[8:10], 8)
	binary.BigEndian.PutUint16(tmpl[10:12], 4)
	binary.BigEndian.PutUint16(tmpl[12:14], 12)
	binary.BigEndian.PutUint16(tmpl[14:16], 4)
	p = append(p, tmpl...)
	ctx := model.PacketContext{Exporter: "1.1.1.1", Listener: "nf", Received: time.Now()}
	if _, e := d.Decode(p, ctx); e != nil {
		t.Fatal(e)
	}
	q := make([]byte, 20)
	binary.BigEndian.PutUint16(q[:2], 9)
	binary.BigEndian.PutUint32(q[8:12], 1700000000)
	binary.BigEndian.PutUint32(q[16:20], 7)
	set := make([]byte, 12)
	binary.BigEndian.PutUint16(set[0:2], 256)
	binary.BigEndian.PutUint16(set[2:4], 12)
	copy(set[4:8], []byte{10, 0, 0, 1})
	copy(set[8:12], []byte{10, 0, 0, 2})
	q = append(q, set...)
	r, e := d.Decode(q, ctx)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.Flows) != 1 || r.Flows[0].DstIP != "10.0.0.2" {
		t.Fatalf("bad %+v", r)
	}
}
func FuzzDecode(f *testing.F) {
	f.Add([]byte{0, 9})
	d := New(templates.New(time.Minute))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = d.Decode(b, model.PacketContext{Received: time.Now()}) })
}
