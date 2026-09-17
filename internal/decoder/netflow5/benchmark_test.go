package netflow5

import (
	"central-flow-collector/internal/model"
	"encoding/binary"
	"testing"
	"time"
)

func BenchmarkDecodeV5_30Flows(b *testing.B) {
	p := make([]byte, 24+30*48)
	binary.BigEndian.PutUint16(p[0:2], 5)
	binary.BigEndian.PutUint16(p[2:4], 30)
	binary.BigEndian.PutUint32(p[4:8], 600000)
	binary.BigEndian.PutUint32(p[8:12], uint32(time.Now().Unix()))
	for i := 0; i < 30; i++ {
		o := 24 + i*48
		copy(p[o:o+4], []byte{10, 0, 0, 1})
		copy(p[o+4:o+8], []byte{10, 0, 0, 2})
		binary.BigEndian.PutUint32(p[o+16:o+20], 10)
		binary.BigEndian.PutUint32(p[o+20:o+24], 1000)
		binary.BigEndian.PutUint16(p[o+32:o+34], 1234)
		binary.BigEndian.PutUint16(p[o+34:o+36], 443)
		p[o+38] = 6
	}
	ctx := model.PacketContext{Exporter: "127.0.0.1", Listener: "bench", Received: time.Now()}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, e := Decode(p, ctx); e != nil {
			b.Fatal(e)
		}
	}
}
