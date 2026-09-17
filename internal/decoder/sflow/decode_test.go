package sflow

import (
	"central-flow-collector/internal/model"
	"encoding/binary"
	"testing"
	"time"
)

func TestSampledIPv4(t *testing.T) {
	rec := make([]byte, 32)
	binary.BigEndian.PutUint32(rec[0:4], 1500)
	binary.BigEndian.PutUint32(rec[4:8], 6)
	copy(rec[8:12], []byte{10, 0, 0, 1})
	copy(rec[12:16], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint32(rec[16:20], 1234)
	binary.BigEndian.PutUint32(rec[20:24], 443)
	f, ok := sampledIPv4(rec)
	if !ok || f.DstPort != 443 {
		t.Fatal("decode failed")
	}
}
func FuzzDecode(f *testing.F) {
	f.Add([]byte{0, 0, 0, 5})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Decode(b, model.PacketContext{Received: time.Now()}) })
}
