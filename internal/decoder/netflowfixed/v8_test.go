package netflowfixed

import (
	"central-flow-collector/internal/model"
	"encoding/binary"
	"testing"
	"time"
)

func TestDecodeV8AggregationSchemes(t *testing.T) {
	sizes := map[byte]int{1: 28, 2: 40, 3: 32, 4: 32, 5: 40, 6: 32, 7: 40, 8: 52, 9: 32, 10: 40, 11: 40, 12: 40, 13: 40, 14: 40}
	for scheme, size := range sizes {
		t.Run(string(rune('A'+scheme)), func(t *testing.T) {
			pkt := make([]byte, 28+size)
			binary.BigEndian.PutUint16(pkt[0:2], 8)
			binary.BigEndian.PutUint16(pkt[2:4], 1)
			binary.BigEndian.PutUint32(pkt[4:8], 10000)
			binary.BigEndian.PutUint32(pkt[8:12], 1700000000)
			binary.BigEndian.PutUint32(pkt[12:16], 0)
			binary.BigEndian.PutUint32(pkt[16:20], 7)
			pkt[22], pkt[23] = scheme, 1
			binary.BigEndian.PutUint32(pkt[28+4:28+8], 3)
			binary.BigEndian.PutUint32(pkt[28+8:28+12], 900)
			binary.BigEndian.PutUint32(pkt[28+12:28+16], 9000)
			binary.BigEndian.PutUint32(pkt[28+16:28+20], 8000)
			res, err := DecodeV8(pkt, model.PacketContext{Received: time.Unix(1700000000, 0), Exporter: "test"})
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Flows) != 1 || res.Flows[0].Packets != 3 || res.Flows[0].Bytes != 900 {
				t.Fatalf("unexpected flow: %+v", res.Flows)
			}
		})
	}
}

func TestDecodeV8RejectsUnknownScheme(t *testing.T) {
	pkt := make([]byte, 28)
	binary.BigEndian.PutUint16(pkt, 8)
	binary.BigEndian.PutUint16(pkt[2:], 1)
	pkt[22] = 99
	if _, err := DecodeV8(pkt, model.PacketContext{}); err == nil {
		t.Fatal("expected unsupported scheme error")
	}
}
