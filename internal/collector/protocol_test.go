package collector

import (
	"central-flow-collector/internal/analytics"
	"central-flow-collector/internal/config"
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/storage"
	"encoding/binary"
	"testing"
	"time"
)

type protocolStore struct {
	storage.Backend
	flows []model.Flow
}

func (s *protocolStore) Write(f model.Flow) error { s.flows = append(s.flows, f); return nil }

func TestFixedProtocolsReachStorageAndLiveStream(t *testing.T) {
	for _, version := range []uint16{1, 5, 7} {
		cfg := config.Default()
		cfg.Analytics.DedupEnabled = false
		store := &protocolStore{}
		c := New(cfg, nil, store, analytics.New(), nil)
		header, size := 24, 48
		if version == 1 {
			header = 16
		}
		if version == 7 {
			size = 52
		}
		b := make([]byte, header+size)
		binary.BigEndian.PutUint16(b, version)
		binary.BigEndian.PutUint16(b[2:], 1)
		binary.BigEndian.PutUint32(b[8:], 1700000000)
		copy(b[header:], []byte{192, 0, 2, 1, 203, 0, 113, 1})
		binary.BigEndian.PutUint32(b[header+16:], 2)
		binary.BigEndian.PutUint32(b[header+20:], 1000)
		if version == 5 {
			binary.BigEndian.PutUint16(b[22:], 0x400a)
		}
		c.process(packet{data: b, ctx: model.PacketContext{Exporter: "192.0.2.254", Listener: "nf", Protocol: "netflow", Received: time.Now()}})
		c.cancel()
		if len(store.flows) != 1 {
			t.Fatalf("version %d did not reach storage", version)
		}
		want := uint64(1000)
		if version == 5 {
			want *= 10
		}
		if store.flows[0].Bytes != want {
			t.Fatalf("version %d sampling bytes %d", version, store.flows[0].Bytes)
		}
		flows, _ := c.LiveSnapshot()
		if len(flows) != 1 || flows[0].Protocol != packetProtocol("netflow", b) {
			t.Fatal("live protocol mismatch")
		}
	}
}
