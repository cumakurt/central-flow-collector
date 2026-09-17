package collector

import (
	"central-flow-collector/internal/model"
	"encoding/binary"
	"testing"
)

func TestSequenceUnitsAndSessions(t *testing.T) {
	for _, version := range []uint16{5, 7, 9, 10} {
		c := &Collector{exporters: map[string]*model.ExporterStat{}}
		p := packet{data: make([]byte, 24), ctx: model.PacketContext{Exporter: "192.0.2.1", Protocol: "netflow", Listener: "nf", SourcePort: 1234}}
		binary.BigEndian.PutUint16(p.data, version)
		step := uint32(3)
		if version == 9 {
			step = 1
		}
		first := uint32(0xfffffffe)
		r := model.DecodeResult{Sequence: first, Flows: make([]model.Flow, 3)}
		c.observeSequence(p, r)
		r.Sequence = first + step
		c.observeSequence(p, r)
		p.ctx.SourcePort++
		r.Sequence = 1000
		c.observeSequence(p, r)
		x := c.exporters["192.0.2.1|netflow|nf"]
		if x.SequenceGaps != 0 {
			t.Fatalf("version %d false gaps: %d", version, x.SequenceGaps)
		}
		r.Sequence += step + 2
		c.observeSequence(p, r)
		if x.SequenceGaps != 2 {
			t.Fatalf("version %d missed real gap: %d", version, x.SequenceGaps)
		}
	}
}

func TestIPFIXOptionsSequence(t *testing.T) {
	c := &Collector{exporters: map[string]*model.ExporterStat{}}
	p := packet{ctx: model.PacketContext{Protocol: "ipfix"}}
	c.observeSequence(p, model.DecodeResult{Sequence: 0, Options: make([]model.Flow, 2)})
	c.observeSequence(p, model.DecodeResult{Sequence: 2, Flows: make([]model.Flow, 1)})
	if c.exporters["|ipfix|"].SequenceGaps != 0 {
		t.Fatal("options counted as packet sequence")
	}
}

func TestIPFIXBiflowCountsOneWireRecord(t *testing.T) {
	c := &Collector{exporters: map[string]*model.ExporterStat{}}
	p := packet{ctx: model.PacketContext{Protocol: "ipfix"}}
	c.observeSequence(p, model.DecodeResult{Sequence: 0, DataRecords: 1, Flows: make([]model.Flow, 2)})
	c.observeSequence(p, model.DecodeResult{Sequence: 1, DataRecords: 1, Flows: make([]model.Flow, 2)})
	if c.exporters["|ipfix|"].LastSequence != 1 || c.exporters["|ipfix|"].SequenceGaps != 0 {
		t.Fatal("normalized reverse flow changed wire sequence units")
	}
}
