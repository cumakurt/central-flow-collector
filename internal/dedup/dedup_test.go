package dedup

import (
	"central-flow-collector/internal/model"
	"testing"
	"time"
)

func TestDetectorWindow(t *testing.T) {
	d := New(2*time.Second, 1000)
	now := time.Now()
	f := model.Flow{Exporter: "1.2.3.4", Protocol: "netflow", SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 123, DstPort: 443, IPProtocol: 6, Bytes: 100, Packets: 2, Sequence: 7, StartTime: now.Add(-time.Second), EndTime: now}
	if !d.Accept(f, now) {
		t.Fatal("first rejected")
	}
	if d.Accept(f, now.Add(time.Second)) {
		t.Fatal("duplicate accepted")
	}
	if !d.Accept(f, now.Add(3*time.Second)) {
		t.Fatal("expired duplicate rejected")
	}
	if d.Stats().Duplicates != 1 {
		t.Fatalf("stats=%+v", d.Stats())
	}
}
func TestDetectorDistinctSequence(t *testing.T) {
	d := New(time.Minute, 1000)
	now := time.Now()
	a := model.Flow{Exporter: "e", SrcIP: "a", DstIP: "b", Sequence: 1}
	b := a
	b.Sequence = 2
	if !d.Accept(a, now) || !d.Accept(b, now) {
		t.Fatal("distinct sequence deduplicated")
	}
}
