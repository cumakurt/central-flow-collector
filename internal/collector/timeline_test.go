package collector

import (
	"testing"
	"time"
)

func TestProtocolTimelineCountsBeyondLiveBuffer(t *testing.T) {
	c := &Collector{}
	now := time.Now()
	for i := 0; i < 1000; i++ {
		c.recordProtocol(now, "ipfix", false)
	}
	c.recordProtocol(now, "sflow", true)
	var packets, flows uint64
	for _, b := range c.ProtocolTimeline() {
		packets += b.Protocols["ipfix"].Packets
		flows += b.Protocols["sflow"].Flows
	}
	if packets != 1000 || flows != 1 {
		t.Fatalf("wrong counts: %d %d", packets, flows)
	}
	c.recordProtocol(now.Add(-20*time.Minute), "netflow9", false)
	for _, b := range c.ProtocolTimeline() {
		if b.Protocols["netflow9"].Packets != 0 {
			t.Fatal("expired bucket included")
		}
	}
}
