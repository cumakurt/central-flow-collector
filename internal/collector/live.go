package collector

import (
	"encoding/binary"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"central-flow-collector/internal/model"
)

type LivePacket struct {
	Time     time.Time `json:"time"`
	Exporter string    `json:"exporter"`
	Listener string    `json:"listener"`
	Protocol string    `json:"flow_protocol"`
	Size     int       `json:"size"`
	Accepted bool      `json:"accepted"`
	Reason   string    `json:"reason,omitempty"`
}

func packetProtocol(listenerProtocol string, payload []byte) string {
	if strings.EqualFold(listenerProtocol, "netflow") && len(payload) >= 2 {
		switch binary.BigEndian.Uint16(payload[:2]) {
		case 1:
			return "netflow1"
		case 5:
			return "netflow5"
		case 7:
			return "netflow7"
		case 8:
			return "netflow8"
		case 9:
			return "netflow9"
		case 10:
			return "ipfix"
		}
	}
	return strings.ToLower(listenerProtocol)
}

func (c *Collector) recordLivePacket(exporter, listener, protocol string, payload []byte, accepted bool, reason string) {
	now := time.Now().UTC()
	proto := packetProtocol(protocol, payload)
	c.recordProtocol(now, proto, false)
	// Under heavy load, observation yields to ingestion rather than blocking it.
	if !c.liveMu.TryLock() {
		return
	}
	c.livePackets[c.livePacketNext] = LivePacket{Time: now, Exporter: exporter, Listener: listener, Protocol: proto, Size: len(payload), Accepted: accepted, Reason: reason}
	c.livePacketNext = (c.livePacketNext + 1) % len(c.livePackets)
	if c.livePacketCount < len(c.livePackets) {
		c.livePacketCount++
	}
	c.liveMu.Unlock()
}

func (c *Collector) recordLiveFlow(f model.Flow) {
	c.recordLiveFlows(time.Now().UTC(), []model.Flow{f})
}

func (c *Collector) recordLiveFlows(now time.Time, flows []model.Flow) {
	if len(flows) == 0 {
		return
	}
	c.recordProtocolN(now, flows[0].Protocol, true, uint64(len(flows)))
	if !c.liveMu.TryLock() {
		return
	}
	for i := range flows {
		c.liveFlows[c.liveFlowNext] = flows[i]
		c.liveFlowNext = (c.liveFlowNext + 1) % len(c.liveFlows)
		if c.liveFlowCount < len(c.liveFlows) {
			c.liveFlowCount++
		}
	}
	c.liveMu.Unlock()
}

func (c *Collector) LiveSnapshot() ([]model.Flow, []LivePacket) {
	c.liveMu.Lock()
	defer c.liveMu.Unlock()
	flows := make([]model.Flow, 0, c.liveFlowCount)
	for i := 0; i < c.liveFlowCount; i++ {
		index := (c.liveFlowNext - 1 - i + len(c.liveFlows)) % len(c.liveFlows)
		flows = append(flows, c.liveFlows[index])
	}
	packets := make([]LivePacket, 0, c.livePacketCount)
	for i := 0; i < c.livePacketCount; i++ {
		index := (c.livePacketNext - 1 - i + len(c.livePackets)) % len(c.livePackets)
		packets = append(packets, c.livePackets[index])
	}
	return flows, packets
}

// ProtocolBucket contains collector-wide counts for a five-second interval.
type ProtocolCount struct {
	Packets uint64 `json:"packets"`
	Flows   uint64 `json:"flows"`
}
type ProtocolBucket struct {
	Timestamp time.Time                `json:"timestamp"`
	Protocols map[string]ProtocolCount `json:"protocols"`
}

var protocolTimelineNames = [...]string{"netflow5", "netflow9", "ipfix", "sflow", "other", "netflow1", "netflow7", "netflow8"}

type protocolTimelineSlot struct {
	mu      sync.Mutex
	second  atomic.Int64
	packets [len(protocolTimelineNames)]atomic.Uint64
	flows   [len(protocolTimelineNames)]atomic.Uint64
}

func protocolTimelineIndex(protocol string) int {
	switch protocol {
	case "netflow1":
		return 5
	case "netflow7":
		return 6
	case "netflow8":
		return 7
	case "netflow5":
		return 0
	case "netflow9":
		return 1
	case "ipfix":
		return 2
	case "sflow", "sflow5":
		return 3
	default:
		return 4
	}
}

func (c *Collector) recordProtocol(now time.Time, protocol string, flow bool) {
	c.recordProtocolN(now, protocol, flow, 1)
}

func (c *Collector) recordProtocolN(now time.Time, protocol string, flow bool, n uint64) {
	if n == 0 {
		return
	}
	second := now.Unix() / 5 * 5
	index := (second / 5) % int64(len(c.timeline))
	if index < 0 {
		index += int64(len(c.timeline))
	}
	slot := &c.timeline[index]
	if slot.second.Load() != second {
		slot.mu.Lock()
		if slot.second.Load() != second {
			slot.second.Store(0)
			for i := range slot.packets {
				slot.packets[i].Store(0)
				slot.flows[i].Store(0)
			}
			slot.second.Store(second)
		}
		slot.mu.Unlock()
	}
	pi := protocolTimelineIndex(protocol)
	if flow {
		slot.flows[pi].Add(n)
	} else {
		slot.packets[pi].Add(n)
	}
}

func (c *Collector) ProtocolTimeline() []ProtocolBucket {
	now := time.Now().Unix() / 5 * 5
	out := make([]ProtocolBucket, 0, len(c.timeline))
	for second := now - int64(len(c.timeline)-1)*5; second <= now; second += 5 {
		bucket := ProtocolBucket{Timestamp: time.Unix(second, 0).UTC(), Protocols: map[string]ProtocolCount{}}
		index := (second / 5) % int64(len(c.timeline))
		if index < 0 {
			index += int64(len(c.timeline))
		}
		slot := &c.timeline[index]
		slot.mu.Lock()
		if slot.second.Load() == second {
			for i, name := range protocolTimelineNames {
				packets := slot.packets[i].Load()
				flows := slot.flows[i].Load()
				if packets != 0 || flows != 0 {
					bucket.Protocols[name] = ProtocolCount{Packets: packets, Flows: flows}
				}
			}
		}
		slot.mu.Unlock()
		out = append(out, bucket)
	}
	return out
}
