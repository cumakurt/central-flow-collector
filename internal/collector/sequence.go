package collector

import (
	"central-flow-collector/internal/model"
	"encoding/binary"
	"time"
)

type sequenceKey struct {
	exporter, listener, protocol string
	port                         uint16
	domain                       uint32
}

type sequenceState struct {
	next uint32
	seen time.Time
}

func (c *Collector) observeSequence(p packet, r model.DecodeResult) {
	k := p.ctx.Exporter + "|" + p.ctx.Protocol + "|" + p.ctx.Listener
	c.mu.Lock()
	defer c.mu.Unlock()
	x := c.exporters[k]
	if x == nil {
		x = &model.ExporterStat{Address: p.ctx.Exporter, Protocol: p.ctx.Protocol, Listener: p.ctx.Listener, Allowed: true, FirstSeen: time.Now().UTC()}
		c.exporters[k] = x
	}
	now := time.Now().UTC()
	x.LastSeen = now
	x.Flows += uint64(len(r.Flows))
	if r.MissingTemplate {
		x.MissingTemplates++
	}
	proto := packetProtocol(p.ctx.Protocol, p.data)
	if proto == "netflow1" {
		return
	}
	increment := uint32(1)
	domain := r.ObservationDomain
	switch proto {
	case "ipfix":
		increment = uint32(len(r.Flows) + len(r.Options))
		if r.DataRecords > 0 {
			increment = uint32(r.DataRecords)
		}
	case "netflow5", "netflow7", "netflow8":
		increment = uint32(len(r.Flows))
		if proto == "netflow5" && len(p.data) >= 22 {
			domain = uint32(binary.BigEndian.Uint16(p.data[20:22]))
		}
	}
	key := sequenceKey{p.ctx.Exporter, p.ctx.Listener, proto, p.ctx.SourcePort, domain}
	if c.sequences == nil {
		c.sequences = map[sequenceKey]sequenceState{}
	}
	if r.MissingTemplate {
		// The next IPFIX sequence cannot be inferred without all record counts.
		delete(c.sequences, key)
		return
	}
	previous, exists := c.sequences[key]
	if exists && now.Sub(previous.seen) < 30*time.Minute {
		delta := int32(r.Sequence - previous.next)
		if delta < 0 {
			return
		} // Reordered datagram, including around uint32 wrap.
		if delta > 0 {
			x.SequenceGaps += uint64(delta)
		}
	}
	if !exists && len(c.sequences) >= 4096 {
		for key, state := range c.sequences {
			if now.Sub(state.seen) >= 30*time.Minute {
				delete(c.sequences, key)
			}
		}
		if len(c.sequences) >= 4096 {
			return
		}
	}
	c.sequences[key] = sequenceState{next: r.Sequence + increment, seen: now}
	x.LastSequence = r.Sequence
}
