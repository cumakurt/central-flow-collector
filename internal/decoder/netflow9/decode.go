package netflow9

import (
	"central-flow-collector/internal/decoder/fields"
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/templates"
	"encoding/binary"
	"fmt"
	"time"
)

type Decoder struct{ Cache *templates.Cache }

func New(c *templates.Cache) *Decoder { return &Decoder{Cache: c} }

func (d *Decoder) Decode(pkt []byte, ctx model.PacketContext) (model.DecodeResult, error) {
	if len(pkt) < 20 {
		return model.DecodeResult{}, fmt.Errorf("netflow9 packet too short")
	}
	if binary.BigEndian.Uint16(pkt[:2]) != 9 {
		return model.DecodeResult{}, fmt.Errorf("not netflow9")
	}
	uptime := binary.BigEndian.Uint32(pkt[4:8])
	export := time.Unix(int64(binary.BigEndian.Uint32(pkt[8:12])), 0).UTC()
	seq := binary.BigEndian.Uint32(pkt[12:16])
	domain := binary.BigEndian.Uint32(pkt[16:20])
	res := model.DecodeResult{Sequence: seq, ObservationDomain: domain}
	for pos := 20; pos < len(pkt); {
		if pos+4 > len(pkt) {
			return res, fmt.Errorf("truncated set header")
		}
		sid := binary.BigEndian.Uint16(pkt[pos:])
		size := int(binary.BigEndian.Uint16(pkt[pos+2:]))
		if size < 4 || pos+size > len(pkt) {
			return res, fmt.Errorf("invalid set length %d", size)
		}
		data := pkt[pos+4 : pos+size]
		key := templates.Key{Exporter: ctx.Exporter, Listener: ctx.Listener, SourcePort: ctx.SourcePort, Protocol: "netflow9", Domain: domain, TemplateID: sid}
		switch {
		case sid == 0 || sid == 1:
			parsed, err := templates.Parse(data, false, sid == 1)
			if err != nil {
				return res, err
			}
			for _, t := range parsed {
				key.TemplateID = t.ID
				d.Cache.Put(key, t)
				res.TemplatesAdded++
			}
		case sid >= 256:
			t, ok := d.Cache.Get(key)
			if !ok {
				res.MissingTemplate = true
				break
			}
			base := model.Flow{ReceiveTime: ctx.Received, Exporter: ctx.Exporter, Listener: ctx.Listener, Protocol: "netflow9", ObsDomain: domain, Sequence: seq}
			records, err := fields.Records(data, t, base, export, &uptime)
			if err != nil {
				return res, err
			}
			if t.ScopeCount > 0 {
				res.Options = append(res.Options, records...)
				d.Cache.PutOptions(key, records)
			} else {
				for i := range records {
					d.Cache.ApplyOptions(key, &records[i])
				}
				res.Flows = append(res.Flows, records...)
			}
		}
		pos += size
	}
	return res, nil
}
