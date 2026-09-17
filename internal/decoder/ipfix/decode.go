package ipfix

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
	if len(pkt) < 16 {
		return model.DecodeResult{}, fmt.Errorf("ipfix packet too short")
	}
	if binary.BigEndian.Uint16(pkt[:2]) != 10 {
		return model.DecodeResult{}, fmt.Errorf("not ipfix")
	}
	if total := int(binary.BigEndian.Uint16(pkt[2:4])); total != len(pkt) {
		return model.DecodeResult{}, fmt.Errorf("invalid ipfix length %d", total)
	}
	export := time.Unix(int64(binary.BigEndian.Uint32(pkt[4:8])), 0).UTC()
	seq := binary.BigEndian.Uint32(pkt[8:12])
	domain := binary.BigEndian.Uint32(pkt[12:16])
	res := model.DecodeResult{Sequence: seq, ObservationDomain: domain}
	for pos := 16; pos < len(pkt); {
		if pos+4 > len(pkt) {
			return res, fmt.Errorf("truncated set header")
		}
		sid := binary.BigEndian.Uint16(pkt[pos:])
		size := int(binary.BigEndian.Uint16(pkt[pos+2:]))
		if size < 4 || pos+size > len(pkt) {
			return res, fmt.Errorf("invalid set length %d", size)
		}
		data := pkt[pos+4 : pos+size]
		key := templates.Key{Exporter: ctx.Exporter, Listener: ctx.Listener, SourcePort: ctx.SourcePort, Protocol: "ipfix", Domain: domain, TemplateID: sid}
		switch {
		case sid == 2 || sid == 3:
			parsed, err := templates.Parse(data, true, sid == 3)
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
			base := model.Flow{ReceiveTime: ctx.Received, Exporter: ctx.Exporter, Listener: ctx.Listener, Protocol: "ipfix", ObsDomain: domain, Sequence: seq}
			records, err := fields.Records(data, t, base, export, nil)
			if err != nil {
				return res, err
			}
			res.DataRecords += len(records)
			if t.ScopeCount > 0 {
				res.Options = append(res.Options, records...)
				d.Cache.PutOptions(key, records)
			} else {
				for i := range records {
					d.Cache.ApplyOptions(key, &records[i])
				}
				for _, record := range records {
					res.Flows = append(res.Flows, record)
					if reverse, ok := fields.Reverse(record, export); ok {
						res.Flows = append(res.Flows, reverse)
					}
				}
			}
		}
		pos += size
	}
	return res, nil
}
