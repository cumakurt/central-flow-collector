package netflowfixed

import (
	"central-flow-collector/internal/model"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// DecodeV8 decodes Cisco's aggregation export. Aggregation records contain
// counters and keys rather than ordinary v5 addresses; every supported scheme
// is normalized into a flow and the aggregation identity is retained in custom.
func DecodeV8(pkt []byte, ctx model.PacketContext) (model.DecodeResult, error) {
	if len(pkt) < 28 || binary.BigEndian.Uint16(pkt) != 8 {
		return model.DecodeResult{}, fmt.Errorf("invalid netflow v8 packet")
	}
	count := int(binary.BigEndian.Uint16(pkt[2:]))
	if count < 1 || count > 64 {
		return model.DecodeResult{}, fmt.Errorf("invalid v8 flow count %d", count)
	}
	uptime := binary.BigEndian.Uint32(pkt[4:])
	export := time.Unix(int64(binary.BigEndian.Uint32(pkt[8:])), int64(binary.BigEndian.Uint32(pkt[12:]))).UTC()
	seq := binary.BigEndian.Uint32(pkt[16:])
	scheme := pkt[22]
	version := pkt[23]
	sizes := map[byte]int{1: 28, 2: 40, 3: 32, 4: 32, 5: 40, 6: 32, 7: 40, 8: 52, 9: 32, 10: 40, 11: 40, 12: 40, 13: 40, 14: 40}
	size, ok := sizes[scheme]
	if !ok {
		return model.DecodeResult{}, fmt.Errorf("unsupported netflow v8 aggregation scheme %d", scheme)
	}
	if len(pkt) != 28+count*size {
		return model.DecodeResult{}, fmt.Errorf("invalid v8 packet length: need %d got %d", 28+count*size, len(pkt))
	}
	res := model.DecodeResult{Sequence: seq}
	for i := 0; i < count; i++ {
		r := pkt[28+i*size : 28+(i+1)*size]
		f := model.Flow{ReceiveTime: ctx.Received, Exporter: ctx.Exporter, Listener: ctx.Listener, Protocol: "netflow8", Sequence: seq, Packets: uint64(binary.BigEndian.Uint32(r[4:])), Bytes: uint64(binary.BigEndian.Uint32(r[8:])), StartTime: export.Add(-time.Duration(uptime-binary.BigEndian.Uint32(r[12:])) * time.Millisecond), EndTime: export.Add(-time.Duration(uptime-binary.BigEndian.Uint32(r[16:])) * time.Millisecond), Custom: map[string]string{"aggregation_scheme": fmt.Sprint(scheme), "aggregation_version": fmt.Sprint(version)}}
		decodeV8Key(&f, r, scheme)
		res.Flows = append(res.Flows, f)
	}
	return res, nil
}

func decodeV8Key(f *model.Flow, r []byte, scheme byte) {
	u16 := func(o int) uint16 { return binary.BigEndian.Uint16(r[o:]) }
	u32 := func(o int) uint32 { return binary.BigEndian.Uint32(r[o:]) }
	switch scheme {
	case 1, 9:
		f.SrcAS = uint32(u16(20))
		f.DstAS = uint32(u16(22))
		f.IngressIf = uint32(u16(24))
		f.EgressIf = uint32(u16(26))
	case 2, 10:
		f.IPProtocol = uint8(r[20])
		f.SrcPort = u16(24)
		f.DstPort = u16(26)
		f.IngressIf = uint32(u16(28))
		f.EgressIf = uint32(u16(30))
		if scheme == 10 {
			f.TOS = r[28]
			f.DSCP = f.TOS >> 2
			f.ECN = f.TOS & 3
		}
	case 3:
		f.SrcIP = net.IP(r[20:24]).String()
		f.SrcPrefix = fmt.Sprintf("%s/%d", f.SrcIP, r[24])
		f.SrcAS = uint32(u16(26))
		f.IngressIf = uint32(u16(28))
	case 4:
		f.DstIP = net.IP(r[20:24]).String()
		f.DstPrefix = fmt.Sprintf("%s/%d", f.DstIP, r[24])
		f.DstAS = uint32(u16(26))
		f.EgressIf = uint32(u16(28))
	case 5, 11:
		f.SrcIP = net.IP(r[20:24]).String()
		f.DstIP = net.IP(r[24:28]).String()
		f.SrcPrefix = fmt.Sprintf("%s/%d", f.SrcIP, r[28])
		f.DstPrefix = fmt.Sprintf("%s/%d", f.DstIP, r[29])
		f.SrcAS = uint32(u16(30))
		f.DstAS = uint32(u16(32))
		f.IngressIf = uint32(u16(34))
		f.EgressIf = uint32(u16(36))
		if scheme == 11 {
			f.TOS = r[38]
			f.DSCP = f.TOS >> 2
			f.ECN = f.TOS & 3
		}
	case 6:
		f.DstIP = net.IP(r[20:24]).String()
		f.DstPrefix = fmt.Sprintf("%s/%d", f.DstIP, r[24])
		f.DstAS = uint32(u16(26))
		f.EgressIf = uint32(u16(28))
	case 7:
		f.SrcIP = net.IP(r[20:24]).String()
		f.DstIP = net.IP(r[24:28]).String()
		f.SrcPort = u16(28)
		f.DstPort = u16(30)
		f.IPProtocol = r[32]
		f.TOS = r[33]
		f.DSCP = f.TOS >> 2
		f.ECN = f.TOS & 3
	case 8:
		f.DstIP = net.IP(r[0:4]).String()
		f.SrcIP = net.IP(r[4:8]).String()
		f.SrcPort = u16(24)
		f.DstPort = u16(26)
		f.IPProtocol = r[28]
		f.TOS = r[29]
		f.DSCP = f.TOS >> 2
		f.ECN = f.TOS & 3
		f.IngressIf = uint32(u16(30))
		f.EgressIf = uint32(u16(32))
	case 12, 13, 14:
		f.TOS = r[20]
		f.DSCP = f.TOS >> 2
		f.ECN = f.TOS & 3
	}
	_ = u32
}
