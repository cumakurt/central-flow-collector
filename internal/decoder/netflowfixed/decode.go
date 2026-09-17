package netflowfixed

import (
	"central-flow-collector/internal/model"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"time"
)

func Decode(pkt []byte, ctx model.PacketContext) (model.DecodeResult, error) {
	if len(pkt) < 16 {
		return model.DecodeResult{}, errors.New("fixed netflow packet too short")
	}
	version := binary.BigEndian.Uint16(pkt[:2])
	if version == 8 {
		return DecodeV8(pkt, ctx)
	}
	header, size, maximum := 24, 48, 30
	switch version {
	case 1:
		header, maximum = 16, 24
	case 5:
	case 7:
		size, maximum = 52, 27
	default:
		return model.DecodeResult{}, fmt.Errorf("unsupported fixed netflow version %d", version)
	}
	if len(pkt) < header {
		return model.DecodeResult{}, errors.New("truncated netflow header")
	}
	count := int(binary.BigEndian.Uint16(pkt[2:4]))
	if count < 1 || count > maximum {
		return model.DecodeResult{}, fmt.Errorf("invalid flow count %d", count)
	}
	need := header + count*size
	if len(pkt) != need {
		return model.DecodeResult{}, fmt.Errorf("truncated packet: need %d got %d", need, len(pkt))
	}
	uptime := binary.BigEndian.Uint32(pkt[4:8])
	unixSecs := binary.BigEndian.Uint32(pkt[8:12])
	unixNsecs := binary.BigEndian.Uint32(pkt[12:16])
	var seq uint32
	var sampling uint16
	if version != 1 {
		seq = binary.BigEndian.Uint32(pkt[16:20])
	}
	if version == 5 {
		sampling = binary.BigEndian.Uint16(pkt[22:24]) & 0x3fff
	}
	exportTime := time.Unix(int64(unixSecs), int64(unixNsecs)).UTC()
	out := model.DecodeResult{Sequence: seq}
	for i := 0; i < count; i++ {
		o := header + i*size
		r := pkt[o : o+size]
		first := binary.BigEndian.Uint32(r[24:28])
		last := binary.BigEndian.Uint32(r[28:32])
		start := exportTime.Add(-time.Duration(uptime-first) * time.Millisecond)
		end := exportTime.Add(-time.Duration(uptime-last) * time.Millisecond)
		f := model.Flow{ReceiveTime: ctx.Received, StartTime: start, EndTime: end, Exporter: ctx.Exporter, Listener: ctx.Listener, Protocol: "netflow" + strconv.Itoa(int(version)), SrcIP: net.IP(r[0:4]).String(), DstIP: net.IP(r[4:8]).String(), NextHop: net.IP(r[8:12]).String(), IngressIf: uint32(binary.BigEndian.Uint16(r[12:14])), EgressIf: uint32(binary.BigEndian.Uint16(r[14:16])), Packets: uint64(binary.BigEndian.Uint32(r[16:20])), Bytes: uint64(binary.BigEndian.Uint32(r[20:24])), SrcPort: binary.BigEndian.Uint16(r[32:34]), DstPort: binary.BigEndian.Uint16(r[34:36]), TCPFlags: uint16(r[37]), IPProtocol: r[38], TOS: r[39], SrcAS: uint32(binary.BigEndian.Uint16(r[40:42])), DstAS: uint32(binary.BigEndian.Uint16(r[42:44])), Sequence: seq, Sampling: uint32(sampling)}
		f.DSCP = f.TOS >> 2
		f.ECN = f.TOS & 3
		f.Custom = map[string]string{"dscp_present": "1"}
		if version == 1 {
			f.TCPFlags = uint16(r[40])
			f.SrcAS, f.DstAS = 0, 0
		} else {
			for _, item := range []struct {
				ip     string
				bits   byte
				target *string
			}{{f.SrcIP, r[44], &f.SrcPrefix}, {f.DstIP, r[45], &f.DstPrefix}} {
				if item.bits <= 32 {
					addr, _ := netip.ParseAddr(item.ip)
					*item.target = netip.PrefixFrom(addr, int(item.bits)).Masked().String()
				}
			}
		}
		if version == 5 {
			f.Custom["engine_type"] = strconv.Itoa(int(pkt[20]))
			f.Custom["engine_id"] = strconv.Itoa(int(pkt[21]))
			f.Custom["sampling_mode"] = strconv.Itoa(int(binary.BigEndian.Uint16(pkt[22:24]) >> 14))
		}
		if version == 7 {
			f.Custom["netflow7_flags"] = strconv.Itoa(int(r[36]))
			f.Custom["netflow7_flow_flags"] = strconv.Itoa(int(binary.BigEndian.Uint16(r[46:48])))
			f.Custom["router_sc"] = net.IP(r[48:52]).String()
		}
		out.Flows = append(out.Flows, f)
	}
	return out, nil
}
