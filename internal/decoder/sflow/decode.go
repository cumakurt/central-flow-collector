package sflow

import (
	"central-flow-collector/internal/model"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

func Decode(pkt []byte, ctx model.PacketContext) (model.DecodeResult, error) {
	p := 0
	u32 := func() (uint32, error) {
		if p+4 > len(pkt) {
			return 0, errors.New("truncated sflow")
		}
		v := binary.BigEndian.Uint32(pkt[p : p+4])
		p += 4
		return v, nil
	}
	ver, e := u32()
	if e != nil {
		return model.DecodeResult{}, e
	}
	if ver != 5 {
		return model.DecodeResult{}, fmt.Errorf("unsupported sflow version %d", ver)
	}
	at, _ := u32()
	switch at {
	case 1:
		p += 4
	case 2:
		p += 16
	default:
		return model.DecodeResult{}, fmt.Errorf("invalid agent address type %d", at)
	}
	if p > len(pkt) {
		return model.DecodeResult{}, errors.New("truncated agent address")
	}
	subAgent, e := u32()
	if e != nil {
		return model.DecodeResult{}, e
	}
	seq, e := u32()
	if e != nil {
		return model.DecodeResult{}, e
	}
	_, e = u32()
	if e != nil {
		return model.DecodeResult{}, e
	}
	ns, e := u32()
	if e != nil {
		return model.DecodeResult{}, e
	}
	if ns > 100000 {
		return model.DecodeResult{}, errors.New("too many sflow samples")
	}
	res := model.DecodeResult{Sequence: seq, ObservationDomain: subAgent}
	for i := uint32(0); i < ns; i++ {
		typ, e := u32()
		if e != nil {
			return res, e
		}
		ln, e := u32()
		if e != nil {
			return res, e
		}
		padded := (uint64(ln) + 3) &^ uint64(3)
		if padded > uint64(len(pkt)-p) {
			return res, errors.New("truncated sflow sample")
		}
		sample := pkt[p : p+int(ln)]
		p += int(padded)
		format := typ & 0xfff
		enterprise := typ >> 12
		if enterprise != 0 {
			continue
		}
		flows, e := decodeSample(sample, format, ctx, seq)
		if e != nil {
			return res, e
		}
		for i := range flows {
			flows[i].ObsDomain = subAgent
		}
		res.Flows = append(res.Flows, flows...)
	}
	if p != len(pkt) {
		return res, errors.New("trailing sflow datagram bytes")
	}
	return res, nil
}
func decodeSample(b []byte, format uint32, ctx model.PacketContext, seq uint32) ([]model.Flow, error) {
	var header int
	switch format {
	case 1:
		header = 32
	case 3:
		header = 44
	default:
		return nil, nil
	}
	if len(b) < header {
		return nil, errors.New("truncated flow sample")
	}
	u32 := func(off int) uint32 { return binary.BigEndian.Uint32(b[off : off+4]) }
	base := model.Flow{ReceiveTime: ctx.Received, StartTime: ctx.Received, EndTime: ctx.Received, Exporter: ctx.Exporter, Listener: ctx.Listener, Protocol: "sflow5", Sequence: seq, Packets: 1, Custom: map[string]string{}}
	base.Custom["sample_sequence"] = fmt.Sprint(u32(0))
	var records uint32
	if format == 1 {
		source := u32(4)
		base.Custom["source_type"] = fmt.Sprint(source >> 24)
		base.Custom["source_index"] = fmt.Sprint(source & 0xffffff)
		base.Sampling = u32(8)
		base.Custom["sample_pool"] = fmt.Sprint(u32(12))
		base.Custom["sample_drops"] = fmt.Sprint(u32(16))
		input, output := u32(20), u32(24)
		base.Custom["input_format"] = fmt.Sprint(input >> 30)
		base.Custom["output_format"] = fmt.Sprint(output >> 30)
		if input>>30 == 0 {
			base.IngressIf = input & 0x3fffffff
		}
		if output>>30 == 0 {
			base.EgressIf = output & 0x3fffffff
		}
		records = u32(28)
	} else {
		base.Custom["source_type"] = fmt.Sprint(u32(4))
		base.Custom["source_index"] = fmt.Sprint(u32(8))
		base.Sampling = u32(12)
		base.Custom["sample_pool"] = fmt.Sprint(u32(16))
		base.Custom["sample_drops"] = fmt.Sprint(u32(20))
		base.Custom["input_format"] = fmt.Sprint(u32(24))
		base.Custom["output_format"] = fmt.Sprint(u32(32))
		if u32(24) == 0 {
			base.IngressIf = u32(28)
		}
		if u32(32) == 0 {
			base.EgressIf = u32(36)
		}
		records = u32(40)
	}
	if records > uint32((len(b)-header)/8) {
		return nil, errors.New("invalid flow record count")
	}
	p := header
	var packet model.Flow
	found, raw := false, false
	for i := uint32(0); i < records; i++ {
		if p+8 > len(b) {
			return nil, errors.New("truncated flow record header")
		}
		typ := u32(p)
		ln := uint64(u32(p + 4))
		p += 8
		padded := (ln + 3) &^ uint64(3)
		if padded > uint64(len(b)-p) {
			return nil, errors.New("truncated flow record")
		}
		rec := b[p : p+int(ln)]
		p += int(padded)
		enterprise, kind := typ>>12, typ&0xfff
		if enterprise == 0 && (kind == 1 || kind == 3 || kind == 4) {
			minimum := map[uint32]int{1: 16, 3: 32, 4: 56}[kind]
			if len(rec) < minimum {
				return nil, errors.New("truncated sampled packet record")
			}
			if kind == 1 && uint64(binary.BigEndian.Uint32(rec[12:16])) > uint64(len(rec)-16) {
				return nil, errors.New("truncated sampled header")
			}
			f, ok := decodeRecord(rec, kind)
			if ok && (!found || (kind == 1 && !raw)) {
				packet, found, raw = f, true, kind == 1
			}
		} else if enterprise == 0 && kind == 1001 {
			if len(rec) < 16 {
				return nil, errors.New("truncated extended switch record")
			}
			base.VLAN = uint16(binary.BigEndian.Uint32(rec[:4]))
			base.Custom["source_priority"] = fmt.Sprint(binary.BigEndian.Uint32(rec[4:8]))
			base.Custom["destination_vlan"] = fmt.Sprint(binary.BigEndian.Uint32(rec[8:12]))
			base.Custom["destination_priority"] = fmt.Sprint(binary.BigEndian.Uint32(rec[12:16]))
		} else if enterprise == 0 && kind == 1002 {
			if len(rec) < 4 {
				return nil, errors.New("truncated extended router record")
			}
			size := 4
			switch binary.BigEndian.Uint32(rec[:4]) {
			case 1:
			case 2:
				size = 16
			default:
				return nil, errors.New("invalid next hop address type")
			}
			if len(rec) < 4+size+8 {
				return nil, errors.New("truncated extended router address")
			}
			base.NextHop = net.IP(rec[4 : 4+size]).String()
			base.Custom["src_prefix_length"] = fmt.Sprint(binary.BigEndian.Uint32(rec[4+size : 8+size]))
			base.Custom["dst_prefix_length"] = fmt.Sprint(binary.BigEndian.Uint32(rec[8+size : 12+size]))
		} else if enterprise == 0 && kind == 1003 {
			if err := extendedGateway(rec, &base); err != nil {
				return nil, err
			}
		} else if enterprise == 0 && kind == 1007 {
			offset := 0
			var err error
			base.NATSrcIP, err = readAddress(rec, &offset)
			if err != nil {
				return nil, err
			}
			base.NATDstIP, err = readAddress(rec, &offset)
			if err != nil {
				return nil, err
			}
			if offset != len(rec) {
				return nil, errors.New("invalid extended NAT length")
			}
			base.Custom["nat_present"] = "1"
		} else {
			base.Custom[fmt.Sprintf("sflow_%d_%d", enterprise, kind)] = fmt.Sprintf("%x", rec)
		}
	}
	if p != len(b) {
		return nil, errors.New("trailing flow sample bytes")
	}
	if !found {
		return nil, nil
	}
	packet.ReceiveTime, packet.StartTime, packet.EndTime = base.ReceiveTime, base.StartTime, base.EndTime
	packet.Exporter, packet.Listener, packet.Protocol = base.Exporter, base.Listener, base.Protocol
	packet.Sequence, packet.Sampling, packet.Packets = base.Sequence, base.Sampling, 1
	packet.IngressIf, packet.EgressIf = base.IngressIf, base.EgressIf
	if base.VLAN != 0 {
		packet.VLAN = base.VLAN
	}
	packet.NextHop = base.NextHop
	packet.SrcAS, packet.DstAS = base.SrcAS, base.DstAS
	packet.NATSrcIP, packet.NATDstIP = base.NATSrcIP, base.NATDstIP
	if packet.Custom == nil {
		packet.Custom = map[string]string{}
	}
	for key, value := range base.Custom {
		packet.Custom[key] = value
	}
	packet.DSCP, packet.ECN = packet.TOS>>2, packet.TOS&3
	packet.Custom["dscp_present"] = "1"
	for _, item := range []struct {
		ip, key string
		target  *string
	}{
		{packet.SrcIP, "src_prefix_length", &packet.SrcPrefix},
		{packet.DstIP, "dst_prefix_length", &packet.DstPrefix},
	} {
		addr, err := netip.ParseAddr(item.ip)
		bits, e := strconv.Atoi(packet.Custom[item.key])
		if err == nil && e == nil && bits >= 0 && bits <= addr.BitLen() {
			*item.target = netip.PrefixFrom(addr, bits).Masked().String()
		}
	}
	return []model.Flow{packet}, nil
}
func decodeRecord(b []byte, format uint32) (model.Flow, bool) {
	switch format {
	case 1:
		return rawHeader(b)
	case 3:
		return sampledIPv4(b)
	case 4:
		return sampledIPv6(b)
	}
	return model.Flow{}, false
}
func sampledIPv4(b []byte) (model.Flow, bool) {
	if len(b) < 32 {
		return model.Flow{}, false
	}
	return model.Flow{Bytes: uint64(binary.BigEndian.Uint32(b[0:4])), IPProtocol: uint8(binary.BigEndian.Uint32(b[4:8])), SrcIP: net.IP(b[8:12]).String(), DstIP: net.IP(b[12:16]).String(), SrcPort: uint16(binary.BigEndian.Uint32(b[16:20])), DstPort: uint16(binary.BigEndian.Uint32(b[20:24])), TCPFlags: uint16(binary.BigEndian.Uint32(b[24:28])), TOS: uint8(binary.BigEndian.Uint32(b[28:32]))}, true
}
func sampledIPv6(b []byte) (model.Flow, bool) {
	if len(b) < 56 {
		return model.Flow{}, false
	}
	return model.Flow{Bytes: uint64(binary.BigEndian.Uint32(b[0:4])), IPProtocol: uint8(binary.BigEndian.Uint32(b[4:8])), SrcIP: net.IP(b[8:24]).String(), DstIP: net.IP(b[24:40]).String(), SrcPort: uint16(binary.BigEndian.Uint32(b[40:44])), DstPort: uint16(binary.BigEndian.Uint32(b[44:48])), TCPFlags: uint16(binary.BigEndian.Uint32(b[48:52])), TOS: uint8(binary.BigEndian.Uint32(b[52:56]))}, true
}
func rawHeader(b []byte) (model.Flow, bool) {
	if len(b) < 16 {
		return model.Flow{}, false
	}
	protocol := binary.BigEndian.Uint32(b[:4])
	frame := binary.BigEndian.Uint32(b[4:8])
	hl := uint64(binary.BigEndian.Uint32(b[12:16]))
	if hl > uint64(len(b)-16) {
		return model.Flow{}, false
	}
	h := b[16 : 16+int(hl)]
	f := model.Flow{Bytes: uint64(frame), Packets: 1}
	var ether uint16
	off := 0
	switch protocol {
	case 1:
		if len(h) < 14 {
			return model.Flow{}, false
		}
		f.DstMAC = net.HardwareAddr(h[:6]).String()
		f.SrcMAC = net.HardwareAddr(h[6:12]).String()
		ether = binary.BigEndian.Uint16(h[12:14])
		off = 14
		for ether == 0x8100 || ether == 0x88a8 || ether == 0x9100 {
			if off+4 > len(h) {
				return model.Flow{}, false
			}
			f.VLAN = binary.BigEndian.Uint16(h[off:off+2]) & 0xfff
			ether = binary.BigEndian.Uint16(h[off+2 : off+4])
			off += 4
		}
	case 11:
		ether = 0x0800
	case 12:
		ether = 0x86dd
	default:
		return model.Flow{}, false
	}
	if ether == 0x8847 || ether == 0x8848 {
		for {
			if off+4 > len(h) {
				return model.Flow{}, false
			}
			bottom := h[off+2]&1 != 0
			off += 4
			if bottom {
				break
			}
		}
		if off >= len(h) {
			return model.Flow{}, false
		}
		switch h[off] >> 4 {
		case 4:
			ether = 0x0800
		case 6:
			ether = 0x86dd
		default:
			return model.Flow{}, false
		}
	}
	switch ether {
	case 0x0800:
		if len(h) < off+20 || h[off]>>4 != 4 {
			return model.Flow{}, false
		}
		ihl := int(h[off]&15) * 4
		if ihl < 20 || len(h) < off+ihl {
			return model.Flow{}, false
		}
		f.IPProtocol = h[off+9]
		f.SrcIP = net.IP(h[off+12 : off+16]).String()
		f.DstIP = net.IP(h[off+16 : off+20]).String()
		f.TOS = h[off+1]
		// Later fragments do not contain a transport header.
		if binary.BigEndian.Uint16(h[off+6:off+8])&0x1fff == 0 {
			portsAndFlags(&f, h, off+ihl)
		}
	case 0x86dd:
		if len(h) < off+40 || h[off]>>4 != 6 {
			return model.Flow{}, false
		}
		f.IPProtocol = h[off+6]
		f.TOS = (h[off]&15)<<4 | h[off+1]>>4
		f.SrcIP = net.IP(h[off+8 : off+24]).String()
		f.DstIP = net.IP(h[off+24 : off+40]).String()
		pos := off + 40
		for {
			next := f.IPProtocol
			if next != 0 && next != 43 && next != 44 && next != 51 && next != 60 {
				break
			}
			if pos+2 > len(h) {
				return f, true
			}
			size := (int(h[pos+1]) + 1) * 8
			if next == 51 {
				size = (int(h[pos+1]) + 2) * 4
			}
			if next == 44 {
				size = 8
			}
			if pos+size > len(h) {
				return f, true
			}
			f.IPProtocol = h[pos]
			if next == 44 && binary.BigEndian.Uint16(h[pos+2:pos+4])&0xfff8 != 0 {
				return f, true
			}
			pos += size
		}
		portsAndFlags(&f, h, pos)
	default:
		return model.Flow{}, false
	}
	f.DSCP, f.ECN = f.TOS>>2, f.TOS&3
	f.Custom = map[string]string{"dscp_present": "1"}
	return f, true
}
func portsAndFlags(f *model.Flow, b []byte, off int) {
	if (f.IPProtocol == 6 || f.IPProtocol == 17) && len(b) >= off+4 {
		f.SrcPort = binary.BigEndian.Uint16(b[off : off+2])
		f.DstPort = binary.BigEndian.Uint16(b[off+2 : off+4])
	}
	if f.IPProtocol == 6 && len(b) >= off+14 {
		f.TCPFlags = uint16(b[off+13])
	}
}
