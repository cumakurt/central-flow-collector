package fields

import (
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/templates"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func Apply(f *model.Flow, fld templates.Field, b []byte) {
	id := fld.ID
	if fld.Enterprise != 0 || fld.EnterpriseSpecific {
		custom(f, fmt.Sprintf("pen_%d_ie_%d", fld.Enterprise, id), fmt.Sprintf("%x", b))
		return
	}
	switch id {
	case 1:
		f.Bytes = u64(b)
	case 2:
		f.Packets = u64(b)
	case 4:
		f.IPProtocol = uint8(u64(b))
	case 5:
		f.TOS = uint8(u64(b))
		f.DSCP = f.TOS >> 2
		f.ECN = f.TOS & 3
		custom(f, "dscp_present", "1")
	case 6:
		f.TCPFlags = uint16(u64(b))
	case 7:
		f.SrcPort = uint16(u64(b))
	case 8:
		if len(b) == 4 {
			f.SrcIP = net.IP(b).String()
		}
	case 9, 29:
		custom(f, "src_prefix_length", strconv.FormatUint(u64(b), 10))
	case 10:
		f.IngressIf = uint32(u64(b))
	case 11:
		f.DstPort = uint16(u64(b))
	case 12:
		if len(b) == 4 {
			f.DstIP = net.IP(b).String()
		}
	case 13, 30:
		custom(f, "dst_prefix_length", strconv.FormatUint(u64(b), 10))
	case 14:
		f.EgressIf = uint32(u64(b))
	case 15:
		if len(b) == 4 {
			f.NextHop = net.IP(b).String()
		}
	case 16:
		f.SrcAS = uint32(u64(b))
	case 17:
		f.DstAS = uint32(u64(b))
	case 21:
		custom(f, "end_sys_uptime", strconv.FormatUint(u64(b), 10))
	case 22:
		custom(f, "start_sys_uptime", strconv.FormatUint(u64(b), 10))
	case 27:
		if len(b) == 16 {
			f.SrcIP = net.IP(b).String()
		}
	case 28:
		if len(b) == 16 {
			f.DstIP = net.IP(b).String()
		}
	case 62:
		if len(b) == 16 {
			f.NextHop = net.IP(b).String()
		}
	case 32: // ICMP type/code retained custom
		custom(f, "icmp_type_code", fmt.Sprintf("%d", u64(b)))
	case 34, 50:
		f.Sampling = uint32(u64(b))
	case 56:
		f.SrcMAC = mac(b)
	case 57, 80:
		f.DstMAC = mac(b)
	case 58:
		f.VLAN = uint16(u64(b))
	case 61:
		f.Direction = uint8(u64(b))
	case 95:
		f.AppID = fmt.Sprintf("%x", b)
	case 96:
		f.AppName = strings.TrimRight(string(b), "\x00")
	case 85:
		f.Bytes = u64(b)
	case 86:
		f.Packets = u64(b)
	case 136:
		custom(f, "flow_end_reason", fmt.Sprintf("%d", u64(b)))
	case 148:
		custom(f, "flow_id", fmt.Sprintf("%d", u64(b)))
	case 150:
		if len(b) <= 8 {
			f.StartTime = time.Unix(int64(u64(b)), 0).UTC()
		}
	case 151:
		if len(b) <= 8 {
			f.EndTime = time.Unix(int64(u64(b)), 0).UTC()
		}
	case 152:
		if len(b) <= 8 {
			f.StartTime = time.UnixMilli(int64(u64(b))).UTC()
		}
	case 153:
		if len(b) <= 8 {
			f.EndTime = time.UnixMilli(int64(u64(b))).UTC()
		}
	case 154, 156:
		if len(b) == 8 {
			f.StartTime = ntpTime(b)
		}
	case 155, 157:
		if len(b) == 8 {
			f.EndTime = ntpTime(b)
		}
	case 158:
		custom(f, "start_delta_microseconds", strconv.FormatUint(u64(b), 10))
	case 159:
		custom(f, "end_delta_microseconds", strconv.FormatUint(u64(b), 10))
	case 160:
		custom(f, "system_init_milliseconds", strconv.FormatUint(u64(b), 10))
	case 225, 281:
		if len(b) == 4 || len(b) == 16 {
			f.NATSrcIP = net.IP(b).String()
			custom(f, "nat_present", "1")
		}
	case 226, 282:
		if len(b) == 4 || len(b) == 16 {
			f.NATDstIP = net.IP(b).String()
			custom(f, "nat_present", "1")
		}
	case 227:
		f.NATSrcPort = uint16(u64(b))
		custom(f, "nat_present", "1")
	case 228:
		f.NATDstPort = uint16(u64(b))
		custom(f, "nat_present", "1")
	case 233:
		custom(f, "firewall_event", strconv.FormatUint(u64(b), 10))
	case 230:
		custom(f, "nat_event", strconv.FormatUint(u64(b), 10))
	case 234:
		custom(f, "ingress_vrf_id", strconv.FormatUint(u64(b), 10))
	case 235:
		custom(f, "egress_vrf_id", strconv.FormatUint(u64(b), 10))
	case 236:
		f.VRF = strings.TrimRight(string(b), "\x00")
	case 346:
		custom(f, "private_enterprise_number", strconv.FormatUint(u64(b), 10))
	default:
		key := fmt.Sprintf("ie_%d", id)
		if fld.Enterprise != 0 {
			key = fmt.Sprintf("pen_%d_ie_%d", fld.Enterprise, id)
		}
		custom(f, key, fmt.Sprintf("%x", b))
	}
}

func ntpTime(b []byte) time.Time {
	seconds := int64(binary.BigEndian.Uint32(b[:4])) - 2208988800
	nanos := (uint64(binary.BigEndian.Uint32(b[4:])) * 1000000000) >> 32
	return time.Unix(seconds, int64(nanos)).UTC()
}
func u64(b []byte) uint64 {
	if len(b) == 0 {
		return 0
	}
	if len(b) > 8 {
		b = b[len(b)-8:]
	}
	var x uint64
	for _, v := range b {
		x = x<<8 | uint64(v)
	}
	return x
}
func mac(b []byte) string {
	if len(b) < 6 {
		return ""
	}
	return net.HardwareAddr(b[:6]).String()
}
func custom(f *model.Flow, k, v string) {
	if f.Custom == nil {
		f.Custom = map[string]string{}
	}
	f.Custom[k] = v
}
func ReadVarField(data []byte, pos *int, length uint16) ([]byte, error) {
	l := int(length)
	if length == 65535 {
		if *pos >= len(data) {
			return nil, fmt.Errorf("missing varlen")
		}
		v := int(data[*pos])
		*pos++
		if v < 255 {
			l = v
		} else {
			if *pos+2 > len(data) {
				return nil, fmt.Errorf("truncated varlen")
			}
			l = int(binary.BigEndian.Uint16(data[*pos : *pos+2]))
			*pos += 2
		}
	}
	if l < 0 || *pos+l > len(data) {
		return nil, fmt.Errorf("field length %d exceeds set", l)
	}
	b := data[*pos : *pos+l]
	*pos += l
	return b, nil
}
