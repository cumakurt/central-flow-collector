package sflow

import (
	"central-flow-collector/internal/model"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func readAddress(b []byte, pos *int) (string, error) {
	if *pos+4 > len(b) {
		return "", fmt.Errorf("truncated sflow address")
	}
	kind := binary.BigEndian.Uint32(b[*pos:])
	*pos += 4
	size := 4
	if kind == 2 {
		size = 16
	} else if kind != 1 {
		return "", fmt.Errorf("invalid sflow address type %d", kind)
	}
	if *pos+size > len(b) {
		return "", fmt.Errorf("truncated sflow address value")
	}
	address := net.IP(b[*pos : *pos+size]).String()
	*pos += size
	return address, nil
}

func extendedGateway(b []byte, f *model.Flow) error {
	pos := 0
	next, err := readAddress(b, &pos)
	if err != nil {
		return err
	}
	if len(b)-pos < 16 {
		return fmt.Errorf("truncated extended gateway")
	}
	u32 := func(off int) uint32 { return binary.BigEndian.Uint32(b[off:]) }
	f.Custom["bgp_next_hop"] = next
	f.Custom["router_as"] = strconv.FormatUint(uint64(u32(pos)), 10)
	f.SrcAS = u32(pos + 4)
	f.Custom["src_peer_as"] = strconv.FormatUint(uint64(u32(pos+8)), 10)
	segments := u32(pos + 12)
	pos += 16
	if uint64(segments) > uint64((len(b)-pos)/8) {
		return fmt.Errorf("invalid AS path segment count")
	}
	path := []string{}
	for i := uint32(0); i < segments; i++ {
		if pos+8 > len(b) {
			return fmt.Errorf("truncated AS path")
		}
		kind, count := u32(pos), u32(pos+4)
		pos += 8
		if (kind != 1 && kind != 2) || uint64(count) > uint64((len(b)-pos)/4) {
			return fmt.Errorf("invalid AS path segment")
		}
		members := []string{}
		f.DstAS = 0 // An unordered origin AS_SET has no single origin ASN.
		for j := uint32(0); j < count; j++ {
			asn := u32(pos)
			pos += 4
			members = append(members, strconv.FormatUint(uint64(asn), 10))
			if kind == 2 {
				f.DstAS = asn
			}
		}
		segment := strings.Join(members, " ")
		if kind == 1 {
			segment = "{" + segment + "}"
		}
		path = append(path, segment)
	}
	f.Custom["dst_as_path"] = strings.Join(path, " ")
	if pos+4 > len(b) {
		return fmt.Errorf("truncated BGP communities")
	}
	count := u32(pos)
	pos += 4
	if uint64(count) > uint64((len(b)-pos)/4) {
		return fmt.Errorf("invalid BGP community count")
	}
	communities := []string{}
	for i := uint32(0); i < count; i++ {
		value := u32(pos)
		pos += 4
		communities = append(communities, fmt.Sprintf("%d:%d", value>>16, value&65535))
	}
	if pos+4 != len(b) {
		return fmt.Errorf("invalid extended gateway length")
	}
	f.Custom["bgp_communities"] = strings.Join(communities, " ")
	f.Custom["bgp_local_pref"] = strconv.FormatUint(uint64(u32(pos)), 10)
	return nil
}
