package templates

import (
	"encoding/binary"
	"fmt"
)

// Parse validates the entire template set before the caller updates its cache.
// UDP withdrawals are ignored as required by RFC 7011 section 8.4.
func Parse(b []byte, ipfix, options bool) ([]Template, error) {
	var out []Template
	for pos := 0; pos < len(b); {
		if len(b)-pos < 4 {
			for _, v := range b[pos:] {
				if v != 0 {
					return nil, fmt.Errorf("nonzero template padding")
				}
			}
			break
		}
		tid := binary.BigEndian.Uint16(b[pos:])
		count := int(binary.BigEndian.Uint16(b[pos+2:]))
		pos += 4
		if ipfix && count == 0 {
			if tid < 256 && ((!options && tid != 2) || (options && tid != 3)) {
				return nil, fmt.Errorf("invalid withdrawal id %d", tid)
			}
			continue
		}
		t := Template{ID: tid}
		if options {
			if pos+2 > len(b) {
				return nil, fmt.Errorf("truncated options template")
			}
			other := int(binary.BigEndian.Uint16(b[pos:]))
			pos += 2
			if ipfix {
				t.ScopeCount = other
			} else {
				if count%4 != 0 || other%4 != 0 {
					return nil, fmt.Errorf("invalid v9 options field lengths")
				}
				t.ScopeCount = count / 4
				count = (count + other) / 4
			}
			if t.ScopeCount == 0 || t.ScopeCount > count {
				return nil, fmt.Errorf("invalid options scope count")
			}
		}
		if tid < 256 || count == 0 || count > 1024 {
			return nil, fmt.Errorf("invalid template %d/%d", tid, count)
		}
		minimum := 0
		for i := 0; i < count; i++ {
			if pos+4 > len(b) {
				return nil, fmt.Errorf("truncated template field")
			}
			id := binary.BigEndian.Uint16(b[pos:])
			length := binary.BigEndian.Uint16(b[pos+2:])
			pos += 4
			field := Field{ID: id, Length: length}
			if !ipfix && length == 65535 {
				return nil, fmt.Errorf("variable length field in netflow v9")
			}
			if ipfix && id&0x8000 != 0 {
				if pos+4 > len(b) {
					return nil, fmt.Errorf("truncated enterprise number")
				}
				field.ID &= 0x7fff
				field.EnterpriseSpecific = true
				field.Enterprise = binary.BigEndian.Uint32(b[pos:])
				pos += 4
			}
			minimum += int(length)
			t.Fields = append(t.Fields, field)
		}
		if minimum == 0 {
			return nil, fmt.Errorf("template has no record bytes")
		}
		out = append(out, t)
	}
	return out, nil
}
