package netflowfixed

import (
	"central-flow-collector/internal/model"
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

func fixture(version uint16) []byte {
	header, size := 24, 48
	if version == 1 {
		header = 16
	}
	if version == 7 {
		size = 52
	}
	b := make([]byte, header+size)
	binary.BigEndian.PutUint16(b, version)
	binary.BigEndian.PutUint16(b[2:], 1)
	binary.BigEndian.PutUint32(b[4:], 10000)
	binary.BigEndian.PutUint32(b[8:], 1700000000)
	if version != 1 {
		binary.BigEndian.PutUint32(b[16:], 42)
	}
	r := b[header:]
	copy(r, []byte{192, 0, 2, 1, 203, 0, 113, 1, 192, 0, 2, 254})
	binary.BigEndian.PutUint16(r[12:], 12)
	binary.BigEndian.PutUint16(r[14:], 13)
	binary.BigEndian.PutUint32(r[16:], 9)
	binary.BigEndian.PutUint32(r[20:], 900)
	binary.BigEndian.PutUint32(r[24:], 8000)
	binary.BigEndian.PutUint32(r[28:], 9000)
	binary.BigEndian.PutUint16(r[32:], 12345)
	binary.BigEndian.PutUint16(r[34:], 443)
	r[38], r[39] = 6, 184
	if version == 1 {
		r[40] = 18
	} else {
		r[37] = 18
		r[44] = 24
		r[45] = 24
	}
	if version == 7 {
		copy(r[48:], []byte{192, 0, 2, 253})
	}
	return b
}

func TestFixedVersions(t *testing.T) {
	for _, version := range []uint16{1, 5, 7} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			b := fixture(version)
			r, err := Decode(b, model.PacketContext{})
			if err != nil || len(r.Flows) != 1 {
				t.Fatalf("%+v %v", r, err)
			}
			f := r.Flows[0]
			if f.Protocol != fmt.Sprintf("netflow%d", version) || f.SrcIP != "192.0.2.1" || f.DstPort != 443 || f.Packets != 9 || f.Bytes != 900 || f.TCPFlags != 18 || f.DSCP != 46 || !f.StartTime.Equal(time.Unix(1699999998, 0)) {
				t.Fatalf("bad decode: %+v", f)
			}
			if version == 7 && f.Custom["router_sc"] != "192.0.2.253" {
				t.Fatal("missing v7 router")
			}
			if version == 1 && (f.SrcAS != 0 || f.Sequence != 0) {
				t.Fatal("v1 decoded nonexistent fields")
			}
			for i := 0; i < len(b); i++ {
				if _, err := Decode(b[:i], model.PacketContext{}); err == nil {
					t.Fatalf("accepted truncated packet at %d", i)
				}
			}
		})
	}
}

func FuzzDecode(f *testing.F) {
	for _, version := range []uint16{1, 5, 7} {
		f.Add(fixture(version))
	}
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Decode(b, model.PacketContext{}) })
}
