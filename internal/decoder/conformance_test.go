package decoder_test

import (
	"central-flow-collector/internal/decoder/ipfix"
	"central-flow-collector/internal/decoder/netflow9"
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/templates"
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

func words(values ...uint16) []byte {
	b := make([]byte, 2*len(values))
	for i, v := range values {
		binary.BigEndian.PutUint16(b[i*2:], v)
	}
	return b
}

func message(version uint16, sets ...[]byte) []byte {
	header := 16
	if version == 9 {
		header = 20
	}
	b := make([]byte, header)
	binary.BigEndian.PutUint16(b, version)
	if version == 9 {
		binary.BigEndian.PutUint32(b[4:], 10000)
		binary.BigEndian.PutUint32(b[8:], 1700000000)
		binary.BigEndian.PutUint32(b[16:], 7)
	} else {
		binary.BigEndian.PutUint32(b[4:], 1700000000)
		binary.BigEndian.PutUint32(b[12:], 7)
	}
	for _, set := range sets {
		b = append(b, set...)
	}
	if version == 10 {
		binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	}
	return b
}

func set(id uint16, data []byte) []byte {
	return append(words(id, uint16(len(data)+4)), data...)
}

type decoder interface {
	Decode([]byte, model.PacketContext) (model.DecodeResult, error)
}

func newDecoder(version uint16, cache *templates.Cache) decoder {
	if version == 9 {
		return netflow9.New(cache)
	}
	return ipfix.New(cache)
}

func templateSet(version uint16, fields ...uint16) []byte {
	id := uint16(2)
	if version == 9 {
		id = 0
	}
	return set(id, append(words(256, uint16(len(fields)/2)), words(fields...)...))
}

func TestTemplateSessionIsolation(t *testing.T) {
	for _, version := range []uint16{9, 10} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			d := newDecoder(version, templates.New(time.Hour))
			ctx := model.PacketContext{Exporter: "192.0.2.1", Listener: "a", SourcePort: 1234, Received: time.Now()}
			if _, err := d.Decode(message(version, templateSet(version, 8, 4)), ctx); err != nil {
				t.Fatal(err)
			}
			data := message(version, set(256, []byte{192, 0, 2, 9}))
			for _, other := range []model.PacketContext{
				{Exporter: ctx.Exporter, Listener: "b", SourcePort: 1234},
				{Exporter: ctx.Exporter, Listener: "a", SourcePort: 1235},
				{Exporter: "192.0.2.2", Listener: "a", SourcePort: 1234},
			} {
				res, err := d.Decode(data, other)
				if err != nil || !res.MissingTemplate || len(res.Flows) != 0 {
					t.Fatalf("session collision: %+v %v", res, err)
				}
			}
			res, err := d.Decode(data, ctx)
			if err != nil || len(res.Flows) != 1 || res.Flows[0].SrcIP != "192.0.2.9" {
				t.Fatalf("%+v %v", res, err)
			}
		})
	}
}

func TestShortRecordsAndPadding(t *testing.T) {
	for _, version := range []uint16{9, 10} {
		d := newDecoder(version, templates.New(time.Hour))
		ctx := model.PacketContext{Received: time.Now()}
		res, err := d.Decode(message(version, templateSet(version, 4, 1), set(256, []byte{6, 17, 1})), ctx)
		if err != nil || len(res.Flows) != 3 {
			t.Fatalf("version %d lost short records: %+v %v", version, res, err)
		}
		res, err = d.Decode(message(version, templateSet(version, 8, 4), set(256, []byte{192, 0, 2, 1, 0, 0})), ctx)
		if err != nil || len(res.Flows) != 1 {
			t.Fatalf("padding: %+v %v", res, err)
		}
		if _, err = d.Decode(message(version, set(256, []byte{192, 0, 2, 1, 99})), ctx); err == nil {
			t.Fatal("accepted truncated nonzero record")
		}
	}
}

func TestIPFIXEnterpriseAndVariableLength(t *testing.T) {
	d := ipfix.New(templates.New(time.Hour))
	// PEN 32473 IE 8 must not overwrite sourceIPv4Address (standard IE 8).
	template := append(words(256, 3, 8, 4, 0x8008, 4), []byte{0, 0, 126, 217}...)
	template = append(template, words(400, 65535)...)
	data := []byte{192, 0, 2, 1, 203, 0, 113, 1, 255, 1, 0}
	data = append(data, make([]byte, 256)...)
	res, err := d.Decode(message(10, set(2, template), set(256, data)), model.PacketContext{})
	if err != nil || len(res.Flows) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	f := res.Flows[0]
	if f.SrcIP != "192.0.2.1" || f.Custom["pen_32473_ie_8"] != "cb007101" || len(f.Custom["ie_400"]) != 512 {
		t.Fatalf("bad fields: %+v", f)
	}
	if _, err := d.Decode(message(10, set(256, data[:len(data)-1])), model.PacketContext{}); err == nil {
		t.Fatal("accepted truncated variable length")
	}
}

func TestOptionsSamplingAndRefresh(t *testing.T) {
	for _, version := range []uint16{9, 10} {
		t.Run(fmt.Sprint(version), func(t *testing.T) {
			cache := templates.New(time.Hour)
			d := newDecoder(version, cache)
			ctx := model.PacketContext{Received: time.Now()}
			optionID := uint16(3)
			option := words(300, 2, 1, 10, 4, 34, 4)
			if version == 9 {
				optionID = 1
				option = words(300, 4, 4, 2, 4, 34, 4)
			}
			optionSet := set(optionID, option)
			res, err := d.Decode(message(version, optionSet, set(300, []byte{0, 0, 0, 12, 0, 0, 0, 100})), ctx)
			if err != nil || len(res.Flows) != 0 || len(res.Options) != 1 || res.MissingTemplate {
				t.Fatalf("bad options: %+v %v", res, err)
			}
			if _, err = d.Decode(message(version, optionSet), ctx); err != nil {
				t.Fatal(err)
			}
			res, err = d.Decode(message(version, templateSet(version, 10, 4, 2, 4), set(256, []byte{0, 0, 0, 12, 0, 0, 0, 3, 0, 0, 0, 13, 0, 0, 0, 4})), ctx)
			if err != nil || len(res.Flows) != 2 {
				t.Fatalf("%+v %v", res, err)
			}
			if res.Flows[0].Sampling != 100 || res.Flows[0].Packets != 3 || res.Flows[1].Sampling != 0 {
				t.Fatalf("scope leakage: %+v", res.Flows)
			}
			found := false
			for _, info := range cache.Snapshot() {
				if info.TemplateID == 300 && len(info.Options) == 1 {
					found = true
				}
			}
			if !found {
				t.Fatal("options missing from template metadata")
			}
		})
	}
}

func TestIPFIXUDPWithdrawalIgnored(t *testing.T) {
	d := ipfix.New(templates.New(time.Hour))
	ctx := model.PacketContext{}
	_, err := d.Decode(message(10, templateSet(10, 8, 4), set(2, words(256, 0))), ctx)
	if err != nil {
		t.Fatal(err)
	}
	res, err := d.Decode(message(10, set(256, []byte{192, 0, 2, 1})), ctx)
	if err != nil || res.MissingTemplate || len(res.Flows) != 1 {
		t.Fatalf("UDP withdrawal removed template: %+v %v", res, err)
	}
}

func TestFieldOrderAndUptime(t *testing.T) {
	d := netflow9.New(templates.New(time.Hour))
	p := message(9, templateSet(9, 9, 1, 8, 4, 22, 4), set(256, []byte{24, 192, 0, 2, 99, 255, 255, 255, 240}))
	binary.BigEndian.PutUint32(p[4:], 16)
	res, err := d.Decode(p, model.PacketContext{})
	if err != nil || len(res.Flows) != 1 {
		t.Fatalf("%+v %v", res, err)
	}
	f := res.Flows[0]
	if f.SrcPrefix != "192.0.2.0/24" || !f.StartTime.Equal(time.Unix(1700000000, 0).Add(-32*time.Millisecond)) {
		t.Fatalf("bad normalization: %+v", f)
	}
}

func TestMalformedTemplatesAndFraming(t *testing.T) {
	for _, version := range []uint16{9, 10} {
		d := newDecoder(version, templates.New(time.Hour))
		for _, bad := range [][]byte{
			message(version, templateSet(version, 8, 0)),
			message(version, set(256, []byte{1, 2, 3})),
			message(version, []byte{0}),
		} {
			// Unknown templates are recoverable, framing and zero-size templates are not.
			r, err := d.Decode(bad, model.PacketContext{})
			if err == nil && !r.MissingTemplate {
				t.Fatalf("accepted malformed version %d packet", version)
			}
		}
	}
}

func TestIPFIXTimeAndIPv6NextHop(t *testing.T) {
	cache := templates.New(time.Hour)
	d := ipfix.New(cache)
	// NTP: 2023-11-14T22:13:20.5Z; the fraction is binary, not microseconds.
	b := make([]byte, 24)
	binary.BigEndian.PutUint32(b, 3908988800)
	binary.BigEndian.PutUint32(b[4:], 0x80000000)
	copy(b[8:], []byte{0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	r, err := d.Decode(message(10, templateSet(10, 154, 8, 62, 16), set(256, b)), model.PacketContext{})
	if err != nil || len(r.Flows) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	if !r.Flows[0].StartTime.Equal(time.Unix(1700000000, 500000000)) || r.Flows[0].NextHop != "2001:db8::1" {
		t.Fatalf("time/next hop: %+v", r.Flows[0])
	}
}

func FuzzTemplateMessage(f *testing.F) {
	for _, version := range []uint16{9, 10} {
		f.Add(message(version, templateSet(version, 8, 4, 12, 4), set(256, []byte{192, 0, 2, 1, 203, 0, 113, 1})))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) < 2 {
			return
		}
		version := binary.BigEndian.Uint16(b)
		_, _ = newDecoder(version, templates.New(time.Minute)).Decode(b, model.PacketContext{})
	})
}
