package fields

import (
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/templates"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// Reverse normalizes RFC 5103 reverse IEs into a second directional flow.
// Post-forwarding counters (IEs 23/24) are deliberately not reverse counters.
func Reverse(f model.Flow, export time.Time) (model.Flow, bool) {
	const prefix = "pen_29305_ie_"
	hasCounters := false
	for _, id := range []string{"1", "2", "85", "86"} {
		if _, ok := f.Custom[prefix+id]; ok {
			hasCounters = true
		}
	}
	if !hasCounters {
		return model.Flow{}, false
	}
	r := model.Flow{ReceiveTime: f.ReceiveTime, Exporter: f.Exporter, Listener: f.Listener, Protocol: f.Protocol, ObsDomain: f.ObsDomain, Sequence: f.Sequence, Sampling: f.Sampling, AppID: f.AppID, AppName: f.AppName, VRF: f.VRF,
		SrcIP: f.DstIP, DstIP: f.SrcIP, SrcPort: f.DstPort, DstPort: f.SrcPort, IPProtocol: f.IPProtocol, SrcAS: f.DstAS, DstAS: f.SrcAS, SrcPrefix: f.DstPrefix, DstPrefix: f.SrcPrefix, SrcMAC: f.DstMAC, DstMAC: f.SrcMAC, IngressIf: f.EgressIf, EgressIf: f.IngressIf, VLAN: f.VLAN,
		Custom: map[string]string{"biflow_direction": "reverse"}}
	for key, value := range f.Custom {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		id, err := strconv.ParseUint(strings.TrimPrefix(key, prefix), 10, 16)
		if err != nil {
			continue
		}
		b, err := hex.DecodeString(value)
		if err != nil {
			continue
		}
		Apply(&r, templates.Field{ID: uint16(id), Length: uint16(len(b))}, b)
	}
	finalize(&r, export, nil)
	return r, true
}
