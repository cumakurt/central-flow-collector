package fields

import (
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/templates"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Records uses the template's minimum wire length to distinguish short records
// from padding. A fixed four-byte cutoff loses valid reduced-size IPFIX records.
func Records(b []byte, t templates.Template, base model.Flow, export time.Time, uptime *uint32) ([]model.Flow, error) {
	minimum := 0
	for _, field := range t.Fields {
		if field.Length == 65535 {
			minimum++
		} else {
			minimum += int(field.Length)
		}
	}
	if minimum == 0 {
		return nil, fmt.Errorf("template %d has no record bytes", t.ID)
	}
	var out []model.Flow
	for pos := 0; pos < len(b); {
		if len(b)-pos < minimum {
			if base.Protocol == "netflow9" && len(b)-pos > 3 {
				return out, fmt.Errorf("truncated netflow record")
			}
			for _, v := range b[pos:] {
				if v != 0 {
					return out, fmt.Errorf("nonzero set padding or truncated record")
				}
			}
			break
		}
		f := base
		for i, field := range t.Fields {
			v, err := ReadVarField(b, &pos, field.Length)
			if err != nil {
				return out, err
			}
			if i < t.ScopeCount {
				key := fmt.Sprintf("scope_%d_%d", field.Enterprise, field.ID)
				if field.EnterpriseSpecific && field.Enterprise == 0 {
					key = fmt.Sprintf("scope_pen_0_%d", field.ID)
				}
				custom(&f, key, fmt.Sprintf("%x", v))
				continue
			}
			Apply(&f, field, v)
		}
		finalize(&f, export, uptime)
		out = append(out, f)
	}
	return out, nil
}

func finalize(f *model.Flow, export time.Time, uptime *uint32) {
	// PAN-OS v9 identifies its private field namespace using IE 346. Do not
	// interpret another exporter's same-numbered private fields as App-ID.
	if f.Protocol == "netflow9" && f.Custom["private_enterprise_number"] == "25461" {
		if app, err := hex.DecodeString(f.Custom["ie_56701"]); err == nil && len(app) > 0 {
			f.AppName = strings.TrimRight(string(app), "\x00")
		}
		if user, err := hex.DecodeString(f.Custom["ie_56702"]); err == nil && len(user) > 0 {
			custom(f, "user_name", strings.TrimRight(string(user), "\x00"))
		}
	}
	if f.VRF == "" {
		f.VRF = f.Custom["ingress_vrf_id"]
	}
	for _, item := range []struct {
		ip, key string
		target  *string
	}{
		{f.SrcIP, "src_prefix_length", &f.SrcPrefix},
		{f.DstIP, "dst_prefix_length", &f.DstPrefix},
	} {
		ip, err := netip.ParseAddr(item.ip)
		bits, e := strconv.Atoi(f.Custom[item.key])
		if err == nil && e == nil && bits >= 0 && bits <= ip.BitLen() {
			*item.target = netip.PrefixFrom(ip, bits).Masked().String()
		}
	}
	for _, item := range []struct {
		key, delta string
		target     *time.Time
	}{
		{"start_sys_uptime", "start_delta_microseconds", &f.StartTime},
		{"end_sys_uptime", "end_delta_microseconds", &f.EndTime},
	} {
		if !item.target.IsZero() {
			continue
		}
		if delta, err := strconv.ParseUint(f.Custom[item.delta], 10, 32); err == nil {
			*item.target = export.Add(-time.Duration(delta) * time.Microsecond)
		} else if ms, err := strconv.ParseUint(f.Custom[item.key], 10, 32); err == nil {
			if uptime != nil {
				*item.target = export.Add(-time.Duration(*uptime-uint32(ms)) * time.Millisecond)
			} else if boot, err := strconv.ParseInt(f.Custom["system_init_milliseconds"], 10, 64); err == nil {
				*item.target = time.UnixMilli(boot).Add(time.Duration(ms) * time.Millisecond).UTC()
			}
		}
		if item.target.IsZero() {
			*item.target = export
		}
	}
}
