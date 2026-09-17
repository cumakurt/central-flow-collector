package templates

import (
	"central-flow-collector/internal/model"
	"reflect"
	"strconv"
	"strings"
	"time"
)

// PutOptions retains bounded scope-specific metadata without counting it as traffic.
func (c *Cache) PutOptions(k Key, records []model.Flow) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t, ok := c.items[k]
	if !ok || t.ScopeCount == 0 {
		return
	}
	options := append([]model.Flow(nil), t.Options...)
	for _, record := range records {
		replaced := false
		for i := range options {
			if reflect.DeepEqual(scopes(options[i]), scopes(record)) {
				options[i] = record
				replaced = true
				break
			}
		}
		if !replaced {
			if len(options) == 256 {
				options = options[1:]
			}
			options = append(options, record)
		}
	}
	t.Options = options
	c.items[k] = t
}

func scopes(f model.Flow) map[string]string {
	out := map[string]string{}
	if f.AppID != "" {
		out["application_id"] = f.AppID
	}
	for key, value := range f.Custom {
		if strings.HasPrefix(key, "scope_") || key == "ie_48" || key == "ie_302" {
			out[key] = value
		}
	}
	return out
}

func (c *Cache) ApplyOptions(k Key, f *model.Flow) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var sampling, application *model.Flow
	samplingScore, applicationScore := -1, -1
	session := k
	session.TemplateID = 0
	for id := range c.optionKeys[session] {
		key := k
		key.TemplateID = id
		t, exists := c.items[key]
		if !exists {
			continue
		}
		if c.ttl > 0 && time.Since(t.Updated) > c.ttl {
			continue
		}
		for i := range t.Options {
			o := &t.Options[i]
			if c.ttl > 0 && time.Since(o.ReceiveTime) > c.ttl {
				continue
			}
			if !matchesScope(k, *f, *o) {
				continue
			}
			score := len(scopes(*o))
			if o.Sampling > 0 && (score > samplingScore || (score == samplingScore && sampling != nil && o.ReceiveTime.After(sampling.ReceiveTime))) {
				sampling, samplingScore = o, score
			}
			if o.AppName != "" && (score > applicationScore || (score == applicationScore && application != nil && o.ReceiveTime.After(application.ReceiveTime))) {
				application, applicationScore = o, score
			}
		}
	}
	if sampling != nil && f.Sampling == 0 {
		f.Sampling = sampling.Sampling
	}
	if application != nil && f.AppName == "" {
		f.AppName = application.AppName
	}
}

func matchesScope(k Key, f, option model.Flow) bool {
	for _, id := range []string{"ie_48", "ie_302"} {
		if value, ok := option.Custom[id]; ok && value != f.Custom[id] {
			return false
		}
	}
	if option.AppID != "" && option.AppID != f.AppID {
		return false
	}
	matched := false
	for key, value := range option.Custom {
		if !strings.HasPrefix(key, "scope_") {
			continue
		}
		matched = true
		if !strings.HasPrefix(key, "scope_0_") {
			return false
		}
		id, err := strconv.Atoi(strings.TrimPrefix(key, "scope_0_"))
		if err != nil {
			return false
		}
		if k.Protocol != "netflow9" {
			if id == 95 {
				if value != f.AppID {
					return false
				}
				continue
			}
			if id != 149 && id != 10 && id != 14 {
				if value != f.Custom["ie_"+strconv.Itoa(id)] {
					return false
				}
				continue
			}
		}
		n, err := strconv.ParseUint(value, 16, 64)
		if err != nil {
			return false
		}
		if k.Protocol == "netflow9" {
			switch id {
			case 1: // System scope applies to the exporting system.
			case 2:
				if n != uint64(f.IngressIf) {
					return false
				}
			case 5:
				if n != uint64(k.TemplateID) {
					return false
				}
			default:
				return false
			}
		} else {
			switch id {
			case 149:
				if n != uint64(k.Domain) {
					return false
				}
			case 10:
				if n != uint64(f.IngressIf) {
					return false
				}
			case 14:
				if n != uint64(f.EgressIf) {
					return false
				}
			case 95:
				if value != f.AppID {
					return false
				}
			default:
				if value != f.Custom["ie_"+strconv.Itoa(id)] {
					return false
				}
			}
		}
	}
	return matched
}
