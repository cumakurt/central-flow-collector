package templates

import (
	"central-flow-collector/internal/model"
	"fmt"
	"reflect"
	"sort"
	"sync"
	"time"
)

type Field struct {
	ID                 uint16
	Length             uint16
	Enterprise         uint32
	EnterpriseSpecific bool
}
type Template struct {
	ID         uint16
	Fields     []Field
	Updated    time.Time
	ScopeCount int
	Options    []model.Flow
}
type Key struct {
	Exporter, Protocol string
	Domain             uint32
	TemplateID         uint16
	Listener           string
	SourcePort         uint16
}

type Cache struct {
	mu         sync.RWMutex
	items      map[Key]Template
	optionKeys map[Key]map[uint16]struct{}
	ttl        time.Duration
}

func New(ttl time.Duration) *Cache {
	return &Cache{items: map[Key]Template{}, optionKeys: map[Key]map[uint16]struct{}{}, ttl: ttl}
}
func (c *Cache) Put(k Key, t Template) {
	c.mu.Lock()
	defer c.mu.Unlock()
	t.Updated = time.Now()
	if old, ok := c.items[k]; ok && old.ScopeCount == t.ScopeCount && reflect.DeepEqual(old.Fields, t.Fields) {
		t.Options = old.Options
	}
	c.items[k] = t
	session := k
	session.TemplateID = 0
	if t.ScopeCount > 0 {
		if c.optionKeys[session] == nil {
			c.optionKeys[session] = map[uint16]struct{}{}
		}
		c.optionKeys[session][k.TemplateID] = struct{}{}
	} else {
		delete(c.optionKeys[session], k.TemplateID)
	}
}
func (c *Cache) Get(k Key) (Template, bool) {
	c.mu.RLock()
	t, ok := c.items[k]
	c.mu.RUnlock()
	if !ok {
		return Template{}, false
	}
	if c.ttl > 0 && time.Since(t.Updated) > c.ttl {
		c.mu.Lock()
		if current, exists := c.items[k]; exists && current.Updated == t.Updated {
			delete(c.items, k)
		}
		c.mu.Unlock()
		return Template{}, false
	}
	return t, true
}
func (c *Cache) DeleteExporter(exporter string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k := range c.items {
		if k.Exporter == exporter {
			delete(c.items, k)
		}
	}
	for k := range c.optionKeys {
		if k.Exporter == exporter {
			delete(c.optionKeys, k)
		}
	}
}
func (k Key) String() string {
	return fmt.Sprintf("%s/%s/%d/%d", k.Exporter, k.Protocol, k.Domain, k.TemplateID)
}

type Info struct {
	Exporter   string       `json:"exporter"`
	Protocol   string       `json:"protocol"`
	Domain     uint32       `json:"observation_domain"`
	TemplateID uint16       `json:"template_id"`
	FieldCount int          `json:"field_count"`
	Updated    time.Time    `json:"updated"`
	AgeSeconds int64        `json:"age_seconds"`
	Listener   string       `json:"listener,omitempty"`
	SourcePort uint16       `json:"source_port,omitempty"`
	ScopeCount int          `json:"scope_count,omitempty"`
	Options    []model.Flow `json:"options,omitempty"`
}

func (c *Cache) Snapshot() []Info {
	now := time.Now()
	c.mu.RLock()
	out := make([]Info, 0, len(c.items))
	for k, t := range c.items {
		if c.ttl > 0 && now.Sub(t.Updated) > c.ttl {
			continue
		}
		out = append(out, Info{Exporter: k.Exporter, Protocol: k.Protocol, Domain: k.Domain, TemplateID: k.TemplateID, FieldCount: len(t.Fields), Updated: t.Updated, AgeSeconds: int64(now.Sub(t.Updated).Seconds()), Listener: k.Listener, SourcePort: k.SourcePort, ScopeCount: t.ScopeCount, Options: append([]model.Flow(nil), t.Options...)})
	}
	c.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool {
		if out[i].Exporter == out[j].Exporter {
			if out[i].Domain == out[j].Domain {
				return out[i].TemplateID < out[j].TemplateID
			}
			return out[i].Domain < out[j].Domain
		}
		return out[i].Exporter < out[j].Exporter
	})
	return out
}
