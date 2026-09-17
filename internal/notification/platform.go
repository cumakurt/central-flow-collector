package notification

import (
	"central-flow-collector/internal/model"
	"container/heap"
	"context"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Evaluator func(context.Context, RuleDefinition, time.Time) ([]Observation, error)
type dueRule struct {
	ID string
	At time.Time
}
type ruleHeap []dueRule

func (h ruleHeap) Len() int           { return len(h) }
func (h ruleHeap) Less(i, j int) bool { return h[i].At.Before(h[j].At) }
func (h ruleHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }
func (h *ruleHeap) Push(x any)        { *h = append(*h, x.(dueRule)) }
func (h *ruleHeap) Pop() any          { old := *h; x := old[len(old)-1]; *h = old[:len(old)-1]; return x }

type Platform struct {
	legacy              chan model.Alert
	legacyDropped       atomic.Uint64
	mu                  sync.Mutex
	state               platformState
	path                string
	vault               cipher.AEAD
	channels            map[string]Channel
	evaluate            Evaluator
	schedule            ruleHeap
	nextSend            map[string]time.Time
	wake                chan struct{}
	ctx                 context.Context
	cancel              context.CancelFunc
	wg                  sync.WaitGroup
	once                sync.Once
	started             bool
	persistenceError    bool
	evaluations         uint64
	seasonalEvaluations uint64
	seasonalWithheld    uint64
	seasonalErrors      uint64
	evaluationErrors    uint64
	lastEvaluationError string
	simulationGate      chan struct{}
	testGate            chan struct{}
}

func OpenPlatform(dir string, evaluate Evaluator) (*Platform, error) {
	if e := os.MkdirAll(dir, 0700); e != nil {
		return nil, e
	}
	if st, err := os.Stat(filepath.Join(dir, "notification-state.json")); err == nil {
		if st.Size() > 32<<20 {
			return nil, errors.New("notification state too large")
		}
		if _, err = os.Stat(filepath.Join(dir, "notification-key")); err != nil {
			return nil, errors.New("notification key missing; restore it with notification state")
		}
	}
	vault, e := openVault(dir)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &Platform{legacy: make(chan model.Alert, 256), state: emptyState(), path: filepath.Join(dir, "notification-state.json"), vault: vault, channels: map[string]Channel{"email": EmailChannel{}, "telegram": newTelegramChannel()}, evaluate: evaluate, nextSend: map[string]time.Time{}, wake: make(chan struct{}, 1), ctx: ctx, cancel: cancel, simulationGate: make(chan struct{}, 1), testGate: make(chan struct{}, 2)}
	b, e := os.ReadFile(p.path)
	if e == nil {
		if len(b) > 32<<20 {
			return nil, errors.New("notification state too large")
		}
		if e = json.Unmarshal(b, &p.state); e != nil || p.state.Version != 1 || p.state.Channels == nil || p.state.Rules == nil || p.state.Alerts == nil || p.state.Policies == nil || p.state.Revisions == nil || p.state.Silences == nil {
			cancel()
			return nil, errors.New("invalid notification state")
		}
	} else if !os.IsNotExist(e) {
		cancel()
		return nil, e
	}
	if len(p.state.Rules) > MaxRules || len(p.state.Channels) > 100 || len(p.state.Deliveries) > MaxDeliveries || len(p.state.Alerts) > MaxInstances {
		cancel()
		return nil, errors.New("notification state limits exceeded")
	}
	// A crash after remote acceptance may result in one duplicate. Stable IDs
	// and Message-ID make this explicit at-least-once delivery, not exactly-once.
	for i := range p.state.Deliveries {
		if p.state.Deliveries[i].Status == "SENDING" {
			p.state.Deliveries[i].Status = "RETRYING"
		}
	}
	p.rebuildScheduleLocked()
	return p, nil
}
func (p *Platform) Start() {
	p.mu.Lock()
	if p.started {
		p.mu.Unlock()
		return
	}
	p.started = true
	p.mu.Unlock()
	p.wg.Add(4)
	go p.legacyLoop()
	go p.ruleLoop()
	go p.deliveryLoop()
	go p.deliveryLoop()
}
func (p *Platform) Close() { p.once.Do(func() { p.cancel(); p.wg.Wait() }) }
func (p *Platform) rebuildScheduleLocked() {
	p.schedule = nil
	now := time.Now().UTC()
	for id, r := range p.state.Rules {
		if r.Enabled {
			heap.Push(&p.schedule, dueRule{id, now})
		}
	}
}
func (p *Platform) reschedule() {
	p.mu.Lock()
	p.rebuildScheduleLocked()
	p.mu.Unlock()
	select {
	case p.wake <- struct{}{}:
	default:
	}
}
func (p *Platform) ruleLoop() {
	defer p.wg.Done()
	for {
		p.mu.Lock()
		wait := time.Hour
		var r RuleDefinition
		var due bool
		if len(p.schedule) > 0 {
			wait = time.Until(p.schedule[0].At)
			if wait <= 0 {
				x := heap.Pop(&p.schedule).(dueRule)
				r = p.state.Rules[x.ID]
				due = r.Enabled
				heap.Push(&p.schedule, dueRule{x.ID, time.Now().Add(time.Duration(r.IntervalSeconds) * time.Second)})
			}
		}
		p.mu.Unlock()
		if due {
			at := time.Now().UTC()
			ctx, cancel := context.WithTimeout(p.ctx, 20*time.Second)
			obs, e := p.evaluate(ctx, r, at)
			cancel()
			if e == nil {
				e = p.transaction(func(s *platformState) error {
					current, ok := s.Rules[r.ID]
					if !ok || !current.Enabled || current.Revision != r.Revision {
						return nil
					}
					_, err := applyEvaluation(s, r, obs, at)
					return err
				})
			}
			p.mu.Lock()
			p.evaluations++
			if r.Kind == "seasonal" {
				p.seasonalEvaluations++
				if e != nil {
					p.seasonalErrors++
				} else if len(obs) == 0 {
					p.seasonalWithheld++
				}
			}
			if e != nil {
				p.evaluationErrors++
				p.lastEvaluationError = "Rule evaluation failed; check storage availability and group limits"
			}
			p.mu.Unlock()
			if p.ctx.Err() != nil {
				return
			}
			continue
		}
		if wait < time.Millisecond {
			wait = time.Millisecond
		}
		timer := time.NewTimer(wait)
		select {
		case <-p.ctx.Done():
			timer.Stop()
			return
		case <-p.wake:
			timer.Stop()
		case <-timer.C:
		}
	}
}

func (p *Platform) Channels() []ChannelConfig {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := []ChannelConfig{}
	for _, c := range p.state.Channels {
		cfg := c.Config
		cfg.Recipients = append([]string(nil), cfg.Recipients...)
		out = append(out, cfg)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func (p *Platform) SaveChannel(in ChannelInput) (ChannelConfig, error) {
	c := in.ChannelConfig
	if c.ID == "" {
		c.ID = newID("channel-")
	}
	impl, ok := p.channels[c.Type]
	if !ok {
		return c, errors.New("unsupported channel type")
	}
	err := p.transaction(func(s *platformState) error {
		old, exists := s.Channels[c.ID]
		if !exists && len(s.Channels) >= 100 {
			return errors.New("channel limit reached")
		}
		if exists && old.Config.Type != c.Type {
			return errors.New("channel type cannot be changed")
		}
		secret := in.Password
		if c.Type == "telegram" {
			secret = in.BotToken
		}
		if secret == "" && exists {
			var err error
			secret, err = p.unseal(c.ID, old.Secret)
			if err != nil {
				return err
			}
		}
		if err := impl.Validate(c, secret); err != nil {
			return err
		}
		sealed, err := p.seal(c.ID, secret)
		if err != nil {
			return err
		}
		c.PasswordSet = c.Type == "email" && secret != ""
		c.TokenSet = c.Type == "telegram" && secret != ""
		c.Health = "Untested"
		c.LastTest = old.Config.LastTest
		c.LastDelivery = old.Config.LastDelivery
		s.Channels[c.ID] = storedChannel{c, sealed}
		return nil
	})
	return c, err
}
func (p *Platform) Policies() []NotificationPolicy {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := []NotificationPolicy{}
	for _, x := range p.state.Policies {
		x.Routes = append([]Route(nil), x.Routes...)
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func (p *Platform) SavePolicy(x NotificationPolicy) (NotificationPolicy, error) {
	if x.ID == "" {
		x.ID = newID("policy-")
	}
	if x.Name == "" || len(x.Name) > 120 || len(x.Routes) == 0 || len(x.Routes) > 16 {
		return x, errors.New("policy requires name and 1..16 routes")
	}
	e := p.transaction(func(s *platformState) error {
		if _, ok := s.Policies[x.ID]; !ok && len(s.Policies) >= 200 {
			return errors.New("policy limit reached")
		}
		seen := map[string]bool{}
		for _, r := range x.Routes {
			if _, ok := s.Channels[r.ChannelID]; !ok {
				return errors.New("channel does not exist")
			}
			if seen[r.ChannelID] {
				return errors.New("use distinct channels for escalation recipients")
			}
			seen[r.ChannelID] = true
			if r.DelaySeconds < 0 || r.DelaySeconds > 86400 || !contains([]string{"0", "300", "900", "3600"}, fmtInt(r.DigestSeconds)) {
				return errors.New("invalid delivery timing")
			}
		}
		s.Policies[x.ID] = x
		return nil
	})
	return x, e
}
func (p *Platform) Rules() []RuleDefinition {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := []RuleDefinition{}
	for _, r := range p.state.Rules {
		out = append(out, r)
	}
	b, _ := json.Marshal(out)
	_ = json.Unmarshal(b, &out)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
func (p *Platform) SaveRule(r RuleDefinition, user string) (RuleDefinition, error) {
	if err := r.Validate(); err != nil {
		return r, err
	}
	if r.ID == "" {
		r.ID = newID("rule-")
	}
	err := p.transaction(func(s *platformState) error {
		old, exists := s.Rules[r.ID]
		if !exists && len(s.Rules) >= MaxRules {
			return errors.New("rule limit reached")
		}
		if _, ok := s.Policies[r.PolicyID]; !ok {
			return errors.New("select an existing notification policy")
		}
		if exists && r.Revision != old.Revision {
			return errors.New("rule changed; reload before saving")
		}
		r.Revision = old.Revision + 1
		r.UpdatedAt = time.Now().UTC()
		r.UpdatedBy = user
		s.Rules[r.ID] = r
		s.Revisions[r.ID] = append(s.Revisions[r.ID], r)
		if len(s.Revisions[r.ID]) > 20 {
			s.Revisions[r.ID] = s.Revisions[r.ID][len(s.Revisions[r.ID])-20:]
		}
		// Existing instances belong to the old rule revision. Retire them without
		// claiming telemetry recovery, and cancel queued notifications.
		for k, a := range s.Alerts {
			if a.RuleID == r.ID {
				a.State = "NORMAL"
				event(s, a, r.UpdatedAt, "Rule revision changed; previous evaluation retired")
				delete(s.Alerts, k)
			}
		}
		for i := range s.Deliveries {
			d := &s.Deliveries[i]
			if d.Context.RuleID == r.ID && (d.Status == "PENDING" || d.Status == "RETRYING") {
				d.Status = "SUPPRESSED"
				d.Result = "Rule revision changed"
			}
		}
		return nil
	})
	if err == nil {
		p.reschedule()
	}
	return r, err
}
func (p *Platform) SaveSilence(x Silence) (Silence, error) {
	if x.ID == "" {
		x.ID = newID("silence-")
	}
	if x.Reason == "" || len(x.Reason) > 500 || !x.Until.After(x.From) || x.Until.Sub(x.From) > 31*24*time.Hour {
		return x, errors.New("silence requires a reason and a positive period up to 31 days")
	}
	e := p.transaction(func(s *platformState) error {
		if len(s.Silences) >= 1000 {
			return errors.New("silence limit reached")
		}
		if x.RuleID != "" {
			if _, ok := s.Rules[x.RuleID]; !ok {
				return errors.New("rule does not exist")
			}
		}
		s.Silences[x.ID] = x
		return nil
	})
	return x, e
}
func (p *Platform) Delete(kind, id string) error {
	e := p.transaction(func(s *platformState) error {
		switch kind {
		case "channels":
			for _, pol := range s.Policies {
				for _, r := range pol.Routes {
					if r.ChannelID == id {
						return errors.New("channel is referenced by a policy")
					}
				}
			}
			for _, d := range s.Deliveries {
				if d.ChannelID == id && (d.Status == "PENDING" || d.Status == "RETRYING" || d.Status == "SENDING") {
					return errors.New("channel has active deliveries")
				}
			}
			delete(s.Channels, id)
		case "policies":
			for _, r := range s.Rules {
				if r.PolicyID == id {
					return errors.New("policy is referenced by a rule")
				}
			}
			delete(s.Policies, id)
		case "rules":
			delete(s.Rules, id)
			delete(s.Revisions, id)
			for k, a := range s.Alerts {
				if a.RuleID == id {
					delete(s.Alerts, k)
				}
			}
			for i := range s.Deliveries {
				d := &s.Deliveries[i]
				if d.Context.RuleID == id && (d.Status == "PENDING" || d.Status == "RETRYING") {
					d.Status = "SUPPRESSED"
					d.Result = "Rule deleted"
				}
			}
		case "silences":
			delete(s.Silences, id)
		default:
			return errors.New("unknown resource")
		}
		return nil
	})
	if e == nil {
		p.reschedule()
	}
	return e
}
func (p *Platform) Settings() PlatformSettings {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.state.Settings
}
func (p *Platform) SaveSettings(s PlatformSettings) error {
	if e := ValidatePortalURL(s.PortalURL); e != nil {
		return e
	}
	if s.RetentionDays < 1 || s.RetentionDays > 365 || s.MaxAttempts < 1 || s.MaxAttempts > 10 || s.MaxAgeSeconds < 60 || s.MaxAgeSeconds > 604800 {
		return errors.New("invalid retention or retry budget")
	}
	return p.transaction(func(st *platformState) error { st.Settings = s; return nil })
}
func (p *Platform) Snapshot(kind string, offset, limit int) any {
	p.mu.Lock()
	defer p.mu.Unlock()
	var data any
	switch kind {
	case "alerts":
		a := []AlertInstance{}
		for _, x := range p.state.Alerts {
			a = append(a, x)
		}
		sort.Slice(a, func(i, j int) bool { return a[i].LastEvaluated.After(a[j].LastEvaluated) })
		data = a[min(offset, len(a)):min(offset+limit, len(a))]
	case "history":
		a := p.state.Deliveries
		out := []Delivery{}
		for i := len(a) - 1 - offset; i >= 0 && len(out) < limit; i-- {
			out = append(out, a[i])
		}
		data = out
	case "events":
		a := p.state.Events
		out := []AlertEvent{}
		for i := len(a) - 1 - offset; i >= 0 && len(out) < limit; i-- {
			out = append(out, a[i])
		}
		data = out
	case "silences":
		a := []Silence{}
		for _, x := range p.state.Silences {
			a = append(a, x)
		}
		sort.Slice(a, func(i, j int) bool { return a[i].From.After(a[j].From) })
		data = a[min(offset, len(a)):min(offset+limit, len(a))]
	default:
		data = p.state.Revisions[kind]
	}
	b, _ := json.Marshal(data)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}
func (p *Platform) Acknowledge(id string) error {
	return p.transaction(func(s *platformState) error {
		for k, a := range s.Alerts {
			if a.ID == id && a.State == "FIRING" {
				a.State = "ACKNOWLEDGED"
				event(s, a, time.Now().UTC(), "Acknowledged by operator")
				s.Alerts[k] = a
				return nil
			}
		}
		return errors.New("firing alert not found")
	})
}
func (p *Platform) Retry(id string) error {
	return p.transaction(func(s *platformState) error {
		for i := range s.Deliveries {
			d := &s.Deliveries[i]
			if d.ID == id && d.Status == "FAILED" {
				d.Status = "RETRYING"
				d.Attempts = 0
				d.Created = time.Now().UTC()
				d.Due = d.Created
				d.Result = "Manual retry"
				return nil
			}
		}
		return errors.New("failed delivery not found")
	})
}
