package notification

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

func fmtInt(v int) string { return strconv.Itoa(v) }

type PlatformHealth struct {
	SeasonalEvaluations uint64 `json:"seasonal_evaluations"`
	SeasonalWithheld    uint64 `json:"seasonal_withheld"`
	SeasonalErrors      uint64 `json:"seasonal_errors"`
	Healthy             bool   `json:"healthy"`
	Rules               int    `json:"rules"`
	Enabled             int    `json:"enabled"`
	Firing              int    `json:"firing"`
	Queue               int    `json:"queue"`
	Failed              int    `json:"failed"`
	Evaluations         uint64 `json:"evaluations"`
	EvaluationErrors    uint64 `json:"evaluation_errors"`
	LastError           string `json:"last_error"`
}

func (p *Platform) Health() PlatformHealth {
	p.mu.Lock()
	defer p.mu.Unlock()
	h := PlatformHealth{Healthy: !p.persistenceError, Rules: len(p.state.Rules), Evaluations: p.evaluations, EvaluationErrors: p.evaluationErrors, LastError: p.lastEvaluationError}
	h.SeasonalEvaluations = p.seasonalEvaluations
	h.SeasonalWithheld = p.seasonalWithheld
	h.SeasonalErrors = p.seasonalErrors
	for _, r := range p.state.Rules {
		if r.Enabled {
			h.Enabled++
		}
	}
	for _, a := range p.state.Alerts {
		if a.State == "FIRING" || a.State == "ACKNOWLEDGED" {
			h.Firing++
		}
	}
	for _, d := range p.state.Deliveries {
		switch d.Status {
		case "PENDING", "RETRYING", "SENDING":
			h.Queue++
		case "FAILED":
			h.Failed++
		}
	}
	return h
}

func (p *Platform) claim(now time.Time) (Delivery, ChannelConfig, string, bool) {
	var delivery Delivery
	var config ChannelConfig
	var secret string
	found := false
	// Avoid serializing snapshots when no work is due.
	p.mu.Lock()
	due := false
	for _, d := range p.state.Deliveries {
		if (d.Status == "PENDING" || d.Status == "RETRYING") && !d.Due.After(now) && !p.nextSend[d.ChannelID].After(now) {
			due = true
			break
		}
	}
	p.mu.Unlock()
	if !due {
		return delivery, config, secret, false
	}
	err := p.transaction(func(s *platformState) error {
		for i := range s.Deliveries {
			d := &s.Deliveries[i]
			if (d.Status != "PENDING" && d.Status != "RETRYING") || d.Due.After(now) || p.nextSend[d.ChannelID].After(now) {
				continue
			}
			ch, ok := s.Channels[d.ChannelID]
			if !ok || !ch.Config.Enabled {
				d.Status = "SUPPRESSED"
				d.Result = "Channel disabled or removed"
				continue
			}
			if now.Sub(d.Created) > time.Duration(s.Settings.MaxAgeSeconds)*time.Second {
				d.Status = "FAILED"
				d.Result = "Delivery age budget exhausted"
				continue
			}
			r, exists := s.Rules[d.Context.RuleID]
			if exists {
				if !r.Enabled || suppressed(s, r, d.Context.Entity, now) {
					d.Status = "SUPPRESSED"
					d.Result = "Rule disabled or silenced"
					continue
				}
				if d.Delayed {
					a, ok := s.Alerts[alertKey(r.ID, d.Context.Entity)]
					if !ok || a.State != "FIRING" || !a.FiredAt.Equal(d.Context.FiredAt) {
						d.Status = "SUPPRESSED"
						d.Result = "Escalation cancelled: alert recovered, acknowledged or restarted"
						continue
					}
				}
			}
			var e error
			secret, e = p.unseal(d.ChannelID, ch.Secret)
			if e != nil {
				d.Status = "FAILED"
				d.Result = "Channel secret unavailable"
				continue
			}
			config = ch.Config
			d.Status = "SENDING"
			d.Attempts++
			delivery = *d
			found = true
			p.nextSend[config.ID] = now.Add(time.Minute / time.Duration(config.PerMinute))
			return nil
		}
		return nil
	})
	if err != nil || !found {
		return delivery, config, secret, false
	}
	return delivery, config, secret, true
}
func (p *Platform) deliveryLoop() {
	defer p.wg.Done()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case <-ticker.C:
		}
		d, c, secret, ok := p.claim(time.Now().UTC())
		if !ok {
			continue
		}
		start := time.Now()
		m, err := renderDelivery(d, p.Settings().PortalURL)
		if err == nil {
			_, err = p.channels[c.Type].Send(p.ctx, c, secret, m, d.ID)
		}
		_ = p.finish(d, c, time.Since(start), err)
	}
}
func (p *Platform) finish(d Delivery, c ChannelConfig, duration time.Duration, sendErr error) error {
	return p.transaction(func(s *platformState) error {
		for i := range s.Deliveries {
			current := &s.Deliveries[i]
			if current.ID != d.ID {
				continue
			}
			current.DurationMS = duration.Milliseconds()
			current.Status = "SENT"
			current.Result = "Delivered"
			ch := s.Channels[c.ID]
			if sendErr != nil {
				current.Status = "FAILED"
				current.Result = "Delivery failed; verify channel configuration"
				var failure *DeliveryError
				if errors.As(sendErr, &failure) {
					current.Result = failure.Reason
					if failure.Temporary && current.Attempts < s.Settings.MaxAttempts && time.Since(current.Created) < time.Duration(s.Settings.MaxAgeSeconds)*time.Second {
						current.Status = "RETRYING"
						j := make([]byte, 1)
						_, _ = rand.Read(j)
						delay := time.Minute*time.Duration(1<<min(current.Attempts-1, 8)) + time.Duration(j[0])*time.Millisecond*100
						if failure.RetryAfter > delay {
							delay = failure.RetryAfter
						}
						current.Due = time.Now().Add(delay)
					}
				}
				if p.ctx.Err() != nil {
					current.Status = "RETRYING"
					current.Result = "Interrupted by shutdown"
					current.Due = time.Now().Add(time.Minute)
				}
				ch.Config.Health = "Degraded"
			} else {
				ch.Config.Health = "Healthy"
				ch.Config.LastDelivery = time.Now().UTC()
			}
			s.Channels[c.ID] = ch
			s.Events = append(s.Events, AlertEvent{time.Now().UTC(), d.Context.AlertID, d.Context.RuleID, current.Status, c.Type + ": " + current.Result})
			return nil
		}
		return errors.New("delivery not found")
	})
}

type ChannelTestRequest struct {
	Send      bool   `json:"send"`
	Recipient string `json:"recipient"`
	Subject   string `json:"subject"`
	Message   string `json:"message"`
}
type ChannelTestResult struct {
	Stages  []TestStage `json:"stages"`
	Success bool        `json:"success"`
	Error   string      `json:"error,omitempty"`
}

func (p *Platform) TestChannel(ctx context.Context, id string, req ChannelTestRequest) (ChannelTestResult, error) {
	select {
	case p.testGate <- struct{}{}:
		defer func() { <-p.testGate }()
	default:
		return ChannelTestResult{}, errors.New("channel test concurrency limit reached")
	}
	p.mu.Lock()
	ch, ok := p.state.Channels[id]
	p.mu.Unlock()
	if !ok {
		return ChannelTestResult{}, errors.New("channel not found")
	}
	secret, e := p.unseal(id, ch.Secret)
	if e != nil {
		return ChannelTestResult{}, e
	}
	if req.Recipient != "" {
		if e = safeAddress(req.Recipient); e != nil {
			return ChannelTestResult{}, e
		}
		ch.Config.Recipients = []string{req.Recipient}
	}
	impl := p.channels[ch.Config.Type]
	var stages []TestStage
	if !req.Send {
		stages, e = impl.Test(ctx, ch.Config, secret)
	} else {
		name := req.Subject
		if name == "" {
			name = "Notification Test"
		}
		summary := req.Message
		if summary == "" {
			summary = "Administrator requested a notification channel test."
		}
		at := time.Now().UTC()
		m, err := RenderMessage(MessageContext{NotificationID: newID("CFC-NOT-"), RuleName: name, Summary: summary, Entity: ch.Config.Name, State: "TEST", Priority: "info", At: at, From: at}, p.Settings().PortalURL)
		if err != nil {
			return ChannelTestResult{}, err
		}
		stages, e = impl.Send(ctx, ch.Config, secret, m, newID("CFC-NOT-"))
	}
	result := ChannelTestResult{Stages: stages, Success: e == nil}
	if e != nil {
		result.Error = "Channel validation or delivery failed"
		var de *DeliveryError
		if errors.As(e, &de) {
			result.Error = de.Reason
		}
	}
	if err := p.transaction(func(s *platformState) error {
		current, ok := s.Channels[id]
		if !ok {
			return nil
		}
		current.Config.LastTest = time.Now().UTC()
		current.Config.Health = "Healthy"
		if e != nil {
			current.Config.Health = "Degraded"
		}
		s.Channels[id] = current
		return nil
	}); err != nil {
		return result, err
	}
	return result, nil
}

type SimulationResult struct {
	WithheldEvaluations int              `json:"withheld_evaluations"`
	From                time.Time        `json:"from"`
	To                  time.Time        `json:"to"`
	Evaluations         int              `json:"evaluations"`
	DistinctEntities    int              `json:"distinct_entities"`
	Counts              EvaluationCounts `json:"counts"`
	Notifications       map[string]int   `json:"notifications"`
	Latest              *RenderedMessage `json:"latest,omitempty"`
	Events              []AlertEvent     `json:"events"`
	Explanation         string           `json:"explanation"`
}

func (p *Platform) Simulate(ctx context.Context, r RuleDefinition, from, to time.Time) (SimulationResult, error) {
	out := SimulationResult{From: from, To: to, Notifications: map[string]int{}, Events: []AlertEvent{}, Explanation: "Starts from NORMAL. Replays scheduled evaluations and current policies/silences; estimates attempts, not provider acceptance. Comparison with a zero previous period is undefined and does not fire."}
	if err := r.Validate(); err != nil {
		return out, err
	}
	if r.Kind == "system" {
		return out, errors.New("historical system snapshots are unavailable; system rules cannot be simulated")
	}
	if !to.After(from) || to.Sub(from) > 24*time.Hour || to.After(time.Now().Add(time.Minute)) {
		return out, errors.New("simulation requires a past period up to 24 hours")
	}
	steps := int(to.Sub(from)/time.Second) / r.IntervalSeconds
	if steps < 1 || steps > 1440 {
		return out, errors.New("simulation requires 1..1440 evaluation intervals")
	}
	select {
	case p.simulationGate <- struct{}{}:
		defer func() { <-p.simulationGate }()
	default:
		return out, errors.New("another simulation is running")
	}
	p.mu.Lock()
	b, _ := json.Marshal(p.state)
	p.mu.Unlock()
	var s platformState
	_ = json.Unmarshal(b, &s)
	s.Alerts = map[string]AlertInstance{}
	s.Deliveries = []Delivery{}
	s.Events = []AlertEvent{}
	s.Rules = map[string]RuleDefinition{r.ID: r}
	if _, ok := s.Policies[r.PolicyID]; !ok {
		return out, errors.New("select a notification policy before simulation")
	}
	entities := map[string]bool{}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	for at := from.Add(time.Duration(r.IntervalSeconds) * time.Second); !at.After(to); at = at.Add(time.Duration(r.IntervalSeconds) * time.Second) {
		obs, err := p.evaluate(ctx, r, at)
		if err != nil {
			return out, errors.New("simulation query failed; shorten the period or narrow the scope")
		}
		c, err := applyEvaluation(&s, r, obs, at)
		if err != nil {
			return out, err
		}
		for _, o := range obs {
			entities[o.Entity] = true
		}
		if len(entities) > MaxInstances {
			return out, errors.New("simulation entity capacity exceeded")
		}
		out.Evaluations++
		if r.Kind == "seasonal" && len(obs) == 0 {
			out.WithheldEvaluations++
		}
		out.Counts.RawTriggers += c.RawTriggers
		out.Counts.AfterDedup += c.AfterDedup
		out.Counts.AfterCooldown += c.AfterCooldown
		out.Counts.Suppressed += c.Suppressed
		out.Counts.Recoveries += c.Recoveries
		for i := range s.Deliveries {
			d := &s.Deliveries[i]
			if d.Status != "PENDING" || d.Due.After(at) {
				continue
			}
			if d.Delayed {
				a := s.Alerts[alertKey(r.ID, d.Context.Entity)]
				if a.State != "FIRING" || !a.FiredAt.Equal(d.Context.FiredAt) {
					d.Status = "SUPPRESSED"
					continue
				}
			}
			if suppressed(&s, r, d.Context.Entity, at) {
				d.Status = "SUPPRESSED"
				continue
			}
			d.Status = "SENT"
			out.Notifications[d.ChannelType]++
		}
	}
	out.DistinctEntities = len(entities)
	if r.Kind == "seasonal" {
		out.Explanation += fmt.Sprintf(" Seasonal analysis uses complete UTC hours with a one-minute grace period. %d evaluations withheld because comparable unsampled history or current records were unavailable; missing groups never imply recovery.", out.WithheldEvaluations)
	}
	if len(s.Events) > 100 {
		s.Events = s.Events[len(s.Events)-100:]
	}
	out.Events = s.Events
	if len(s.Deliveries) > 0 {
		m, e := renderDelivery(s.Deliveries[len(s.Deliveries)-1], s.Settings.PortalURL)
		if e != nil {
			return out, e
		}
		out.Latest = &m
	}
	return out, nil
}

func (p *Platform) Metrics() string {
	h := p.Health()
	return fmt.Sprintf("cfc_alert_rules_total %d\ncfc_alert_rules_enabled %d\ncfc_alert_evaluations_total %d\ncfc_alert_evaluation_errors_total %d\ncfc_alerts_firing %d\ncfc_notification_queue_depth %d\ncfc_notification_failed_retained %d\ncfc_anomaly_evaluations_total %d\ncfc_anomaly_evaluations_withheld_total %d\ncfc_anomaly_evaluation_errors_total %d\n", h.Rules, h.Enabled, h.Evaluations, h.EvaluationErrors, h.Firing, h.Queue, h.Failed, h.SeasonalEvaluations, h.SeasonalWithheld, h.SeasonalErrors)
}
