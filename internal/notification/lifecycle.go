package notification

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"time"
)

func compare(value, threshold float64, op string) bool {
	switch op {
	case "gt":
		return value > threshold
	case "gte":
		return value >= threshold
	case "lt":
		return value < threshold
	case "lte":
		return value <= threshold
	}
	return false
}
func breached(r RuleDefinition, o Observation, a AlertInstance) bool {
	v := o.Value
	if r.Kind == "seasonal" {
		if o.Baseline == nil || o.Baseline.History < 3 {
			return false
		}
		width := o.Baseline.Upper - o.Baseline.Expected
		if a.State == "FIRING" || a.State == "ACKNOWLEDGED" {
			recovery := r.Threshold / 2
			if r.RecoveryThreshold != nil {
				recovery = *r.RecoveryThreshold
			}
			width *= recovery / r.Threshold
		}
		return math.Abs(v-o.Baseline.Expected) > width
	}
	if r.Kind == "match" {
		return v > 0
	}
	if r.Kind == "absence" {
		return v == 0
	}
	if r.Kind == "comparison" {
		if o.Previous == 0 {
			return false
		}
		if v < r.MinimumCurrent {
			return false
		}
		v = (v - o.Previous) / o.Previous * 100
	}
	threshold := r.Threshold
	if (a.State == "FIRING" || a.State == "ACKNOWLEDGED") && r.RecoveryThreshold != nil {
		threshold = *r.RecoveryThreshold
	}
	return compare(v, threshold, r.Operator)
}
func suppressed(s *platformState, r RuleDefinition, entity string, at time.Time) bool {
	for _, si := range s.Silences {
		if !at.Before(si.From) && at.Before(si.Until) && (si.RuleID == "" || si.RuleID == r.ID) && (si.Entity == "" || si.Entity == entity) {
			return true
		}
	}
	return false
}
func alertKey(rule, entity string) string { return rule + "\x00" + entity }
func event(s *platformState, a AlertInstance, at time.Time, detail string) {
	s.Events = append(s.Events, AlertEvent{at, a.ID, a.RuleID, a.State, detail})
}
func contextFor(r RuleDefinition, a AlertInstance, at time.Time) MessageContext {
	dims := map[string]string{}
	var add func(Condition)
	add = func(c Condition) {
		if c.Op == "and" {
			for _, child := range c.Children {
				add(child)
			}
		} else if c.Op == "eq" && len(c.Values) == 1 {
			dims[c.Field] = c.Values[0]
		}
	}
	add(r.Condition)
	for k, v := range a.Dimensions {
		dims[k] = v
	}
	m := MessageContext{AlertID: a.ID, RuleID: r.ID, RuleName: r.Name, Summary: r.Summary(), Entity: a.Entity, State: a.State, Priority: r.Priority, Observed: a.Observed, Threshold: r.Threshold, Metric: r.Metric, WindowSeconds: r.WindowSeconds, At: at, From: at.Add(-time.Duration(r.WindowSeconds) * time.Second), FiredAt: a.FiredAt, Dimensions: dims}
	if r.Kind == "seasonal" && a.Baseline != nil {
		b := a.Baseline
		m.Threshold = b.Upper
		if a.Observed < b.Expected {
			m.Threshold = b.Lower
		}
		m.Summary += fmt.Sprintf(" Expected %g; entry range %g–%g; observed %g; %d comparable UTC weeks. Sampling verified as 1:1 for observed records; exporter completeness unavailable. Confidence: limited.", b.Expected, b.Lower, b.Upper, a.Observed, b.History)
		m.At = b.WindowEnd
		m.ExclusiveEnd = true
		m.From = b.WindowEnd.Add(-time.Duration(r.WindowSeconds) * time.Second)
	}
	return m
}

type EvaluationCounts struct {
	RawTriggers   int `json:"raw_triggers"`
	AfterDedup    int `json:"after_dedup"`
	AfterCooldown int `json:"after_cooldown"`
	Suppressed    int `json:"suppressed"`
	Recoveries    int `json:"recoveries"`
}

// applyEvaluation is used unchanged by the scheduler and historical simulation.
// Missing groups in a successful complete query have zero values; errors must
// never call this function because unavailable data is not evidence of recovery.
func applyEvaluation(s *platformState, r RuleDefinition, obs []Observation, at time.Time) (EvaluationCounts, error) {
	counts := EvaluationCounts{}
	if len(obs) > MaxGroups {
		return counts, errors.New("rule group limit exceeded")
	}
	if !r.Schedule.Active(at) {
		for k, a := range s.Alerts {
			if a.RuleID == r.ID && a.State == "PENDING" {
				a.State = "NORMAL"
				s.Alerts[k] = a
			}
		}
		return counts, nil
	}
	byEntity := map[string]Observation{}
	for _, o := range obs {
		if len(o.Entity) > 1024 || !finite(o.Value) || !finite(o.Previous) {
			return counts, errors.New("invalid observation")
		}
		if r.Kind == "seasonal" && (o.Baseline == nil || o.Baseline.History < 3 || !finite(o.Baseline.Expected) || !finite(o.Baseline.Upper) || !finite(o.Baseline.Lower)) {
			continue
		}
		byEntity[o.Entity] = o
	}
	if r.Kind != "seasonal" && len(r.GroupBy) == 0 && len(byEntity) == 0 {
		byEntity["scope"] = Observation{Entity: "scope"}
	}
	for _, a := range s.Alerts {
		if a.RuleID == r.ID && (a.State == "PENDING" || a.State == "FIRING" || a.State == "ACKNOWLEDGED") {
			if _, ok := byEntity[a.Entity]; !ok && r.Kind != "seasonal" {
				byEntity[a.Entity] = Observation{Entity: a.Entity, Dimensions: a.Dimensions}
			}
		}
	}
	keys := make([]string, 0, len(byEntity))
	for k := range byEntity {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, entity := range keys {
		notificationSuppressed := false
		o := byEntity[entity]
		k := alertKey(r.ID, entity)
		a, exists := s.Alerts[k]
		if !exists {
			if !breached(r, o, AlertInstance{}) {
				continue
			}
			if len(s.Alerts) >= MaxInstances {
				return counts, errors.New("alert instance capacity reached")
			}
			a = AlertInstance{ID: newID("CFC-ALT-"), RuleID: r.ID, Revision: r.Revision, Entity: entity, State: "NORMAL"}
		}
		// A scheduler gap cannot prove continuously true FOR duration.
		if a.State == "PENDING" && !a.LastEvaluated.IsZero() && at.Sub(a.LastEvaluated) > time.Duration(2*r.IntervalSeconds)*time.Second {
			a.State = "NORMAL"
		}
		a.LastEvaluated = at
		a.Observed = o.Value
		if r.Kind == "seasonal" {
			if a.Baseline != nil && !o.Baseline.WindowEnd.After(a.Baseline.WindowEnd) {
				continue
			}
			if a.State == "PENDING" && a.Baseline != nil && o.Baseline.WindowEnd.Sub(a.Baseline.WindowEnd) > time.Duration(r.WindowSeconds)*time.Second {
				a.State = "NORMAL"
			}
			a.Baseline = o.Baseline
		}
		a.Dimensions = o.Dimensions
		if breached(r, o, a) {
			counts.RawTriggers++
			if a.State == "NORMAL" || a.State == "RECOVERED" {
				a.State = "PENDING"
				a.Since = at
				event(s, a, at, "Condition entered pending")
			}
			newFiring := a.State == "PENDING" && at.Sub(a.Since) >= time.Duration(r.ForSeconds)*time.Second
			if newFiring {
				a.State = "FIRING"
				a.FiredAt = at
				counts.AfterDedup++
				event(s, a, at, "Condition satisfied FOR duration")
			}
			if a.State == "FIRING" && (a.LastNotified.IsZero() || at.Sub(a.LastNotified) >= time.Duration(r.CooldownSeconds)*time.Second) {
				if suppressed(s, r, entity, at) {
					notificationSuppressed = true
					event(s, a, at, "Notification suppressed by silence or maintenance")
				} else {
					if e := enqueuePolicy(s, r, a, at); e != nil {
						return counts, e
					}
					a.LastNotified = at
					counts.AfterCooldown++
				}
			}
		} else if a.State == "FIRING" || a.State == "ACKNOWLEDGED" {
			a.State = "RECOVERED"
			counts.Recoveries++
			event(s, a, at, "Condition normalized")
			if r.Recovery && !suppressed(s, r, entity, at) {
				if e := enqueuePolicy(s, r, a, at); e != nil {
					return counts, e
				}
			}
		} else if a.State == "PENDING" {
			a.State = "NORMAL"
			event(s, a, at, "Condition normalized before FOR duration")
		}
		if notificationSuppressed {
			counts.Suppressed++
		}
		s.Alerts[k] = a
	}
	return counts, nil
}

func enqueuePolicy(s *platformState, r RuleDefinition, a AlertInstance, at time.Time) error {
	p, ok := s.Policies[r.PolicyID]
	if !ok {
		return errors.New("notification policy unavailable")
	}
	for _, route := range p.Routes {
		ch, ok := s.Channels[route.ChannelID]
		if !ok || !ch.Config.Enabled {
			continue
		}
		ctx := contextFor(r, a, at)
		ctx.NotificationID = newID("CFC-NOT-")
		due := at
		delay := route.DelaySeconds
		if a.State == "RECOVERED" {
			delay = 0
		}
		if delay > 0 {
			due = a.FiredAt.Add(time.Duration(delay) * time.Second)
			if due.Before(at) {
				due = at
			}
		}
		if route.DigestSeconds > 0 {
			due = due.Add(time.Duration(route.DigestSeconds) * time.Second)
		}
		// A channel digest has bounded context count, and its deadline is not
		// pushed forward by subsequent events.
		merged := false
		if route.DigestSeconds > 0 && delay == 0 {
			for i := range s.Deliveries {
				d := &s.Deliveries[i]
				if d.ChannelID == route.ChannelID && d.Status == "PENDING" && d.DigestSeconds == route.DigestSeconds && !d.Delayed && d.Due.After(at) && len(d.Digest) < 49 {
					d.Digest = append(d.Digest, ctx)
					merged = true
					break
				}
			}
		}
		if merged {
			continue
		}
		if len(s.Deliveries) >= MaxDeliveries {
			idx := -1
			for i, d := range s.Deliveries {
				if d.Status == "SENT" || d.Status == "SUPPRESSED" {
					idx = i
					break
				}
			}
			if idx < 0 {
				return errors.New("notification queue and history capacity reached")
			}
			s.Deliveries = append(s.Deliveries[:idx], s.Deliveries[idx+1:]...)
		}
		s.Deliveries = append(s.Deliveries, Delivery{ID: ctx.NotificationID, ChannelID: route.ChannelID, ChannelName: ch.Config.Name, ChannelType: ch.Config.Type, Status: "PENDING", Created: at, Due: due, Context: ctx, DigestSeconds: route.DigestSeconds, Delayed: delay > 0})
	}
	return nil
}

func renderDelivery(d Delivery, base string) (RenderedMessage, error) {
	c := d.Context
	if len(d.Digest) > 0 {
		c.RuleName = fmt.Sprintf("%d operational notifications", len(d.Digest)+1)
		c.Summary = "Digest: " + d.Context.RuleName + " — " + d.Context.Entity
		for _, x := range d.Digest {
			line := "; " + x.State + " " + x.RuleName + " — " + x.Entity
			if len(c.Summary)+len(line) > 3900 {
				c.Summary += "; open notification history for remaining entries"
				break
			}
			c.Summary += line
		}
	}
	return RenderMessage(c, base)
}
