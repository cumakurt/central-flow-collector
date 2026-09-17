package notification

import (
	"central-flow-collector/internal/model"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
)

// AdoptPlatform moves existing analytics alerts to the shared durable delivery
// path. Webhook/syslog and report attachments retain compatibility adapters.
func (m *Manager) AdoptPlatform(p *Platform) error {
	if err := p.importLegacy(m.cfg); err != nil {
		return err
	}
	m.platform.Store(p)
	return nil
}
func (p *Platform) importLegacy(cfg Config) error {
	p.mu.Lock()
	_, exists := p.state.Policies["legacy-operations"]
	p.mu.Unlock()
	if exists {
		return nil
	}
	routes := []Route{}
	if cfg.SMTPAddr != "" {
		host, port, err := net.SplitHostPort(cfg.SMTPAddr)
		if err != nil {
			return errors.New("legacy SMTP address is invalid")
		}
		n, err := strconv.Atoi(port)
		if err != nil {
			return err
		}
		c := ChannelConfig{ID: "legacy-email", Name: "Configured SMTP", Type: "email", Enabled: true, Host: host, Port: n, Username: cfg.SMTPUsername, Security: "starttls", From: cfg.SMTPFrom, SenderName: "Central Flow Collector", Recipients: strings.Split(cfg.SMTPTo, ","), TimeoutSeconds: 10, PerMinute: 30}
		if n == 465 {
			c.Security = "smtps"
		}
		for i := range c.Recipients {
			c.Recipients[i] = strings.TrimSpace(c.Recipients[i])
		}
		if _, err = p.SaveChannel(ChannelInput{ChannelConfig: c, Password: cfg.SMTPPassword}); err != nil {
			return err
		}
		routes = append(routes, Route{ChannelID: c.ID})
	}
	if cfg.TelegramBotToken != "" {
		c := ChannelConfig{ID: "legacy-telegram", Name: "Configured Telegram", Type: "telegram", Enabled: true, ChatID: cfg.TelegramChatID, ParseMode: "HTML", TimeoutSeconds: 10, PerMinute: 20}
		if _, err := p.SaveChannel(ChannelInput{ChannelConfig: c, BotToken: cfg.TelegramBotToken}); err != nil {
			return err
		}
		routes = append(routes, Route{ChannelID: c.ID})
	}
	if len(routes) == 0 {
		return nil
	}
	_, err := p.SavePolicy(NotificationPolicy{ID: "legacy-operations", Name: "Built-in operational rules", Routes: routes})
	return err
}
func (p *Platform) observeLegacy(a model.Alert) {
	select {
	case p.legacy <- a:
	default:
		p.legacyDropped.Add(1)
	}
}
func (p *Platform) legacyLoop() {
	defer p.wg.Done()
	for {
		select {
		case <-p.ctx.Done():
			return
		case a := <-p.legacy:
			err := p.transaction(func(s *platformState) error {
				if _, ok := s.Policies["legacy-operations"]; !ok {
					return nil
				}
				id := "legacy/" + a.Type
				key := alertKey(id, a.Entity)
				instance := s.Alerts[key]
				now := time.Now().UTC()
				if !instance.LastNotified.IsZero() && now.Sub(instance.LastNotified) < 30*time.Minute {
					return nil
				}
				if instance.ID == "" {
					if len(s.Alerts) >= MaxInstances {
						return errors.New("alert instance capacity reached")
					}
					instance = AlertInstance{ID: newID("CFC-ALT-"), RuleID: id, Entity: a.Entity, Since: now, FiredAt: now}
				}
				instance.State = "FIRING"
				instance.LastEvaluated = now
				instance.LastNotified = now
				instance.Observed = a.Observed
				r := RuleDefinition{ID: id, Name: a.Title, Description: a.Reason, Kind: "aggregate", Metric: a.Type, Operator: "gt", Threshold: a.Threshold, WindowSeconds: 60, PolicyID: "legacy-operations", Priority: a.Severity}
				if suppressed(s, r, a.Entity, now) {
					return nil
				}
				event(s, instance, now, a.Reason)
				if e := enqueuePolicy(s, r, instance, now); e != nil {
					return e
				}
				s.Alerts[key] = instance
				return nil
			})
			if err != nil {
				p.legacyDropped.Add(1)
			}
		}
	}
}
