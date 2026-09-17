package analytics

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Rule struct {
	ID            string  `json:"id"`
	Type          string  `json:"type"`
	Enabled       bool    `json:"enabled"`
	Severity      string  `json:"severity"`
	Threshold     float64 `json:"threshold"`
	WindowSeconds int     `json:"window_seconds"`
	MinSamples    int     `json:"min_samples"`
	Description   string  `json:"description"`
}

func defaultRules() map[string]Rule {
	a := []Rule{
		{ID: "traffic-spike", Type: "traffic_spike", Enabled: true, Severity: "medium", Threshold: 5, WindowSeconds: 1, MinSamples: 1, Description: "One-second bitrate exceeds the EWMA traffic baseline by this factor."},
		{ID: "large-transfer", Type: "large_transfer", Enabled: true, Severity: "info", Threshold: 100 * 1024 * 1024, WindowSeconds: 0, MinSamples: 1, Description: "Single flow byte threshold used for capacity visibility."},
		{ID: "exporter-down", Type: "exporter_down", Enabled: true, Severity: "high", Threshold: 300, WindowSeconds: 300, MinSamples: 1, Description: "Seconds without exporter telemetry before an operational availability alert."},
		{ID: "baseline-anomaly", Type: "baseline_anomaly", Enabled: true, Severity: "medium", Threshold: 4.0, WindowSeconds: 60, MinSamples: 20, Description: "Per-host minute byte volume exceeds its seasonality-aware traffic baseline."},
	}
	m := make(map[string]Rule, len(a))
	for _, r := range a {
		m[r.Type] = r
	}
	return m
}

func (e *Engine) ConfigureRules(path string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.rulesPath = path
	if e.rules == nil {
		e.rules = defaultRules()
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return e.saveRulesLocked()
	}
	if err != nil {
		return err
	}
	var rr []Rule
	if err = json.Unmarshal(b, &rr); err != nil {
		return err
	}
	merged := defaultRules()
	for _, r := range rr {
		if err := validateRule(r); err != nil {
			return err
		}
		merged[r.Type] = r
	}
	e.rules = merged
	return nil
}

func validateRule(r Rule) error {
	r.ID = strings.TrimSpace(r.ID)
	r.Type = strings.TrimSpace(r.Type)
	if r.ID == "" || r.Type == "" {
		return errors.New("alert rule id and type are required")
	}
	if _, ok := defaultRules()[r.Type]; !ok {
		return errors.New("unsupported alert rule type: " + r.Type)
	}
	switch r.Severity {
	case "info", "low", "medium", "high", "critical":
	default:
		return errors.New("invalid alert severity")
	}
	if r.Threshold <= 0 {
		return errors.New("threshold must be > 0")
	}
	if r.WindowSeconds < 0 || r.WindowSeconds > 86400 {
		return errors.New("window_seconds must be 0..86400")
	}
	if r.MinSamples < 1 || r.MinSamples > 1000000 {
		return errors.New("min_samples must be 1..1000000")
	}
	return nil
}

func (e *Engine) saveRulesLocked() error {
	if e.rulesPath == "" {
		return nil
	}
	rr := make([]Rule, 0, len(e.rules))
	for _, r := range e.rules {
		rr = append(rr, r)
	}
	sort.Slice(rr, func(i, j int) bool { return rr[i].Type < rr[j].Type })
	b, err := json.MarshalIndent(rr, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(e.rulesPath), 0750); err != nil {
		return err
	}
	tmp := e.rulesPath + ".tmp"
	if err = os.WriteFile(tmp, append(b, '\n'), 0640); err != nil {
		return err
	}
	return os.Rename(tmp, e.rulesPath)
}

func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rr := make([]Rule, 0, len(e.rules))
	for _, r := range e.rules {
		rr = append(rr, r)
	}
	sort.Slice(rr, func(i, j int) bool { return rr[i].Type < rr[j].Type })
	return rr
}

func (e *Engine) UpsertRule(r Rule) error {
	if err := validateRule(r); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.rules == nil {
		e.rules = defaultRules()
	}
	e.rules[r.Type] = r
	return e.saveRulesLocked()
}

func (e *Engine) DeleteRule(t string) error {
	d, ok := defaultRules()[t]
	if !ok {
		return errors.New("unsupported alert rule type")
	}
	d.Enabled = false
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.rules == nil {
		e.rules = defaultRules()
	}
	e.rules[t] = d
	return e.saveRulesLocked()
}

func (e *Engine) ruleLocked(t string) Rule {
	if r, ok := e.rules[t]; ok {
		return r
	}
	return defaultRules()[t]
}

func (e *Engine) Rule(t string) Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.ruleLocked(t)
}
