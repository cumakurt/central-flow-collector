package notification

import (
	"central-flow-collector/internal/intelligence"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"central-flow-collector/internal/model"
)

const (
	MaxRules      = 10000
	MaxGroups     = 1000
	MaxInstances  = 10000
	MaxDeliveries = 5000
)

// Condition is an allowlisted predicate tree, never executable text or SQL.
type Condition struct {
	Op       string      `json:"op"`
	Field    string      `json:"field,omitempty"`
	Values   []string    `json:"values,omitempty"`
	Children []Condition `json:"children,omitempty"`
}

var Fields = []string{"src_ip", "dst_ip", "src_network", "dst_network", "src_port", "dst_port", "protocol", "exporter", "ingress_if", "egress_if", "src_as", "dst_as", "src_country", "dst_country", "application", "bytes", "packets", "duration_ms", "direction"}

func contains(a []string, v string) bool {
	for _, x := range a {
		if x == v {
			return true
		}
	}
	return false
}
func numericField(f string) bool {
	return contains([]string{"src_port", "dst_port", "protocol", "ingress_if", "egress_if", "src_as", "dst_as", "bytes", "packets", "duration_ms", "direction"}, f)
}
func (c Condition) Validate() error {
	nodes := 0
	var visit func(Condition, int) error
	visit = func(c Condition, depth int) error {
		nodes++
		if depth > 6 || nodes > 64 {
			return errors.New("condition tree exceeds 6 levels or 64 nodes")
		}
		if contains([]string{"and", "or", "not"}, c.Op) {
			if c.Field != "" || len(c.Values) != 0 || len(c.Children) == 0 || (c.Op == "not" && len(c.Children) != 1) {
				return errors.New("invalid boolean group")
			}
			for _, child := range c.Children {
				if err := visit(child, depth+1); err != nil {
					return err
				}
			}
			return nil
		}
		if !contains(Fields, c.Field) || !contains([]string{"eq", "ne", "in", "not_in", "range", "gt", "gte", "lt", "lte"}, c.Op) || len(c.Children) != 0 {
			return errors.New("unsupported condition field or operator")
		}
		if len(c.Values) < 1 || len(c.Values) > 64 {
			return errors.New("condition requires 1..64 values")
		}
		if c.Op == "range" {
			if len(c.Values) != 2 || !numericField(c.Field) {
				return errors.New("range requires two numeric bounds")
			}
		} else if c.Op != "in" && c.Op != "not_in" && len(c.Values) != 1 {
			return errors.New("operator requires one value")
		}
		if contains([]string{"gt", "gte", "lt", "lte"}, c.Op) && !numericField(c.Field) {
			return errors.New("ordered comparison requires numeric field")
		}
		for _, v := range c.Values {
			if len(v) == 0 || len(v) > 256 || strings.ContainsAny(v, "\r\n\x00") {
				return errors.New("invalid condition value")
			}
			if numericField(c.Field) {
				n, e := strconv.ParseFloat(v, 64)
				if e != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 {
					return errors.New("invalid numeric condition")
				}
				if (strings.HasSuffix(c.Field, "port") && n > 65535) || (c.Field == "protocol" && n > 255) {
					return errors.New("port or protocol out of range")
				}
			}
			if c.Field == "src_network" || c.Field == "dst_network" {
				if _, e := netip.ParsePrefix(v); e != nil {
					return errors.New("invalid CIDR")
				}
			}
			if c.Field == "src_ip" || c.Field == "dst_ip" {
				if _, e := netip.ParseAddr(v); e != nil {
					return errors.New("invalid IP address")
				}
			}
		}
		if c.Op == "range" {
			a, _ := strconv.ParseFloat(c.Values[0], 64)
			b, _ := strconv.ParseFloat(c.Values[1], 64)
			if a > b {
				return errors.New("range bounds are reversed")
			}
		}
		return nil
	}
	return visit(c, 0)
}

func FlowValue(f model.Flow, field string) string {
	switch field {
	case "src_ip", "src_network":
		return f.SrcIP
	case "dst_ip", "dst_network":
		return f.DstIP
	case "src_port":
		return strconv.Itoa(int(f.SrcPort))
	case "dst_port":
		return strconv.Itoa(int(f.DstPort))
	case "protocol":
		return strconv.Itoa(int(f.IPProtocol))
	case "exporter":
		return f.Exporter
	case "ingress_if":
		return strconv.FormatUint(uint64(f.IngressIf), 10)
	case "egress_if":
		return strconv.FormatUint(uint64(f.EgressIf), 10)
	case "src_as":
		return strconv.FormatUint(uint64(f.SrcAS), 10)
	case "dst_as":
		return strconv.FormatUint(uint64(f.DstAS), 10)
	case "src_country":
		return f.SrcCountry
	case "dst_country":
		return f.DstCountry
	case "application":
		return model.ApplicationName(f)
	case "bytes":
		return strconv.FormatUint(f.Bytes, 10)
	case "packets":
		return strconv.FormatUint(f.Packets, 10)
	case "duration_ms":
		if f.StartTime.IsZero() || f.EndTime.IsZero() || f.EndTime.Before(f.StartTime) {
			return ""
		}
		return strconv.FormatInt(f.EndTime.Sub(f.StartTime).Milliseconds(), 10)
	case "direction":
		return strconv.Itoa(int(f.Direction))
	}
	return ""
}
func (c Condition) Match(f model.Flow) bool {
	switch c.Op {
	case "and":
		for _, x := range c.Children {
			if !x.Match(f) {
				return false
			}
		}
		return true
	case "or":
		for _, x := range c.Children {
			if x.Match(f) {
				return true
			}
		}
		return false
	case "not":
		return len(c.Children) == 1 && !c.Children[0].Match(f)
	}
	v := FlowValue(f, c.Field)
	if v == "" {
		return false
	}
	found := false
	for _, x := range c.Values {
		if c.Field == "src_network" || c.Field == "dst_network" {
			p, e := netip.ParsePrefix(x)
			ip, e2 := netip.ParseAddr(v)
			found = found || (e == nil && e2 == nil && p.Contains(ip))
		} else if numericField(c.Field) {
			a, _ := strconv.ParseFloat(v, 64)
			b, _ := strconv.ParseFloat(x, 64)
			found = found || a == b
		} else {
			found = found || v == x
		}
	}
	switch c.Op {
	case "eq", "in":
		return found
	case "ne", "not_in":
		return !found
	}
	a, _ := strconv.ParseFloat(v, 64)
	b, _ := strconv.ParseFloat(c.Values[0], 64)
	switch c.Op {
	case "gt":
		return a > b
	case "gte":
		return a >= b
	case "lt":
		return a < b
	case "lte":
		return a <= b
	case "range":
		hi, _ := strconv.ParseFloat(c.Values[1], 64)
		return a >= b && a <= hi
	}
	return false
}
func (c Condition) Summary() string {
	if len(c.Children) > 0 {
		p := []string{}
		for _, child := range c.Children {
			p = append(p, child.Summary())
		}
		if c.Op == "not" {
			return "NOT (" + strings.Join(p, "") + ")"
		}
		return "(" + strings.Join(p, " "+strings.ToUpper(c.Op)+" ") + ")"
	}
	return c.Field + " " + c.Op + " " + strings.Join(c.Values, ", ")
}

type Schedule struct {
	Timezone    string `json:"timezone,omitempty"`
	Weekdays    []int  `json:"weekdays,omitempty"`
	StartMinute int    `json:"start_minute"`
	EndMinute   int    `json:"end_minute"`
}

func (s Schedule) Active(t time.Time) bool {
	if s.Timezone == "" {
		return true
	}
	loc, e := time.LoadLocation(s.Timezone)
	if e != nil {
		return false
	}
	t = t.In(loc)
	minute := t.Hour()*60 + t.Minute()
	day := int(t.Weekday())
	if s.EndMinute < s.StartMinute && minute < s.EndMinute {
		day = (day + 6) % 7
	}
	found := len(s.Weekdays) == 0
	for _, d := range s.Weekdays {
		found = found || day == d
	}
	if !found {
		return false
	}
	if s.StartMinute == s.EndMinute {
		return true
	}
	if s.StartMinute < s.EndMinute {
		return minute >= s.StartMinute && minute < s.EndMinute
	}
	return minute >= s.StartMinute || minute < s.EndMinute
}

type RuleDefinition struct {
	ID                string    `json:"id"`
	Name              string    `json:"name"`
	Description       string    `json:"description"`
	Enabled           bool      `json:"enabled"`
	Kind              string    `json:"kind"`
	Condition         Condition `json:"condition"`
	Metric            string    `json:"metric"`
	Operator          string    `json:"operator"`
	Threshold         float64   `json:"threshold"`
	RecoveryThreshold *float64  `json:"recovery_threshold,omitempty"`
	MinimumCurrent    float64   `json:"minimum_current"`
	WindowSeconds     int       `json:"window_seconds"`
	IntervalSeconds   int       `json:"interval_seconds"`
	ForSeconds        int       `json:"for_seconds"`
	CooldownSeconds   int       `json:"cooldown_seconds"`
	Recovery          bool      `json:"recovery"`
	GroupBy           []string  `json:"group_by"`
	PolicyID          string    `json:"policy_id"`
	Priority          string    `json:"priority"`
	Schedule          Schedule  `json:"schedule"`
	Revision          int       `json:"revision"`
	UpdatedBy         string    `json:"updated_by"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func (r RuleDefinition) Validate() error {
	if (r.Kind == "match" || r.Kind == "absence") && r.Metric != "flows" {
		return errors.New("match and absence rules use observed flow count")
	}
	if len(r.Name) < 1 || len(r.Name) > 160 || len(r.Description) > 1024 || strings.ContainsAny(r.Name, "\r\n") {
		return errors.New("rule name or description is invalid")
	}
	if !contains([]string{"match", "absence", "aggregate", "comparison", "system", "seasonal"}, r.Kind) {
		return errors.New("unsupported rule kind")
	}
	if r.Kind != "system" {
		if err := r.Condition.Validate(); err != nil {
			return err
		}
	}
	if !contains([]string{"flows", "bytes", "packets", "bps", "bytes_per_sec", "packets_per_sec", "flows_per_sec", "unique_sources", "unique_destinations", "storage_unhealthy", "queue_percent", "disk_percent"}, r.Metric) {
		return errors.New("unsupported metric")
	}
	if r.Kind == "system" {
		if !contains([]string{"storage_unhealthy", "queue_percent", "disk_percent"}, r.Metric) || len(r.GroupBy) > 0 {
			return errors.New("invalid system scope")
		}
	} else if contains([]string{"storage_unhealthy", "queue_percent", "disk_percent"}, r.Metric) {
		return errors.New("system metric requires system rule")
	}
	if !contains([]string{"gt", "gte", "lt", "lte"}, r.Operator) || !finite(r.Threshold) || r.Threshold < 0 || !finite(r.MinimumCurrent) || r.MinimumCurrent < 0 {
		return errors.New("invalid threshold")
	}
	if r.RecoveryThreshold != nil {
		v := *r.RecoveryThreshold
		if !finite(v) || v < 0 || ((r.Operator == "gt" || r.Operator == "gte") && v > r.Threshold) || ((r.Operator == "lt" || r.Operator == "lte") && v < r.Threshold) {
			return errors.New("recovery threshold must be on the normal side of firing threshold")
		}
	}
	if r.WindowSeconds < 60 || r.WindowSeconds > 86400 || r.IntervalSeconds < 60 || r.IntervalSeconds > 3600 || r.ForSeconds < 0 || r.ForSeconds > 86400 || r.CooldownSeconds < 60 || r.CooldownSeconds > 604800 {
		return errors.New("invalid timing: window 60..86400, interval 60..3600, cooldown 60..604800 seconds")
	}
	if r.Kind == "seasonal" {
		if r.WindowSeconds != 3600 || r.IntervalSeconds != 3600 || r.Threshold < 2 || r.Threshold > 10 || r.Operator != "gt" || r.MinimumCurrent <= 0 || r.ForSeconds < 3600 {
			return errors.New("seasonal rules require hourly windows/evaluation, a 2..10 MAD multiplier, gt operator, a positive absolute deviation floor and at least 3600s pending duration")
		}
		if !contains([]string{"bytes", "packets", "flows", "bps", "bytes_per_sec", "packets_per_sec", "flows_per_sec", "unique_sources", "unique_destinations"}, r.Metric) {
			return errors.New("unsupported seasonal metric")
		}
	}
	if r.Kind == "absence" && len(r.GroupBy) > 0 {
		return errors.New("absence requires an explicit scope without group-by")
	}
	if len(r.GroupBy) > 3 {
		return errors.New("at most three group dimensions")
	}
	seen := map[string]bool{}
	for _, g := range r.GroupBy {
		if !contains(Fields, g) || numericField(g) && contains([]string{"bytes", "packets", "duration_ms"}, g) || seen[g] {
			return errors.New("invalid group-by")
		}
		seen[g] = true
	}
	if !contains([]string{"info", "warning", "high", "critical"}, r.Priority) {
		return errors.New("invalid priority")
	}
	if r.Schedule.Timezone != "" {
		if _, e := time.LoadLocation(r.Schedule.Timezone); e != nil {
			return errors.New("invalid schedule timezone")
		}
	}
	if r.Schedule.StartMinute < 0 || r.Schedule.StartMinute > 1439 || r.Schedule.EndMinute < 0 || r.Schedule.EndMinute > 1439 {
		return errors.New("invalid schedule time")
	}
	for _, d := range r.Schedule.Weekdays {
		if d < 0 || d > 6 {
			return errors.New("invalid weekday")
		}
	}
	return nil
}
func finite(v float64) bool { return !math.IsNaN(v) && !math.IsInf(v, 0) }
func (r RuleDefinition) Summary() string {
	if r.Kind == "seasonal" {
		return fmt.Sprintf("Seasonal %s deviation for %s: same UTC hour in the previous four weeks, median/MAD multiplier %g, minimum absolute delta %g and 25%% relative delta; at least three comparable unsampled weeks required.", r.Metric, r.Condition.Summary(), r.Threshold, r.MinimumCurrent)
	}
	if r.Kind == "absence" {
		return fmt.Sprintf("No flow matching %s received within %ds", r.Condition.Summary(), r.WindowSeconds)
	}
	if r.Kind == "match" {
		return fmt.Sprintf("Communication matching %s observed within %ds", r.Condition.Summary(), r.WindowSeconds)
	}
	if r.Kind == "system" {
		return fmt.Sprintf("Collector %s %s %g continuously for %ds", r.Metric, r.Operator, r.Threshold, r.ForSeconds)
	}
	return fmt.Sprintf("%s: %s; %s %s %g within %ds", r.Kind, r.Condition.Summary(), r.Metric, r.Operator, r.Threshold, r.WindowSeconds)
}
func (r RuleDefinition) Cost() string {
	if r.Kind == "seasonal" {
		return "high: five bounded one-hour queries across four historical weeks; 1,000 groups maximum"
	}
	if len(r.GroupBy) > 0 || r.Kind == "comparison" || strings.HasPrefix(r.Metric, "unique_") {
		return "high: grouped or comparative raw aggregation"
	}
	if r.Kind == "system" {
		return "low: current health snapshot"
	}
	return "medium: bounded historical aggregation"
}

type Observation struct {
	Records             uint64                         `json:"records,omitempty"`
	SamplingUnavailable uint64                         `json:"sampling_unavailable,omitempty"`
	Baseline            *intelligence.SeasonalEstimate `json:"baseline,omitempty"`
	Entity              string                         `json:"entity"`
	Value               float64                        `json:"value"`
	Previous            float64                        `json:"previous"`
	Dimensions          map[string]string              `json:"dimensions,omitempty"`
}
type AlertInstance struct {
	Baseline      *intelligence.SeasonalEstimate `json:"baseline,omitempty"`
	ID            string                         `json:"id"`
	RuleID        string                         `json:"rule_id"`
	Revision      int                            `json:"revision"`
	Entity        string                         `json:"entity"`
	State         string                         `json:"state"`
	Since         time.Time                      `json:"since"`
	FiredAt       time.Time                      `json:"fired_at"`
	LastEvaluated time.Time                      `json:"last_evaluated"`
	LastNotified  time.Time                      `json:"last_notified"`
	Observed      float64                        `json:"observed"`
	Dimensions    map[string]string              `json:"dimensions,omitempty"`
}
type AlertEvent struct {
	At      time.Time `json:"at"`
	AlertID string    `json:"alert_id"`
	RuleID  string    `json:"rule_id"`
	State   string    `json:"state"`
	Detail  string    `json:"detail"`
}
type Route struct {
	ChannelID     string `json:"channel_id"`
	DelaySeconds  int    `json:"delay_seconds"`
	DigestSeconds int    `json:"digest_seconds"`
}
type NotificationPolicy struct {
	ID     string  `json:"id"`
	Name   string  `json:"name"`
	Routes []Route `json:"routes"`
}
type Silence struct {
	ID     string    `json:"id"`
	RuleID string    `json:"rule_id"`
	Entity string    `json:"entity"`
	From   time.Time `json:"from"`
	Until  time.Time `json:"until"`
	Reason string    `json:"reason"`
}
