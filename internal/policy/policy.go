package policy

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Rule struct {
	ID       string `json:"id"`
	Priority int    `json:"priority"`
	Action   string `json:"action"`
	Source   string `json:"source"`
	Protocol string `json:"protocol,omitempty"`
	Listener string `json:"listener,omitempty"`
	DestPort int    `json:"dest_port,omitempty"`
	Enabled  bool   `json:"enabled"`
	Comment  string `json:"comment,omitempty"`
}

type compiledRule struct {
	Rule
	prefix netip.Prefix
	any    bool
}
type compiledSet struct {
	rules        []compiledRule
	defaultAllow bool
}

type Decision struct {
	Allowed bool   `json:"allowed"`
	RuleID  string `json:"rule_id,omitempty"`
	Reason  string `json:"reason"`
}

type TraceStep struct {
	RuleID   string `json:"rule_id"`
	Priority int    `json:"priority"`
	Matched  bool   `json:"matched"`
	Detail   string `json:"detail"`
}

type Simulation struct {
	Decision Decision    `json:"decision"`
	Trace    []TraceStep `json:"trace"`
}

type Engine struct {
	ptr  atomic.Pointer[compiledSet]
	path string
	mu   sync.Mutex
}

func New(path, defaultAction string) (*Engine, error) {
	e := &Engine{path: path}
	rules := []Rule{}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &rules); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := e.replace(rules, strings.EqualFold(defaultAction, "allow")); err != nil {
		return nil, err
	}
	return e, nil
}

// Reload atomically reloads the persisted policy file while preserving the
// current default action. It is used by fleet-managed edge collectors; parsing
// or validation failures leave the active compiled policy untouched.
func (e *Engine) Reload() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rules := []Rule{}
	if b, err := os.ReadFile(e.path); err == nil {
		if err := json.Unmarshal(b, &rules); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	cur := e.ptr.Load()
	defaultAllow := false
	if cur != nil {
		defaultAllow = cur.defaultAllow
	}
	return e.replace(rules, defaultAllow)
}

func (e *Engine) Decide(source, protocol, listener string, destPort int) Decision {
	return e.Simulate(source, protocol, listener, destPort).Decision
}

func (e *Engine) Simulate(source, protocol, listener string, destPort int) Simulation {
	ip, err := netip.ParseAddr(source)
	if err != nil {
		return Simulation{Decision: Decision{Reason: "invalid source address"}}
	}
	set := e.ptr.Load()
	if set == nil {
		return Simulation{Decision: Decision{Reason: "policy unavailable"}}
	}
	sim := Simulation{Trace: make([]TraceStep, 0, len(set.rules))}
	for _, r := range set.rules {
		step := TraceStep{RuleID: r.ID, Priority: r.Priority}
		if !r.any && !r.prefix.Contains(ip) {
			step.Detail = fmt.Sprintf("source %s is outside %s", source, r.Source)
			sim.Trace = append(sim.Trace, step)
			continue
		}
		if r.Protocol != "" && !strings.EqualFold(r.Protocol, protocol) {
			step.Detail = fmt.Sprintf("protocol %s does not match %s", protocol, r.Protocol)
			sim.Trace = append(sim.Trace, step)
			continue
		}
		if r.Listener != "" && r.Listener != listener {
			step.Detail = fmt.Sprintf("listener %s does not match %s", listener, r.Listener)
			sim.Trace = append(sim.Trace, step)
			continue
		}
		if r.DestPort != 0 && r.DestPort != destPort {
			step.Detail = fmt.Sprintf("destination port %d does not match %d", destPort, r.DestPort)
			sim.Trace = append(sim.Trace, step)
			continue
		}
		step.Matched = true
		step.Detail = fmt.Sprintf("matched source/protocol/listener/port; action=%s", strings.ToUpper(r.Action))
		sim.Trace = append(sim.Trace, step)
		allow := strings.EqualFold(r.Action, "allow")
		sim.Decision = Decision{Allowed: allow, RuleID: r.ID, Reason: fmt.Sprintf("matched priority %d %s %s", r.Priority, strings.ToUpper(r.Action), r.Source)}
		return sim
	}
	if set.defaultAllow {
		sim.Decision = Decision{Allowed: true, Reason: "default allow: no enabled rule matched"}
	} else {
		sim.Decision = Decision{Allowed: false, Reason: "default deny: no enabled rule matched"}
	}
	return sim
}

func (e *Engine) Rules() []Rule {
	set := e.ptr.Load()
	if set == nil {
		return nil
	}
	out := make([]Rule, 0, len(set.rules))
	for _, r := range set.rules {
		out = append(out, r.Rule)
	}
	return out
}
func (e *Engine) Upsert(r Rule) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if r.ID == "" {
		r.ID = fmt.Sprintf("rule-%d", time.Now().UnixNano())
	}
	r.Action = strings.ToLower(r.Action)
	if !r.Enabled { /* explicitly disabled */
	}
	rules := e.Rules()
	found := false
	for i := range rules {
		if rules[i].ID == r.ID {
			rules[i] = r
			found = true
		}
	}
	if !found {
		rules = append(rules, r)
	}
	return e.persistAndReplace(rules)
}
func (e *Engine) Delete(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	rules := e.Rules()
	out := rules[:0]
	for _, r := range rules {
		if r.ID != id {
			out = append(out, r)
		}
	}
	return e.persistAndReplace(out)
}
func (e *Engine) persistAndReplace(rules []Rule) error {
	set := e.ptr.Load()
	def := false
	if set != nil {
		def = set.defaultAllow
	}
	if err := validate(rules); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(e.path), 0750); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(rules, "", "  ")
	tmp := e.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0640); err != nil {
		return err
	}
	if err := os.Rename(tmp, e.path); err != nil {
		return err
	}
	return e.replace(rules, def)
}
func (e *Engine) replace(rules []Rule, defaultAllow bool) error {
	if err := validate(rules); err != nil {
		return err
	}
	cs := &compiledSet{defaultAllow: defaultAllow}
	for _, r := range rules {
		if !r.Enabled {
			continue
		}
		cr := compiledRule{Rule: r}
		src := strings.TrimSpace(r.Source)
		if src == "" || strings.EqualFold(src, "any") {
			cr.any = true
		} else {
			if !strings.Contains(src, "/") {
				ip, err := netip.ParseAddr(src)
				if err != nil {
					return err
				}
				bits := 32
				if ip.Is6() {
					bits = 128
				}
				src = fmt.Sprintf("%s/%d", ip, bits)
			}
			p, err := netip.ParsePrefix(src)
			if err != nil {
				return err
			}
			cr.prefix = p
		}
		cs.rules = append(cs.rules, cr)
	}
	sort.SliceStable(cs.rules, func(i, j int) bool { return cs.rules[i].Priority < cs.rules[j].Priority })
	e.ptr.Store(cs)
	return nil
}
func validate(rules []Rule) error {
	ids := map[string]bool{}
	for _, r := range rules {
		if r.ID == "" {
			return fmt.Errorf("policy id required")
		}
		if ids[r.ID] {
			return fmt.Errorf("duplicate policy id %s", r.ID)
		}
		ids[r.ID] = true
		if !strings.EqualFold(r.Action, "allow") && !strings.EqualFold(r.Action, "deny") {
			return fmt.Errorf("invalid action %q", r.Action)
		}
		if r.Source != "" && !strings.EqualFold(r.Source, "any") {
			s := r.Source
			if !strings.Contains(s, "/") {
				if _, e := netip.ParseAddr(s); e != nil {
					return fmt.Errorf("invalid source %q", s)
				}
			} else if _, e := netip.ParsePrefix(s); e != nil {
				return fmt.Errorf("invalid source CIDR %q", s)
			}
		}
	}
	return nil
}
