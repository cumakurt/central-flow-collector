package cluster

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type Heartbeat struct {
	NodeID            string         `json:"node_id"`
	Region            string         `json:"region,omitempty"`
	Version           string         `json:"version"`
	StartedAt         time.Time      `json:"started_at,omitempty"`
	StorageBackend    string         `json:"storage_backend,omitempty"`
	Healthy           bool           `json:"healthy"`
	Metrics           map[string]any `json:"metrics,omitempty"`
	ConfigVersion     string         `json:"config_version,omitempty"`
	LastCommandID     string         `json:"last_command_id,omitempty"`
	LastCommandStatus string         `json:"last_command_status,omitempty"`
}

type Node struct {
	Heartbeat
	RemoteIP  string    `json:"remote_ip,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	State     string    `json:"state"`
}

type Command struct {
	ID          string    `json:"id"`
	NodeID      string    `json:"node_id"`
	Action      string    `json:"action"`
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	DeliveredAt time.Time `json:"delivered_at,omitempty"`
	AckedAt     time.Time `json:"acked_at,omitempty"`
	Status      string    `json:"status"`
	Result      string    `json:"result,omitempty"`
}
type Rollout struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Action     string    `json:"action"`
	NodeIDs    []string  `json:"node_ids"`
	Stages     []int     `json:"stages"`
	StageIndex int       `json:"stage_index"`
	Status     string    `json:"status"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	CommandIDs []string  `json:"command_ids"`
}

type HeartbeatResponse struct {
	OK         bool      `json:"ok"`
	ServerTime time.Time `json:"server_time"`
	Command    *Command  `json:"command,omitempty"`
}

type persisted struct {
	Version  int       `json:"version"`
	Nodes    []Node    `json:"nodes"`
	Commands []Command `json:"commands,omitempty"`
	Rollouts []Rollout `json:"rollouts,omitempty"`
}

type Registry struct {
	mu              sync.RWMutex
	path            string
	tokens          []string
	timeout         time.Duration
	expectedNodes   int
	nodes           map[string]Node
	commands        map[string]Command
	rollouts        map[string]Rollout
	dedupMu         sync.Mutex
	dedup           map[string]int64
	dedupWindow     time.Duration
	dedupMax        int
	dedupAccepted   atomic.Uint64
	dedupDuplicates atomic.Uint64
	dedupEvicted    atomic.Uint64
	dedupEnabled    atomic.Bool
}

func NewRegistry(path, token string, timeout time.Duration) (*Registry, error) {
	if timeout < 30*time.Second {
		timeout = 90 * time.Second
	}
	r := &Registry{path: path, tokens: parseTokens(token), timeout: timeout, expectedNodes: 1, nodes: map[string]Node{}, commands: map[string]Command{}, rollouts: map[string]Rollout{}, dedup: map[string]int64{}, dedupWindow: 30 * time.Second, dedupMax: 500000}
	if b, err := os.ReadFile(path); err == nil {
		var p persisted
		if err := json.Unmarshal(b, &p); err != nil {
			return nil, fmt.Errorf("decode cluster registry: %w", err)
		}
		if p.Version != 1 {
			return nil, fmt.Errorf("unsupported cluster registry version %d", p.Version)
		}
		for _, n := range p.Nodes {
			if validNodeID(n.NodeID) {
				r.nodes[n.NodeID] = n
			}
		}
		for _, c := range p.Commands {
			if validNodeID(c.NodeID) && c.ID != "" {
				r.commands[c.ID] = c
			}
		}
		for _, ro := range p.Rollouts {
			if ro.ID != "" {
				r.rollouts[ro.ID] = ro
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return r, nil
}
func parseTokens(raw string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range strings.FieldsFunc(raw, func(r rune) bool { return r == '\n' || r == '\r' || r == ',' }) {
		x = strings.TrimSpace(x)
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
func PrimaryToken(raw string) string {
	xs := parseTokens(raw)
	if len(xs) == 0 {
		return ""
	}
	return xs[0]
}

func validNodeID(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._-", c)) {
			return false
		}
	}
	return true
}
func (r *Registry) Enabled() bool { return r != nil && len(r.tokens) > 0 }
func (r *Registry) Authenticate(token string) bool {
	if r == nil || token == "" || len(r.tokens) == 0 {
		return false
	}
	ok := 0
	for _, want := range r.tokens {
		if len(token) == len(want) {
			ok |= subtle.ConstantTimeCompare([]byte(token), []byte(want))
		}
	}
	return ok == 1
}
func (r *Registry) Heartbeat(h Heartbeat, remote string) error {
	if !validNodeID(h.NodeID) {
		return errors.New("invalid node_id")
	}
	if len(h.Region) > 64 || len(h.Version) > 64 || len(h.ConfigVersion) > 128 || len(h.LastCommandID) > 128 || len(h.LastCommandStatus) > 4096 {
		return errors.New("heartbeat metadata too long")
	}
	now := time.Now().UTC()
	r.mu.Lock()
	if h.LastCommandID != "" {
		if c, ok := r.commands[h.LastCommandID]; ok && c.NodeID == h.NodeID && c.Status == "delivered" {
			c.Status = "acknowledged"
			c.AckedAt = now
			c.Result = h.LastCommandStatus
			r.commands[c.ID] = c
		}
	}
	n, exists := r.nodes[h.NodeID]
	if !exists && len(r.nodes) >= 1000 {
		r.mu.Unlock()
		return errors.New("cluster registry node limit reached")
	}
	if n.FirstSeen.IsZero() {
		n.FirstSeen = now
	}
	n.Heartbeat = h
	n.RemoteIP = remote
	n.LastSeen = now
	n.State = "online"
	r.nodes[h.NodeID] = n
	err := r.persistLocked()
	r.mu.Unlock()
	return err
}
func (r *Registry) persistLocked() error {
	if r.path == "" {
		return nil
	}
	ns := make([]Node, 0, len(r.nodes))
	for _, n := range r.nodes {
		ns = append(ns, n)
	}
	sort.Slice(ns, func(i, j int) bool { return ns[i].NodeID < ns[j].NodeID })
	cs := make([]Command, 0, len(r.commands))
	for _, c := range r.commands {
		cs = append(cs, c)
	}
	sort.Slice(cs, func(i, j int) bool { return cs[i].CreatedAt.Before(cs[j].CreatedAt) })
	rs := make([]Rollout, 0, len(r.rollouts))
	for _, ro := range r.rollouts {
		rs = append(rs, ro)
	}
	sort.Slice(rs, func(i, j int) bool { return rs[i].CreatedAt.Before(rs[j].CreatedAt) })
	b, _ := json.MarshalIndent(persisted{Version: 1, Nodes: ns, Commands: cs, Rollouts: rs}, "", "  ")
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(r.path), 0750); err != nil {
		return err
	}
	tmp := r.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0640); err != nil {
		return err
	}
	return os.Rename(tmp, r.path)
}
func (r *Registry) Nodes() []Node {
	if r == nil {
		return nil
	}
	now := time.Now().UTC()
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Node, 0, len(r.nodes))
	for _, n := range r.nodes {
		if now.Sub(n.LastSeen) > r.timeout {
			n.State = "offline"
		} else if !n.Healthy {
			n.State = "degraded"
		} else {
			n.State = "online"
		}
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeID < out[j].NodeID })
	return out
}

func commandID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("cmd-%d", time.Now().UnixNano())
	}
	return "cmd-" + hex.EncodeToString(b)
}
func (r *Registry) QueueCommand(nodeID, action, createdBy string) (Command, error) {
	if !validNodeID(nodeID) {
		return Command{}, errors.New("invalid node id")
	}
	switch action {
	case "reload_policies", "restart_service", "diagnostics":
	default:
		return Command{}, errors.New("unsupported fleet action")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.nodes[nodeID]; !ok {
		return Command{}, errors.New("node not registered")
	}
	for _, c := range r.commands {
		if c.NodeID == nodeID && c.Status == "pending" {
			return Command{}, errors.New("node already has a pending command")
		}
	}
	c := Command{ID: commandID(), NodeID: nodeID, Action: action, CreatedBy: createdBy, CreatedAt: time.Now().UTC(), Status: "pending"}
	r.commands[c.ID] = c
	return c, r.persistLocked()
}
func (r *Registry) NextCommand(nodeID string) *Command {
	r.mu.Lock()
	defer r.mu.Unlock()
	var best *Command
	for _, c := range r.commands {
		// Until an edge acknowledges a command, return it again on later
		// heartbeats. This makes directive delivery resilient to a lost HTTP
		// response without introducing arbitrary remote command execution.
		if c.NodeID != nodeID || (c.Status != "pending" && c.Status != "delivered") {
			continue
		}
		cc := c
		if best == nil || cc.CreatedAt.Before(best.CreatedAt) {
			best = &cc
		}
	}
	if best != nil {
		c := r.commands[best.ID]
		c.Status = "delivered"
		c.DeliveredAt = time.Now().UTC()
		r.commands[c.ID] = c
		*best = c
		_ = r.persistLocked()
	}
	return best
}
func (r *Registry) Commands() []Command {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Command, 0, len(r.commands))
	for _, c := range r.commands {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

func (r *Registry) Rollouts() []Rollout {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Rollout, 0, len(r.rollouts))
	for _, x := range r.rollouts {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out
}
func normalizeStages(st []int) []int {
	if len(st) == 0 {
		return []int{10, 50, 100}
	}
	out := []int{}
	last := 0
	for _, x := range st {
		if x > last && x <= 100 {
			out = append(out, x)
			last = x
		}
	}
	if len(out) == 0 || out[len(out)-1] != 100 {
		out = append(out, 100)
	}
	return out
}
func (r *Registry) StartRollout(name, action, by string, nodeIDs []string, stages []int) (Rollout, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Rollout{}, errors.New("rollout name required")
	}
	switch action {
	case "reload_policies", "restart_service":
	default:
		return Rollout{}, errors.New("unsupported rollout action")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	uniq := []string{}
	seen := map[string]bool{}
	for _, n := range nodeIDs {
		if !validNodeID(n) || seen[n] {
			continue
		}
		if _, ok := r.nodes[n]; !ok {
			return Rollout{}, fmt.Errorf("node %s not registered", n)
		}
		seen[n] = true
		uniq = append(uniq, n)
	}
	if len(uniq) == 0 {
		return Rollout{}, errors.New("rollout requires nodes")
	}
	ro := Rollout{ID: commandID(), Name: name, Action: action, NodeIDs: uniq, Stages: normalizeStages(stages), StageIndex: 0, Status: "running", CreatedBy: by, CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC()}
	if err := r.queueRolloutStageLocked(&ro); err != nil {
		return Rollout{}, err
	}
	r.rollouts[ro.ID] = ro
	return ro, r.persistLocked()
}
func (r *Registry) queueRolloutStageLocked(ro *Rollout) error {
	pct := ro.Stages[ro.StageIndex]
	target := (len(ro.NodeIDs)*pct + 99) / 100
	if target > len(ro.NodeIDs) {
		target = len(ro.NodeIDs)
	}
	already := map[string]bool{}
	for _, cid := range ro.CommandIDs {
		if c, ok := r.commands[cid]; ok {
			already[c.NodeID] = true
		}
	}
	for _, node := range ro.NodeIDs[:target] {
		if already[node] {
			continue
		}
		c := Command{ID: commandID(), NodeID: node, Action: ro.Action, CreatedBy: ro.CreatedBy, CreatedAt: time.Now().UTC(), Status: "pending"}
		r.commands[c.ID] = c
		ro.CommandIDs = append(ro.CommandIDs, c.ID)
	}
	ro.UpdatedAt = time.Now().UTC()
	return nil
}
func (r *Registry) AdvanceRollout(id string) (Rollout, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	ro, ok := r.rollouts[id]
	if !ok {
		return Rollout{}, errors.New("rollout not found")
	}
	if ro.Status != "running" {
		return ro, errors.New("rollout not running")
	}
	for _, cid := range ro.CommandIDs {
		c := r.commands[cid]
		if c.Status == "acknowledged" && strings.HasPrefix(strings.ToLower(c.Result), "error") {
			ro.Status = "failed"
			ro.UpdatedAt = time.Now().UTC()
			r.rollouts[id] = ro
			_ = r.persistLocked()
			return ro, errors.New("rollout stage failed")
		}
		if c.Status != "acknowledged" {
			return ro, errors.New("current rollout stage has unacknowledged commands")
		}
	}
	if ro.StageIndex+1 >= len(ro.Stages) {
		ro.Status = "completed"
		ro.UpdatedAt = time.Now().UTC()
		r.rollouts[id] = ro
		return ro, r.persistLocked()
	}
	ro.StageIndex++
	if err := r.queueRolloutStageLocked(&ro); err != nil {
		return ro, err
	}
	r.rollouts[id] = ro
	return ro, r.persistLocked()
}

type DedupStats struct {
	Enabled    bool   `json:"enabled"`
	WindowMS   int64  `json:"window_ms"`
	Entries    int    `json:"entries"`
	Accepted   uint64 `json:"accepted"`
	Duplicates uint64 `json:"duplicates"`
	Evicted    uint64 `json:"evicted"`
}

func (r *Registry) ConfigureDedup(window time.Duration, maxEntries int) {
	r.dedupEnabled.Store(true)
	if window < time.Second {
		window = 30 * time.Second
	}
	if maxEntries < 1000 {
		maxEntries = 500000
	}
	r.dedupMu.Lock()
	r.dedupWindow = window
	r.dedupMax = maxEntries
	r.dedupMu.Unlock()
}
func (r *Registry) AcceptFingerprint(fp string, now time.Time) bool {
	if r == nil {
		return true
	}
	fp = strings.TrimSpace(fp)
	if len(fp) < 16 || len(fp) > 128 {
		return true
	}
	n := now.UnixNano()
	r.dedupMu.Lock()
	defer r.dedupMu.Unlock()
	cut := n - r.dedupWindow.Nanoseconds()
	if ts, ok := r.dedup[fp]; ok && ts >= cut {
		r.dedupDuplicates.Add(1)
		return false
	}
	r.dedup[fp] = n
	r.dedupAccepted.Add(1)
	if len(r.dedup) > r.dedupMax {
		for k, ts := range r.dedup {
			if ts < cut {
				delete(r.dedup, k)
				r.dedupEvicted.Add(1)
			}
		}
		for len(r.dedup) > r.dedupMax {
			for k := range r.dedup {
				delete(r.dedup, k)
				r.dedupEvicted.Add(1)
				break
			}
		}
	}
	return true
}
func (r *Registry) DedupStats() DedupStats {
	if r == nil {
		return DedupStats{}
	}
	r.dedupMu.Lock()
	n := len(r.dedup)
	w := r.dedupWindow
	r.dedupMu.Unlock()
	return DedupStats{Enabled: r.Enabled() && r.dedupEnabled.Load(), WindowMS: w.Milliseconds(), Entries: n, Accepted: r.dedupAccepted.Load(), Duplicates: r.dedupDuplicates.Load(), Evicted: r.dedupEvicted.Load()}
}

type DedupResponse struct {
	Accepted bool       `json:"accepted"`
	Stats    DedupStats `json:"stats"`
}

type TopologyStatus struct {
	Expected       int    `json:"expected"`
	Online         int    `json:"online"`
	Degraded       int    `json:"degraded"`
	Offline        int    `json:"offline"`
	QuorumRequired int    `json:"quorum_required"`
	HasQuorum      bool   `json:"has_quorum"`
	Coordinator    string `json:"coordinator,omitempty"`
}

func (r *Registry) ConfigureTopology(expected int) {
	if r == nil {
		return
	}
	if expected < 1 {
		expected = 1
	}
	r.mu.Lock()
	r.expectedNodes = expected
	r.mu.Unlock()
}
func (r *Registry) TopologyStatus() TopologyStatus {
	if r == nil {
		return TopologyStatus{Expected: 1, QuorumRequired: 1}
	}
	nodes := r.Nodes()
	r.mu.RLock()
	expected := r.expectedNodes
	r.mu.RUnlock()
	if expected < 1 {
		expected = 1
	}
	x := TopologyStatus{Expected: expected, QuorumRequired: expected/2 + 1}
	eligible := []string{}
	for _, n := range nodes {
		switch n.State {
		case "online":
			x.Online++
			eligible = append(eligible, n.NodeID)
		case "degraded":
			x.Degraded++
			eligible = append(eligible, n.NodeID)
		default:
			x.Offline++
		}
	}
	x.HasQuorum = x.Online+x.Degraded >= x.QuorumRequired
	sort.Strings(eligible)
	if len(eligible) > 0 {
		x.Coordinator = eligible[0]
	}
	return x
}

// AssignExporter uses rendezvous hashing across currently reachable nodes. It
// minimizes exporter movement when nodes join/leave and is deterministic across
// coordinators that have the same registry view.
func (r *Registry) AssignExporter(key string) (string, bool) {
	if r == nil || strings.TrimSpace(key) == "" {
		return "", false
	}
	nodes := r.Nodes()
	best := ""
	var bestScore uint64
	for _, n := range nodes {
		if n.State == "offline" {
			continue
		}
		sum := sha256.Sum256([]byte(key + "|" + n.NodeID))
		score := binary.BigEndian.Uint64(sum[:8])
		if best == "" || score > bestScore {
			best = n.NodeID
			bestScore = score
		}
	}
	return best, best != ""
}

func NewMTLSHTTPClient(caFile, certFile, keyFile, serverName string, timeout time.Duration) (*http.Client, error) {
	ca, err := os.ReadFile(caFile)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return nil, errors.New("cluster CA file contains no certificates")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	tr := &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{cert}, ServerName: strings.TrimSpace(serverName)}}
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	return &http.Client{Transport: tr, Timeout: timeout}, nil
}

type Client struct {
	URL, Token string
	Interval   time.Duration
	HTTP       *http.Client
}

func (c Client) SendWithDirective(ctx context.Context, h Heartbeat) (HeartbeatResponse, error) {
	if c.URL == "" {
		return HeartbeatResponse{}, errors.New("cluster heartbeat URL is empty")
	}
	b, _ := json.Marshal(h)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(b))
	if err != nil {
		return HeartbeatResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	cl := c.HTTP
	if cl == nil {
		cl = &http.Client{Timeout: 8 * time.Second}
	}
	resp, err := cl.Do(req)
	if err != nil {
		return HeartbeatResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		x, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return HeartbeatResponse{}, fmt.Errorf("cluster heartbeat HTTP %s: %s", resp.Status, strings.TrimSpace(string(x)))
	}
	var out HeartbeatResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		if errors.Is(err, io.EOF) {
			return HeartbeatResponse{OK: true, ServerTime: time.Now().UTC()}, nil
		}
		return HeartbeatResponse{}, err
	}
	return out, nil
}
func (c Client) Send(ctx context.Context, h Heartbeat) error {
	_, err := c.SendWithDirective(ctx, h)
	return err
}

func (c Client) CheckDedup(ctx context.Context, fingerprint string) (bool, error) {
	b, _ := json.Marshal(map[string]string{"fingerprint": fingerprint})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.URL, bytes.NewReader(b))
	if err != nil {
		return true, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.Token)
	cl := c.HTTP
	if cl == nil {
		cl = &http.Client{Timeout: time.Second}
	}
	resp, err := cl.Do(req)
	if err != nil {
		return true, err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		x, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return true, fmt.Errorf("cluster dedup HTTP %s: %s", resp.Status, strings.TrimSpace(string(x)))
	}
	var out DedupResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return true, err
	}
	return out.Accepted, nil
}
