package workspace

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type SavedSearch struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Owner         string            `json:"owner"`
	Query         map[string]string `json:"query"`
	Columns       []string          `json:"columns,omitempty"`
	Sort          string            `json:"sort,omitempty"`
	GroupBy       string            `json:"group_by,omitempty"`
	Visualization string            `json:"visualization,omitempty"`
	TimeConfig    string            `json:"time_config,omitempty"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

type SearchHistory struct {
	ID          string            `json:"id"`
	User        string            `json:"user"`
	Query       map[string]string `json:"query"`
	ExecutedAt  time.Time         `json:"executed_at"`
	ResultCount int               `json:"result_count"`
}

type state struct {
	Saved   []SavedSearch   `json:"saved_searches"`
	History []SearchHistory `json:"search_history"`
}

type Manager struct {
	mu   sync.RWMutex
	path string
	s    state
}

func New(dataDir string) (*Manager, error) {
	m := &Manager{path: filepath.Join(dataDir, "workspace.json")}
	b, err := os.ReadFile(m.path)
	if os.IsNotExist(err) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if len(b) > 0 {
		if err := json.Unmarshal(b, &m.s); err != nil {
			return nil, err
		}
	}
	return m, nil
}

func id(prefix string) string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return prefix + "-" + time.Now().UTC().Format("20060102150405.000000000")
	}
	return prefix + "-" + hex.EncodeToString(b)
}

func cloneMap(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if strings.TrimSpace(v) != "" {
			out[k] = v
		}
	}
	return out
}

func (m *Manager) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(m.path), 0750); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m.s, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0640); err != nil {
		return err
	}
	return os.Rename(tmp, m.path)
}

func (m *Manager) Saved(user string) []SavedSearch {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]SavedSearch, 0)
	for _, x := range m.s.Saved {
		if x.Owner == user {
			x.Query = cloneMap(x.Query)
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out
}

func (m *Manager) UpsertSaved(user string, x SavedSearch) (SavedSearch, error) {
	x.Name = strings.TrimSpace(x.Name)
	if x.Name == "" {
		return x, errors.New("saved search name is required")
	}
	if len(x.Query) == 0 {
		return x, errors.New("saved search query is required")
	}
	x.Sort = strings.TrimSpace(x.Sort)
	x.GroupBy = strings.TrimSpace(x.GroupBy)
	x.Visualization = strings.TrimSpace(x.Visualization)
	x.TimeConfig = strings.TrimSpace(x.TimeConfig)
	if len(x.Columns) > 32 {
		x.Columns = x.Columns[:32]
	}
	for i := range x.Columns {
		x.Columns[i] = strings.TrimSpace(x.Columns[i])
	}
	now := time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	if x.ID != "" {
		for i := range m.s.Saved {
			if m.s.Saved[i].ID == x.ID {
				if m.s.Saved[i].Owner != user {
					return x, errors.New("saved search not found")
				}
				x.Owner = user
				x.CreatedAt = m.s.Saved[i].CreatedAt
				x.UpdatedAt = now
				x.Query = cloneMap(x.Query)
				m.s.Saved[i] = x
				return x, m.saveLocked()
			}
		}
	}
	x.ID = id("search")
	x.Owner = user
	x.CreatedAt = now
	x.UpdatedAt = now
	x.Query = cloneMap(x.Query)
	m.s.Saved = append(m.s.Saved, x)
	return x, m.saveLocked()
}

func (m *Manager) DeleteSaved(user, idv string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, x := range m.s.Saved {
		if x.ID == idv && x.Owner == user {
			m.s.Saved = append(m.s.Saved[:i], m.s.Saved[i+1:]...)
			return m.saveLocked()
		}
	}
	return errors.New("saved search not found")
}

func (m *Manager) RecordHistory(user string, q map[string]string, count int) {
	if len(q) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.s.History = append(m.s.History, SearchHistory{ID: id("history"), User: user, Query: cloneMap(q), ExecutedAt: time.Now().UTC(), ResultCount: count})
	if len(m.s.History) > 500 {
		m.s.History = m.s.History[len(m.s.History)-500:]
	}
	_ = m.saveLocked()
}

func (m *Manager) History(user string, limit int) []SearchHistory {
	if limit < 1 || limit > 100 {
		limit = 25
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]SearchHistory, 0, limit)
	for i := len(m.s.History) - 1; i >= 0 && len(out) < limit; i-- {
		x := m.s.History[i]
		if x.User == user {
			x.Query = cloneMap(x.Query)
			out = append(out, x)
		}
	}
	return out
}

func validWidgetType(v string) bool {
	switch v {
	case "kpi", "topn", "timeline", "traffic_matrix", "exporter_health", "sankey", "heatmap", "protocol_distribution":
		return true
	}
	return false
}
