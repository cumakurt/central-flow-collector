package analytics

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type baselineSnapshot struct {
	Version    int                           `json:"version"`
	SavedAt    time.Time                     `json:"saved_at"`
	MinSamples int                           `json:"min_samples"`
	Hosts      map[string]baselineHostRecord `json:"hosts"`
}

type baselineHostRecord struct {
	Minute        int64                  `json:"minute"`
	Bytes         uint64                 `json:"bytes"`
	Flows         uint64                 `json:"flows"`
	LastAlert     time.Time              `json:"last_alert"`
	Buckets       []baselineBucket       `json:"buckets,omitempty"` // v1 dense compatibility
	SparseBuckets map[int]baselineBucket `json:"sparse_buckets,omitempty"`
}

func baselineSampleCount(st *hostBaselineState) uint64 {
	if st == nil {
		return 0
	}
	var n uint64
	for _, b := range st.Buckets {
		n += b.Count
	}
	return n
}

// SaveBaseline writes the learned seasonal baseline atomically. The snapshot
// intentionally contains only statistical state; no raw flow records are
// duplicated into this file.
func (e *Engine) SaveBaseline(path string) error {
	if path == "" {
		return errors.New("baseline persistence path is empty")
	}
	e.mu.RLock()
	snap := baselineSnapshot{Version: 2, SavedAt: time.Now().UTC(), MinSamples: e.baselineMinSamples, Hosts: make(map[string]baselineHostRecord, len(e.baselineHosts))}
	for host, st := range e.baselineHosts {
		buckets := make(map[int]baselineBucket, len(st.Buckets))
		for idx, b := range st.Buckets {
			if idx >= 0 && idx < 168 && (b.Count != 0 || b.Mean != 0 || b.M2 != 0 || b.EWMA != 0) {
				buckets[idx] = b
			}
		}
		snap.Hosts[host] = baselineHostRecord{Minute: st.Minute, Bytes: st.Bytes, Flows: st.Flows, LastAlert: st.LastAlert, SparseBuckets: buckets}
	}
	e.mu.RUnlock()

	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(b); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	// Best effort directory fsync so rename durability survives sudden power loss.
	if d, er := os.Open(filepath.Dir(path)); er == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	ok = true
	return nil
}

// LoadBaseline restores a previously saved snapshot. Missing snapshots are not
// errors so first-run operation remains simple. Corrupt snapshots are rejected
// rather than partially applied.
func (e *Engine) LoadBaseline(path string) error {
	if path == "" {
		return errors.New("baseline persistence path is empty")
	}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var snap baselineSnapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return fmt.Errorf("decode baseline snapshot: %w", err)
	}
	if snap.Version != 1 && snap.Version != 2 {
		return fmt.Errorf("unsupported baseline snapshot version %d", snap.Version)
	}
	if e.maxTrackedHosts > 0 && len(snap.Hosts) > e.maxTrackedHosts {
		return fmt.Errorf("baseline snapshot contains too many hosts: %d > %d", len(snap.Hosts), e.maxTrackedHosts)
	}
	restored := make(map[string]*hostBaselineState, len(snap.Hosts))
	for host, rec := range snap.Hosts {
		if host == "" {
			return errors.New("baseline snapshot contains empty host key")
		}
		st := &hostBaselineState{Minute: rec.Minute, Bytes: rec.Bytes, Flows: rec.Flows, LastAlert: rec.LastAlert, Buckets: map[int]baselineBucket{}}
		if snap.Version == 1 {
			if len(rec.Buckets) != 168 {
				return fmt.Errorf("baseline snapshot host %q has %d buckets, expected 168", host, len(rec.Buckets))
			}
			for i, b := range rec.Buckets {
				if b.Count != 0 || b.Mean != 0 || b.M2 != 0 || b.EWMA != 0 {
					st.Buckets[i] = b
				}
			}
		} else {
			if len(rec.Buckets) != 0 {
				return fmt.Errorf("baseline v2 snapshot host %q unexpectedly contains legacy dense buckets", host)
			}
			for i, b := range rec.SparseBuckets {
				if i < 0 || i >= 168 {
					return fmt.Errorf("baseline snapshot host %q has invalid bucket %d", host, i)
				}
				if b.Count != 0 || b.Mean != 0 || b.M2 != 0 || b.EWMA != 0 {
					st.Buckets[i] = b
				}
			}
		}
		// v3 snapshots may contain legacy "tenant|host" keys. v4 is a
		// single-organization product, so collapse them to the host component.
		key := host
		if i := strings.LastIndex(host, "|"); i >= 0 && i+1 < len(host) {
			key = host[i+1:]
		}
		if prev, ok := restored[key]; !ok || baselineSampleCount(st) > baselineSampleCount(prev) {
			restored[key] = st
		}
	}
	e.mu.Lock()
	e.baselineHosts = restored
	if snap.MinSamples >= 5 && snap.MinSamples <= 10000 {
		e.baselineMinSamples = snap.MinSamples
	}
	e.mu.Unlock()
	return nil
}
