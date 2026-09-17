package audit

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Event struct {
	Timestamp time.Time `json:"timestamp"`
	User      string    `json:"user"`
	Action    string    `json:"action"`
	Source    string    `json:"source"`
	Object    string    `json:"object,omitempty"`
	Success   bool      `json:"success"`
	Detail    string    `json:"detail,omitempty"`
	PrevHash  string    `json:"prev_hash,omitempty"`
	Hash      string    `json:"hash,omitempty"`
}

type VerifyResult struct {
	OK          bool   `json:"ok"`
	Records     int    `json:"records"`
	Verified    int    `json:"verified"`
	Legacy      int    `json:"legacy"`
	FirstBroken int    `json:"first_broken,omitempty"`
	Error       string `json:"error,omitempty"`
}

type Log struct {
	mu       sync.Mutex
	path     string
	keyPath  string
	key      []byte
	lastHash string
	initErr  error
}

func New(dir string) *Log {
	l := &Log{path: filepath.Join(dir, "audit.jsonl"), keyPath: filepath.Join(dir, "audit.key")}
	l.initErr = l.init()
	return l
}

func (l *Log) init() error {
	if err := os.MkdirAll(filepath.Dir(l.path), 0750); err != nil {
		return err
	}
	if b, err := os.ReadFile(l.keyPath); err == nil {
		if len(b) != 32 {
			return errors.New("audit.key must be 32 bytes")
		}
		l.key = b
	} else if os.IsNotExist(err) {
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		if err := os.WriteFile(l.keyPath, b, 0600); err != nil {
			return err
		}
		l.key = b
	} else {
		return err
	}
	evs := l.readAllUnlocked()
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Hash != "" {
			l.lastHash = evs[i].Hash
			break
		}
	}
	return nil
}

func canonical(e Event) []byte {
	e.Hash = ""
	b, _ := json.Marshal(e)
	return b
}
func (l *Log) hash(e Event) string {
	mac := hmac.New(sha256.New, l.key)
	_, _ = mac.Write(canonical(e))
	return hex.EncodeToString(mac.Sum(nil))
}

func (l *Log) Write(e Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.initErr != nil {
		return
	}
	e.Timestamp = time.Now().UTC()
	e.PrevHash = l.lastHash
	e.Hash = l.hash(e)
	b, _ := json.Marshal(e)
	if f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640); err == nil {
		_, _ = f.Write(append(b, '\n'))
		_ = f.Sync()
		_ = f.Close()
		l.lastHash = e.Hash
	}
}

func (l *Log) readAllUnlocked() []Event {
	b, err := os.ReadFile(l.path)
	if err != nil {
		return nil
	}
	var all []Event
	start := 0
	for i, c := range b {
		if c == '\n' {
			var e Event
			if json.Unmarshal(b[start:i], &e) == nil {
				all = append(all, e)
			}
			start = i + 1
		}
	}
	return all
}

func (l *Log) Read(limit int) []Event {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	l.mu.Lock()
	all := l.readAllUnlocked()
	l.mu.Unlock()
	if len(all) > limit {
		all = all[len(all)-limit:]
	}
	for i, j := 0, len(all)-1; i < j; i, j = i+1, j-1 {
		all[i], all[j] = all[j], all[i]
	}
	return all
}

func (l *Log) Verify() VerifyResult {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.initErr != nil {
		return VerifyResult{OK: false, Error: l.initErr.Error()}
	}
	all := l.readAllUnlocked()
	res := VerifyResult{OK: true, Records: len(all)}
	prev := ""
	for i, e := range all {
		if e.Hash == "" {
			res.Legacy++
			continue
		}
		if e.PrevHash != prev && !(prev == "" && e.PrevHash != "" && res.Legacy > 0) {
			res.OK = false
			res.FirstBroken = i + 1
			res.Error = "audit prev_hash chain mismatch"
			return res
		}
		if !hmac.Equal([]byte(e.Hash), []byte(l.hash(e))) {
			res.OK = false
			res.FirstBroken = i + 1
			res.Error = "audit HMAC mismatch"
			return res
		}
		prev = e.Hash
		res.Verified++
	}
	return res
}

func (l *Log) Export(path string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.initErr != nil {
		return l.initErr
	}
	if path == "" {
		return errors.New("export path required")
	}
	src, err := os.ReadFile(l.path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	if err := os.WriteFile(path, src, 0640); err != nil {
		return err
	}
	vr := l.VerifyUnlocked()
	if !vr.OK {
		return fmt.Errorf("audit export integrity failed: %s", vr.Error)
	}
	return nil
}
func (l *Log) VerifyUnlocked() VerifyResult {
	if l.initErr != nil {
		return VerifyResult{OK: false, Error: l.initErr.Error()}
	}
	all := l.readAllUnlocked()
	res := VerifyResult{OK: true, Records: len(all)}
	prev := ""
	for i, e := range all {
		if e.Hash == "" {
			res.Legacy++
			continue
		}
		if e.PrevHash != prev && !(prev == "" && e.PrevHash != "" && res.Legacy > 0) {
			res.OK = false
			res.FirstBroken = i + 1
			res.Error = "audit prev_hash chain mismatch"
			return res
		}
		if !hmac.Equal([]byte(e.Hash), []byte(l.hash(e))) {
			res.OK = false
			res.FirstBroken = i + 1
			res.Error = "audit HMAC mismatch"
			return res
		}
		prev = e.Hash
		res.Verified++
	}
	return res
}
