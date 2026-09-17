package dedup

import (
	"central-flow-collector/internal/model"
	"crypto/sha256"
	"encoding/binary"
	"hash"
	"sync"
	"sync/atomic"
	"time"
)

type Stats struct {
	Enabled    bool   `json:"enabled"`
	WindowMS   int64  `json:"window_ms"`
	Entries    int    `json:"entries"`
	Accepted   uint64 `json:"accepted"`
	Duplicates uint64 `json:"duplicates"`
	Evicted    uint64 `json:"evicted"`
}

type key [16]byte

type Detector struct {
	mu         sync.Mutex
	seen       map[key]int64
	window     time.Duration
	max        int
	sweepAt    int64
	accepted   atomic.Uint64
	duplicates atomic.Uint64
	evicted    atomic.Uint64
}

func New(window time.Duration, maxEntries int) *Detector {
	if window < time.Second {
		window = 30 * time.Second
	}
	if maxEntries < 1000 {
		maxEntries = 200000
	}
	return &Detector{seen: make(map[key]int64, min(maxEntries, 65536)), window: window, max: maxEntries}
}

func putString(h hash.Hash, s string) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(len(s)))
	_, _ = h.Write(b[:])
	_, _ = h.Write([]byte(s))
}
func put64(h hash.Hash, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	_, _ = h.Write(b[:])
}
func put32(h hash.Hash, v uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], v)
	_, _ = h.Write(b[:])
}
func put16(h hash.Hash, v uint16) {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	_, _ = h.Write(b[:])
}

func fingerprint(f model.Flow) key {
	h := sha256.New()
	putString(h, f.Exporter)
	putString(h, f.Protocol)
	put32(h, f.ObsDomain)
	put32(h, f.Sequence)
	putString(h, f.SrcIP)
	putString(h, f.DstIP)
	put16(h, f.SrcPort)
	put16(h, f.DstPort)
	_, _ = h.Write([]byte{f.IPProtocol})
	put64(h, f.Packets)
	put64(h, f.Bytes)
	put32(h, f.IngressIf)
	put32(h, f.EgressIf)
	put16(h, f.VLAN)
	put64(h, uint64(f.StartTime.UnixNano()))
	put64(h, uint64(f.EndTime.UnixNano()))
	sum := h.Sum(nil)
	var k key
	copy(k[:], sum[:16])
	return k
}

func FingerprintHex(f model.Flow) string {
	k := fingerprint(f)
	const hexchars = "0123456789abcdef"
	b := make([]byte, len(k)*2)
	for i, v := range k {
		b[i*2] = hexchars[v>>4]
		b[i*2+1] = hexchars[v&0x0f]
	}
	return string(b)
}

// Accept returns false if the normalized flow was observed inside the configured
// duplicate window. The map is bounded; oldest/expired entries are swept before
// emergency eviction is used.
func (d *Detector) Accept(f model.Flow, now time.Time) bool {
	k := fingerprint(f)
	n := now.UnixNano()
	cutoff := n - d.window.Nanoseconds()
	d.mu.Lock()
	defer d.mu.Unlock()
	if ts, ok := d.seen[k]; ok && ts >= cutoff {
		d.duplicates.Add(1)
		return false
	}
	d.seen[k] = n
	d.accepted.Add(1)
	if n >= d.sweepAt {
		d.sweepAt = n + max(d.window/4, time.Second).Nanoseconds()
		for kk, ts := range d.seen {
			if ts < cutoff {
				delete(d.seen, kk)
				d.evicted.Add(1)
			}
		}
	}
	// Capacity pressure must not trigger a full-map expiry sweep for every new
	// unique flow. Once the map is at its hard bound, evict only the number of
	// entries required to restore the bound; scheduled expiry sweeps remain
	// governed by sweepAt above.
	for len(d.seen) > d.max {
		for kk := range d.seen {
			delete(d.seen, kk)
			d.evicted.Add(1)
			break
		}
	}
	return true
}

func (d *Detector) Stats() Stats {
	d.mu.Lock()
	n := len(d.seen)
	d.mu.Unlock()
	return Stats{Enabled: true, WindowMS: d.window.Milliseconds(), Entries: n, Accepted: d.accepted.Load(), Duplicates: d.duplicates.Load(), Evicted: d.evicted.Load()}
}
