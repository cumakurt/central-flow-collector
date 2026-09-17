package enrichment

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"central-flow-collector/internal/model"
)

// PrefixRecord is an offline GeoIP/ASN record. Data is supplied by the operator
// and is intentionally not downloaded by the collector at runtime.
type PrefixRecord struct {
	CIDR    string `json:"cidr"`
	Country string `json:"country,omitempty"`
	ASN     uint32 `json:"asn,omitempty"`
	ASName  string `json:"as_name,omitempty"`
	Region  string `json:"region,omitempty"`
	City    string `json:"city,omitempty"`
	prefix  netip.Prefix
}

type Site struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	CIDR        string   `json:"cidr"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	prefix      netip.Prefix
}

type Status struct {
	Enabled       bool      `json:"enabled"`
	PrefixFile    string    `json:"prefix_file,omitempty"`
	Prefixes      int       `json:"prefixes"`
	Sites         int       `json:"sites"`
	Lookups       uint64    `json:"lookups"`
	PrefixHits    uint64    `json:"prefix_hits"`
	SiteHits      uint64    `json:"site_hits"`
	InvalidIPs    uint64    `json:"invalid_ips"`
	LastReload    time.Time `json:"last_reload,omitempty"`
	LastError     string    `json:"last_error,omitempty"`
	Provenance    string    `json:"provenance"`
	RemoteEnabled bool      `json:"remote_enabled"`
	RemoteError   string    `json:"remote_error,omitempty"`
	CachedIPs     int       `json:"cached_ips"`
}

type Engine struct {
	mu              sync.RWMutex
	enabled         bool
	prefixFile      string
	sitesFile       string
	prefixes        []PrefixRecord
	sites           []Site
	lastReload      time.Time
	lastError       string
	lookups         atomic.Uint64
	prefixHits      atomic.Uint64
	siteHits        atomic.Uint64
	invalidIPs      atomic.Uint64
	remoteEnabled   bool
	remoteURL       string
	remoteClient    *http.Client
	remoteMu        sync.Mutex
	remoteCache     map[string]remoteEntry
	remoteBusy      bool
	remoteScheduled bool
	remoteError     string
	remoteNext      time.Time
	remoteDay       time.Time
	remoteRequests  int
}

type remoteEntry struct {
	info    GeoInfo
	expires time.Time
}

func New(dataDir string, enabled bool, prefixFile string) (*Engine, error) {
	e := &Engine{enabled: enabled, prefixFile: strings.TrimSpace(prefixFile), sitesFile: filepath.Join(dataDir, "sites.json"), remoteEnabled: false, remoteURL: "https://ipwho.is", remoteClient: &http.Client{Timeout: 2 * time.Second}, remoteCache: map[string]remoteEntry{}}
	if err := e.reloadLocked(); err != nil {
		return nil, err
	}
	return e, nil
}

// NewWithRemote enables the free ipwho.is fallback for public IPs not found in
// the local CIDR file. Local records always take precedence.
func NewWithRemote(dataDir string, enabled bool, prefixFile string, remoteEnabled bool, remoteURL string) (*Engine, error) {
	e, err := New(dataDir, enabled, prefixFile)
	if err != nil {
		return nil, err
	}
	e.remoteEnabled = remoteEnabled && enabled
	if strings.TrimSpace(remoteURL) != "" {
		e.remoteURL = strings.TrimRight(strings.TrimSpace(remoteURL), "/")
	}
	return e, nil
}

func parsePrefix(cidr string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(cidr))
	if err != nil {
		return netip.Prefix{}, err
	}
	return p.Masked(), nil
}

func (e *Engine) reloadLocked() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	var prefixes []PrefixRecord
	if e.enabled && e.prefixFile != "" {
		f, err := os.Open(e.prefixFile)
		if err != nil {
			if !os.IsNotExist(err) {
				e.lastError = err.Error()
				return fmt.Errorf("open enrichment prefix file: %w", err)
			}
		} else {
			r := csv.NewReader(bufio.NewReaderSize(f, 256*1024))
			r.TrimLeadingSpace = true
			r.FieldsPerRecord = -1
			line := 0
			for {
				rec, err := r.Read()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					_ = f.Close()
					e.lastError = fmt.Sprintf("CSV line %d: %v", line+1, err)
					return errors.New(e.lastError)
				}
				line++
				if len(rec) == 0 {
					continue
				}
				first := strings.TrimSpace(rec[0])
				if first == "" || strings.HasPrefix(first, "#") || strings.EqualFold(first, "cidr") {
					continue
				}
				if len(rec) < 2 {
					_ = f.Close()
					return fmt.Errorf("enrichment CSV line %d requires at least cidr,country", line)
				}
				p, err := parsePrefix(first)
				if err != nil {
					_ = f.Close()
					return fmt.Errorf("enrichment CSV line %d invalid CIDR %q: %w", line, first, err)
				}
				x := PrefixRecord{CIDR: p.String(), Country: strings.ToUpper(strings.TrimSpace(rec[1])), prefix: p}
				if len(rec) > 2 && strings.TrimSpace(rec[2]) != "" {
					n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToUpper(strings.TrimSpace(rec[2])), "AS"), 10, 32)
					if err != nil {
						_ = f.Close()
						return fmt.Errorf("enrichment CSV line %d invalid ASN: %w", line, err)
					}
					x.ASN = uint32(n)
				}
				if len(rec) > 3 {
					x.ASName = strings.TrimSpace(rec[3])
				}
				if len(rec) > 4 {
					x.Region = strings.TrimSpace(rec[4])
				}
				if len(rec) > 5 {
					x.City = strings.TrimSpace(rec[5])
				}
				prefixes = append(prefixes, x)
			}
			_ = f.Close()
		}
	}
	sort.Slice(prefixes, func(i, j int) bool { return prefixes[i].prefix.Bits() > prefixes[j].prefix.Bits() })

	var sites []Site
	if b, err := os.ReadFile(e.sitesFile); err == nil {
		if err := json.Unmarshal(b, &sites); err != nil {
			e.lastError = "parse sites.json: " + err.Error()
			return errors.New(e.lastError)
		}
		for i := range sites {
			p, err := parsePrefix(sites[i].CIDR)
			if err != nil {
				e.lastError = fmt.Sprintf("site %q invalid CIDR: %v", sites[i].ID, err)
				return errors.New(e.lastError)
			}
			sites[i].CIDR = p.String()
			sites[i].prefix = p
		}
	} else if !os.IsNotExist(err) {
		e.lastError = err.Error()
		return err
	}
	sort.Slice(sites, func(i, j int) bool { return sites[i].prefix.Bits() > sites[j].prefix.Bits() })

	e.prefixes = prefixes
	e.sites = sites
	e.lastReload = time.Now().UTC()
	e.lastError = ""
	return nil
}

func (e *Engine) Reload() error { return e.reloadLocked() }

type GeoInfo struct {
	IP      string `json:"ip"`
	Country string `json:"country,omitempty"`
	Region  string `json:"region,omitempty"`
	City    string `json:"city,omitempty"`
	ASN     uint32 `json:"asn,omitempty"`
	ASName  string `json:"as_name,omitempty"`
	Site    string `json:"site,omitempty"`
	Private bool   `json:"private"`
}

func (e *Engine) LookupIP(ip string) GeoInfo {
	out := GeoInfo{IP: ip}
	if addr, err := netip.ParseAddr(ip); err == nil {
		out.Private = addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
	}
	p, site, matched, siteMatched := e.lookup(ip)
	if matched {
		out.Country, out.Region, out.City, out.ASN, out.ASName = p.Country, p.Region, p.City, p.ASN, p.ASName
	}
	if siteMatched {
		out.Site = site.Name
	}
	if !matched && !out.Private && e.remoteEnabled {
		if remote, ok := e.remoteLookup(ip); ok {
			remote.Site = out.Site
			return remote
		}
	}
	return out
}

func publicIP(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || a.IsLoopback() || a.IsLinkLocalUnicast() {
		return false
	}
	for _, cidr := range []string{"100.64.0.0/10", "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "198.18.0.0/15", "240.0.0.0/4", "2001:db8::/32"} {
		if netip.MustParsePrefix(cidr).Contains(a) {
			return false
		}
	}
	return true
}

func (e *Engine) remoteLookup(ip string) (GeoInfo, bool) {
	if !e.remoteEnabled || !publicIP(ip) {
		return GeoInfo{}, false
	}
	e.remoteMu.Lock()
	if x, ok := e.remoteCache[ip]; ok && time.Now().Before(x.expires) {
		e.remoteMu.Unlock()
		return x.info, x.info.Country != ""
	}
	if time.Since(e.remoteDay) >= 24*time.Hour {
		e.remoteDay = time.Now()
		e.remoteRequests = 0
	}
	if e.remoteBusy || time.Now().Before(e.remoteNext) || e.remoteRequests >= 1000 {
		e.remoteMu.Unlock()
		return GeoInfo{}, false
	}
	e.remoteBusy = true
	e.remoteRequests++
	e.remoteNext = time.Now().Add(time.Second)
	e.remoteMu.Unlock()
	var lookupErr error
	defer func() {
		e.remoteMu.Lock()
		e.remoteBusy = false
		if lookupErr != nil {
			e.remoteError = lookupErr.Error()
			if len(e.remoteCache) >= 4096 {
				for k := range e.remoteCache {
					delete(e.remoteCache, k)
					break
				}
			}
			e.remoteCache[ip] = remoteEntry{expires: time.Now().Add(5 * time.Minute)}
		}
		e.remoteMu.Unlock()
	}()
	resp, err := e.remoteClient.Get(e.remoteURL + "/" + ip)
	if err != nil {
		lookupErr = err
		return GeoInfo{}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		lookupErr = fmt.Errorf("Location service returned HTTP %d", resp.StatusCode)
		if resp.StatusCode == 429 {
			e.remoteMu.Lock()
			e.remoteNext = time.Now().Add(24 * time.Hour)
			e.remoteMu.Unlock()
		}
		return GeoInfo{}, false
	}
	var x struct {
		Success    bool   `json:"success"`
		Message    string `json:"message"`
		Country    string `json:"country_code"`
		Region     string `json:"region"`
		City       string `json:"city"`
		Connection struct {
			ASN uint32 `json:"asn"`
			Org string `json:"org"`
		} `json:"connection"`
	}
	if err = json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&x); err != nil {
		lookupErr = err
		return GeoInfo{}, false
	}
	if !x.Success || len(x.Country) != 2 {
		lookupErr = fmt.Errorf("Location lookup unavailable: %s", x.Message)
		return GeoInfo{}, false
	}
	info := GeoInfo{IP: ip, Country: strings.ToUpper(x.Country), Region: x.Region, City: x.City, ASN: x.Connection.ASN, ASName: x.Connection.Org}
	e.remoteMu.Lock()
	if len(e.remoteCache) >= 4096 {
		for k := range e.remoteCache {
			delete(e.remoteCache, k)
			break
		}
	}
	e.remoteCache[ip] = remoteEntry{info: info, expires: time.Now().Add(24 * time.Hour)}
	e.remoteError = ""
	e.remoteMu.Unlock()
	return info, true
}

// A single scheduled lookup keeps network latency out of the ingestion path.
func (e *Engine) cachedLocation(ip string) GeoInfo {
	if !e.remoteEnabled || !publicIP(ip) {
		return GeoInfo{}
	}
	e.remoteMu.Lock()
	x, ok := e.remoteCache[ip]
	if ok && time.Now().Before(x.expires) {
		e.remoteMu.Unlock()
		return x.info
	}
	if e.remoteScheduled || e.remoteBusy || time.Now().Before(e.remoteNext) {
		e.remoteMu.Unlock()
		return GeoInfo{}
	}
	e.remoteScheduled = true
	e.remoteMu.Unlock()
	go func() {
		_, _ = e.remoteLookup(ip)
		e.remoteMu.Lock()
		e.remoteScheduled = false
		e.remoteMu.Unlock()
	}()
	return GeoInfo{}
}

func (e *Engine) lookup(ip string) (PrefixRecord, Site, bool, bool) {
	if strings.TrimSpace(ip) == "" {
		return PrefixRecord{}, Site{}, false, false
	}
	e.lookups.Add(1)
	a, err := netip.ParseAddr(ip)
	if err != nil {
		e.invalidIPs.Add(1)
		return PrefixRecord{}, Site{}, false, false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	var pr PrefixRecord
	ph := false
	if e.enabled {
		for _, x := range e.prefixes {
			if x.prefix.Contains(a) {
				pr = x
				ph = true
				e.prefixHits.Add(1)
				break
			}
		}
	}
	var site Site
	sh := false
	for _, x := range e.sites {
		if x.prefix.Contains(a) {
			site = x
			sh = true
			e.siteHits.Add(1)
			break
		}
	}
	return pr, site, ph, sh
}

func ensureCustom(f *model.Flow) {
	if f.Custom == nil {
		f.Custom = map[string]string{}
	}
}

// Enrich fills only information that can be derived from configured offline data.
// Exporter-provided ASN values are preserved and tagged as exporter-provided.
func (e *Engine) Enrich(f *model.Flow) {
	if f == nil {
		return
	}
	src, ss, srcOK, ssOK := e.lookup(f.SrcIP)
	dst, ds, dstOK, dsOK := e.lookup(f.DstIP)
	if !srcOK {
		if x := e.cachedLocation(f.SrcIP); x.Country != "" || x.City != "" || x.ASN != 0 {
			src = PrefixRecord{Country: x.Country, Region: x.Region, City: x.City, ASN: x.ASN, ASName: x.ASName}
			srcOK = true
		}
	}
	if !dstOK {
		if x := e.cachedLocation(f.DstIP); x.Country != "" || x.City != "" || x.ASN != 0 {
			dst = PrefixRecord{Country: x.Country, Region: x.Region, City: x.City, ASN: x.ASN, ASName: x.ASName}
			dstOK = true
		}
	}
	if srcOK {
		f.SrcCountry = src.Country
		f.SrcASName = src.ASName
		if f.SrcAS == 0 && src.ASN != 0 {
			f.SrcAS = src.ASN
			ensureCustom(f)
			f.Custom["src_as_source"] = "enriched"
		} else if f.SrcAS != 0 {
			ensureCustom(f)
			f.Custom["src_as_source"] = "exporter"
		}
		ensureCustom(f)
		f.Custom["src_geo_source"] = "remote_api"
		if _, _, local, _ := e.lookup(f.SrcIP); local {
			f.Custom["src_geo_source"] = "offline_prefix"
		}
		if src.Region != "" {
			f.Custom["src_region"] = src.Region
		}
		if src.City != "" {
			f.Custom["src_city"] = src.City
		}
	}
	if dstOK {
		f.DstCountry = dst.Country
		f.DstASName = dst.ASName
		if f.DstAS == 0 && dst.ASN != 0 {
			f.DstAS = dst.ASN
			ensureCustom(f)
			f.Custom["dst_as_source"] = "enriched"
		} else if f.DstAS != 0 {
			ensureCustom(f)
			f.Custom["dst_as_source"] = "exporter"
		}
		ensureCustom(f)
		f.Custom["dst_geo_source"] = "remote_api"
		if _, _, local, _ := e.lookup(f.DstIP); local {
			f.Custom["dst_geo_source"] = "offline_prefix"
		}
		if dst.Region != "" {
			f.Custom["dst_region"] = dst.Region
		}
		if dst.City != "" {
			f.Custom["dst_city"] = dst.City
		}
	}
	if ssOK {
		f.SrcSite = ss.Name
	}
	if dsOK {
		f.DstSite = ds.Name
	}
}

func (e *Engine) Sites() []Site {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Site, len(e.sites))
	copy(out, e.sites)
	for i := range out {
		out[i].prefix = netip.Prefix{}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func validSiteID(s string) bool {
	if len(s) < 1 || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

func (e *Engine) UpsertSite(s Site) error {
	s.ID = strings.TrimSpace(s.ID)
	s.Name = strings.TrimSpace(s.Name)
	s.CIDR = strings.TrimSpace(s.CIDR)
	if !validSiteID(s.ID) {
		return errors.New("site id must be 1..64 letters, digits, '-' or '_'")
	}
	if s.Name == "" {
		return errors.New("site name required")
	}
	if len(s.Name) > 128 || len(s.Description) > 512 {
		return errors.New("site name/description too long")
	}
	if len(s.Tags) > 20 {
		return errors.New("site supports at most 20 tags")
	}
	for i := range s.Tags {
		s.Tags[i] = strings.TrimSpace(s.Tags[i])
		if len(s.Tags[i]) > 64 {
			return errors.New("site tag too long")
		}
	}
	p, err := parsePrefix(s.CIDR)
	if err != nil {
		return fmt.Errorf("invalid site CIDR: %w", err)
	}
	s.CIDR = p.String()
	s.prefix = p
	e.mu.Lock()
	defer e.mu.Unlock()
	replaced := false
	for i := range e.sites {
		if e.sites[i].ID == s.ID {
			e.sites[i] = s
			replaced = true
			break
		}
	}
	if !replaced {
		e.sites = append(e.sites, s)
	}
	sort.Slice(e.sites, func(i, j int) bool { return e.sites[i].prefix.Bits() > e.sites[j].prefix.Bits() })
	return e.saveSitesLocked()
}

func (e *Engine) DeleteSite(id string) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	found := false
	out := e.sites[:0]
	for _, x := range e.sites {
		if x.ID == id {
			found = true
			continue
		}
		out = append(out, x)
	}
	if !found {
		return errors.New("site not found")
	}
	e.sites = out
	return e.saveSitesLocked()
}

func (e *Engine) saveSitesLocked() error {
	clean := make([]Site, len(e.sites))
	copy(clean, e.sites)
	for i := range clean {
		clean[i].prefix = netip.Prefix{}
	}
	b, err := json.MarshalIndent(clean, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(e.sitesFile), 0750); err != nil {
		return err
	}
	tmp := e.sitesFile + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0640); err != nil {
		return err
	}
	return os.Rename(tmp, e.sitesFile)
}

func (e *Engine) Status() Status {
	e.mu.RLock()
	defer e.mu.RUnlock()
	provenance := "offline operator-supplied CIDR prefix data"
	if e.remoteEnabled {
		provenance += "; public-IP fallback: " + e.remoteURL
	}
	e.remoteMu.Lock()
	defer e.remoteMu.Unlock()
	return Status{RemoteEnabled: e.remoteEnabled, RemoteError: e.remoteError, CachedIPs: len(e.remoteCache), Enabled: e.enabled, PrefixFile: e.prefixFile, Prefixes: len(e.prefixes), Sites: len(e.sites), Lookups: e.lookups.Load(), PrefixHits: e.prefixHits.Load(), SiteHits: e.siteHits.Load(), InvalidIPs: e.invalidIPs.Load(), LastReload: e.lastReload, LastError: e.lastError, Provenance: provenance}
}
