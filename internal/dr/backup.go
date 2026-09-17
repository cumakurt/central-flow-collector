package dr

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type ManifestEntry struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
}
type Manifest struct {
	Format        int             `json:"format"`
	CreatedAt     time.Time       `json:"created_at"`
	ConfigSource  string          `json:"config_source"`
	DataSource    string          `json:"data_source"`
	IncludesFlows bool            `json:"includes_flows"`
	Entries       []ManifestEntry `json:"entries"`
}
type VerifyResult struct {
	Valid         bool      `json:"valid"`
	Entries       int       `json:"entries"`
	IncludesFlows bool      `json:"includes_flows"`
	CreatedAt     time.Time `json:"created_at"`
	Errors        []string  `json:"errors,omitempty"`
}
type CheckItem struct {
	Path      string `json:"path"`
	Exists    bool   `json:"exists"`
	Readable  bool   `json:"readable"`
	Writable  bool   `json:"writable"`
	JSONValid *bool  `json:"json_valid,omitempty"`
	Error     string `json:"error,omitempty"`
}
type CheckReport struct {
	Healthy bool        `json:"healthy"`
	DataDir string      `json:"data_dir"`
	Items   []CheckItem `json:"items"`
}

type fileItem struct {
	src, name string
	info      fs.FileInfo
	hash      string
}

func safeArchiveName(n string) bool {
	n = filepath.ToSlash(n)
	return n != "" && !strings.HasPrefix(n, "/") && !strings.HasPrefix(n, "../") && !strings.Contains(n, "/../") && n != ".."
}
func hashFile(path string) (string, int64, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", 0, e
	}
	defer f.Close()
	h := sha256.New()
	n, e := io.Copy(h, f)
	if e != nil {
		return "", 0, e
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func Create(configPath, dataDir, out string, includeFlows bool) (Manifest, error) {
	if strings.TrimSpace(out) == "" {
		return Manifest{}, errors.New("backup output path is required")
	}
	var items []fileItem
	add := func(src, name string, info fs.FileInfo) error {
		if !safeArchiveName(name) {
			return fmt.Errorf("unsafe archive path %q", name)
		}
		h, _, e := hashFile(src)
		if e != nil {
			return e
		}
		items = append(items, fileItem{src: src, name: filepath.ToSlash(name), info: info, hash: h})
		return nil
	}
	ci, e := os.Stat(configPath)
	if e != nil {
		return Manifest{}, fmt.Errorf("config: %w", e)
	}
	if !ci.Mode().IsRegular() {
		return Manifest{}, errors.New("config is not a regular file")
	}
	if e = add(configPath, "config/config.yaml", ci); e != nil {
		return Manifest{}, e
	}
	e = filepath.WalkDir(dataDir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, er := filepath.Rel(dataDir, path)
		if er != nil {
			return er
		}
		if rel == "." {
			return nil
		}
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			// Backups live under dataDir for the web administration center. Never
			// recursively include prior backup archives in a new backup.
			if rel == "backups" {
				return filepath.SkipDir
			}
			if rel == "flows" && !includeFlows {
				return filepath.SkipDir
			}
			return nil
		}
		if rel == "bootstrap-admin.txt" || strings.HasPrefix(filepath.Base(rel), ".write-probe-") {
			return nil
		}
		info, er := d.Info()
		if er != nil {
			return er
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		return add(path, "data/"+rel, info)
	})
	if e != nil {
		return Manifest{}, e
	}
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
	m := Manifest{Format: 1, CreatedAt: time.Now().UTC(), ConfigSource: configPath, DataSource: dataDir, IncludesFlows: includeFlows, Entries: make([]ManifestEntry, 0, len(items))}
	for _, x := range items {
		m.Entries = append(m.Entries, ManifestEntry{Path: x.name, SHA256: x.hash, Size: x.info.Size(), Mode: uint32(x.info.Mode().Perm())})
	}
	if e = os.MkdirAll(filepath.Dir(out), 0750); e != nil {
		return Manifest{}, e
	}
	tmp := out + ".tmp"
	f, e := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if e != nil {
		return Manifest{}, e
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	failed := true
	defer func() {
		if failed {
			_ = tw.Close()
			_ = gz.Close()
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	for _, x := range items {
		h := &tar.Header{Name: x.name, Mode: int64(x.info.Mode().Perm()), Size: x.info.Size(), ModTime: x.info.ModTime(), Typeflag: tar.TypeReg}
		if e = tw.WriteHeader(h); e != nil {
			return Manifest{}, e
		}
		sf, er := os.Open(x.src)
		if er != nil {
			return Manifest{}, er
		}
		_, er = io.Copy(tw, sf)
		_ = sf.Close()
		if er != nil {
			return Manifest{}, er
		}
	}
	mb, _ := json.MarshalIndent(m, "", "  ")
	mb = append(mb, '\n')
	if e = tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(mb)), ModTime: time.Now(), Typeflag: tar.TypeReg}); e != nil {
		return Manifest{}, e
	}
	if _, e = tw.Write(mb); e != nil {
		return Manifest{}, e
	}
	if e = tw.Close(); e != nil {
		return Manifest{}, e
	}
	if e = gz.Close(); e != nil {
		return Manifest{}, e
	}
	if e = f.Sync(); e != nil {
		return Manifest{}, e
	}
	if e = f.Close(); e != nil {
		return Manifest{}, e
	}
	if e = os.Chmod(tmp, 0600); e != nil {
		return Manifest{}, e
	}
	if e = os.Rename(tmp, out); e != nil {
		return Manifest{}, e
	}
	failed = false
	return m, nil
}

func scanArchive(path string, captureManifest bool) (Manifest, map[string]string, error) {
	f, e := os.Open(path)
	if e != nil {
		return Manifest{}, nil, e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return Manifest{}, nil, e
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	hashes := map[string]string{}
	var m Manifest
	haveManifest := false
	for {
		h, e := tr.Next()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return m, nil, e
		}
		if h.Typeflag != tar.TypeReg {
			return m, nil, fmt.Errorf("unsupported archive entry %q", h.Name)
		}
		if !safeArchiveName(h.Name) {
			return m, nil, fmt.Errorf("unsafe archive entry %q", h.Name)
		}
		if h.Size < 0 {
			return m, nil, fmt.Errorf("invalid archive size for %q", h.Name)
		}
		if h.Name == "manifest.json" {
			if h.Size > 16<<20 {
				return m, nil, errors.New("backup manifest is unreasonably large")
			}
			b, er := io.ReadAll(io.LimitReader(tr, h.Size+1))
			if er != nil {
				return m, nil, er
			}
			if int64(len(b)) != h.Size {
				return m, nil, fmt.Errorf("short archive entry %q", h.Name)
			}
			if captureManifest {
				if er = json.Unmarshal(b, &m); er != nil {
					return m, nil, er
				}
			}
			haveManifest = true
			continue
		}
		hash := sha256.New()
		n, er := io.CopyN(hash, tr, h.Size)
		if er != nil {
			return m, nil, er
		}
		if n != h.Size {
			return m, nil, fmt.Errorf("short archive entry %q", h.Name)
		}
		hashes[h.Name] = hex.EncodeToString(hash.Sum(nil))
	}
	if !haveManifest {
		return m, nil, errors.New("backup manifest is missing")
	}
	return m, hashes, nil
}
func Verify(path string) (VerifyResult, error) {
	m, h, e := scanArchive(path, true)
	if e != nil {
		return VerifyResult{Valid: false, Errors: []string{e.Error()}}, e
	}
	r := VerifyResult{Valid: true, Entries: len(m.Entries), IncludesFlows: m.IncludesFlows, CreatedAt: m.CreatedAt}
	seen := map[string]bool{}
	for _, x := range m.Entries {
		seen[x.Path] = true
		if h[x.Path] == "" {
			r.Valid = false
			r.Errors = append(r.Errors, "missing: "+x.Path)
		} else if h[x.Path] != x.SHA256 {
			r.Valid = false
			r.Errors = append(r.Errors, "checksum mismatch: "+x.Path)
		}
	}
	for n := range h {
		if !seen[n] {
			r.Valid = false
			r.Errors = append(r.Errors, "unexpected: "+n)
		}
	}
	if !r.Valid {
		return r, errors.New("backup integrity verification failed")
	}
	return r, nil
}

func Restore(archive, configPath, dataDir string, force bool) error {
	if !force {
		return errors.New("restore requires --force; stop the flowcollector service before restoring")
	}
	vr, e := Verify(archive)
	if e != nil || !vr.Valid {
		return errors.New("backup verification failed")
	}
	m, _, e := scanArchive(archive, true)
	if e != nil {
		return e
	}
	entries := map[string]ManifestEntry{}
	for _, x := range m.Entries {
		entries[x.Path] = x
	}
	st, e := os.Stat(dataDir)
	if e != nil {
		return fmt.Errorf("data directory must exist before restore: %w", e)
	}
	uid, gid := ownerIDs(st)
	stamp := time.Now().UTC().Format("20060102T150405Z")
	if _, e := os.Stat(configPath); e == nil {
		_ = copyFile(configPath, configPath+".pre-restore."+stamp, 0600)
	}
	f, e := os.Open(archive)
	if e != nil {
		return e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return e
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, e := tr.Next()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return e
		}
		if h.Name == "manifest.json" {
			continue
		}
		want, ok := entries[h.Name]
		if !ok {
			return fmt.Errorf("unexpected archive entry %q", h.Name)
		}
		if !safeArchiveName(h.Name) {
			return fmt.Errorf("unsafe archive entry %q", h.Name)
		}
		var target string
		if h.Name == "config/config.yaml" {
			target = configPath
		} else if strings.HasPrefix(h.Name, "data/") {
			rel := strings.TrimPrefix(h.Name, "data/")
			if !safeArchiveName(rel) {
				return fmt.Errorf("unsafe data entry %q", h.Name)
			}
			target = filepath.Join(dataDir, filepath.FromSlash(rel))
			clean := filepath.Clean(target)
			root := filepath.Clean(dataDir) + string(os.PathSeparator)
			if clean != filepath.Clean(dataDir) && !strings.HasPrefix(clean, root) {
				return fmt.Errorf("restore path escapes data directory: %q", h.Name)
			}
		} else {
			continue
		}
		if h.Size != want.Size {
			return fmt.Errorf("size mismatch for %s", h.Name)
		}
		if e = os.MkdirAll(filepath.Dir(target), 0750); e != nil {
			return e
		}
		mode := fs.FileMode(want.Mode)
		if mode == 0 {
			mode = 0640
		}
		tmp := target + ".restore-tmp"
		out, e := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode.Perm())
		if e != nil {
			return e
		}
		hash := sha256.New()
		n, cpErr := io.CopyN(io.MultiWriter(out, hash), tr, h.Size)
		closeErr := out.Close()
		if cpErr != nil {
			return cpErr
		}
		if closeErr != nil {
			return closeErr
		}
		if n != h.Size {
			return fmt.Errorf("short archive entry %q", h.Name)
		}
		if hex.EncodeToString(hash.Sum(nil)) != want.SHA256 {
			_ = os.Remove(tmp)
			return fmt.Errorf("checksum mismatch during restore: %s", h.Name)
		}
		if strings.HasPrefix(h.Name, "data/") && uid >= 0 {
			_ = os.Chown(tmp, uid, gid)
		}
		if e = os.Rename(tmp, target); e != nil {
			return e
		}
	}
	return nil
}

// RestoreDataOnly verifies and restores only data/* entries from a metadata
// archive. It intentionally leaves the base /etc configuration untouched so
// it can run safely under the hardened service account (ProtectSystem=strict,
// /etc/flowcollector read-only). Portal-managed admin-settings.json is part of
// dataDir and is therefore restored and becomes effective after config reload.
func RestoreDataOnly(archive, dataDir string, force bool) error {
	if !force {
		return errors.New("data-only restore requires force")
	}
	vr, e := Verify(archive)
	if e != nil || !vr.Valid {
		return errors.New("backup verification failed")
	}
	m, _, e := scanArchive(archive, true)
	if e != nil {
		return e
	}
	entries := map[string]ManifestEntry{}
	for _, x := range m.Entries {
		entries[x.Path] = x
	}
	st, e := os.Stat(dataDir)
	if e != nil {
		return fmt.Errorf("data directory must exist before restore: %w", e)
	}
	uid, gid := ownerIDs(st)
	f, e := os.Open(archive)
	if e != nil {
		return e
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return e
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, e := tr.Next()
		if errors.Is(e, io.EOF) {
			break
		}
		if e != nil {
			return e
		}
		if h.Name == "manifest.json" || h.Name == "config/config.yaml" {
			continue
		}
		if !strings.HasPrefix(h.Name, "data/") {
			continue
		}
		want, ok := entries[h.Name]
		if !ok {
			return fmt.Errorf("unexpected archive entry %q", h.Name)
		}
		rel := strings.TrimPrefix(h.Name, "data/")
		if !safeArchiveName(rel) {
			return fmt.Errorf("unsafe data entry %q", h.Name)
		}
		target := filepath.Join(dataDir, filepath.FromSlash(rel))
		clean := filepath.Clean(target)
		root := filepath.Clean(dataDir) + string(os.PathSeparator)
		if clean != filepath.Clean(dataDir) && !strings.HasPrefix(clean, root) {
			return fmt.Errorf("restore path escapes data directory: %q", h.Name)
		}
		if h.Size != want.Size {
			return fmt.Errorf("size mismatch for %s", h.Name)
		}
		if e = os.MkdirAll(filepath.Dir(target), 0750); e != nil {
			return e
		}
		mode := fs.FileMode(want.Mode)
		if mode == 0 {
			mode = 0640
		}
		tmp := target + ".restore-tmp"
		out, e := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode.Perm())
		if e != nil {
			return e
		}
		hash := sha256.New()
		n, cpErr := io.CopyN(io.MultiWriter(out, hash), tr, h.Size)
		closeErr := out.Close()
		if cpErr != nil {
			_ = os.Remove(tmp)
			return cpErr
		}
		if closeErr != nil {
			_ = os.Remove(tmp)
			return closeErr
		}
		if n != h.Size {
			_ = os.Remove(tmp)
			return fmt.Errorf("short archive entry %q", h.Name)
		}
		if hex.EncodeToString(hash.Sum(nil)) != want.SHA256 {
			_ = os.Remove(tmp)
			return fmt.Errorf("checksum mismatch during restore: %s", h.Name)
		}
		if uid >= 0 {
			_ = os.Chown(tmp, uid, gid)
		}
		if e = os.Rename(tmp, target); e != nil {
			_ = os.Remove(tmp)
			return e
		}
	}
	return nil
}

func copyFile(src, dst string, mode fs.FileMode) error {
	in, e := os.Open(src)
	if e != nil {
		return e
	}
	defer in.Close()
	out, e := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	_, e = io.Copy(out, in)
	if e2 := out.Close(); e == nil {
		e = e2
	}
	return e
}

func Check(dataDir string) CheckReport {
	r := CheckReport{Healthy: true, DataDir: dataDir}
	paths := []string{"users.json", "policies.json", "workspace.json", "alert-rules.json", "api-tokens.json", "storage-settings.json", "sites.json", "admin-settings.json", "admin-config-history.json", "notification-state.json", "notification-key", "routing-prefixes.json"}
	for _, n := range paths {
		p := filepath.Join(dataDir, n)
		it := CheckItem{Path: p}
		st, e := os.Stat(p)
		if os.IsNotExist(e) {
			r.Items = append(r.Items, it)
			continue
		}
		if e != nil {
			it.Error = e.Error()
			r.Healthy = false
			r.Items = append(r.Items, it)
			continue
		}
		it.Exists = true
		if !st.Mode().IsRegular() {
			it.Error = "not a regular file"
			r.Healthy = false
			r.Items = append(r.Items, it)
			continue
		}
		if f, e := os.Open(p); e == nil {
			it.Readable = true
			_ = f.Close()
		} else {
			it.Error = e.Error()
			r.Healthy = false
		}
		if f, e := os.OpenFile(p, os.O_WRONLY|os.O_APPEND, 0); e == nil {
			it.Writable = true
			_ = f.Close()
		} else {
			if it.Error == "" {
				it.Error = e.Error()
			}
			r.Healthy = false
		}
		if strings.HasSuffix(n, ".json") {
			b, e := os.ReadFile(p)
			valid := e == nil && json.Valid(b)
			it.JSONValid = &valid
			if !valid {
				r.Healthy = false
				if e != nil {
					it.Error = e.Error()
				} else {
					it.Error = "invalid JSON"
				}
			}
		}
		r.Items = append(r.Items, it)
	}
	return r
}
