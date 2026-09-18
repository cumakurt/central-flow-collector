package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// SyncWebBind reconciles the persisted portal override after an installer has
// selected web.bind in YAML. Normal startup never rewrites explicit settings.
// Run with the data directory owner's identity, or restore file ownership after
// installation. Environment overrides retain their usual runtime precedence.
func SyncWebBind(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	c := Default()
	if err := parseYAMLSubset(string(b), &c); err != nil {
		return err
	}
	p := AdminOverridePath(c.Storage.DataDir)
	b, err = os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	// Preserve unknown fields and secrets, including fields introduced by newer
	// versions. Only the bind field is changed.
	var sections map[string]json.RawMessage
	if err := json.Unmarshal(b, &sections); err != nil {
		return fmt.Errorf("admin settings: %w", err)
	}
	var web map[string]json.RawMessage
	if raw, ok := sections["web"]; ok {
		if err := json.Unmarshal(raw, &web); err != nil {
			return fmt.Errorf("admin web settings: %w", err)
		}
	}
	if web == nil {
		return nil
	}
	var bind string
	if err := json.Unmarshal(web["bind"], &bind); err == nil && bind == c.Web.Bind {
		return nil
	}
	web["bind"], err = json.Marshal(c.Web.Bind)
	if err != nil {
		return err
	}
	sections["web"], err = json.Marshal(web)
	if err != nil {
		return err
	}
	updated, err := json.MarshalIndent(sections, "", "  ")
	if err != nil {
		return err
	}
	// Keep a private backup before atomically replacing the overlay. Unique
	// filenames avoid following a pre-existing temporary-file symlink.
	backup, err := writePrivateTemp(p+".backup-", b)
	if err != nil {
		return err
	}
	tmp, err := writePrivateTemp(p+".tmp-", append(updated, '\n'))
	if err != nil {
		return fmt.Errorf("backup saved to %s: %w", backup, err)
	}
	defer os.Remove(tmp)
	return os.Rename(tmp, p)
}

func writePrivateTemp(pattern string, b []byte) (string, error) {
	f, err := os.CreateTemp(filepath.Dir(pattern), filepath.Base(pattern))
	if err != nil {
		return "", err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
