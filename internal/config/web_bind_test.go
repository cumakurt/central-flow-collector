package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyncWebBind(t *testing.T) {
	for _, bind := range []string{"0.0.0.0", "127.0.0.1", "192.0.2.10", "::"} {
		t.Run(bind, func(t *testing.T) {
			t.Setenv("FLOWCOLLECTOR_WEB_BIND", "")
			dir := t.TempDir()
			p := filepath.Join(dir, "config.yaml")
			body := "web:\n  bind: \"" + bind + "\"\nstorage:\n  data_dir: \"" + filepath.ToSlash(dir) + "\"\n"
			if err := os.WriteFile(p, []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
			override := `{"web":{"bind":"localhost","port":8181,"tls":false,"future":"preserved"},"notifications":{"smtp_password":"keep-secret"},"future_section":{"key":123}}`
			op := AdminOverridePath(dir)
			if err := os.WriteFile(op, []byte(override), 0600); err != nil {
				t.Fatal(err)
			}
			if err := SyncWebBind(p); err != nil {
				t.Fatal(err)
			}
			c, err := Load(p)
			if err != nil {
				t.Fatal(err)
			}
			if c.Web.Bind != bind || c.Web.Port != 8181 || c.Notifications.SMTPPassword != "keep-secret" {
				t.Fatalf("unexpected effective web settings: %+v", c.Web)
			}
			b, err := os.ReadFile(op)
			if err != nil {
				t.Fatal(err)
			}
			var got, want map[string]any
			if err := json.Unmarshal(b, &got); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal([]byte(override), &want); err != nil {
				t.Fatal(err)
			}
			want["web"].(map[string]any)["bind"] = bind
			g, _ := json.Marshal(got)
			w, _ := json.Marshal(want)
			if string(g) != string(w) {
				t.Fatal("unrelated overlay settings changed")
			}
			backups, _ := filepath.Glob(op + ".backup-*")
			if len(backups) != 1 {
				t.Fatalf("backups: %v", backups)
			}
			original, err := os.ReadFile(backups[0])
			if err != nil || string(original) != override {
				t.Fatal("backup did not preserve original")
			}
			if err := SyncWebBind(p); err != nil {
				t.Fatal(err)
			}
			backups, _ = filepath.Glob(op + ".backup-*")
			if len(backups) != 1 {
				t.Fatal("unchanged overlay should not be rewritten")
			}
			t.Setenv("FLOWCOLLECTOR_WEB_BIND", "127.0.0.2")
			c, err = Load(p)
			if err != nil || c.Web.Bind != "127.0.0.2" {
				t.Fatal("environment precedence changed")
			}
		})
	}
}

func TestSyncWebBindNoOverlayOrInvalidOverlay(t *testing.T) {
	for _, overlay := range []string{"", "{}", `{"web":null}`, "invalid"} {
		t.Run(overlay, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, "config.yaml")
			if err := os.WriteFile(p, []byte("storage:\n  data_dir: \""+filepath.ToSlash(dir)+"\"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			op := AdminOverridePath(dir)
			if overlay != "" {
				if err := os.WriteFile(op, []byte(overlay), 0600); err != nil {
					t.Fatal(err)
				}
			}
			err := SyncWebBind(p)
			if (err != nil) != (overlay == "invalid") {
				t.Fatalf("unexpected error: %v", err)
			}
			b, err := os.ReadFile(op)
			if overlay == "" && !os.IsNotExist(err) {
				t.Fatal("unexpected overlay created")
			}
			if string(b) != overlay {
				t.Fatal("overlay changed")
			}
			files, _ := os.ReadDir(dir)
			for _, file := range files {
				if strings.Contains(file.Name(), ".backup-") {
					t.Fatal("unnecessary backup")
				}
			}
		})
	}
}
