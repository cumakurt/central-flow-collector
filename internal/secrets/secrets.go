package secrets

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"central-flow-collector/internal/config"
)

// Resolve expands a secret reference while preserving backward compatibility
// with literal values. Supported forms are @env:NAME and @file:/absolute/path.
// File references are trimmed and capped to 64 KiB to avoid accidentally
// loading arbitrary large files into process memory.
func Resolve(v string) (string, error) {
	if strings.HasPrefix(v, "@env:") {
		name := strings.TrimSpace(strings.TrimPrefix(v, "@env:"))
		if name == "" {
			return "", errors.New("empty secret environment variable name")
		}
		x, ok := os.LookupEnv(name)
		if !ok {
			return "", fmt.Errorf("secret environment variable %s is not set", name)
		}
		return x, nil
	}
	if strings.HasPrefix(v, "@file:") {
		path := strings.TrimSpace(strings.TrimPrefix(v, "@file:"))
		if path == "" {
			return "", errors.New("empty secret file path")
		}
		f, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer f.Close()
		st, err := f.Stat()
		if err != nil {
			return "", err
		}
		if st.Size() > 64<<10 {
			return "", fmt.Errorf("secret file %s exceeds 64KiB", path)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	return v, nil
}

// Apply resolves every sensitive configuration value in memory. The original
// configuration file is never rewritten with resolved secret material.
func Apply(c *config.Config) error {
	if c == nil {
		return errors.New("nil config")
	}
	fields := []struct {
		name string
		p    *string
	}{
		{"storage.clickhouse_password", &c.Storage.ClickHousePassword},
		{"oidc.client_secret", &c.OIDC.ClientSecret},
		{"ldap.bind_password", &c.LDAP.BindPassword},
		{"notifications.webhook_secret", &c.Notifications.WebhookSecret},
		{"notifications.telegram_bot_token", &c.Notifications.TelegramBotToken},
		{"notifications.smtp_password", &c.Notifications.SMTPPassword},
	}
	for _, f := range fields {
		x, err := Resolve(*f.p)
		if err != nil {
			return fmt.Errorf("resolve %s: %w", f.name, err)
		}
		*f.p = x
	}
	return nil
}
