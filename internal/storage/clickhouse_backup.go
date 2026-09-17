package storage

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ClickHouseBackupManifest struct {
	Format    int       `json:"format"`
	CreatedAt time.Time `json:"created_at"`
	Database  string    `json:"database"`
	Table     string    `json:"table"`
	From      time.Time `json:"from,omitempty"`
	To        time.Time `json:"to,omitempty"`
	Rows      uint64    `json:"rows"`
	SHA256    string    `json:"sha256"`
	Archive   string    `json:"archive"`
}

type lineCountWriter struct {
	w    io.Writer
	rows uint64
	prev byte
}

func (x *lineCountWriter) Write(p []byte) (int, error) {
	for _, b := range p {
		if b == '\n' {
			x.rows++
		}
		x.prev = b
	}
	return x.w.Write(p)
}

func (c *ClickHouse) streamDo(ctx context.Context, query string, body io.Reader, extra url.Values) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint(query, extra), body)
	if err != nil {
		return nil, err
	}
	if c.cfg.User != "" {
		req.SetBasicAuth(c.cfg.User, c.cfg.Password)
	}
	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()
		return nil, fmt.Errorf("clickhouse HTTP %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	return resp, nil
}

// LogicalBackup streams ClickHouse JSONEachRow into a gzip archive and writes a
// checksum manifest next to it. It is transportable across ClickHouse hosts and
// does not require server-side backup-disk configuration.
func (c *ClickHouse) LogicalBackup(ctx context.Context, output string, from, to time.Time) (ClickHouseBackupManifest, error) {
	if output == "" {
		return ClickHouseBackupManifest{}, errors.New("backup output is required")
	}
	if !to.IsZero() && !from.IsZero() && to.Before(from) {
		return ClickHouseBackupManifest{}, errors.New("backup end precedes start")
	}
	where := []string{}
	vals := url.Values{}
	if !from.IsZero() {
		where = append(where, "receive_time >= {from:DateTime64(3)}")
		vals.Set("param_from", chTime(from))
	}
	if !to.IsZero() {
		where = append(where, "receive_time <= {to:DateTime64(3)}")
		vals.Set("param_to", chTime(to))
	}
	sql := fmt.Sprintf("SELECT * FROM `%s`.`%s`", c.cfg.Database, c.cfg.Table)
	if len(where) > 0 {
		sql += " WHERE " + strings.Join(where, " AND ")
	}
	sql += " ORDER BY receive_time FORMAT JSONEachRow"
	resp, err := c.streamDo(ctx, sql, nil, vals)
	if err != nil {
		return ClickHouseBackupManifest{}, err
	}
	defer resp.Body.Close()
	if err = os.MkdirAll(filepath.Dir(output), 0750); err != nil {
		return ClickHouseBackupManifest{}, err
	}
	tmp := output + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return ClickHouseBackupManifest{}, err
	}
	ok := false
	defer func() {
		_ = f.Close()
		if !ok {
			_ = os.Remove(tmp)
		}
	}()
	gz := gzip.NewWriter(f)
	lc := &lineCountWriter{w: gz}
	if _, err = io.Copy(lc, resp.Body); err != nil {
		return ClickHouseBackupManifest{}, err
	}
	if err = gz.Close(); err != nil {
		return ClickHouseBackupManifest{}, err
	}
	if err = f.Sync(); err != nil {
		return ClickHouseBackupManifest{}, err
	}
	if err = f.Close(); err != nil {
		return ClickHouseBackupManifest{}, err
	}
	if err = os.Rename(tmp, output); err != nil {
		return ClickHouseBackupManifest{}, err
	}
	ok = true
	sum, err := fileSHA256(output)
	if err != nil {
		return ClickHouseBackupManifest{}, err
	}
	m := ClickHouseBackupManifest{Format: 1, CreatedAt: time.Now().UTC(), Database: c.cfg.Database, Table: c.cfg.Table, From: from, To: to, Rows: lc.rows, SHA256: sum, Archive: filepath.Base(output)}
	mb, _ := json.MarshalIndent(m, "", "  ")
	mb = append(mb, '\n')
	mp := output + ".manifest.json"
	mt := mp + ".tmp"
	if err = os.WriteFile(mt, mb, 0600); err != nil {
		return m, err
	}
	if err = os.Rename(mt, mp); err != nil {
		return m, err
	}
	return m, nil
}
func fileSHA256(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func VerifyClickHouseBackup(path string) (ClickHouseBackupManifest, error) {
	mb, err := os.ReadFile(path + ".manifest.json")
	if err != nil {
		return ClickHouseBackupManifest{}, err
	}
	var m ClickHouseBackupManifest
	if err = json.Unmarshal(mb, &m); err != nil {
		return m, err
	}
	if m.Format != 1 {
		return m, fmt.Errorf("unsupported clickhouse backup format %d", m.Format)
	}
	sum, err := fileSHA256(path)
	if err != nil {
		return m, err
	}
	if sum != m.SHA256 {
		return m, errors.New("clickhouse backup checksum mismatch")
	}
	return m, nil
}
func (c *ClickHouse) LogicalRestore(ctx context.Context, path string, force bool) (ClickHouseBackupManifest, error) {
	if !force {
		return ClickHouseBackupManifest{}, errors.New("clickhouse restore requires --force")
	}
	m, err := VerifyClickHouseBackup(path)
	if err != nil {
		return m, err
	}
	f, err := os.Open(path)
	if err != nil {
		return m, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return m, err
	}
	defer gz.Close()
	q := fmt.Sprintf("INSERT INTO `%s`.`%s` FORMAT JSONEachRow", c.cfg.Database, c.cfg.Table)
	resp, err := c.streamDo(ctx, q, gz, nil)
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return m, nil
}
