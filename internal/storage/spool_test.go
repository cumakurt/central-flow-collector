package storage

import (
	"central-flow-collector/internal/model"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestClickHouseSpoolReplay(t *testing.T) {
	inserts := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if strings.HasPrefix(q, "CREATE") || strings.HasPrefix(q, "ALTER") {
			w.WriteHeader(200)
			return
		}
		if strings.HasPrefix(q, "INSERT INTO") {
			inserts++
			w.WriteHeader(200)
			return
		}
		t.Fatalf("unexpected query %s", q)
	}))
	defer ts.Close()
	ch, err := NewClickHouse(ClickHouseConfig{URL: ts.URL, Database: "flowcollector", Table: "flows", DataDir: t.TempDir(), BatchSize: 10, FlushMS: 1000, QueueSize: 64, RetentionDays: 7, SpoolEnabled: true, SpoolMaxBytes: 1 << 20, SpoolReplaySeconds: 60})
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	batch := []model.Flow{{ReceiveTime: time.Now(), SrcIP: "10.0.0.1", DstIP: "8.8.8.8", Bytes: 100}}
	if err := ch.spoolBatch(batch); err != nil {
		t.Fatal(err)
	}
	files, bytesN, err := ch.spoolUsage()
	if err != nil || files != 1 || bytesN == 0 {
		t.Fatalf("usage files=%d bytes=%d err=%v", files, bytesN, err)
	}
	ch.replaySpoolOne()
	files, _, _ = ch.spoolUsage()
	if files != 0 || ch.replayed.Load() != 1 || inserts != 1 {
		t.Fatalf("replay files=%d replayed=%d inserts=%d", files, ch.replayed.Load(), inserts)
	}
}

func TestWALCorruptionIsQuarantined(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if strings.HasPrefix(q, "CREATE") || strings.HasPrefix(q, "ALTER") {
			w.WriteHeader(200)
			return
		}
		if strings.HasPrefix(q, "INSERT INTO") {
			w.WriteHeader(200)
			return
		}
		t.Fatalf("unexpected query %s", q)
	}))
	defer ts.Close()
	ch, err := NewClickHouse(ClickHouseConfig{URL: ts.URL, Database: "flowcollector", Table: "flows", DataDir: t.TempDir(), BatchSize: 10, FlushMS: 1000, QueueSize: 64, RetentionDays: 7, SpoolEnabled: true, SpoolMaxBytes: 1 << 20, SpoolReplaySeconds: 60, SpoolSegmentBytes: 1 << 20, SpoolFsync: true})
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	if err := ch.spoolBatch([]model.Flow{{ReceiveTime: time.Now(), SrcIP: "10.0.0.1", Bytes: 10}}); err != nil {
		t.Fatal(err)
	}
	ents, err := os.ReadDir(ch.spoolDir)
	if err != nil {
		t.Fatal(err)
	}
	var p string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".wal") {
			p = filepath.Join(ch.spoolDir, e.Name())
			break
		}
	}
	if p == "" {
		t.Fatal("wal missing")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	b[len(b)-1] ^= 0xff
	if err = os.WriteFile(p, b, 0640); err != nil {
		t.Fatal(err)
	}
	ch.replaySpoolOne()
	st := ch.Stats()
	if st.SpoolCorrupt != 1 || st.SpoolQuarantined != 1 {
		t.Fatalf("stats %+v", st)
	}
	qents, err := os.ReadDir(filepath.Join(ch.spoolDir, "corrupt"))
	if err != nil || len(qents) != 1 {
		t.Fatalf("quarantine err=%v entries=%d", err, len(qents))
	}
}

func TestRecoverValidWALTemp(t *testing.T) {
	dir := t.TempDir()
	spool := filepath.Join(dir, "clickhouse-spool")
	if err := os.MkdirAll(spool, 0750); err != nil {
		t.Fatal(err)
	}
	data, err := encodeWALSegment([]model.Flow{{ReceiveTime: time.Now(), SrcIP: "10.0.0.1", Bytes: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(spool, "00000000000000000001-000001.wal.tmp"), data, 0640); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if strings.HasPrefix(q, "CREATE") || strings.HasPrefix(q, "ALTER") {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()
	ch, err := NewClickHouse(ClickHouseConfig{URL: ts.URL, Database: "flowcollector", Table: "flows", DataDir: dir, BatchSize: 10, FlushMS: 1000, QueueSize: 64, RetentionDays: 7, SpoolEnabled: true, SpoolMaxBytes: 1 << 20, SpoolReplaySeconds: 60, SpoolSegmentBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	if ch.Stats().SpoolRecovered != 1 {
		t.Fatalf("stats %+v", ch.Stats())
	}
	files, _, _ := ch.spoolUsage()
	if files != 1 {
		t.Fatalf("files=%d", files)
	}
}
