package storage

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"central-flow-collector/internal/model"
)

func TestLocalReportsWriteFailure(t *testing.T) {
	l, err := NewLocal(t.TempDir(), 64, 7)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	now := time.Now().UTC()
	// A directory at the expected file path makes opening the flow file fail,
	// including when tests run as root.
	if err := os.Mkdir(filepath.Join(l.dir, "flows", now.Format("2006-01-02")+".jsonl"), 0750); err != nil {
		t.Fatal(err)
	}
	if err := l.Write(model.Flow{ReceiveTime: now}); err != nil {
		t.Fatal(err)
	}
	if err := l.syncWrites(context.Background()); err == nil {
		t.Fatal("write failure hidden from query barrier")
	}
	if l.Stats().Healthy {
		t.Fatal("failed storage reported healthy")
	}
}

func TestLocalRejectsWritesAfterClose(t *testing.T) {
	l, err := NewLocal(t.TempDir(), 64, 7)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Write(model.Flow{}); err == nil {
		t.Fatal("closed storage accepted data")
	}
}

func TestLocalConcurrentClose(t *testing.T) {
	l, err := NewLocal(t.TempDir(), 64, 7)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.Close(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

func BenchmarkSpoolBatch(b *testing.B) {
	for _, count := range []int{100, 1000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			c := &ClickHouse{cfg: ClickHouseConfig{SpoolEnabled: true, SpoolSegmentBytes: 1 << 20}, spoolDir: b.TempDir()}
			flows := make([]model.Flow, count)
			for i := range flows {
				flows[i] = model.Flow{ReceiveTime: time.Unix(100, 0), SrcIP: "192.0.2.1", Bytes: uint64(i)}
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := c.spoolBatch(flows); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestWALSegmentsRespectLimitAndPreserveOrder(t *testing.T) {
	c := &ClickHouse{cfg: ClickHouseConfig{SpoolEnabled: true, SpoolSegmentBytes: 1 << 20}, spoolDir: t.TempDir()}
	flows := make([]model.Flow, 6)
	for i := range flows {
		flows[i] = model.Flow{Bytes: uint64(i), AppName: string(bytes.Repeat([]byte{'x'}, 400000))}
	}
	if err := c.spoolBatch(flows); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(c.spoolDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 2 {
		t.Fatal("batch was not split")
	}
	count := 0
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(c.spoolDir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > 1<<20 {
			t.Fatal("segment exceeds size limit")
		}
		decoded, err := decodeWAL(bytes.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range decoded {
			if f.Bytes != uint64(count) {
				t.Fatal("record order changed")
			}
			count++
		}
	}
	if count != len(flows) {
		t.Fatalf("lost records: %d", count)
	}
}
