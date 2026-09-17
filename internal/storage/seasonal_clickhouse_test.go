package storage

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"central-flow-collector/internal/model"
	"central-flow-collector/internal/notification"
)

func TestSeasonalClickHouseParity(t *testing.T) {
	endpoint := os.Getenv("CFC_TEST_CLICKHOUSE_URL")
	if endpoint == "" {
		t.Skip("set CFC_TEST_CLICKHOUSE_URL for isolated ClickHouse parity test")
	}
	db := fmt.Sprintf("cfc_seasonal_test_%d", time.Now().UnixNano())
	ch, err := NewClickHouse(ClickHouseConfig{URL: endpoint, Database: db, Table: "flows", DataDir: t.TempDir(), RetentionDays: 35, BatchSize: 1, FlushMS: 100, QueueSize: 64})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = ch.Close()
		if err := ch.exec(context.Background(), "DROP DATABASE `"+db+"`"); err != nil {
			t.Error(err)
		}
	})
	local, err := NewLocal(t.TempDir(), 64, 35)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	at := time.Now().UTC()
	end := at.Add(-time.Minute).Truncate(time.Hour)
	for week := 0; week <= 4; week++ {
		value := uint64(10_000_000)
		if week == 0 {
			value = 20_000_000
		}
		f := model.Flow{ReceiveTime: end.AddDate(0, 0, -7*week).Add(-30 * time.Minute), SrcIP: "192.0.2.1", DstIP: "198.51.100.1", Exporter: "192.0.2.254", Bytes: value, Packets: 100, Sampling: 1, IPProtocol: 6}
		if err = local.Write(f); err != nil {
			t.Fatal(err)
		}
		if err = ch.Write(f); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for ch.Stats().Written < 5 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if ch.Stats().Written != 5 {
		t.Fatal(ch.Stats())
	}
	var r notification.RuleDefinition
	for _, candidate := range notification.RuleTemplates() {
		if candidate.Kind == "seasonal" {
			r = candidate
		}
	}
	for _, metric := range []string{"bytes", "packets", "flows", "bps", "unique_destinations"} {
		r.Metric = metric
		a, err := notification.EvaluateSeasonal(context.Background(), r, at, local.EvaluateAlertRule)
		if err != nil {
			t.Fatal(err)
		}
		b, err := notification.EvaluateSeasonal(context.Background(), r, at, ch.EvaluateAlertRule)
		if err != nil {
			t.Fatal(err)
		}
		if len(a) != 1 || !reflect.DeepEqual(a, b) {
			t.Fatalf("%s local=%+v clickhouse=%+v", metric, a, b)
		}
		if a[0].Baseline.History != 4 {
			t.Fatal(a)
		}
	}
}
