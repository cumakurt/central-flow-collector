package storage

import (
	"central-flow-collector/internal/intelligence"
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/notification"
	"context"
	"fmt"
	"os"
	"reflect"
	"sort"
	"testing"
	"time"
)

// Opt-in integration test creates and drops only its uniquely named database.
func TestIntelligenceClickHouseParity(t *testing.T) {
	endpoint := os.Getenv("CFC_TEST_CLICKHOUSE_URL")
	if endpoint == "" {
		t.Skip("set CFC_TEST_CLICKHOUSE_URL for isolated ClickHouse parity test")
	}
	db := fmt.Sprintf("cfc_intelligence_test_%d", time.Now().UnixNano())
	ch, err := NewClickHouse(ClickHouseConfig{URL: endpoint, Database: db, Table: "flows", DataDir: t.TempDir(), RetentionDays: 7, BatchSize: 1, FlushMS: 100, QueueSize: 64})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = ch.Close()
		if err := ch.exec(context.Background(), "DROP DATABASE `"+db+"`"); err != nil {
			t.Error(err)
		}
	})
	local, err := NewLocal(t.TempDir(), 64, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	from := time.Now().UTC().Truncate(time.Hour)
	for i := 0; i < 12; i++ {
		f := model.Flow{ReceiveTime: from.Add(time.Duration(i-6) * 10 * time.Minute), StartTime: from, EndTime: from.Add(time.Duration(i) * time.Second), SrcIP: "192.0.2.1", DstIP: fmt.Sprintf("198.51.100.%d", i%3+1), Bytes: uint64(i * 100), Packets: uint64(i), IPProtocol: 6, AppName: "https", Exporter: "192.0.2.254", Sampling: uint32(i % 3), SrcAS: 64512, DstAS: 64513, SrcCountry: "TR", DstCountry: "DE", IngressIf: 1, EgressIf: 2, DstPort: 443}
		if i == 2 {
			f.StartTime = time.Time{}
		}
		f.SrcSite = "Users"
		f.DstSite = "Services"
		if i == 7 {
			f.SrcIP = "2001:db8::1"
			f.DstIP = "2001:db8:1::2"
		}
		if err = local.Write(f); err != nil {
			t.Fatal(err)
		}
		if err = ch.Write(f); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for ch.Stats().Written < 12 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if ch.Stats().Written != 12 {
		t.Fatal(ch.Stats())
	}
	q := Query{From: from, To: from.Add(time.Hour)}
	for _, metric := range []string{"bytes", "packets", "flows", "bps", "unique_sources", "unique_destinations"} {
		for _, dim := range []string{"src_network", "application", "dst_port"} {
			t.Run("alert_rule/"+metric+"/"+dim, func(t *testing.T) {
				r := storageTestRule()
				r.Metric = metric
				r.GroupBy = []string{dim}
				r.WindowSeconds = 3600
				r.Condition = notification.Condition{Op: "or", Children: []notification.Condition{{Op: "eq", Field: "protocol", Values: []string{"6"}}, {Op: "eq", Field: "src_network", Values: []string{"2001:db8::/32"}}}}
				a, e := local.EvaluateAlertRule(context.Background(), r, q.To)
				if e != nil {
					t.Fatal(e)
				}
				b, e := ch.EvaluateAlertRule(context.Background(), r, q.To)
				if e != nil {
					t.Fatal(e)
				}
				sort.Slice(a, func(i, j int) bool { return a[i].Entity < a[j].Entity })
				sort.Slice(b, func(i, j int) bool { return b[i].Entity < b[j].Entity })
				if !reflect.DeepEqual(a, b) {
					t.Fatalf("local=%+v ClickHouse=%+v", a, b)
				}
			})
		}
	}
	for _, kind := range []string{"changes", "concentration", "distribution", "relationships", "diversity", "temporal", "quality", "persistence", "anomalies"} {
		dims := []string{"application", "src_network", "ingress_if", "src_site", "dst_country"}
		if kind == "distribution" {
			dims = []string{"bytes", "packets", "duration_ms", "bytes_per_packet"}
		}
		for _, dim := range dims {
			t.Run(kind+"/"+dim, func(t *testing.T) {
				s := intelligenceSpec()
				s.Kind = kind
				s.Dimension = dim
				a, err := local.IntelligenceGroups(context.Background(), q, s)
				if err != nil {
					t.Fatal(err)
				}
				b, err := ch.IntelligenceGroups(context.Background(), q, s)
				if err != nil {
					t.Fatal(err)
				}
				order := func(gs []intelligence.Group) {
					sort.Slice(gs, func(i, j int) bool { return fmt.Sprintf("%+v", gs[i]) < fmt.Sprintf("%+v", gs[j]) })
				}
				order(a)
				order(b)
				if !reflect.DeepEqual(a, b) {
					t.Fatalf("local=%+v\nclickhouse=%+v", a, b)
				}
			})
		}
	}
}
