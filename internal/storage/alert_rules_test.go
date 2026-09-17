package storage

import (
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/notification"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

func storageTestRule() notification.RuleDefinition {
	return notification.RuleDefinition{ID: "r", Name: "Usage", Kind: "comparison", Condition: notification.Condition{Op: "and", Children: []notification.Condition{{Op: "eq", Field: "protocol", Values: []string{"6"}}, {Op: "not", Children: []notification.Condition{{Op: "eq", Field: "dst_port", Values: []string{"53"}}}}}}, Metric: "bytes", Operator: "gt", Threshold: 100, WindowSeconds: 300, IntervalSeconds: 60, CooldownSeconds: 1800, Priority: "high", GroupBy: []string{"src_network"}}
}
func TestRuleAggregationWindowsAndBooleanFilters(t *testing.T) {
	l, e := NewLocal(t.TempDir(), 64, 7)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	at := time.Now().UTC()
	flows := []model.Flow{{ReceiveTime: at.Add(-6 * time.Minute), SrcIP: "10.0.0.1", IPProtocol: 6, DstPort: 443, Bytes: 100}, {ReceiveTime: at.Add(-4 * time.Minute), SrcIP: "10.0.0.2", IPProtocol: 6, DstPort: 443, Bytes: 300}, {ReceiveTime: at.Add(-4 * time.Minute), SrcIP: "10.0.0.2", IPProtocol: 6, DstPort: 53, Bytes: 900}, {ReceiveTime: at, SrcIP: "10.0.0.2", IPProtocol: 6, DstPort: 443, Bytes: 500}}
	for _, f := range flows {
		if e = l.Write(f); e != nil {
			t.Fatal(e)
		}
	}
	out, e := l.EvaluateAlertRule(context.Background(), storageTestRule(), at)
	if e != nil {
		t.Fatal(e)
	}
	if len(out) != 1 || out[0].Value != 300 || out[0].Previous != 100 || out[0].Dimensions["src_network"] != "10.0.0.0/24" {
		t.Fatalf("%+v", out)
	}
	r := storageTestRule()
	r.Metric = "bps"
	out, e = l.EvaluateAlertRule(context.Background(), r, at)
	if e != nil || out[0].Value != 8 {
		t.Fatalf("bps %+v %v", out, e)
	}
}
func TestRuleSQLParametersAndBounds(t *testing.T) {
	r := storageTestRule()
	r.Condition = notification.Condition{Op: "eq", Field: "application", Values: []string{"x' OR 1=1 --"}}
	if e := r.Validate(); e != nil {
		t.Fatal(e)
	}
	sql, p := buildRuleSQL(r, time.Now(), "flows")
	if strings.Contains(sql, "OR 1=1") || p.Get("param_condition_0") != "x' OR 1=1 --" || p.Get("group_by_overflow_mode") != "throw" || p.Get("max_memory_usage") == "" || p.Get("max_execution_time") == "" {
		t.Fatal(sql, p)
	}
	if !strings.Contains(sql, "receive_time < {to:") {
		t.Fatal("window must be half-open")
	}
}
func TestRuleLocalGroupBound(t *testing.T) {
	l, e := NewLocal(t.TempDir(), 2048, 7)
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	at := time.Now().UTC()
	for i := 0; i < notification.MaxGroups+1; i++ {
		if e = l.Write(model.Flow{ReceiveTime: at.Add(-time.Minute), SrcIP: fmt.Sprintf("10.%d.%d.1", i/256, i%256), IPProtocol: 6, Bytes: 1}); e != nil {
			t.Fatal(e)
		}
	}
	r := storageTestRule()
	r.GroupBy = []string{"src_ip"}
	if _, e = l.EvaluateAlertRule(context.Background(), r, at); e == nil {
		t.Fatal("unbounded grouping accepted")
	}
}
func BenchmarkRuleLocalScan(b *testing.B) {
	for _, n := range []int{100000, 1000000} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			l, e := NewLocal(b.TempDir(), 8192, 7)
			if e != nil {
				b.Fatal(e)
			}
			defer l.Close()
			at := time.Now().UTC()
			for i := 0; i < n; i++ {
				if e = l.Write(model.Flow{ReceiveTime: at.Add(-time.Minute), SrcIP: fmt.Sprintf("10.0.0.%d", i%100), DstPort: 443, IPProtocol: 6, Bytes: uint64(i%10000 + 1)}); e != nil {
					b.Fatal(e)
				}
			}
			if e = l.syncWrites(context.Background()); e != nil {
				b.Fatal(e)
			}
			r := storageTestRule()
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, e = l.EvaluateAlertRule(context.Background(), r, at); e != nil {
					b.Fatal(e)
				}
			}
		})
	}
}
