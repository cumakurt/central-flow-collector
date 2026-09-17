package storage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"central-flow-collector/internal/model"
)

func TestAggregateFiltersAndRankingBeforeLimit(t *testing.T) {
	l, err := NewLocal(t.TempDir(), 64, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	now := time.Now().UTC().Truncate(time.Second)
	flows := []model.Flow{
		{SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12000, DstPort: 443, IPProtocol: 6, Bytes: 1000, Packets: 10, DstCountry: "DE"},
		{SrcIP: "10.0.0.2", DstIP: "10.0.0.1", SrcPort: 443, DstPort: 12000, IPProtocol: 6, Bytes: 50, Packets: 2, SrcCountry: "DE"},
		{SrcIP: "10.0.0.1", DstIP: "10.0.0.3", SrcPort: 12000, DstPort: 53, IPProtocol: 17, Bytes: 9000, Packets: 1},
	}
	for i := 0; i < 4; i++ {
		flows = append(flows, model.Flow{SrcIP: "10.0.0.4", DstIP: "10.0.0.5", SrcPort: 30000, DstPort: 80, IPProtocol: 6, Bytes: 1, Packets: 500})
	}
	for _, f := range flows {
		f.ReceiveTime = now
		if f.Bytes == 1000 {
			f.StartTime, f.EndTime = now.Add(-time.Second), now
		}
		if err := l.Write(f); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	q := AggregateQuery{From: now.Add(-time.Second), To: now.Add(time.Second), Limit: 1}
	for _, tc := range []struct{ metric, ip string }{{"bytes", "10.0.0.1"}, {"packets", "10.0.0.4"}, {"flows", "10.0.0.4"}, {"peers", "10.0.0.1"}} {
		q.Metric = tc.metric
		rows, err := l.Assets(ctx, q)
		if err != nil || len(rows) != 1 || rows[0].IP != tc.ip {
			t.Fatalf("metric %s: %+v, %v", tc.metric, rows, err)
		}
	}
	q.Metric = "packets"
	conversations, err := l.Conversations(ctx, q)
	if err != nil || len(conversations) != 1 || conversations[0].AIP != "10.0.0.4" {
		t.Fatalf("packet ranking: %+v, %v", conversations, err)
	}
	q.Metric = "bytes"
	q.Limit = 10
	q.Filters = Query{IPProtocol: 6, IPProtocolSet: true, Country: "DE"}
	assets, err := l.Assets(ctx, q)
	if err != nil || len(assets) != 2 || assets[0].BytesIn+assets[0].BytesOut != 1050 || assets[0].Peers != 1 {
		t.Fatalf("filtered assets: %+v, %v", assets, err)
	}
	conversations, err = l.Conversations(ctx, q)
	if err != nil || len(conversations) != 1 || conversations[0].BytesAB != 1000 || conversations[0].BytesBA != 50 {
		t.Fatalf("filtered conversation: %+v, %v", conversations, err)
	}
	q.Filters.DstPort = 443
	conversations, err = l.Conversations(ctx, q)
	if err != nil || len(conversations) != 1 || conversations[0].Flows != 1 || conversations[0].BytesBA != 0 {
		t.Fatalf("directional filter must precede aggregation: %+v, %v", conversations, err)
	}
	host, err := l.InvestigateHost(ctx, HostQuery{IP: "10.0.0.1", From: q.From, To: q.To, Filters: Query{Host: "10.0.0.2", IPProtocol: 6, IPProtocolSet: true}})
	if err != nil || host.BytesIn != 50 || host.BytesOut != 1000 || host.Flows != 2 || len(host.TopPeers) != 1 || len(host.Timeline) != 1 {
		t.Fatalf("host lens: %+v, %v", host, err)
	}
	q.Filters = Query{MinDurationMS: 500, MaxDurationMS: 1500}
	conversations, err = l.Conversations(ctx, q)
	if err != nil || len(conversations) != 1 || conversations[0].BytesAB != 1000 || conversations[0].Flows != 1 {
		t.Fatalf("duration lens: %+v, %v", conversations, err)
	}
	q.Filters = Query{Host: "192.0.2.1"}
	assets, err = l.Assets(ctx, q)
	if err != nil || len(assets) != 0 {
		t.Fatalf("empty result: %+v, %v", assets, err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = l.Assets(ctx, q); err != context.Canceled {
		t.Fatalf("cancellation: %v", err)
	}
}

func TestParseAggregateSharedFilters(t *testing.T) {
	values := url.Values{"metric": {"peers"}, "ip_protocol": {"TCP"}, "src_cidr": {"10.0.0.0/8"}, "min_bytes": {"1024"}, "limit": {"25"}}
	q, err := ParseAggregateQuery(values)
	if err != nil || q.Metric != "peers" || q.Filters.IPProtocol != 6 || q.Filters.SrcCIDR != "10.0.0.0/8" || q.Filters.MinBytes != 1024 || q.Limit != 25 {
		t.Fatalf("query: %+v, %v", q, err)
	}
	for key, value := range map[string]string{"metric": "bytes DESC; DROP TABLE flows", "ip_protocol": "banana", "src_cidr": "invalid", "min_bytes": "-1", "limit": "1001"} {
		if _, err := ParseAggregateQuery(url.Values{key: {value}}); err == nil {
			t.Errorf("accepted %s=%s", key, value)
		}
	}
}

func TestClickHouseAggregatePredicatesAndOrder(t *testing.T) {
	type request struct {
		sql    string
		params url.Values
	}
	var mu sync.Mutex
	var queries []request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()
		sql := params.Get("query")
		if strings.HasPrefix(sql, "SELECT") {
			mu.Lock()
			queries = append(queries, request{sql, params})
			mu.Unlock()
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	ch, err := NewClickHouse(ClickHouseConfig{URL: srv.URL, Database: "flowcollector", Table: "flows", RetentionDays: 7, BatchSize: 100, FlushMS: 1000, QueueSize: 64})
	if err != nil {
		t.Fatal(err)
	}
	defer ch.Close()
	now := time.Now().UTC()
	filters := Query{IPProtocol: 6, IPProtocolSet: true, SrcCIDR: "10.0.0.0/8", App: "a' OR 1=1 --", Host: "10.0.0.2", MinBytes: 100, MinDurationMS: 500, MaxDurationMS: 1500}
	q := AggregateQuery{From: now.Add(-time.Hour), To: now, Metric: "packets", Limit: 25, Filters: filters}
	if _, err = ch.Assets(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if _, err = ch.Conversations(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	if _, err = ch.InvestigateHost(context.Background(), HostQuery{IP: "10.0.0.1", From: q.From, To: q.To, Filters: filters}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(queries) != 8 {
		t.Fatalf("got %d queries, want assets, conversations and 6 host aggregates", len(queries))
	}
	for i, r := range queries {
		if !strings.Contains(r.sql, "greatest(0, dateDiff('millisecond', start_time, end_time))") || !strings.Contains(r.sql, "{min_duration:Int64}") || !strings.Contains(r.sql, "{max_duration:Int64}") || r.params.Get("param_min_duration") != "500" || r.params.Get("param_max_duration") != "1500" {
			t.Errorf("query %d missing bounded duration predicates", i)
		}
		if !strings.Contains(r.sql, "ip_protocol={ip_protocol:UInt8}") || !strings.Contains(r.sql, "isIPAddressInRange(src_ip,{src_cidr:String})") || !strings.Contains(r.sql, "application_name = {app:String}") || !strings.Contains(r.sql, "bytes>={min_bytes:UInt64}") {
			t.Errorf("query %d missing shared predicates: %s", i, r.sql)
		}
		if strings.Contains(r.sql, filters.App) || r.params.Get("param_app") != filters.App || r.params.Get("param_ip_protocol") != "6" {
			t.Errorf("query %d did not parameterize filters", i)
		}
		if i >= 2 && (r.params.Get("param_host") != "10.0.0.1" || r.params.Get("param_lens_host") != "10.0.0.2" || !strings.Contains(r.sql, "{lens_host:String}")) {
			t.Errorf("query %d overwrote profile IP with peer lens", i)
		}
	}
	if strings.Count(queries[0].sql, "ip_protocol={ip_protocol:UInt8}") != 2 || !strings.Contains(queries[0].sql, "ORDER BY packets_in + packets_out DESC, ip ASC\nLIMIT 25") {
		t.Error("assets must filter both UNION branches and rank before LIMIT")
	}
	if !strings.Contains(queries[1].sql, "ORDER BY packets_a_to_b + packets_b_to_a DESC") {
		t.Error("conversation packet ranking missing")
	}
}
