package storage

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"central-flow-collector/internal/model"
)

func TestServiceSelectorsMatchEitherPortAndProtocol(t *testing.T) {
	smtp, err := trafficSelectorForService("smtp")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		flow model.Flow
		want bool
	}{
		{"destination smtp", model.Flow{DstPort: 25, IPProtocol: 6}, true},
		{"source submission response", model.Flow{SrcPort: 587, IPProtocol: 6}, true},
		{"wrong transport", model.Flow{DstPort: 25, IPProtocol: 17}, false},
		{"unknown transport falls back to service port", model.Flow{DstPort: 25, IPProtocol: 0}, true},
		{"unrelated port", model.Flow{DstPort: 2525, IPProtocol: 6}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := matchTrafficSelector(tc.flow, smtp); got != tc.want {
				t.Fatalf("match=%v want=%v", got, tc.want)
			}
		})
	}
}

func TestCustomPortSelectorMatchesUnknownTransportButProtocolSeriesDoesNot(t *testing.T) {
	port := TrafficSelector{Key: "port:tcp:443", Label: "TCP 443", Kind: "port", Port: 443, Protocols: []uint16{6}}
	if !matchTrafficSelector(model.Flow{DstPort: 443, IPProtocol: 0}, port) {
		t.Fatal("port-backed selector should retain traffic when exporter omits ip_protocol")
	}
	tcp := TrafficSelector{Key: "protocol:6", Label: "TCP", Kind: "protocol", Protocols: []uint16{6}}
	if matchTrafficSelector(model.Flow{DstPort: 443, IPProtocol: 0}, tcp) {
		t.Fatal("protocol-only selector must not classify unknown transport as TCP")
	}
}

func TestLocalAnalyzeTrafficSeriesSingleScanSemantics(t *testing.T) {
	dir := t.TempDir()
	l, err := NewLocal(dir, 64, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	now := time.Now().UTC().Truncate(time.Minute)
	flows := []model.Flow{
		{ReceiveTime: now, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 40000, DstPort: 25, IPProtocol: 6, Bytes: 100, Packets: 2},
		{ReceiveTime: now.Add(time.Second), SrcIP: "10.0.0.2", DstIP: "10.0.0.1", SrcPort: 25, DstPort: 40000, IPProtocol: 6, Bytes: 60, Packets: 1},
		{ReceiveTime: now.Add(2 * time.Second), SrcIP: "10.0.0.3", DstIP: "8.8.8.8", SrcPort: 50000, DstPort: 53, IPProtocol: 17, Bytes: 80, Packets: 1},
		{ReceiveTime: now.Add(3 * time.Second), SrcIP: "10.0.0.4", DstIP: "10.0.0.5", SrcPort: 51000, DstPort: 8443, IPProtocol: 6, AppName: "Internal API", Bytes: 200, Packets: 4},
	}
	for _, f := range flows {
		if err := l.Write(f); err != nil {
			t.Fatal(err)
		}
	}
	smtp, _ := trafficSelectorForService("smtp")
	dns, _ := trafficSelectorForService("dns")
	selectors := []TrafficSelector{
		smtp,
		dns,
		{Key: "port:tcp:8443", Label: "TCP 8443", Kind: "port", Port: 8443, Protocols: []uint16{6}},
		{Key: "app:internal api", Label: "Internal API", Kind: "application", App: "Internal API"},
	}
	out, err := l.AnalyzeTrafficSeries(context.Background(), Query{From: now.Add(-time.Minute), To: now.Add(time.Minute)}, selectors)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Series) != 4 {
		t.Fatalf("series=%d", len(out.Series))
	}
	if out.Series[0].Totals.Flows != 2 || out.Series[0].Totals.Bytes != 160 {
		t.Fatalf("smtp totals=%+v", out.Series[0].Totals)
	}
	if out.Series[1].Totals.Flows != 1 || out.Series[1].Totals.Bytes != 80 {
		t.Fatalf("dns totals=%+v", out.Series[1].Totals)
	}
	if out.Series[2].Totals.Flows != 1 || out.Series[3].Totals.Flows != 1 {
		t.Fatalf("custom totals port=%+v app=%+v", out.Series[2].Totals, out.Series[3].Totals)
	}
}

func TestParseQueryServiceAndEitherPort(t *testing.T) {
	q, err := ParseQuery(map[string][]string{"service": {"smtp"}, "port": {"587"}})
	if err != nil {
		t.Fatal(err)
	}
	if q.Service != "smtp" || q.Port != 587 {
		t.Fatalf("query=%+v", q)
	}
	if _, err := ParseQuery(map[string][]string{"service": {"not-a-service"}}); err == nil {
		t.Fatal("expected invalid service error")
	}
}

func TestClickHouseAnalyzeTrafficSeriesBuildsSingleScanQuery(t *testing.T) {
	var mu sync.Mutex
	var selected []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sql := r.URL.Query().Get("query")
		if strings.HasPrefix(sql, "SELECT series,") {
			mu.Lock()
			selected = append(selected, sql)
			mu.Unlock()
			_, _ = w.Write([]byte("{\"series\":\"s0\",\"ts\":1760000000,\"bytes\":100,\"packets\":2,\"flows\":1}\n"))
			return
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
	smtp, _ := trafficSelectorForService("smtp")
	selectors := []TrafficSelector{
		smtp,
		{Key: "port:tcp:8443", Label: "TCP 8443", Kind: "port", Port: 8443, Protocols: []uint16{6}},
		{Key: "app:odd", Label: "Odd App", Kind: "application", App: "x' OR 1=1 --"},
	}
	out, err := ch.AnalyzeTrafficSeries(context.Background(), Query{From: now.Add(-time.Hour), To: now}, selectors)
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Series) != 3 || out.Series[0].Totals.Bytes != 100 {
		t.Fatalf("out=%+v", out)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(selected) != 1 {
		t.Fatalf("service series SELECT count=%d, want 1", len(selected))
	}
	sql := selected[0]
	for _, want := range []string{"arrayJoin(arrayConcat(", "src_port=25 OR dst_port=25", "ip_protocol=0 OR ip_protocol IN (6)", "src_port=8443 OR dst_port=8443", "application_name={series_app_2:String}"} {
		if !strings.Contains(sql, want) {
			t.Fatalf("query missing %q: %s", want, sql)
		}
	}
	if strings.Contains(sql, selectors[2].App) {
		t.Fatal("custom application was interpolated into SQL")
	}
}
