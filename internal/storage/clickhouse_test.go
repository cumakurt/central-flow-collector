package storage

import (
	"central-flow-collector/internal/model"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestClickHouseBatchAndQuery(t *testing.T) {
	var mu sync.Mutex
	var inserts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		switch {
		case strings.HasPrefix(q, "CREATE DATABASE"), strings.HasPrefix(q, "CREATE TABLE"), strings.HasPrefix(q, "CREATE MATERIALIZED VIEW"), strings.HasPrefix(q, "ALTER TABLE"):
			w.WriteHeader(200)
		case strings.HasPrefix(q, "INSERT INTO"):
			b, _ := io.ReadAll(r.Body)
			mu.Lock()
			inserts = append(inserts, string(b))
			mu.Unlock()
			w.WriteHeader(200)
		case strings.Contains(q, "FROM flowcollector.flows") && strings.Contains(q, "ORDER BY receive_time DESC"):
			if r.URL.Query().Get("param_from") == "" || r.URL.Query().Get("param_to") == "" || r.URL.Query().Get("param_tenant") != "acme" {
				t.Errorf("missing query parameters")
			}
			fmt.Fprintln(w, `{"receive_ms":1700000000000,"collector_node":"node-a","tenant":"acme","start_ms":0,"end_ms":0,"exporter":"10.0.0.1","listener":"nf","flow_protocol":"netflow","observation_domain":0,"src_ip":"10.1.1.1","dst_ip":"8.8.8.8","src_port":1234,"dst_port":53,"ip_protocol":17,"packets":2,"bytes":200,"tcp_flags":0,"tos":0,"dscp":0,"ecn":0,"ingress_if":0,"egress_if":0,"next_hop":"","src_as":0,"dst_as":0,"src_prefix":"","dst_prefix":"","vlan":0,"src_mac":"","dst_mac":"","nat_src_ip":"","nat_dst_ip":"","nat_src_port":0,"nat_dst_port":0,"direction":0,"sampling_rate":0,"sequence":0,"application_id":"","application_name":"","vrf":"","custom_json":"{}"}`)
		default:
			t.Fatalf("unexpected query: %s", q)
		}
	}))
	defer srv.Close()
	ch, err := NewClickHouse(ClickHouseConfig{URL: srv.URL, Database: "flowcollector", Table: "flows", RetentionDays: 7, BatchSize: 1, FlushMS: 100, QueueSize: 64})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := ch.Write(model.Flow{ReceiveTime: now, CollectorNode: "node-a", Tenant: "acme", Exporter: "10.0.0.1", Listener: "nf", Protocol: "netflow", SrcIP: "10.1.1.1", DstIP: "8.8.8.8", Bytes: 200}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for ch.Stats().Written < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if ch.Stats().Written != 1 {
		t.Fatalf("write did not flush: %+v", ch.Stats())
	}
	mu.Lock()
	if len(inserts) != 1 || !strings.Contains(inserts[0], `"src_ip":"10.1.1.1"`) || !strings.Contains(inserts[0], `"tenant":"acme"`) {
		t.Fatalf("unexpected insert body: %v", inserts)
	}
	mu.Unlock()
	rows, err := ch.Query(context.Background(), Query{From: now.Add(-time.Hour), To: now, Tenant: "acme", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].DstIP != "8.8.8.8" || rows[0].Bytes != 200 || rows[0].Tenant != "acme" {
		t.Fatalf("bad rows: %+v", rows)
	}
	_ = ch.Close()
}

func TestClickHouseRejectsUnsafeIdentifier(t *testing.T) {
	_, err := NewClickHouse(ClickHouseConfig{URL: "http://127.0.0.1:8123", Database: "db;drop", Table: "flows", RetentionDays: 7, BatchSize: 1, FlushMS: 100, QueueSize: 64})
	if err == nil {
		t.Fatal("expected identifier validation error")
	}
}

func TestClickHouseWorksWithoutCreateDatabaseGrantWhenDatabaseExists(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		if strings.HasPrefix(q, "CREATE DATABASE") {
			http.Error(w, "ACCESS_DENIED", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(q, "CREATE TABLE") || strings.HasPrefix(q, "CREATE MATERIALIZED VIEW") || strings.HasPrefix(q, "ALTER TABLE") {
			w.WriteHeader(http.StatusOK)
			return
		}
		t.Fatalf("unexpected query: %s", q)
	}))
	defer srv.Close()

	ch, err := NewClickHouse(ClickHouseConfig{
		URL: srv.URL, Database: "flowcollector", Table: "flows", User: "flowcollector", Password: "secret",
		RetentionDays: 7, BatchSize: 1, FlushMS: 100, QueueSize: 64,
	})
	if err != nil {
		t.Fatalf("least-privileged schema bootstrap failed: %v", err)
	}
	_ = ch.Close()
}

func TestClickHouseClusterDDLAndDistributedInsert(t *testing.T) {
	var mu sync.Mutex
	var queries []string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("query")
		mu.Lock()
		queries = append(queries, q)
		mu.Unlock()
		w.WriteHeader(200)
	}))
	defer ts.Close()
	ch, err := NewClickHouse(ClickHouseConfig{URL: ts.URL, Database: "flowcollector", Table: "flows", Cluster: "prod", DistributedTable: "flows_all", ReplicaPath: "/clickhouse/tables/{shard}/flowcollector/flows", ReplicaName: "{replica}", RetentionDays: 7, BatchSize: 1, FlushMS: 50, QueueSize: 64})
	if err != nil {
		t.Fatal(err)
	}
	if err := ch.Write(model.Flow{ReceiveTime: time.Now(), Tenant: "acme", SrcIP: "10.0.0.1", DstIP: "8.8.8.8", Bytes: 100}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	_ = ch.Close()
	mu.Lock()
	joined := strings.Join(queries, "\n")
	mu.Unlock()
	for _, want := range []string{"ON CLUSTER `prod`", "ReplicatedMergeTree", "ENGINE = Distributed", "INSERT INTO flowcollector.flows_all"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in queries:\n%s", want, joined)
		}
	}
}
