package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestRegistryAuthPersistAndOffline(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nodes.json")
	r, e := NewRegistry(p, "secret", 50*time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	if !r.Authenticate("secret") || r.Authenticate("bad") {
		t.Fatal("auth")
	}
	if e = r.Heartbeat(Heartbeat{NodeID: "edge-1", Region: "tr", Version: "1.6.0", Healthy: true}, "127.0.0.1"); e != nil {
		t.Fatal(e)
	}
	r2, e := NewRegistry(p, "secret", 50*time.Millisecond)
	if e != nil {
		t.Fatal(e)
	}
	n := r2.Nodes()
	if len(n) != 1 || n[0].NodeID != "edge-1" {
		t.Fatalf("nodes=%+v", n)
	}
}
func TestInvalidNode(t *testing.T) {
	r, _ := NewRegistry(filepath.Join(t.TempDir(), "n.json"), "x", time.Minute)
	if r.Heartbeat(Heartbeat{NodeID: "bad node"}, "") == nil {
		t.Fatal("expected invalid")
	}
}

func TestClientSend(t *testing.T) {
	var auth string
	var got Heartbeat
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()
	c := Client{URL: ts.URL, Token: "cluster-secret"}
	if err := c.Send(context.Background(), Heartbeat{NodeID: "edge-2", Healthy: true}); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer cluster-secret" || got.NodeID != "edge-2" {
		t.Fatalf("auth=%q got=%+v", auth, got)
	}
}

func TestFleetCommandDeliveryRetryAndAck(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nodes.json")
	r, err := NewRegistry(p, "secret", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Heartbeat(Heartbeat{NodeID: "edge-1", Version: "1.7.0", Healthy: true}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	cmd, err := r.QueueCommand("edge-1", "reload_policies", "admin")
	if err != nil {
		t.Fatal(err)
	}
	first := r.NextCommand("edge-1")
	second := r.NextCommand("edge-1")
	if first == nil || second == nil || first.ID != cmd.ID || second.ID != cmd.ID {
		t.Fatalf("command retry failed: first=%+v second=%+v", first, second)
	}
	if err := r.Heartbeat(Heartbeat{NodeID: "edge-1", Version: "1.7.0", Healthy: true, LastCommandID: cmd.ID, LastCommandStatus: "ok"}, "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if next := r.NextCommand("edge-1"); next != nil {
		t.Fatalf("acked command redelivered: %+v", next)
	}
	cc := r.Commands()
	if len(cc) != 1 || cc[0].Status != "acknowledged" || cc[0].Result != "ok" {
		t.Fatalf("commands=%+v", cc)
	}
}

func TestDedupClientCoordinator(t *testing.T) {
	var calls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Errorf("bad auth")
		}
		_ = json.NewEncoder(w).Encode(DedupResponse{Accepted: calls == 1, Stats: DedupStats{Enabled: true}})
	}))
	defer ts.Close()
	c := Client{URL: ts.URL, Token: "secret"}
	ok, err := c.CheckDedup(context.Background(), "0123456789abcdef0123456789abcdef")
	if err != nil || !ok {
		t.Fatalf("first ok=%v err=%v", ok, err)
	}
	ok, err = c.CheckDedup(context.Background(), "0123456789abcdef0123456789abcdef")
	if err != nil || ok {
		t.Fatalf("second ok=%v err=%v", ok, err)
	}
}

func TestCoordinatorDedupBoundedAndExpires(t *testing.T) {
	r, err := NewRegistry(filepath.Join(t.TempDir(), "nodes.json"), "secret", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	r.ConfigureDedup(30*time.Second, 1000)
	now := time.Now().UTC()
	fp1 := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if !r.AcceptFingerprint(fp1, now) || r.AcceptFingerprint(fp1, now.Add(time.Millisecond)) {
		t.Fatal("duplicate was not rejected")
	}
	for i := 0; i < 1000; i++ {
		fp := fmt.Sprintf("%032x", i+100)
		if !r.AcceptFingerprint(fp, now.Add(time.Duration(i+2)*time.Millisecond)) {
			t.Fatalf("new fingerprint %d rejected", i)
		}
	}
	st := r.DedupStats()
	if st.Entries > 1000 || st.Duplicates != 1 || st.Evicted == 0 {
		t.Fatalf("unexpected bounded stats: %+v", st)
	}
	if !r.AcceptFingerprint(fp1, now.Add(31*time.Second)) {
		t.Fatal("expired fingerprint should be accepted again")
	}
}
func TestStagedRollout(t *testing.T) {
	r, e := NewRegistry(t.TempDir()+"/r.json", "tok", time.Minute)
	if e != nil {
		t.Fatal(e)
	}
	for _, n := range []string{"n1", "n2", "n3", "n4"} {
		if e := r.Heartbeat(Heartbeat{NodeID: n, Healthy: true}, "127.0.0.1"); e != nil {
			t.Fatal(e)
		}
	}
	ro, e := r.StartRollout("policy", "reload_policies", "admin", []string{"n1", "n2", "n3", "n4"}, []int{25, 50, 100})
	if e != nil {
		t.Fatal(e)
	}
	if len(ro.CommandIDs) != 1 {
		t.Fatalf("stage1=%d", len(ro.CommandIDs))
	}
	c := r.NextCommand("n1")
	if c == nil {
		t.Fatal("no command")
	}
	if e := r.Heartbeat(Heartbeat{NodeID: "n1", Healthy: true, LastCommandID: c.ID, LastCommandStatus: "ok"}, "127.0.0.1"); e != nil {
		t.Fatal(e)
	}
	ro, e = r.AdvanceRollout(ro.ID)
	if e != nil {
		t.Fatal(e)
	}
	if len(ro.CommandIDs) != 2 {
		t.Fatalf("stage2=%d", len(ro.CommandIDs))
	}
}

func TestTokenRotationAcceptsPrimaryAndSecondary(t *testing.T) {
	r, err := NewRegistry(filepath.Join(t.TempDir(), "nodes.json"), "new-token\nold-token", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if PrimaryToken("new-token\nold-token") != "new-token" {
		t.Fatal("primary token mismatch")
	}
	if !r.Authenticate("new-token") || !r.Authenticate("old-token") || r.Authenticate("other") {
		t.Fatal("rotating cluster token acceptance failed")
	}
}

func TestTopologyQuorumCoordinatorAndAssignment(t *testing.T) {
	r, err := NewRegistry(filepath.Join(t.TempDir(), "nodes.json"), "secret", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	r.ConfigureTopology(3)
	for _, n := range []string{"node-c", "node-a", "node-b"} {
		if err := r.Heartbeat(Heartbeat{NodeID: n, Healthy: true}, "127.0.0.1"); err != nil {
			t.Fatal(err)
		}
	}
	st := r.TopologyStatus()
	if st.Expected != 3 || st.Online != 3 || !st.HasQuorum || st.QuorumRequired != 2 || st.Coordinator != "node-a" {
		t.Fatalf("unexpected topology: %+v", st)
	}
	first, ok := r.AssignExporter("tenant-a|192.0.2.10")
	if !ok || first == "" {
		t.Fatal("assignment missing")
	}
	for i := 0; i < 20; i++ {
		n, ok := r.AssignExporter("tenant-a|192.0.2.10")
		if !ok || n != first {
			t.Fatalf("assignment is not deterministic: %q != %q", n, first)
		}
	}
}
