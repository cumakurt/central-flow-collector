package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"central-flow-collector/internal/auth"
	"central-flow-collector/internal/model"
	"central-flow-collector/internal/storage"
)

func TestAggregateHandlersShareFlowLens(t *testing.T) {
	store, err := storage.NewLocal(t.TempDir(), 64, 7)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Now().UTC()
	for _, f := range []model.Flow{
		{ReceiveTime: now, SrcIP: "10.0.0.1", DstIP: "10.0.0.2", SrcPort: 12000, DstPort: 443, IPProtocol: 6, Bytes: 100, Packets: 1},
		{ReceiveTime: now, SrcIP: "10.0.0.1", DstIP: "10.0.0.3", SrcPort: 12000, DstPort: 53, IPProtocol: 17, Bytes: 900, Packets: 5},
	} {
		if err = store.Write(f); err != nil {
			t.Fatal(err)
		}
	}
	s := &Server{Store: store}
	for _, tc := range []struct {
		name    string
		handler func(http.ResponseWriter, *http.Request, auth.Session)
	}{{"assets", s.assets}, {"conversations", s.conversations}, {"ip", s.investigateHost}} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/v1/"+tc.name+"?ip_protocol=TCP&tenant=ignored", nil)
			request.SetPathValue("ip", "10.0.0.1")
			response := httptest.NewRecorder()
			tc.handler(response, request, auth.Session{})
			if response.Code != 200 {
				t.Fatalf("%d: %s", response.Code, response.Body.String())
			}
			switch tc.name {
			case "assets":
				var rows []storage.AssetSummary
				if err := json.Unmarshal(response.Body.Bytes(), &rows); err != nil {
					t.Fatal(err)
				}
				if len(rows) != 2 || rows[0].BytesIn+rows[0].BytesOut != 100 {
					t.Fatalf("assets ignored filter: %+v", rows)
				}
			case "conversations":
				var rows []storage.ConversationSummary
				if err := json.Unmarshal(response.Body.Bytes(), &rows); err != nil {
					t.Fatal(err)
				}
				if len(rows) != 1 || rows[0].Protocol != 6 || rows[0].BytesAB != 100 {
					t.Fatalf("conversations ignored filter: %+v", rows)
				}
			case "ip":
				var profile storage.HostInvestigation
				if err := json.Unmarshal(response.Body.Bytes(), &profile); err != nil {
					t.Fatal(err)
				}
				if profile.Flows != 1 || profile.BytesOut != 100 {
					t.Fatalf("IP profile ignored filter: %+v", profile)
				}
			}
			bad := httptest.NewRequest(http.MethodGet, "/api/v1/"+tc.name+"?src_cidr=invalid", nil)
			bad.SetPathValue("ip", "10.0.0.1")
			response = httptest.NewRecorder()
			tc.handler(response, bad, auth.Session{})
			if response.Code != 400 {
				t.Fatalf("invalid filter returned %d", response.Code)
			}
		})
	}
	for _, query := range []string{"metric=peers", "metric=arbitrary"} {
		response := httptest.NewRecorder()
		s.conversations(response, httptest.NewRequest(http.MethodGet, "/api/v1/conversations?"+query, nil), auth.Session{})
		if response.Code != 400 {
			t.Fatalf("invalid conversation metric returned %d", response.Code)
		}
	}
}
