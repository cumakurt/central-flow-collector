package enrichment

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRemoteCountryCodeAndPrivateFiltering(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"success":true,"country":"United States","country_code":"US","city":"Example","connection":{"asn":15169}}`))
	}))
	defer server.Close()
	e, err := NewWithRemote(t.TempDir(), true, "", true, server.URL)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"", "invalid", "127.0.0.1", "10.0.0.1", "::1", "169.254.0.1", "100.64.0.1", "203.0.113.1"} {
		if _, ok := e.remoteLookup(ip); ok {
			t.Fatalf("unexpected result for %s", ip)
		}
	}
	if calls != 0 {
		t.Fatal("non-public addresses sent externally")
	}
	for i := 0; i < 2; i++ {
		g := e.LookupIP("8.8.8.8")
		if g.Country != "US" || g.ASN != 15169 {
			t.Fatalf("invalid location: %+v", g)
		}
	}
	if calls != 1 {
		t.Fatalf("cache failed: %d requests", calls)
	}
}
