package api

import (
	product "central-flow-collector"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPublicAboutAndEmbeddedLicense(t *testing.T) {
	// Attribution must work before sign-in and without collector/storage services.
	s := New(nil, nil, nil, nil, nil, nil, nil, nil)
	response := httptest.NewRecorder()
	s.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/v1/about", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("about status %d", response.Code)
	}
	var metadata struct {
		Product struct {
			Developer  string `json:"developer"`
			Email      string `json:"email"`
			Source     string `json:"source"`
			License    string `json:"license"`
			LicenseURL string `json:"license_url"`
		} `json:"product"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &metadata); err != nil {
		t.Fatal(err)
	}
	if metadata.Product.Developer != "Cuma KURT" || metadata.Product.Email != "cumakurt@gmail.com" || metadata.Product.Source != "https://github.com/cumakurt/central-flow-collector" || metadata.Product.License != "AGPL-3.0-only" || metadata.Version == "" {
		t.Fatalf("incorrect attribution: %+v", metadata)
	}
	response = httptest.NewRecorder()
	s.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, metadata.Product.LicenseURL, nil))
	if response.Code != http.StatusOK || !strings.HasPrefix(response.Header().Get("Content-Type"), "text/plain") {
		t.Fatalf("license response: %d %v", response.Code, response.Header())
	}
	if response.Body.String() != product.LicenseText || response.Body.Len() < 30000 || !strings.Contains(response.Body.String(), "Remote Network Interaction") {
		t.Fatal("license route must serve the complete embedded document")
	}
}
