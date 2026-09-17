package api

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestSPAHandlerRootServesIndexWithoutRedirectLoop(t *testing.T) {
	sub := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<!doctype html><title>collector</title>")},
		"app.js":     &fstest.MapFile{Data: []byte("console.log('ok')")},
	}
	fh := http.FileServer(http.FS(fs.FS(sub)))
	h := spaHandler(fh)

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want 200; Location=%q", rr.Code, rr.Header().Get("Location"))
	}
	if got := rr.Header().Get("Location"); got != "" {
		t.Fatalf("GET / unexpectedly redirected to %q", got)
	}
}

func TestSPAHandlerStaticAsset(t *testing.T) {
	sub := fstest.MapFS{"app.js": &fstest.MapFile{Data: []byte("console.log('ok')")}}
	h := spaHandler(http.FileServer(http.FS(fs.FS(sub))))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/app.js", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /app.js status = %d, want 200", rr.Code)
	}
}

func TestEmbeddedPortalHasCSPCompatibleModalClose(t *testing.T) {
	index, err := webFS.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	app, err := webFS.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	combined := string(index) + "\n" + string(app)
	if strings.Contains(combined, `onclick="`) {
		t.Fatal("embedded portal contains inline onclick handler blocked by script-src 'self'")
	}
	if !strings.Contains(string(index), "data-modal-close") {
		t.Fatal("modal close button missing delegated data-modal-close hook")
	}
	if !strings.Contains(string(app), "closest('[data-modal-close]')") {
		t.Fatal("modal delegated close handler missing")
	}
}

func TestSecurityHeadersHardenBrowserSurface(t *testing.T) {
	s := &Server{}
	h := s.securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/", nil))
	for _, name := range []string{"X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy", "Cross-Origin-Opener-Policy", "Content-Security-Policy"} {
		if rr.Header().Get(name) == "" {
			t.Fatalf("missing security header %s", name)
		}
	}
	csp := rr.Header().Get("Content-Security-Policy")
	for _, directive := range []string{"object-src 'none'", "frame-ancestors 'none'", "base-uri 'self'", "form-action 'self'"} {
		if !strings.Contains(csp, directive) {
			t.Fatalf("CSP missing %q: %s", directive, csp)
		}
	}
}

func TestDecodeRejectsTrailingJSONValue(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api", strings.NewReader(`{"name":"one"}{"name":"two"}`))
	var dst struct {
		Name string `json:"name"`
	}
	if decode(rr, req, &dst) {
		t.Fatal("decode accepted multiple JSON values")
	}
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rr.Code)
	}
}
