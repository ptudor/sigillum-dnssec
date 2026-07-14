package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ptudor/dnssec-validator/internal/config"
)

func TestWithWriteDeadlinePassthrough(t *testing.T) {
	handler := withWriteDeadline(time.Second, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusNoContent)
	}
}

func TestIsCacheableStaticAsset(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{path: "/app.js", want: true},
		{path: "/style.css", want: true},
		{path: "/image.png", want: true},
		{path: "/index.html", want: false},
		{path: "/api/validate", want: false},
	}

	for _, tc := range cases {
		got := isCacheableStaticAsset(tc.path)
		if got != tc.want {
			t.Fatalf("isCacheableStaticAsset(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestNormalizeBasePath(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{input: "", want: ""},
		{input: " /dnssec ", want: "/dnssec"},
		{input: "/dnssec/", want: "/dnssec"},
		{input: "/", want: ""},
	}

	for _, tc := range cases {
		if got := normalizeBasePath(tc.input); got != tc.want {
			t.Fatalf("normalizeBasePath(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestJoinWithBasePath(t *testing.T) {
	cases := []struct {
		base    string
		pattern string
		want    string
	}{
		{base: "", pattern: "/health", want: "/health"},
		{base: "/dnssec", pattern: "/health", want: "/dnssec/health"},
		{base: "/dnssec", pattern: "/", want: "/dnssec/"},
	}

	for _, tc := range cases {
		if got := joinWithBasePath(tc.base, tc.pattern); got != tc.want {
			t.Fatalf("joinWithBasePath(%q, %q) = %q, want %q", tc.base, tc.pattern, got, tc.want)
		}
	}
}

func TestParseCIDRs(t *testing.T) {
	nets, err := parseCIDRs([]string{"203.0.113.0/24", "2001:db8::/32"})
	if err != nil {
		t.Fatalf("parseCIDRs unexpected error: %v", err)
	}
	if len(nets) != 2 {
		t.Fatalf("parseCIDRs length = %d, want 2", len(nets))
	}

	if _, err := parseCIDRs([]string{"bad-cidr"}); err == nil {
		t.Fatal("parseCIDRs expected error for invalid CIDR")
	}
}

func TestAllowCIDRs(t *testing.T) {
	nets, err := parseCIDRs([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatalf("parseCIDRs unexpected error: %v", err)
	}

	allowedHandler := allowCIDRs(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), nets)

	reqAllowed := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	reqAllowed.RemoteAddr = "203.0.113.7:12345"
	rrAllowed := httptest.NewRecorder()
	allowedHandler.ServeHTTP(rrAllowed, reqAllowed)
	if rrAllowed.Code != http.StatusNoContent {
		t.Fatalf("allowed request status = %d, want %d", rrAllowed.Code, http.StatusNoContent)
	}

	reqDenied := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	reqDenied.RemoteAddr = "198.51.100.7:12345"
	rrDenied := httptest.NewRecorder()
	allowedHandler.ServeHTTP(rrDenied, reqDenied)
	if rrDenied.Code != http.StatusForbidden {
		t.Fatalf("denied request status = %d, want %d", rrDenied.Code, http.StatusForbidden)
	}
	if ct := rrDenied.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("denied Content-Type = %q, want application/problem+json", ct)
	}

	var problem ProblemDetails
	if err := json.Unmarshal(rrDenied.Body.Bytes(), &problem); err != nil {
		t.Fatalf("failed to parse problem details: %v", err)
	}
	if problem.Type != ErrTypeForbidden {
		t.Fatalf("problem.Type = %q, want %q", problem.Type, ErrTypeForbidden)
	}
}

// TestMetricsDefaultLoopbackOnly (R-098): with the default configuration the
// /metrics route is served only to loopback clients — a remote client is 403'd,
// a loopback client gets through. This is the end-to-end proof that the
// loopback-only default is actually wired into the route, not just the config.
func TestMetricsDefaultLoopbackOnly(t *testing.T) {
	cfg := config.DefaultConfig()
	store := NewAnchorsStore("/nonexistent", "http://nonexistent")
	s := NewServer(cfg, store)

	// Remote (non-loopback) client: denied.
	reqRemote := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	reqRemote.RemoteAddr = "203.0.113.7:1234"
	wRemote := httptest.NewRecorder()
	s.mux.ServeHTTP(wRemote, reqRemote)
	if wRemote.Code != http.StatusForbidden {
		t.Errorf("non-loopback /metrics status = %d, want 403 (default must be loopback-only)", wRemote.Code)
	}

	// Loopback client: allowed.
	reqLocal := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	reqLocal.RemoteAddr = "127.0.0.1:1234"
	wLocal := httptest.NewRecorder()
	s.mux.ServeHTTP(wLocal, reqLocal)
	if wLocal.Code != http.StatusOK {
		t.Errorf("loopback /metrics status = %d, want 200", wLocal.Code)
	}
}
