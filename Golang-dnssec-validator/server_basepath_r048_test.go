package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// R-048: the exact configured base path must redirect to its slash form (so
// browser-relative asset/API URLs resolve under the prefix), preserving the query
// string and the request method.
func TestR048_BasePathRedirectsToSlash(t *testing.T) {
	cfg := DefaultConfig()
	cfg.BasePath = "/dnssec"
	store := NewAnchorsStore("/nonexistent", "http://nonexistent")
	s := NewServer(cfg, store)

	// Exact base path (no trailing slash) → 308 to "/dnssec/".
	req := httptest.NewRequest(http.MethodGet, "/dnssec?domain=example.com&mode=quick", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusPermanentRedirect {
		t.Fatalf("exact base path status = %d, want 308", w.Code)
	}
	loc := w.Header().Get("Location")
	if loc != "/dnssec/?domain=example.com&mode=quick" {
		t.Fatalf("redirect Location = %q, want /dnssec/?domain=example.com&mode=quick", loc)
	}

	// HEAD is also redirected (method preserved by 308).
	reqHead := httptest.NewRequest(http.MethodHead, "/dnssec", nil)
	wHead := httptest.NewRecorder()
	s.mux.ServeHTTP(wHead, reqHead)
	if wHead.Code != http.StatusPermanentRedirect {
		t.Fatalf("HEAD exact base path status = %d, want 308", wHead.Code)
	}
}
