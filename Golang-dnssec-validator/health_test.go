package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ptudor/dnssec-validator/internal/dns"
)

func TestHealthzHandler_NotReadyWithoutAnchors(t *testing.T) {
	store := NewAnchorsStore("/nonexistent", "http://nonexistent")
	hc := NewHealthChecker(store)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	hc.HealthzHandler()(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	if got := w.Body.String(); got != "NOT_READY" {
		t.Fatalf("body = %q, want %q", got, "NOT_READY")
	}
}

func TestHealthzHandler_ReadyWithAnchors(t *testing.T) {
	store := NewAnchorsStore("/nonexistent", "http://nonexistent")
	store.anchors = &dns.RootAnchors{
		Zone: ".",
		Anchors: []dns.Anchor{
			{
				KeyTag:    20326,
				Algorithm: 8,
				Digest:    "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
				ValidFrom: "2017-02-02T00:00:00Z",
			},
		},
	}
	store.loadedAt = time.Now()

	hc := NewHealthChecker(store)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()

	hc.HealthzHandler()(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}
	if got := w.Body.String(); got != "OK" {
		t.Fatalf("body = %q, want %q", got, "OK")
	}
}
