package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ptudor/dnssec-validator/internal/dns"
)

// R-039: a nonempty anchor set with NO currently-active anchor (all future-dated,
// expired, or invalid-date) must fail readiness — it is unavailable trust, not a
// bogus root.
func TestHealthz_NotReadyWithNoActiveAnchor(t *testing.T) {
	future := time.Now().Add(365 * 24 * time.Hour).Format(time.RFC3339)
	store := NewAnchorsStore("/nonexistent", "http://nonexistent")
	store.anchors = &dns.RootAnchors{
		Zone: ".",
		Anchors: []dns.Anchor{{
			KeyTag:    20326,
			Algorithm: 8,
			Digest:    "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
			ValidFrom: future, // not yet valid → no active anchor
		}},
	}
	store.loadedAt = time.Now()

	hc := NewHealthChecker(store)

	// Detailed check should report degraded with an explicit no-active-anchor note.
	st := hc.Check(context.Background())
	if st.Status == "healthy" {
		t.Fatalf("health must not be healthy with zero active anchors: %+v", st.Checks)
	}
	if got := st.Checks["root_anchors"]; got == "available" {
		t.Fatalf("root_anchors check must not read 'available' with no active anchor")
	}

	// Readiness probe must be NOT_READY.
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	hc.HealthzHandler()(w, req)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("/healthz status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}
