package main

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ptudor/dnssec-validator/internal/config"
)

// R-086: a global cap bounds concurrent validations. The N+1th request is
// rejected with 503 + Retry-After before any work starts.
func TestValidationConcurrencyCap_RejectsWhenFull(t *testing.T) {
	store := NewAnchorsStore("/nonexistent", "https://nonexistent.invalid")
	cfg := config.DefaultConfig()
	cfg.MaxConcurrentValidations = 1
	h := NewHandlers(store, cfg)

	// Occupy the only slot.
	if !h.acquireValidationSlot() {
		t.Fatal("first acquire should succeed")
	}

	// A request arriving while at capacity is rejected before touching anchors/DNS.
	rr := httptest.NewRecorder()
	h.HandleValidateJSON(rr, httptest.NewRequest(http.MethodGet, "/api/validate?domain=example.com", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 at capacity, got %d (body: %s)", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("expected Retry-After header on a capacity rejection")
	}
	if !strings.Contains(rr.Body.String(), "capacity") {
		t.Errorf("expected a capacity message, got: %s", rr.Body.String())
	}

	// Freeing the slot lets a new validation proceed past the cap.
	h.releaseValidationSlot()
	if !h.acquireValidationSlot() {
		t.Error("acquire should succeed after a release")
	}
	h.releaseValidationSlot()
}

// R-086: the slot semaphore holds exactly MaxConcurrentValidations tokens.
func TestAcquireValidationSlot_HardCap(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.MaxConcurrentValidations = 3
	h := NewHandlers(NewAnchorsStore("/x", "https://x.invalid"), cfg)

	for i := 0; i < 3; i++ {
		if !h.acquireValidationSlot() {
			t.Fatalf("acquire %d should succeed within cap", i)
		}
	}
	if h.acquireValidationSlot() {
		t.Fatal("acquire past the cap must fail")
	}
	h.releaseValidationSlot()
	if !h.acquireValidationSlot() {
		t.Fatal("acquire should succeed after a release")
	}
}

// R-087: a cleartext root_anchors_url is rejected at config validation.
func TestValidate_RootAnchorsURLRequiresHTTPS(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.RootAnchorsURL = "http://internet.any53.com/dns/anchors/root-anchors.json"
	err := cfg.Validate()
	if err == nil {
		t.Fatal("expected error for cleartext root_anchors_url")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("error should mention https, got: %v", err)
	}

	// https:// and an empty URL both pass.
	cfg.RootAnchorsURL = "https://internet.any53.com/dns/anchors/root-anchors.json"
	if err := cfg.Validate(); err != nil {
		t.Errorf("https URL should validate, got: %v", err)
	}
	cfg.RootAnchorsURL = ""
	if err := cfg.Validate(); err != nil {
		t.Errorf("empty URL should validate (file-only), got: %v", err)
	}
}

// R-087: max_concurrent_validations must be positive.
func TestValidate_MaxConcurrentValidationsPositive(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.MaxConcurrentValidations = 0
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for non-positive max_concurrent_validations")
	}
}

// R-091: the per-IP bucket map is bounded even under churn of many unique IPs
// within a single cleanup interval.
func TestRateLimiter_BoundedByMaxBuckets(t *testing.T) {
	rl := NewRateLimiter(10, 30, 5*time.Minute)
	defer rl.Stop()
	rl.maxBuckets = 100

	// Churn far more unique IPs than the cap, all fresh (none stale).
	for i := 0; i < 5000; i++ {
		rl.Allow("10." + strconv.Itoa(i/256%256) + "." + strconv.Itoa(i%256) + ".1:1234")
	}

	rl.mu.Lock()
	n := len(rl.limiters)
	rl.mu.Unlock()
	if n > rl.maxBuckets {
		t.Errorf("bucket map grew to %d, exceeding cap %d (R-091 memory DoS)", n, rl.maxBuckets)
	}
}
