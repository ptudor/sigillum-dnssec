//go:build !windows

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/validate"
)

// RDAYBLUEX-026: the per-zone validation endpoint shares the aggregate
// endpoint's contract for a cold validation that outlasts the wait budget —
// 503 with Retry-After and a non-JSON error body — while a stale result is
// still served and the background run seeds the cache.

func TestRDAYBLUEX026_ColdPerZoneTimeoutIs503(t *testing.T) {
	d, _, _, domain := signableZoneDaemon(t)
	d.markReady()
	srv := NewWebServer(d)
	origWait, origFn := validationMaxWait, zoneValidateFn
	validationMaxWait = 100 * time.Millisecond
	// The gate the fake validation blocks on; swapped atomically between
	// phases so a background run never races the test's reassignment.
	var gate atomic.Pointer[chan struct{}]
	release := make(chan struct{})
	gate.Store(&release)
	zoneValidateFn = func(_ *validate.Validator, dom string) *validate.ValidationResult {
		<-*gate.Load()
		return &validate.ValidationResult{Domain: dom}
	}
	// quiesce waits until no background validation is in flight for the
	// zone, so globals are restored only once every run has finished.
	quiesce := func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			dashboardZoneValidationCache.mu.Lock()
			e := dashboardZoneValidationCache.byZone[domain]
			idle := e == nil || e.inflight == nil
			dashboardZoneValidationCache.mu.Unlock()
			if idle {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("background validation did not finish")
	}
	t.Cleanup(func() {
		if g := gate.Load(); g != nil {
			select {
			case <-*g:
			default:
				close(*g)
			}
		}
		quiesce()
		validationMaxWait, zoneValidateFn = origWait, origFn
		dashboardZoneValidationCache.mu.Lock()
		dashboardZoneValidationCache.byZone = map[string]*zoneValEntry{}
		dashboardZoneValidationCache.mu.Unlock()
	})
	get := func() *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		srv.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/validate/"+domain, nil))
		return rr
	}

	rr := get()
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("a cold validation past the budget must be 503, got %d: %s", rr.Code, rr.Body.String())
	}
	if rr.Header().Get("Retry-After") != "5" {
		t.Fatalf("Retry-After must be bounded, got %q", rr.Header().Get("Retry-After"))
	}
	if strings.TrimSpace(rr.Body.String()) == "null" || strings.Contains(rr.Header().Get("Content-Type"), "json") {
		t.Fatalf("no JSON null success body: %q %q", rr.Body.String(), rr.Header().Get("Content-Type"))
	}
	if !strings.Contains(rr.Body.String(), "validation in progress") {
		t.Fatalf("error body: %q", rr.Body.String())
	}

	// Unknown zones stay 404 regardless.
	rr = httptest.NewRecorder()
	srv.Handler.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/validate/nope.example.", nil))
	if rr.Code != http.StatusNotFound {
		t.Fatalf("unknown zone must be 404, got %d", rr.Code)
	}

	// Release the computation: the background run seeds the cache and the
	// next request gets the normal JSON result.
	close(release)
	quiesce()
	rr = get()
	if rr.Code != http.StatusOK || !strings.Contains(rr.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("after the run finishes the result is served: %d %s", rr.Code, rr.Body.String())
	}
	var res validate.ValidationResult
	if err := json.Unmarshal(rr.Body.Bytes(), &res); err != nil || res.Domain != domain {
		t.Fatalf("normal JSON result: %v %+v", err, res)
	}

	// Stale fallback: an expired cached result is served while the refresh
	// runs past the budget, rather than 503.
	dashboardZoneValidationCache.mu.Lock()
	e := dashboardZoneValidationCache.byZone[domain]
	e.computed = time.Now().Add(-validationCacheTTL - time.Minute)
	dashboardZoneValidationCache.mu.Unlock()
	second := make(chan struct{})
	gate.Store(&second)
	rr = get()
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), domain) {
		t.Fatalf("a stale result is still served during a slow refresh: %d %s", rr.Code, rr.Body.String())
	}
	close(second)
	quiesce()
}
