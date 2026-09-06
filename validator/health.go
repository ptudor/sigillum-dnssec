package main

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/ptudor/sigillum-dnssec/validator/internal/dns"
)

// HealthStatus represents the health check response
type HealthStatus struct {
	Status    string            `json:"status"` // healthy, degraded, unhealthy
	Version   string            `json:"version"`
	BuildTime string            `json:"build_time"`
	Checks    map[string]string `json:"checks,omitempty"`
	Uptime    string            `json:"uptime,omitempty"`
}

// HealthChecker provides health check functionality
type HealthChecker struct {
	startTime    time.Time
	anchorsStore *AnchorsStore
}

// NewHealthChecker creates a new health checker
func NewHealthChecker(anchorsStore *AnchorsStore) *HealthChecker {
	return &HealthChecker{
		startTime:    time.Now(),
		anchorsStore: anchorsStore,
	}
}

// Check performs all health checks
func (h *HealthChecker) Check(ctx context.Context) *HealthStatus {
	status := &HealthStatus{
		Status:    "healthy",
		Version:   Version,
		BuildTime: BuildTime,
		Checks:    make(map[string]string),
		Uptime:    time.Since(h.startTime).Round(time.Second).String(),
	}

	var degraded bool

	// Check root anchors availability. Readiness must reflect whether a
	// currently-ACTIVE, PINNED anchor exists, not merely that the raw set is
	// nonempty: a set consisting only of future-dated, expired, invalid-date or
	// unpinned anchors cannot validate the root and must fail readiness
	// (R-039, RA6X-008).
	if h.anchorsStore != nil {
		anchors := h.anchorsStore.Get()
		switch {
		case anchors == nil || len(anchors.Anchors) == 0:
			status.Checks["root_anchors"] = "unavailable"
			degraded = true
		case len(dns.GetActivePinnedAnchors(anchors)) == 0:
			status.Checks["root_anchors"] = "no active pinned anchor (all future/expired/invalid/unpinned)"
			degraded = true
		default:
			status.Checks["root_anchors"] = "available"
		}
	} else {
		status.Checks["root_anchors"] = "not configured"
		degraded = true
	}

	// Determine overall status
	if degraded {
		status.Status = "degraded"
	}

	return status
}

// HealthHandler returns the detailed health check handler
func (h *HealthChecker) HealthHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		status := h.Check(ctx)

		setSecurityHeaders(w)
		setNoStore(w)
		w.Header().Set("Content-Type", "application/json")

		if status.Status != "healthy" {
			w.WriteHeader(http.StatusServiceUnavailable)
		}

		json.NewEncoder(w).Encode(status)
	}
}

// HealthzHandler returns the simple health check handler (for k8s probes)
func (h *HealthChecker) HealthzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		status := h.Check(ctx)

		setSecurityHeaders(w)
		setNoStore(w)
		w.Header().Set("Content-Type", "text/plain")

		// /healthz is a readiness probe endpoint. Any non-healthy state is not ready.
		if status.Status != "healthy" {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte("NOT_READY"))
			return
		}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}
}

// setSecurityHeaders sets standard security headers
func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	// Modern browsers ignore X-XSS-Protection, and the legacy auditor it enabled has
	// itself been a source of side-channel issues; current OWASP guidance is to send 0
	// to disable it and rely on the strict CSP above.
	w.Header().Set("X-XSS-Protection", "0")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
	w.Header().Set("X-Permitted-Cross-Domain-Policies", "none")
	// Note: HSTS should be configured at the reverse proxy level
	// to avoid issues with subdomains that may not support HTTPS
}

func setNoStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
}
