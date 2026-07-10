package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ptudor/dnssec-validator/internal/rdap"
	"github.com/ptudor/dnssec-validator/internal/validator"
)

// Handlers contains HTTP handlers for the validator
type Handlers struct {
	anchorsStore *AnchorsStore
	config       *Config
	rdapClient   *rdap.Client

	// validationSem globally caps concurrent validations (R-086). Each extended
	// validation fans out to every authoritative NS of every zone in the chain,
	// so without a global bound a modest number of concurrent requests becomes a
	// large volume of outbound DNS (an amplifier) and many goroutines.
	validationSem chan struct{}
}

// NewHandlers creates new HTTP handlers
func NewHandlers(anchorsStore *AnchorsStore, config *Config) *Handlers {
	var rdapClient *rdap.Client
	if config.RDAPBaseURL != "" {
		rdapClient = rdap.NewClient(config.RDAPBaseURL, config.QueryTimeout)
	}
	max := config.MaxConcurrentValidations
	if max <= 0 {
		max = 100 // defensive: Validate() rejects <= 0, but never build a nil/0 semaphore
	}
	return &Handlers{
		anchorsStore:  anchorsStore,
		config:        config,
		rdapClient:    rdapClient,
		validationSem: make(chan struct{}, max),
	}
}

// acquireValidationSlot takes a global validation slot without blocking and
// bumps the in-flight gauge on success, tying the gauge to the real in-flight
// count. Returns false when at capacity (R-086).
func (h *Handlers) acquireValidationSlot() bool {
	select {
	case h.validationSem <- struct{}{}:
		IncrementActiveValidations()
		return true
	default:
		return false
	}
}

// releaseValidationSlot returns a slot and decrements the in-flight gauge.
func (h *Handlers) releaseValidationSlot() {
	<-h.validationSem
	DecrementActiveValidations()
}

// HandleValidateSSE handles SSE validation requests
func (h *Handlers) HandleValidateSSE(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	statusCode := "200" // Track actual status for metrics
	requestID := GenerateRequestID()

	// Set request ID header for tracing
	w.Header().Set("X-Request-ID", requestID)

	defer func() {
		RecordAPIRequest("/validate", r.Method, statusCode, time.Since(startTime).Seconds())
	}()

	// Log incoming request
	LogRequest(requestID, r.Method, r.URL.Path, extractClientIP(r))

	// Only GET requests
	if r.Method != http.MethodGet {
		statusCode = "405"
		writeProblemDetails(w, ErrTypeMethodNotAllowed, "Method Not Allowed",
			http.StatusMethodNotAllowed, "only GET method is supported", r.URL.Path)
		return
	}

	// Get domain parameter
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		statusCode = "400"
		writeProblemDetails(w, ErrTypeInvalidDomain, "Invalid Domain",
			http.StatusBadRequest, "domain parameter is required", r.URL.Path)
		return
	}

	// Validate domain format
	domain = strings.TrimSpace(domain)
	if !isValidDomain(domain) {
		statusCode = "400"
		writeProblemDetails(w, ErrTypeInvalidDomain, "Invalid Domain",
			http.StatusBadRequest, "invalid domain name format", r.URL.Path)
		return
	}

	// Get mode parameter (quick or extended)
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "extended"
	}

	// Enforce the global concurrency cap before committing to any work or SSE
	// headers: reject with 503 + Retry-After when at capacity (R-086).
	if !h.acquireValidationSlot() {
		statusCode = "503"
		w.Header().Set("Retry-After", "5")
		writeProblemDetails(w, ErrTypeServiceUnavailable, "Service Unavailable",
			http.StatusServiceUnavailable, "server is at validation capacity; please retry shortly", r.URL.Path)
		return
	}
	defer h.releaseValidationSlot()

	// Create SSE writer
	sse, err := NewSSEWriter(w)
	if err != nil {
		statusCode = "500"
		writeProblemDetails(w, ErrTypeInternalServerError, "Internal Server Error",
			http.StatusInternalServerError, "streaming not supported", r.URL.Path)
		return
	}

	IncrementActiveSSEConnections()
	defer DecrementActiveSSEConnections()

	// Create context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), h.config.TotalTimeout)
	defer cancel()

	// Stop validation work immediately if SSE writes fail (e.g., client disconnected).
	var cancelOnce sync.Once
	cancelOnWriteError := func(err error, eventType string) {
		if err == nil {
			return
		}
		cancelOnce.Do(func() {
			LogWarn("handlers", "sse write failed; canceling validation",
				"event", eventType,
				"request_id", requestID,
				"domain", domain,
				"error", err.Error(),
			)
			cancel()
		})
	}

	// Set retry interval
	if err := sse.WriteRetry(3000); err != nil {
		cancelOnWriteError(err, "retry")
		return
	}

	// Get anchors
	anchors := h.anchorsStore.Get()
	if anchors == nil || len(anchors.Anchors) == 0 {
		statusCode = "503"
		err := sse.WriteEvent("error", validator.ErrorEvent{
			Message: "root trust anchors not available",
			Fatal:   true,
		})
		cancelOnWriteError(err, "error")
		return
	}

	// Create validator
	v := validator.NewValidator(
		h.config.QueryTimeout,
		h.config.TotalTimeout,
		h.config.MaxConcurrent,
		anchors,
		h.config.RecursiveResolver,
	)

	// Set RDAP client for out-of-band DS verification
	if h.rdapClient != nil {
		v.SetRDAPClient(h.rdapClient)
	}

	// Set validation mode (quick = first responding NS, extended = all NS)
	if mode == "quick" {
		v.SetQuickMode(true)
	}

	// Set up event callback
	v.SetEventCallback(func(event validator.SSEEvent) {
		cancelOnWriteError(sse.WriteEvent(event.Type, event.Data), event.Type)
	})

	// Run validation
	result, err := v.Validate(ctx, domain)
	if err != nil && result == nil {
		statusCode = "500"
		LogError("handlers", err, "action", "validate_sse", "request_id", requestID, "domain", domain)
		writeErr := sse.WriteEvent("error", validator.ErrorEvent{
			Message: fmt.Sprintf("validation failed (request_id=%s)", requestID),
			Fatal:   true,
		})
		cancelOnWriteError(writeErr, "error")
		return
	}

	// Record metrics
	RecordValidation(string(result.Result), float64(result.DurationMs)/1000.0)
	LogValidation(requestID, domain, string(result.Result), result.DurationMs)
}

// HandleValidateJSON handles JSON validation requests
func (h *Handlers) HandleValidateJSON(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	requestID := GenerateRequestID()

	// Set request ID header for tracing
	w.Header().Set("X-Request-ID", requestID)

	// Log incoming request
	LogRequest(requestID, r.Method, r.URL.Path, extractClientIP(r))

	// Only GET requests
	if r.Method != http.MethodGet {
		writeProblemDetails(w, ErrTypeMethodNotAllowed, "Method Not Allowed",
			http.StatusMethodNotAllowed, "only GET method is supported", r.URL.Path)
		RecordAPIRequest("/api/validate", r.Method, "405", time.Since(startTime).Seconds())
		return
	}

	// Get domain parameter
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		writeProblemDetails(w, ErrTypeInvalidDomain, "Invalid Domain",
			http.StatusBadRequest, "domain parameter is required", r.URL.Path)
		RecordAPIRequest("/api/validate", r.Method, "400", time.Since(startTime).Seconds())
		return
	}

	// Validate domain format
	domain = strings.TrimSpace(domain)
	if !isValidDomain(domain) {
		writeProblemDetails(w, ErrTypeInvalidDomain, "Invalid Domain",
			http.StatusBadRequest, "invalid domain name format", r.URL.Path)
		RecordAPIRequest("/api/validate", r.Method, "400", time.Since(startTime).Seconds())
		return
	}

	// Get mode parameter (quick or extended)
	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "extended"
	}

	// Enforce the global concurrency cap before starting work (R-086).
	if !h.acquireValidationSlot() {
		w.Header().Set("Retry-After", "5")
		writeProblemDetails(w, ErrTypeServiceUnavailable, "Service Unavailable",
			http.StatusServiceUnavailable, "server is at validation capacity; please retry shortly", r.URL.Path)
		RecordAPIRequest("/api/validate", r.Method, "503", time.Since(startTime).Seconds())
		return
	}
	defer h.releaseValidationSlot()

	// Get anchors
	anchors := h.anchorsStore.Get()
	if anchors == nil || len(anchors.Anchors) == 0 {
		writeProblemDetails(w, ErrTypeServiceUnavailable, "Service Unavailable",
			http.StatusServiceUnavailable, "root trust anchors not available", r.URL.Path)
		RecordAPIRequest("/api/validate", r.Method, "503", time.Since(startTime).Seconds())
		return
	}

	// Create validator
	v := validator.NewValidator(
		h.config.QueryTimeout,
		h.config.TotalTimeout,
		h.config.MaxConcurrent,
		anchors,
		h.config.RecursiveResolver,
	)

	// Set RDAP client for out-of-band DS verification
	if h.rdapClient != nil {
		v.SetRDAPClient(h.rdapClient)
	}

	// Set validation mode (quick = first responding NS, extended = all NS)
	if mode == "quick" {
		v.SetQuickMode(true)
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), h.config.TotalTimeout)
	defer cancel()

	// Run validation
	result, err := v.Validate(ctx, domain)
	if err != nil && result == nil {
		LogError("handlers", err, "action", "validate_json", "request_id", requestID, "domain", domain)
		writeProblemDetails(w, ErrTypeValidationFailed, "Validation Failed",
			http.StatusInternalServerError, fmt.Sprintf("validation failed (request_id=%s)", requestID), r.URL.Path)
		RecordAPIRequest("/api/validate", r.Method, "500", time.Since(startTime).Seconds())
		return
	}

	// Record metrics
	RecordValidation(string(result.Result), float64(result.DurationMs)/1000.0)
	LogValidation(requestID, domain, string(result.Result), result.DurationMs)

	// Write JSON response
	setSecurityHeaders(w)
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
	RecordAPIRequest("/api/validate", r.Method, "200", time.Since(startTime).Seconds())
}

// HandleAnchors returns the current root trust anchors
func (h *Handlers) HandleAnchors(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	statusCode := "200"
	defer func() {
		RecordAPIRequest("/api/anchors", r.Method, statusCode, time.Since(startTime).Seconds())
	}()

	if r.Method != http.MethodGet {
		statusCode = "405"
		writeProblemDetails(w, ErrTypeMethodNotAllowed, "Method Not Allowed",
			http.StatusMethodNotAllowed, "only GET method is supported", r.URL.Path)
		return
	}

	anchors := h.anchorsStore.Get()
	if anchors == nil {
		statusCode = "503"
		writeProblemDetails(w, ErrTypeServiceUnavailable, "Service Unavailable",
			http.StatusServiceUnavailable, "root trust anchors not available", r.URL.Path)
		return
	}

	setSecurityHeaders(w)
	setNoStore(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(anchors)
}

// isValidDomain performs basic domain name validation
func isValidDomain(domain string) bool {
	// Remove trailing dot if present
	domain = strings.TrimSuffix(domain, ".")

	if domain == "" {
		return false
	}

	// Check length
	if len(domain) > 253 {
		return false
	}

	// Split into labels
	labels := strings.Split(domain, ".")
	if len(labels) == 0 {
		return false
	}

	for _, label := range labels {
		// Check label length
		if len(label) == 0 || len(label) > 63 {
			return false
		}

		// Check characters (basic validation)
		for i, c := range label {
			if c == '-' {
				// Hyphen not allowed at start or end
				if i == 0 || i == len(label)-1 {
					return false
				}
			} else if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
				return false
			}
		}
	}

	return true
}
