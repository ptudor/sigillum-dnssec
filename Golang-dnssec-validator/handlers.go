package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ptudor/dnssec-validator/internal/rdap"
	"github.com/ptudor/dnssec-validator/internal/validator"
)

// Handlers contains HTTP handlers for the validator
type Handlers struct {
	anchorsStore *AnchorsStore
	config       *Config
	rdapClient   *rdap.Client
}

// NewHandlers creates new HTTP handlers
func NewHandlers(anchorsStore *AnchorsStore, config *Config) *Handlers {
	var rdapClient *rdap.Client
	if config.RDAPBaseURL != "" {
		rdapClient = rdap.NewClient(config.RDAPBaseURL, config.QueryTimeout)
	}
	return &Handlers{
		anchorsStore: anchorsStore,
		config:       config,
		rdapClient:   rdapClient,
	}
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

	// Set retry interval
	sse.WriteRetry(3000)

	// Get anchors
	anchors := h.anchorsStore.Get()
	if anchors == nil || len(anchors.Anchors) == 0 {
		statusCode = "503"
		sse.WriteEvent("error", validator.ErrorEvent{
			Message: "root trust anchors not available",
			Fatal:   true,
		})
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

	// Set up event callback
	v.SetEventCallback(func(event validator.SSEEvent) {
		sse.WriteEvent(event.Type, event.Data)
	})

	// Create context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), h.config.TotalTimeout)
	defer cancel()

	// Run validation
	result, err := v.Validate(ctx, domain)
	if err != nil && result == nil {
		statusCode = "500"
		sse.WriteEvent("error", validator.ErrorEvent{
			Message: err.Error(),
			Fatal:   true,
		})
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

	// Create context with timeout
	ctx, cancel := context.WithTimeout(r.Context(), h.config.TotalTimeout)
	defer cancel()

	// Run validation
	result, err := v.Validate(ctx, domain)
	if err != nil && result == nil {
		writeProblemDetails(w, ErrTypeValidationFailed, "Validation Failed",
			http.StatusInternalServerError, err.Error(), r.URL.Path)
		RecordAPIRequest("/api/validate", r.Method, "500", time.Since(startTime).Seconds())
		return
	}

	// Record metrics
	RecordValidation(string(result.Result), float64(result.DurationMs)/1000.0)
	LogValidation(requestID, domain, string(result.Result), result.DurationMs)

	// Write JSON response
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
	RecordAPIRequest("/api/validate", r.Method, "200", time.Since(startTime).Seconds())
}

// HandleAnchors returns the current root trust anchors
func (h *Handlers) HandleAnchors(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	defer func() {
		RecordAPIRequest("/api/anchors", r.Method, "200", time.Since(startTime).Seconds())
	}()

	if r.Method != http.MethodGet {
		writeProblemDetails(w, ErrTypeMethodNotAllowed, "Method Not Allowed",
			http.StatusMethodNotAllowed, "only GET method is supported", r.URL.Path)
		return
	}

	anchors := h.anchorsStore.Get()
	if anchors == nil {
		writeProblemDetails(w, ErrTypeServiceUnavailable, "Service Unavailable",
			http.StatusServiceUnavailable, "root trust anchors not available", r.URL.Path)
		return
	}

	setSecurityHeaders(w)
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
