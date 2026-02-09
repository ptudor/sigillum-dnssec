package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ptudor/dnssec-validator/internal/dns"
)

type failingSSEWriter struct {
	header http.Header
}

func (w *failingSSEWriter) Header() http.Header {
	return w.header
}

func (w *failingSSEWriter) WriteHeader(statusCode int) {}

func (w *failingSSEWriter) Write(p []byte) (int, error) {
	return 0, errors.New("forced write failure")
}

func (w *failingSSEWriter) Flush() {}

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected bool
	}{
		// Valid domains
		{name: "simple domain", domain: "example.com", expected: true},
		{name: "subdomain", domain: "www.example.com", expected: true},
		{name: "deep subdomain", domain: "a.b.c.example.com", expected: true},
		{name: "with trailing dot", domain: "example.com.", expected: true},
		{name: "TLD only", domain: "com", expected: true},
		{name: "numeric subdomain", domain: "123.example.com", expected: true},
		{name: "hyphen in middle", domain: "my-domain.com", expected: true},
		{name: "alphanumeric", domain: "abc123.com", expected: true},
		{name: "single char labels", domain: "a.b.c", expected: true},
		{name: "underscore (DNS allows)", domain: "_dmarc.example.com", expected: true},

		// Invalid domains
		{name: "empty string", domain: "", expected: false},
		{name: "just dot", domain: ".", expected: false},
		{name: "double dot", domain: "example..com", expected: false},
		{name: "leading dot", domain: ".example.com", expected: false},
		{name: "hyphen at start", domain: "-example.com", expected: false},
		{name: "hyphen at end", domain: "example-.com", expected: false},
		{name: "label too long", domain: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.com", expected: false}, // 65 chars
		{name: "domain too long", domain: string(make([]byte, 254)) + ".com", expected: false},
		{name: "special chars", domain: "exam!ple.com", expected: false},
		{name: "space in domain", domain: "exam ple.com", expected: false},
		{name: "unicode", domain: "exämple.com", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidDomain(tt.domain)
			if result != tt.expected {
				t.Errorf("isValidDomain(%q) = %v, expected %v", tt.domain, result, tt.expected)
			}
		})
	}
}

func TestIsValidDomainEdgeCases(t *testing.T) {
	// Test maximum valid label length (63 chars)
	maxLabel := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // 63 chars
	if !isValidDomain(maxLabel + ".com") {
		t.Errorf("Domain with 63-char label should be valid")
	}

	// Test one over max label length (64 chars)
	overMaxLabel := maxLabel + "a" // 64 chars
	if isValidDomain(overMaxLabel + ".com") {
		t.Errorf("Domain with 64-char label should be invalid")
	}

	// Test a long domain with many short labels
	// Build a domain like a.a.a.a.a.a... up to near the 253 char limit
	longDomain := ""
	for i := 0; i < 125; i++ { // 125 * 2 = 250 chars ("a." repeated)
		longDomain += "a."
	}
	longDomain += "com" // Now ~253 chars
	// Just verify it doesn't panic
	_ = isValidDomain(longDomain)
}

// newTestHandlers creates Handlers with a pre-loaded anchors store for testing.
func newTestHandlers(withAnchors bool) *Handlers {
	store := NewAnchorsStore("/nonexistent", "http://nonexistent")
	if withAnchors {
		// Directly set anchors on the store to avoid network calls
		store.anchors = &dns.RootAnchors{
			Source:      "test",
			Zone:        ".",
			GeneratedAt: "2024-01-01T00:00:00Z",
			Anchors: []dns.Anchor{
				{
					ID:        "KSK-2024",
					KeyTag:    20326,
					Algorithm: 8,
					Digest:    "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
					ValidFrom: "2017-02-02T00:00:00Z",
					Flags:     257,
				},
			},
			LoadedFrom: "test",
		}
		store.loadedAt = time.Now()
	}
	cfg := DefaultConfig()
	return NewHandlers(store, cfg)
}

// TestHandleAnchors_GET tests the happy path for anchors endpoint
func TestHandleAnchors_GET(t *testing.T) {
	h := newTestHandlers(true)
	req := httptest.NewRequest(http.MethodGet, "/api/anchors", nil)
	w := httptest.NewRecorder()

	h.HandleAnchors(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", ct)
	}

	// Verify security headers are set
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options header")
	}

	// Parse response
	var anchors dns.RootAnchors
	if err := json.Unmarshal(w.Body.Bytes(), &anchors); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(anchors.Anchors) != 1 {
		t.Errorf("anchors count = %d, want 1", len(anchors.Anchors))
	}
}

// TestHandleAnchors_MethodNotAllowed tests POST to anchors endpoint
func TestHandleAnchors_MethodNotAllowed(t *testing.T) {
	h := newTestHandlers(true)
	req := httptest.NewRequest(http.MethodPost, "/api/anchors", nil)
	w := httptest.NewRecorder()

	h.HandleAnchors(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}

	var problem ProblemDetails
	if err := json.Unmarshal(w.Body.Bytes(), &problem); err != nil {
		t.Fatalf("failed to parse problem details: %v", err)
	}

	if problem.Status != 405 {
		t.Errorf("problem.Status = %d, want 405", problem.Status)
	}
}

// TestHandleAnchors_NoAnchors tests when anchors haven't been loaded
func TestHandleAnchors_NoAnchors(t *testing.T) {
	h := newTestHandlers(false)
	req := httptest.NewRequest(http.MethodGet, "/api/anchors", nil)
	w := httptest.NewRecorder()

	h.HandleAnchors(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}

	var problem ProblemDetails
	if err := json.Unmarshal(w.Body.Bytes(), &problem); err != nil {
		t.Fatalf("failed to parse problem details: %v", err)
	}

	if problem.Status != 503 {
		t.Errorf("problem.Status = %d, want 503", problem.Status)
	}
}

// TestHandleValidateJSON_MissingDomain tests missing domain parameter
func TestHandleValidateJSON_MissingDomain(t *testing.T) {
	h := newTestHandlers(true)
	req := httptest.NewRequest(http.MethodGet, "/api/validate", nil)
	w := httptest.NewRecorder()

	h.HandleValidateJSON(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var problem ProblemDetails
	if err := json.Unmarshal(w.Body.Bytes(), &problem); err != nil {
		t.Fatalf("failed to parse problem details: %v", err)
	}

	if problem.Type != ErrTypeInvalidDomain {
		t.Errorf("problem.Type = %q, want %q", problem.Type, ErrTypeInvalidDomain)
	}
}

// TestHandleValidateJSON_InvalidDomain tests invalid domain format
func TestHandleValidateJSON_InvalidDomain(t *testing.T) {
	h := newTestHandlers(true)
	req := httptest.NewRequest(http.MethodGet, "/api/validate?domain=-invalid-.com", nil)
	w := httptest.NewRecorder()

	h.HandleValidateJSON(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestHandleValidateJSON_MethodNotAllowed tests POST to validate endpoint
func TestHandleValidateJSON_MethodNotAllowed(t *testing.T) {
	h := newTestHandlers(true)
	req := httptest.NewRequest(http.MethodPost, "/api/validate?domain=example.com", nil)
	w := httptest.NewRecorder()

	h.HandleValidateJSON(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// TestHandleValidateJSON_NoAnchors tests when anchors are unavailable
func TestHandleValidateJSON_NoAnchors(t *testing.T) {
	h := newTestHandlers(false)
	req := httptest.NewRequest(http.MethodGet, "/api/validate?domain=example.com", nil)
	w := httptest.NewRecorder()

	h.HandleValidateJSON(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
}

// TestHandleValidateSSE_MissingDomain tests SSE endpoint with missing domain
func TestHandleValidateSSE_MissingDomain(t *testing.T) {
	h := newTestHandlers(true)
	req := httptest.NewRequest(http.MethodGet, "/validate", nil)
	w := httptest.NewRecorder()

	h.HandleValidateSSE(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestHandleValidateSSE_InvalidDomain tests SSE endpoint with invalid domain
func TestHandleValidateSSE_InvalidDomain(t *testing.T) {
	h := newTestHandlers(true)
	req := httptest.NewRequest(http.MethodGet, "/validate?domain=exam!ple.com", nil)
	w := httptest.NewRecorder()

	h.HandleValidateSSE(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}
}

// TestHandleValidateSSE_MethodNotAllowed tests POST to SSE endpoint
func TestHandleValidateSSE_MethodNotAllowed(t *testing.T) {
	h := newTestHandlers(true)
	req := httptest.NewRequest(http.MethodPost, "/validate?domain=example.com", nil)
	w := httptest.NewRecorder()

	h.HandleValidateSSE(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want %d", w.Code, http.StatusMethodNotAllowed)
	}
}

// TestHandleValidateSSE_WriteFailureReturnsQuickly verifies that SSE write errors
// stop handler processing promptly instead of continuing expensive validation work.
func TestHandleValidateSSE_WriteFailureReturnsQuickly(t *testing.T) {
	h := newTestHandlers(true)
	// Keep timeout low to ensure this test can't hang on external DNS work.
	h.config.TotalTimeout = 1 * time.Second

	req := httptest.NewRequest(http.MethodGet, "/validate?domain=example.com", nil)
	w := &failingSSEWriter{header: make(http.Header)}

	done := make(chan struct{})
	go func() {
		h.HandleValidateSSE(w, req)
		close(done)
	}()

	select {
	case <-done:
		// success
	case <-time.After(250 * time.Millisecond):
		t.Fatal("HandleValidateSSE did not return promptly after SSE write failure")
	}
}

// TestWriteProblemDetails tests RFC 7807 response formatting
func TestWriteProblemDetails(t *testing.T) {
	w := httptest.NewRecorder()
	writeProblemDetails(w, ErrTypeInvalidDomain, "Invalid Domain",
		http.StatusBadRequest, "domain is invalid", "/api/validate")

	if w.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/problem+json" {
		t.Errorf("Content-Type = %q, want application/problem+json", ct)
	}

	var problem ProblemDetails
	if err := json.Unmarshal(w.Body.Bytes(), &problem); err != nil {
		t.Fatalf("failed to parse problem details: %v", err)
	}

	if problem.Type != ErrTypeInvalidDomain {
		t.Errorf("Type = %q, want %q", problem.Type, ErrTypeInvalidDomain)
	}
	if problem.Title != "Invalid Domain" {
		t.Errorf("Title = %q, want %q", problem.Title, "Invalid Domain")
	}
	if problem.Status != 400 {
		t.Errorf("Status = %d, want 400", problem.Status)
	}
	if problem.Detail != "domain is invalid" {
		t.Errorf("Detail = %q, want %q", problem.Detail, "domain is invalid")
	}
	if problem.Instance != "/api/validate" {
		t.Errorf("Instance = %q, want %q", problem.Instance, "/api/validate")
	}
}

// TestWriteJSONError tests the convenience error wrapper
func TestWriteJSONError(t *testing.T) {
	tests := []struct {
		name           string
		message        string
		status         int
		expectedType   string
		expectedTitle  string
		expectedDetail string
	}{
		{
			name:           "bad request",
			message:        "missing field",
			status:         400,
			expectedType:   ErrTypeBadRequest,
			expectedTitle:  "Bad Request",
			expectedDetail: "missing field",
		},
		{
			name:           "not found",
			message:        "resource not found",
			status:         404,
			expectedType:   ErrTypeNotFound,
			expectedTitle:  "Not Found",
			expectedDetail: "resource not found",
		},
		{
			name:           "internal error masks detail",
			message:        "secret database error",
			status:         500,
			expectedType:   ErrTypeInternalServerError,
			expectedTitle:  "Internal Server Error",
			expectedDetail: "internal server error", // masked
		},
		{
			name:           "service unavailable",
			message:        "backend down",
			status:         503,
			expectedType:   ErrTypeServiceUnavailable,
			expectedTitle:  "Service Unavailable",
			expectedDetail: "backend down",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			writeJSONError(w, tt.message, tt.status)

			if w.Code != tt.status {
				t.Errorf("status = %d, want %d", w.Code, tt.status)
			}

			var problem ProblemDetails
			if err := json.Unmarshal(w.Body.Bytes(), &problem); err != nil {
				t.Fatalf("failed to parse: %v", err)
			}

			if problem.Type != tt.expectedType {
				t.Errorf("Type = %q, want %q", problem.Type, tt.expectedType)
			}
			if problem.Title != tt.expectedTitle {
				t.Errorf("Title = %q, want %q", problem.Title, tt.expectedTitle)
			}
			if problem.Detail != tt.expectedDetail {
				t.Errorf("Detail = %q, want %q", problem.Detail, tt.expectedDetail)
			}
		})
	}
}

// TestHandleValidateJSON_RequestID verifies X-Request-ID header is set
func TestHandleValidateJSON_RequestID(t *testing.T) {
	h := newTestHandlers(true)
	req := httptest.NewRequest(http.MethodGet, "/api/validate", nil)
	w := httptest.NewRecorder()

	h.HandleValidateJSON(w, req)

	reqID := w.Header().Get("X-Request-ID")
	if reqID == "" {
		t.Error("X-Request-ID header not set")
	}
}

// TestHandleAnchors_SecurityHeaders verifies security headers are present
func TestHandleAnchors_SecurityHeaders(t *testing.T) {
	h := newTestHandlers(true)
	req := httptest.NewRequest(http.MethodGet, "/api/anchors", nil)
	w := httptest.NewRecorder()

	h.HandleAnchors(w, req)

	headers := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}

	for name, expected := range headers {
		got := w.Header().Get(name)
		if got != expected {
			t.Errorf("%s = %q, want %q", name, got, expected)
		}
	}
}
