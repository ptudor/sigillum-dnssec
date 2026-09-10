package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dnspkg "github.com/ptudor/sigillum-dnssec/validator/internal/dns"
	"github.com/ptudor/sigillum-dnssec/validator/internal/validator"
)

// RDAYBLUEX-027: both public endpoints parse the mode through one helper
// before any validation slot is taken. Exactly the documented values (and
// empty) are accepted, case-insensitively; everything else is a 400
// problem-details response that never reaches the validator.

func TestRDAYBLUEX027_ModeParsing(t *testing.T) {
	cases := []struct {
		raw  string
		want string // "" = rejected
	}{
		{"", "extended"},
		{"quick", "quick"},
		{"extended", "extended"},
		{"QUICK", "quick"},
		{"Extended", "extended"},
		{" quick ", "quick"},
		{"quik", ""},
		{"fast", ""},
		{"quick,extended", ""},
		{strings.Repeat("extended", 500), ""},
		{"quick\x00", ""},
	}
	for _, c := range cases {
		got, ok := parseValidationMode(c.raw)
		if c.want == "" {
			if ok {
				t.Fatalf("%q must be rejected, got %q", c.raw, got)
			}
			continue
		}
		if !ok || got != c.want {
			t.Fatalf("%q → %q %v, want %q", c.raw, got, ok, c.want)
		}
	}

	for _, endpoint := range []string{"/validate", "/api/validate"} {
		for _, c := range cases {
			t.Run(endpoint+" mode="+strings.TrimSpace(c.raw)[:min(len(strings.TrimSpace(c.raw)), 12)], func(t *testing.T) {
				h := newTestHandlers(true)
				seen := ""
				calls := 0
				h.validateFn = func(_ context.Context, domain, mode string, _ uint16, _ *dnspkg.RootAnchors) (*validator.ValidationResult, error) {
					calls++
					seen = mode
					return &validator.ValidationResult{Domain: domain, Result: validator.StatusSecure}, nil
				}
				h.sseValidateFn = func(_ context.Context, domain, mode string, _ uint16, _ *dnspkg.RootAnchors, _ func(validator.SSEEvent)) (*validator.ValidationResult, error) {
					calls++
					seen = mode
					return &validator.ValidationResult{Domain: domain, Result: validator.StatusSecure}, nil
				}
				q := "?domain=example.com"
				if c.raw != "" {
					q += "&mode=" + strings.NewReplacer(" ", "%20", "\x00", "%00", ",", "%2C").Replace(c.raw)
				}
				req := httptest.NewRequest(http.MethodGet, endpoint+q, nil)
				rr := httptest.NewRecorder()
				if endpoint == "/validate" {
					h.HandleValidateSSE(rr, req)
				} else {
					h.HandleValidateJSON(rr, req)
				}
				if c.want == "" {
					if rr.Code != http.StatusBadRequest {
						t.Fatalf("invalid mode must be 400, got %d: %s", rr.Code, rr.Body.String())
					}
					if !strings.Contains(rr.Header().Get("Content-Type"), "application/problem+json") {
						t.Fatalf("problem-details shape expected, got %q", rr.Header().Get("Content-Type"))
					}
					var prob map[string]any
					if err := json.Unmarshal(rr.Body.Bytes(), &prob); err != nil || prob["status"] != float64(400) || !strings.Contains(prob["detail"].(string), "quick, extended") {
						t.Fatalf("problem body: %s (%v)", rr.Body.String(), err)
					}
					if calls != 0 {
						t.Fatal("an invalid mode must never reach the validation seam")
					}
					if len(h.validationSem) != 0 {
						t.Fatal("an invalid mode must not consume a validation slot")
					}
					return
				}
				if rr.Code != http.StatusOK {
					t.Fatalf("valid mode must succeed, got %d: %s", rr.Code, rr.Body.String())
				}
				if calls != 1 || seen != c.want {
					t.Fatalf("the seam must see the normalized mode %q once, got %q ×%d", c.want, seen, calls)
				}
				if len(h.validationSem) != 0 {
					t.Fatal("the slot must be released after a valid request")
				}
			})
		}
	}
}
