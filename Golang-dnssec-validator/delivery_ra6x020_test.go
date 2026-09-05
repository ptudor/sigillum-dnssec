package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ptudor/dnssec-validator/internal/config"
	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
	"github.com/ptudor/dnssec-validator/internal/validator"
)

// realServer starts the actual HTTP server (real sockets, so write deadlines
// apply) with a validation seam that sleeps for `work` before answering.
func realServer(t *testing.T, work time.Duration, total time.Duration) (*httptest.Server, *Handlers) {
	t.Helper()
	cfg := config.DefaultConfig()
	cfg.TotalTimeout = total
	cfg.TotalTimeoutSec = int(total / time.Second)
	cfg.RateLimitPerSec, cfg.RateLimitBurst = 1000, 1000
	store := NewAnchorsStore("/nonexistent", "https://nonexistent.invalid")
	store.anchors = &dnspkg.RootAnchors{Anchors: []dnspkg.Anchor{{KeyTag: 20326}}}
	s := NewServer(cfg, store)
	s.handlers.validateFn = func(ctx context.Context, domain, mode string, qtype uint16, anchors *dnspkg.RootAnchors) (*validator.ValidationResult, error) {
		select {
		case <-time.After(work):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		return &validator.ValidationResult{Domain: domain, Result: validator.StatusSecure, DurationMs: int64(work / time.Millisecond)}, nil
	}
	srv := httptest.NewServer(s.mux)
	t.Cleanup(srv.Close)
	return srv, s.handlers
}

// A validation that outlives the entry write deadline (here shortened to
// 1 s; in production 30 s against a configurable total timeout) must still
// deliver its completed result over a real socket.
func TestValidateJSON_ResultDeliveredAfterEntryDeadline(t *testing.T) {
	orig := nonSSEWriteTimeout
	nonSSEWriteTimeout = 1 * time.Second
	t.Cleanup(func() { nonSSEWriteTimeout = orig })

	srv, _ := realServer(t, 2*time.Second, 10*time.Second)
	resp, err := srv.Client().Get(srv.URL + "/api/validate?domain=example.com")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading the delayed result must succeed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d, body %s", resp.StatusCode, body)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil || out["domain"] != "example.com" {
		t.Fatalf("completed result must arrive intact: %v %s", err, body)
	}
}

// The total-timeout diagnostics at the default boundary are delivered too:
// work equal to the total timeout ends with a context error the seam turns
// into a result.
func TestValidateJSON_TimeoutDiagnosticsDelivered(t *testing.T) {
	orig := nonSSEWriteTimeout
	nonSSEWriteTimeout = 1 * time.Second
	t.Cleanup(func() { nonSSEWriteTimeout = orig })
	srv, h := realServer(t, time.Hour, 1500*time.Millisecond)
	h.validateFn = func(ctx context.Context, domain, mode string, qtype uint16, anchors *dnspkg.RootAnchors) (*validator.ValidationResult, error) {
		<-ctx.Done() // work runs to the total timeout
		return &validator.ValidationResult{Domain: domain, Result: validator.StatusIndeterminate, DurationMs: 1500}, nil
	}
	resp, err := srv.Client().Get(srv.URL + "/api/validate?domain=example.com")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), "indeterminate") {
		t.Fatalf("timeout diagnostics must be delivered: %d %s", resp.StatusCode, body)
	}
}

// A client that stops reading after the work completes cannot hold the
// handler past the delivery budget, and the request is not counted as 200.
func TestValidateJSON_StalledClientIsCutOff(t *testing.T) {
	orig := nonSSEWriteTimeout
	nonSSEWriteTimeout = 1 * time.Second
	t.Cleanup(func() { nonSSEWriteTimeout = orig })
	srv, h := realServer(t, 200*time.Millisecond, 10*time.Second)
	// Make the result large enough that the kernel buffers cannot absorb it.
	big := strings.Repeat("x", 8<<20)
	h.validateFn = func(ctx context.Context, domain, mode string, qtype uint16, anchors *dnspkg.RootAnchors) (*validator.ValidationResult, error) {
		return &validator.ValidationResult{Domain: domain, Result: validator.StatusSecure, Errors: []string{big}}, nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
		if err != nil {
			return
		}
		defer conn.Close()
		io.WriteString(conn, "GET /api/validate?domain=example.com HTTP/1.1\r\nHost: x\r\n\r\n")
		time.Sleep(15 * time.Second) // never read the response
	}()
	// The handler must finish (deadline expired) well before the client gives up.
	select {
	case <-time.After(14 * time.Second):
		t.Fatal("the stalled client should not keep the server busy this long")
	case <-waitForHandlerIdle(srv, 13*time.Second):
	}
	<-done
}

// waitForHandlerIdle polls the server for a cheap request to complete, which
// only happens promptly once the stalled handler has released its slot; it
// returns a channel closed when the server answers a /healthz probe.
func waitForHandlerIdle(srv *httptest.Server, timeout time.Duration) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		defer close(ch)
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			time.Sleep(500 * time.Millisecond)
			resp, err := srv.Client().Get(srv.URL + "/healthz")
			if err == nil {
				resp.Body.Close()
				return
			}
		}
	}()
	return ch
}
