package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/validator/internal/dns"
	"github.com/ptudor/sigillum-dnssec/validator/internal/validator"
)

// RDAYBLUEX-009: an SSE flush failure is visible. Every SSE method returns
// the flush error, and the stream handler cancels the validation on it,
// releasing its global validation slot promptly.

var errFlushSentinel = errors.New("forced flush failure")

// flushErrorWriter accepts writes but fails FlushError after okFlushes
// successful flushes.
type flushErrorWriter struct {
	header    http.Header
	buf       bytes.Buffer
	okFlushes int
	flushes   int
}

func (w *flushErrorWriter) Header() http.Header         { return w.header }
func (w *flushErrorWriter) WriteHeader(int)             {}
func (w *flushErrorWriter) Write(p []byte) (int, error) { return w.buf.Write(p) }
func (w *flushErrorWriter) Flush()                      {}
func (w *flushErrorWriter) FlushError() error {
	w.flushes++
	if w.flushes > w.okFlushes {
		return errFlushSentinel
	}
	return nil
}

func TestRDAYBLUEX009_EverySSEMethodReturnsFlushError(t *testing.T) {
	w := &flushErrorWriter{header: make(http.Header)}
	sse, err := NewSSEWriter(w)
	if err != nil {
		t.Fatal(err)
	}
	sse.SetStreamID("stream-1")
	calls := map[string]func() error{
		"WriteEvent":    func() error { return sse.WriteEvent("zone", map[string]string{"zone": "."}) },
		"WriteRawEvent": func() error { return sse.WriteRawEvent("progress", `{"a":1}`) },
		"WriteComment":  func() error { return sse.WriteComment("keepalive") },
		"WriteRetry":    func() error { return sse.WriteRetry(3000) },
		"WriteID":       func() error { return sse.WriteID("42") },
	}
	for name, call := range calls {
		if err := call(); !errors.Is(err, errFlushSentinel) {
			t.Errorf("%s must return the flush error, got %v", name, err)
		}
	}
	// The writes themselves went through (framing intact) before the flush failed.
	if !bytes.Contains(w.buf.Bytes(), []byte("event: zone\ndata: {\"zone\":\".\"}\n\n")) {
		t.Fatalf("event framing must be unchanged, got %q", w.buf.String())
	}
	if !bytes.Contains(w.buf.Bytes(), []byte("id: stream-1\n")) {
		t.Fatal("the stream id must still be stamped")
	}
}

// A writer that only implements Flush keeps best-effort behaviour (no error).
func TestRDAYBLUEX009_PlainFlusherStaysBestEffort(t *testing.T) {
	rec := httptest.NewRecorder()
	sse, err := NewSSEWriter(rec)
	if err != nil {
		t.Fatal(err)
	}
	if err := sse.WriteComment("x"); err != nil {
		t.Fatalf("a plain flusher cannot report flush errors; got %v", err)
	}
}

// The stream handler: the first flush (the retry hint) succeeds, the first
// validation event's flush fails, the validation context is cancelled, the
// handler returns promptly and the global validation slot is free again.
func TestRDAYBLUEX009_HandlerCancelsOnFlushFailureAndReleasesSlot(t *testing.T) {
	h := newTestHandlers(true)
	h.config.TotalTimeout = 5 * time.Second
	cancelled := make(chan error, 1)
	h.sseValidateFn = func(ctx context.Context, domain, mode string, qtype uint16, anchors *dns.RootAnchors, emit func(validator.SSEEvent)) (*validator.ValidationResult, error) {
		emit(validator.SSEEvent{Type: "start", Data: map[string]string{"domain": domain}})
		select {
		case <-ctx.Done():
			cancelled <- ctx.Err()
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
			cancelled <- errors.New("validation was not cancelled")
			return nil, errors.New("not cancelled")
		}
	}

	w := &flushErrorWriter{header: make(http.Header), okFlushes: 1}
	req := httptest.NewRequest(http.MethodGet, "/validate?domain=example.com", nil)
	done := make(chan struct{})
	start := time.Now()
	go func() {
		h.HandleValidateSSE(w, req)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the handler did not return promptly after the flush failure")
	}
	if el := time.Since(start); el > 1500*time.Millisecond {
		t.Fatalf("handler took %s", el)
	}
	select {
	case err := <-cancelled:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("the validation context must be cancelled on a flush failure, got %v", err)
		}
	default:
		t.Fatal("the validation seam never observed its context")
	}
	if n := len(h.validationSem); n != 0 {
		t.Fatalf("the validation slot must be released exactly once, %d still held", n)
	}
	if !h.acquireValidationSlot() {
		t.Fatal("another request must be able to acquire the global slot promptly")
	}
	h.releaseValidationSlot()
}
