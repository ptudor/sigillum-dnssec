package main

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/validate"
)

// --- Item 7: a panic in dashboard validation must not kill the daemon ---

// The validation-cache compute goroutine (web.go) runs outside net/http's
// per-request panic recovery, so a panic in ValidateAll would crash the whole
// daemon pre-fix. The recover must also perform the goroutine's cleanup:
// waiters unblock instead of hanging, and inflight is cleared so a later get
// starts a fresh compute.
func TestValidationCache_ComputeRecoversFromPanic(t *testing.T) {
	c := &validationCache{}
	var calls int32
	panicking := func() *validate.ValidateOutput {
		atomic.AddInt32(&calls, 1)
		panic("live-DNS validation exploded")
	}

	// (a) The process survives: an unrecovered panic in the compute goroutine
	// would kill the whole test binary. (b) The waiter unblocks promptly with
	// the nil cold-cache fallback — like the timeout path — rather than
	// hanging on a done channel that never closes or caching a result.
	start := time.Now()
	if got := c.get(1, panicking, time.Minute, 5*time.Second); got != nil {
		t.Errorf("panicking compute must not cache a result, got %+v", got)
	}
	if el := time.Since(start); el > 2*time.Second {
		t.Errorf("waiter did not unblock promptly after the panic: %v", el)
	}

	// (c) inflight was cleared, so a subsequent get starts a fresh compute
	// and serves its result.
	healthy := func() *validate.ValidateOutput {
		atomic.AddInt32(&calls, 1)
		return &validate.ValidateOutput{Zones: map[string]*validate.ValidationResult{}}
	}
	if got := c.get(1, healthy, time.Minute, 5*time.Second); got == nil {
		t.Fatal("get after the panic returned nil — inflight was not cleared for a fresh compute")
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Errorf("expected the panicking compute and one fresh compute (2 calls), got %d", n)
	}
}
