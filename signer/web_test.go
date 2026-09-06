package main

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/validate"
)

// TestValidationCache_BoundedAndSingleFlight (R-043): the dashboard/API
// validation is bounded (returns within maxWait even while a run is slow) and
// single-flight (concurrent requests don't spawn multiple live-DNS runs).
func TestValidationCache_BoundedAndSingleFlight(t *testing.T) {
	var computeCount int32
	gate := make(chan struct{})
	compute := func() *validate.ValidateOutput {
		atomic.AddInt32(&computeCount, 1)
		<-gate // block, simulating a slow many-zone run
		return &validate.ValidateOutput{Zones: map[string]*validate.ValidationResult{}}
	}
	c := &validationCache{}

	// Bounded: while compute is blocked, get returns within its wait budget with
	// the (cold) nil cache rather than hanging on the slow run.
	start := time.Now()
	if got := c.get(compute, time.Minute, 100*time.Millisecond); got != nil {
		t.Errorf("expected nil while compute is blocked, got non-nil")
	}
	if el := time.Since(start); el > 1*time.Second {
		t.Errorf("get exceeded its wait budget: %v", el)
	}

	// Single-flight: more gets while blocked must not spawn additional computes.
	for i := 0; i < 5; i++ {
		c.get(compute, time.Minute, 20*time.Millisecond)
	}

	close(gate) // let the single in-flight compute finish

	var final *validate.ValidateOutput
	for i := 0; i < 200 && final == nil; i++ {
		final = c.get(compute, time.Minute, 200*time.Millisecond)
		if final == nil {
			time.Sleep(10 * time.Millisecond)
		}
	}
	if final == nil {
		t.Fatal("cache was never populated")
	}
	if n := atomic.LoadInt32(&computeCount); n != 1 {
		t.Errorf("single-flight violated: compute ran %d times, want 1", n)
	}

	// TTL: a subsequent get within the TTL serves the cache without recomputing.
	_ = c.get(compute, time.Minute, time.Second)
	if n := atomic.LoadInt32(&computeCount); n != 1 {
		t.Errorf("fresh cache must not recompute; compute ran %d times", n)
	}
}
