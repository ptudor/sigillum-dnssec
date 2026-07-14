package main

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ptudor/dnssec-tudor/internal/validate"
)

// R-018: concurrent and repeated per-zone validation requests must coalesce into a
// single live-DNS computation (single-flight) and be served from a short-TTL cache,
// so the /api/validate/{domain} endpoint cannot be driven to run unbounded parallel
// many-query validations.
func TestR018_PerZoneSingleFlightAndCache(t *testing.T) {
	c := &zoneValidationCache{byZone: map[string]*zoneValEntry{}}
	var calls int32
	compute := func() *validate.ValidationResult {
		atomic.AddInt32(&calls, 1)
		time.Sleep(40 * time.Millisecond) // simulate a live validation
		return &validate.ValidationResult{}
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.get("example.com", compute, time.Minute, time.Second)
		}()
	}
	wg.Wait()

	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("20 concurrent same-zone requests must coalesce to 1 compute, got %d", n)
	}

	// A cached hit within the TTL does not recompute.
	c.get("example.com", compute, time.Minute, time.Second)
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("cached result within TTL must not recompute, got %d", n)
	}

	// A different zone computes independently.
	c.get("other.example", compute, time.Minute, time.Second)
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("a distinct zone must compute independently, got %d total computes", n)
	}
}
