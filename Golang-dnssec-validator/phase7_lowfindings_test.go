package main

import (
	"sync"
	"testing"
	"time"
)

// R-053: RateLimiter.Stop must be idempotent and concurrency-safe (no
// "close of closed channel" panic on a repeated or concurrent shutdown).
func TestR053_RateLimiterStopIdempotent(t *testing.T) {
	rl := NewRateLimiter(10, 30, time.Minute)

	// Sequential repeated Stop.
	rl.Stop()
	rl.Stop()

	// Concurrent Stop from many goroutines.
	rl2 := NewRateLimiter(10, 30, time.Minute)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); rl2.Stop() }()
	}
	wg.Wait()
}

// R-056: when the crypto/rand fast path is unavailable, the deterministic
// fallback must still produce unique, fixed-length IDs (no repeated zeros).
func TestR056_FallbackRequestIDsUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		n := reqIDCounter.Add(1)
		id := formatFallbackRequestID(n)
		if len(id) != 16 {
			t.Fatalf("fallback ID %q has length %d, want 16", id, len(id))
		}
		if seen[id] {
			t.Fatalf("duplicate fallback request ID: %q", id)
		}
		seen[id] = true
	}
}
