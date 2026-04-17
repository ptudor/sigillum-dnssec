package main

import (
	"testing"
	"time"
)

func TestTierDelay(t *testing.T) {
	cases := []struct {
		count int
		want  time.Duration
	}{
		{0, 100 * time.Millisecond},
		{19, 100 * time.Millisecond},
		{20, 500 * time.Millisecond},
		{39, 500 * time.Millisecond},
		{40, 2 * time.Second},
		{1000, 2 * time.Second},
	}
	for _, tc := range cases {
		if got := tierDelay(tc.count); got != tc.want {
			t.Errorf("tierDelay(%d) = %v, want %v", tc.count, got, tc.want)
		}
	}
}

// TestSlidingLimiter_FirstCall asserts that the very first call is not
// delayed — the limiter only enforces inter-request gaps, so an idle
// process shouldn't pay for being first.
func TestSlidingLimiter_FirstCall(t *testing.T) {
	l := newSlidingLimiter()
	start := time.Now()
	l.gate()
	if elapsed := time.Since(start); elapsed > 10*time.Millisecond {
		t.Fatalf("first gate() took %v, should be near-instant", elapsed)
	}
}

// TestSlidingLimiter_EnforcesGap walks a few iterations inside tier 1 and
// confirms each call waits at least tier1 - slack. Kept under 400ms total
// so the test stays fast.
func TestSlidingLimiter_EnforcesGap(t *testing.T) {
	l := newSlidingLimiter()
	l.gate() // Seed the "last" timestamp — no wait.

	const iterations = 3
	start := time.Now()
	for i := 0; i < iterations; i++ {
		l.gate()
	}
	elapsed := time.Since(start)
	// Three more calls at 100ms spacing = ~300ms minimum.
	if elapsed < 250*time.Millisecond {
		t.Fatalf("expected at least ~300ms total, got %v", elapsed)
	}
}

// TestSlidingLimiter_IdleReset confirms the tier counter drops back to 0
// after the idle window, so a fresh burst starts in the cheap tier.
func TestSlidingLimiter_IdleReset(t *testing.T) {
	l := newSlidingLimiter()
	l.idleReset = 10 * time.Millisecond
	// Advance the counter into a higher tier artificially, then wait past
	// the idle window; the next gate() should see count==0 again.
	l.count = 50
	l.last = time.Now().Add(-1 * time.Second) // long since idle
	l.gate()
	// After gate() runs, count was reset to 0, then incremented to 1.
	if l.count != 1 {
		t.Fatalf("expected count=1 after idle reset, got %d", l.count)
	}
}
