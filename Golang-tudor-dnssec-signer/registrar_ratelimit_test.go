package main

import (
	"context"
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
	l.gate(context.Background())
	if elapsed := time.Since(start); elapsed > 10*time.Millisecond {
		t.Fatalf("first gate() took %v, should be near-instant", elapsed)
	}
}

// TestSlidingLimiter_EnforcesGap walks a few iterations inside tier 1 and
// confirms each call waits at least tier1 - slack. Kept under 400ms total
// so the test stays fast.
func TestSlidingLimiter_EnforcesGap(t *testing.T) {
	l := newSlidingLimiter()
	l.gate(context.Background()) // Seed the "last" timestamp — no wait.

	const iterations = 3
	start := time.Now()
	for i := 0; i < iterations; i++ {
		l.gate(context.Background())
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
	l.gate(context.Background())
	// After gate() runs, count was reset to 0, then incremented to 1.
	if l.count != 1 {
		t.Fatalf("expected count=1 after idle reset, got %d", l.count)
	}
}

// TestSlidingLimiter_HonorsContext (R-073): gate returns the context error
// (and consumes no slot) when the caller's context is cancelled during the wait,
// so a graceful shutdown or an expired deadline isn't stuck behind the throttle.
func TestSlidingLimiter_HonorsContext(t *testing.T) {
	l := newSlidingLimiter()
	l.gate(context.Background()) // seed "last"; the next call would wait ~100ms

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before the next gate

	countBefore := l.count
	err := l.gate(ctx)
	if err == nil {
		t.Fatal("gate must return the context error when ctx is cancelled during the wait")
	}
	if l.count != countBefore {
		t.Errorf("a cancelled gate must not consume a slot; count %d -> %d", countBefore, l.count)
	}
}
