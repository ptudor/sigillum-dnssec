package registrar

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

// The very first call is not delayed — an idle process shouldn't pay for
// being first.
func TestWindowLimiter_FirstCall(t *testing.T) {
	l := newWindowLimiter()
	start := time.Now()
	if err := l.gate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Millisecond {
		t.Fatalf("first gate() took %v, should be near-instant", elapsed)
	}
}

// A few calls inside tier 1 each wait about the tier gap (real clock).
func TestWindowLimiter_EnforcesGap(t *testing.T) {
	l := newWindowLimiter()
	if err := l.gate(context.Background()); err != nil {
		t.Fatal(err)
	}
	const iterations = 3
	start := time.Now()
	for i := 0; i < iterations; i++ {
		if err := l.gate(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
		t.Fatalf("expected at least ~300ms total, got %v", elapsed)
	}
}

// Admissions that have left the window no longer count, so a fresh burst
// after an idle minute starts in the cheap tier.
func TestWindowLimiter_IdleReset(t *testing.T) {
	l := newWindowLimiter()
	base := time.Now()
	for i := 0; i < 50; i++ {
		l.admitted = append(l.admitted, base.Add(-2*time.Minute).Add(time.Duration(i)*time.Second))
	}
	l.now = func() time.Time { return base }
	if err := l.gate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := l.admissionsInWindow(); got != 1 {
		t.Fatalf("expected the stale admissions pruned and one fresh admission, got %d", got)
	}
}

// R-073: gate returns the context error (and consumes no slot) when the
// caller's context is cancelled during the wait.
func TestWindowLimiter_HonorsContext(t *testing.T) {
	l := newWindowLimiter()
	if err := l.gate(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := l.admissionsInWindow()
	if err := l.gate(ctx); err == nil {
		t.Fatal("gate must return the context error when ctx is cancelled")
	}
	if l.admissionsInWindow() != before {
		t.Error("a cancelled gate must not consume a slot")
	}
}
