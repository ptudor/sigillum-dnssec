package registrar

import (
	"context"
	"sync"
	"time"
)

// slidingLimiter is a lightweight sliding-scale rate limiter. The first few
// requests are allowed with a small gap between them, after which the gap
// grows in tiers so sustained bursts self-throttle rather than hitting
// Dynadot's 60/min hard limit. The counter resets after an idle window,
// so occasional small bursts don't accumulate "debt" from earlier activity.
//
// Tiers (chosen to match the user's sliding shape — burst-friendly up front,
// then back off):
//
//	req  1..20  → 100ms gap
//	req 21..40  → 500ms gap
//	req 41+     → 2s  gap
//
// After `idleReset` with no calls, the counter returns to zero.
type slidingLimiter struct {
	mu        sync.Mutex
	count     int
	last      time.Time
	idleReset time.Duration
}

// newSlidingLimiter returns a limiter with the default Dynadot-appropriate
// tier and a 60-second idle reset. Exposed as its own constructor so tests
// and future registrar adapters can reuse it.
func newSlidingLimiter() *slidingLimiter {
	return &slidingLimiter{idleReset: 60 * time.Second}
}

// tierDelay returns the minimum inter-request gap for the Nth request in a
// burst (count==0 is the first request). Pure so tests can verify the
// tiers without sleeping.
func tierDelay(count int) time.Duration {
	switch {
	case count < 20:
		return 100 * time.Millisecond
	case count < 40:
		return 500 * time.Millisecond
	default:
		return 2 * time.Second
	}
}

// gate blocks until the caller is allowed to issue its next request, or until
// ctx is cancelled (in which case it returns ctx.Err() and does not consume a
// slot). Safe for concurrent callers — the mutex is held across the wait on
// purpose, which serializes callers (exactly what a rate limiter wants).
// Honoring ctx keeps a graceful shutdown or a caller deadline from being stuck
// behind the 2s throttle tier (R-073).
func (l *slidingLimiter) gate(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	// Reset the tier counter after an idle period so a fresh burst starts
	// back at the cheap 100ms tier rather than the punitive 2s tier.
	if !l.last.IsZero() && now.Sub(l.last) > l.idleReset {
		l.count = 0
	}

	if !l.last.IsZero() {
		minGap := tierDelay(l.count)
		if wait := minGap - now.Sub(l.last); wait > 0 {
			timer := time.NewTimer(wait)
			defer timer.Stop()
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-timer.C:
			}
		}
	}

	l.count++
	l.last = time.Now()
	return nil
}
