package registrar

import (
	"context"
	"sync"
	"time"
)

// Rate limiting for the Dynadot API (RA6X-051).
//
// Dynadot caps a regular account at 60 requests per minute. windowLimiter
// enforces that as a rolling-window quota — no more than `quota` admissions in
// any `window` — and additionally keeps the burst-friendly inter-request
// spacing (tierDelay) so a bulk push self-throttles before the ceiling is
// reached. A reserve of the quota is held back for recovery work (the
// post-DELETE DS restore and its verification, see ReplaceDS), which is
// admitted under a context marked withRecoveryPriority, so an exhausted
// ordinary budget can never starve the one sequence that must complete.
//
// Every HTTP attempt — retries included — is gated. Waiting never holds the
// mutex, so a queued caller observes its own cancellation promptly, and a
// cancelled caller never consumes a slot. The limiter is shared process-wide;
// separate processes that share one Dynadot account share its quota too and
// need external coordination, which this in-process accounting cannot provide.
//
// Tiers (burst-friendly up front, then back off):
//
//	admissions in window  1..20  → 100ms gap
//	admissions in window 21..40  → 500ms gap
//	admissions in window 41+     → 2s  gap

const (
	dynadotWindow          = time.Minute
	dynadotQuota           = 60
	dynadotRecoveryReserve = 10
)

type recoveryPriorityKey struct{}

// withRecoveryPriority marks a context whose requests may draw on the
// recovery reserve of the quota.
func withRecoveryPriority(ctx context.Context) context.Context {
	return context.WithValue(ctx, recoveryPriorityKey{}, true)
}

func hasRecoveryPriority(ctx context.Context) bool {
	v, _ := ctx.Value(recoveryPriorityKey{}).(bool)
	return v
}

// windowLimiter admits requests under a rolling-window quota plus tiered
// spacing. now and wait are injectable for deterministic tests.
type windowLimiter struct {
	mu       sync.Mutex
	window   time.Duration
	quota    int
	reserve  int
	admitted []time.Time // admission times within the window, ascending
	now      func() time.Time
	wait     func(ctx context.Context, d time.Duration) error
}

// newWindowLimiter returns the Dynadot limiter: 60 per rolling minute with 10
// reserved for recovery.
func newWindowLimiter() *windowLimiter {
	return &windowLimiter{
		window:  dynadotWindow,
		quota:   dynadotQuota,
		reserve: dynadotRecoveryReserve,
		now:     time.Now,
		wait:    sleepCtx,
	}
}

// sleepCtx waits for d or until ctx is done, whichever comes first.
func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// tierDelay returns the minimum inter-request gap after `count` admissions in
// the current window (count==0 is the first request). Pure so tests can
// verify the tiers without sleeping.
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

// prune drops admissions that have left the window. Caller holds mu.
func (l *windowLimiter) prune(now time.Time) {
	cutoff := now.Add(-l.window)
	i := 0
	for i < len(l.admitted) && !l.admitted[i].After(cutoff) {
		i++
	}
	if i > 0 {
		l.admitted = append([]time.Time(nil), l.admitted[i:]...)
	}
}

// gate blocks until the caller may issue its next request or ctx is done (in
// which case ctx.Err() is returned and no slot is consumed). Cancellation is
// checked before admission even when no delay is due.
func (l *windowLimiter) gate(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		l.mu.Lock()
		now := l.now()
		l.prune(now)
		limit := l.quota - l.reserve
		if hasRecoveryPriority(ctx) {
			limit = l.quota
		}
		var wait time.Duration
		if n := len(l.admitted); n >= limit && limit > 0 {
			// The slot frees when the limit-th most recent admission leaves the window.
			wait = l.admitted[n-limit].Add(l.window).Sub(now)
		}
		if n := len(l.admitted); n > 0 {
			if gap := tierDelay(n) - now.Sub(l.admitted[n-1]); gap > wait {
				wait = gap
			}
		}
		if wait <= 0 {
			l.admitted = append(l.admitted, now)
			l.mu.Unlock()
			return nil
		}
		l.mu.Unlock()
		if err := l.wait(ctx, wait); err != nil {
			return err
		}
	}
}

// admissionsInWindow reports how many requests were admitted within the
// window ending now (test/diagnostic helper).
func (l *windowLimiter) admissionsInWindow() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.prune(l.now())
	return len(l.admitted)
}
