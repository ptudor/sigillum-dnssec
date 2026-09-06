package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ptudor/sigillum-dnssec/validator/internal/metrics"
)

// defaultMaxBuckets bounds the per-IP bucket map. Without a hard cap, an
// attacker rotating source addresses (trivial within an IPv6 /64) can create
// millions of buckets between cleanup ticks — a memory DoS. R-091.
const defaultMaxBuckets = 50000

// RateLimiter implements per-IP token bucket rate limiting
type RateLimiter struct {
	mu         sync.Mutex
	limiters   map[string]*tokenBucket
	rate       int           // tokens per second
	burst      int           // maximum burst size
	cleanup    time.Duration // cleanup interval
	maxBuckets int           // hard cap on live buckets (R-091)
	stopCh     chan struct{}
	stopOnce   sync.Once // makes Stop idempotent (R-053)
}

type tokenBucket struct {
	tokens    float64
	lastCheck time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate, burst int, cleanup time.Duration) *RateLimiter {
	rl := &RateLimiter{
		limiters:   make(map[string]*tokenBucket),
		rate:       rate,
		burst:      burst,
		cleanup:    cleanup,
		maxBuckets: defaultMaxBuckets,
		stopCh:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go rl.cleanupLoop()

	return rl
}

// Allow checks if a request from the given IP is allowed
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, exists := rl.limiters[ip]
	now := time.Now()

	if !exists {
		// Bound the map before inserting a new IP so churn can't grow it without
		// limit between cleanup ticks (R-091).
		if len(rl.limiters) >= rl.maxBuckets {
			rl.evictLocked(now)
		}
		bucket = &tokenBucket{
			tokens:    float64(rl.burst),
			lastCheck: now,
		}
		rl.limiters[ip] = bucket
	}

	// Refill tokens based on elapsed time
	elapsed := now.Sub(bucket.lastCheck).Seconds()
	bucket.tokens += elapsed * float64(rl.rate)
	if bucket.tokens > float64(rl.burst) {
		bucket.tokens = float64(rl.burst)
	}
	bucket.lastCheck = now

	// Check if we can allow this request
	if bucket.tokens >= 1 {
		bucket.tokens--
		return true
	}
	return false
}

// evictLocked bounds the bucket map when it hits the cap. It first drops idle
// buckets (idle longer than the cleanup interval); if the map is still full —
// the active-churn case, where every bucket is fresh — it evicts down to a
// low-water mark so a fresh insert always fits. Evicting a live bucket only
// resets that IP's tokens to burst (more lenient, never a bypass), so bounding
// memory here is safe. Caller holds rl.mu. R-091.
func (rl *RateLimiter) evictLocked(now time.Time) {
	for ip, bucket := range rl.limiters {
		if now.Sub(bucket.lastCheck) > rl.cleanup {
			delete(rl.limiters, ip)
		}
	}
	if len(rl.limiters) < rl.maxBuckets {
		return
	}
	// Still full: shed ~10% so this doesn't run on every subsequent insert.
	target := rl.maxBuckets - rl.maxBuckets/10
	if target < 1 {
		target = 1
	}
	for ip := range rl.limiters {
		if len(rl.limiters) <= target {
			break
		}
		delete(rl.limiters, ip)
	}
}

// cleanupLoop periodically removes stale entries
func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanup)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for ip, bucket := range rl.limiters {
				if now.Sub(bucket.lastCheck) > rl.cleanup {
					delete(rl.limiters, ip)
				}
			}
			rl.mu.Unlock()
		case <-rl.stopCh:
			return
		}
	}
}

// Stop stops the cleanup goroutine
// Stop halts the background cleanup loop. It is idempotent and concurrency-safe:
// a repeated or concurrent Server.Shutdown (a normal lifecycle expectation) no
// longer panics with "close of closed channel" (R-053).
func (rl *RateLimiter) Stop() {
	rl.stopOnce.Do(func() {
		close(rl.stopCh)
	})
}

// Middleware returns an HTTP middleware that applies rate limiting
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractClientIP(r)

		if !rl.Allow(ip) {
			metrics.RecordRateLimitHit()
			w.Header().Set("Retry-After", "1")
			writeProblemDetails(w, ErrTypeTooManyRequests, "Too Many Requests",
				http.StatusTooManyRequests, "rate limit exceeded, please try again later", r.URL.Path)
			return
		}

		next.ServeHTTP(w, r)
	})
}

var defaultTrustedProxyCIDRs = []string{
	"127.0.0.0/8", // localhost IPv4
	"::1/128",     // localhost IPv6
}

var (
	trustedProxyMu    sync.RWMutex
	trustedProxyNets  []*net.IPNet
	trustedProxyCIDRs []string
)

func init() {
	// Best effort: defaults are valid literals. Keep empty set if something unexpected fails.
	_ = SetTrustedProxyCIDRs(defaultTrustedProxyCIDRs)
}

// SetTrustedProxyCIDRs configures which proxy CIDRs are allowed to supply X-Forwarded-For / X-Real-IP.
// An empty list means proxy headers are never trusted.
func SetTrustedProxyCIDRs(cidrs []string) error {
	nets := make([]*net.IPNet, 0, len(cidrs))
	normalized := make([]string, 0, len(cidrs))

	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}

		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return err
		}

		nets = append(nets, network)
		normalized = append(normalized, cidr)
	}

	trustedProxyMu.Lock()
	trustedProxyNets = nets
	trustedProxyCIDRs = normalized
	trustedProxyMu.Unlock()
	return nil
}

func currentTrustedProxyCIDRs() []string {
	trustedProxyMu.RLock()
	defer trustedProxyMu.RUnlock()
	out := make([]string, len(trustedProxyCIDRs))
	copy(out, trustedProxyCIDRs)
	return out
}

// isFromTrustedProxy checks if the remote address is from a trusted proxy
func isFromTrustedProxy(remoteAddr string) bool {
	ip := net.ParseIP(remoteAddr)
	if ip == nil {
		return false
	}
	trustedProxyMu.RLock()
	defer trustedProxyMu.RUnlock()
	for _, network := range trustedProxyNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// extractClientIP gets the client IP from the request.
//
// Proxy headers are only honored when the direct peer (r.RemoteAddr) is itself a
// trusted proxy. Within X-Forwarded-For, the real client is the RIGHTMOST entry that
// is not one of our own trusted proxies: each proxy in the chain appends the peer it
// received the request from, so the rightmost untrusted address is the closest hop we
// did not generate. Taking the leftmost entry (the previous behavior) trusts a value
// the remote client fully controls, letting anyone spoof their attributed IP — and
// thereby evade per-IP rate limiting and pollute logs — by sending a forged
// X-Forwarded-For header.
func extractClientIP(r *http.Request) string {
	// Get the direct connection IP.
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}

	// Never trust proxy headers from an untrusted direct peer.
	if !isFromTrustedProxy(remoteIP) {
		return remoteIP
	}

	// Walk X-Forwarded-For right-to-left, skipping our own trusted-proxy hops. The
	// first untrusted, parseable address is the real client.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		for i := len(ips) - 1; i >= 0; i-- {
			candidate := strings.TrimSpace(ips[i])
			if net.ParseIP(candidate) == nil {
				continue // skip empty/garbage entries
			}
			if isFromTrustedProxy(candidate) {
				continue // another known proxy hop; keep walking left
			}
			return candidate
		}
	}

	// Fall back to X-Real-IP (set by the reverse proxy to the connecting peer).
	if xri := strings.TrimSpace(r.Header.Get("X-Real-IP")); xri != "" {
		if net.ParseIP(xri) != nil {
			return xri
		}
	}

	// XFF held only trusted-proxy hops (or none): the direct peer is the best answer.
	return remoteIP
}
