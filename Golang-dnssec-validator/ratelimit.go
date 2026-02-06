package main

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// RateLimiter implements per-IP token bucket rate limiting
type RateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*tokenBucket
	rate     int           // tokens per second
	burst    int           // maximum burst size
	cleanup  time.Duration // cleanup interval
	stopCh   chan struct{}
}

type tokenBucket struct {
	tokens    float64
	lastCheck time.Time
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate, burst int, cleanup time.Duration) *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[string]*tokenBucket),
		rate:     rate,
		burst:    burst,
		cleanup:  cleanup,
		stopCh:   make(chan struct{}),
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
func (rl *RateLimiter) Stop() {
	close(rl.stopCh)
}

// Middleware returns an HTTP middleware that applies rate limiting
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractClientIP(r)

		if !rl.Allow(ip) {
			RecordRateLimitHit()
			w.Header().Set("Retry-After", "1")
			writeProblemDetails(w, ErrTypeTooManyRequests, "Too Many Requests",
				http.StatusTooManyRequests, "rate limit exceeded, please try again later", r.URL.Path)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// trustedProxies contains CIDR ranges of trusted reverse proxies
// Only requests from these ranges will have X-Forwarded-For headers trusted
var trustedProxies = []string{
	"127.0.0.0/8",    // localhost
	"10.0.0.0/8",     // private class A
	"172.16.0.0/12",  // private class B
	"192.168.0.0/16", // private class C
	"::1/128",        // IPv6 localhost
	"fc00::/7",       // IPv6 unique local
}

var trustedProxyNets []*net.IPNet

func init() {
	for _, cidr := range trustedProxies {
		_, network, err := net.ParseCIDR(cidr)
		if err == nil {
			trustedProxyNets = append(trustedProxyNets, network)
		}
	}
}

// isFromTrustedProxy checks if the remote address is from a trusted proxy
func isFromTrustedProxy(remoteAddr string) bool {
	ip := net.ParseIP(remoteAddr)
	if ip == nil {
		return false
	}
	for _, network := range trustedProxyNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// extractClientIP gets the client IP from the request
// Only trusts X-Forwarded-For when request comes from a trusted proxy
func extractClientIP(r *http.Request) string {
	// Get the direct connection IP
	remoteIP, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		remoteIP = r.RemoteAddr
	}

	// Only trust proxy headers if request is from a trusted proxy
	if isFromTrustedProxy(remoteIP) {
		// Check X-Forwarded-For header (first IP in the chain is the client)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			ips := strings.Split(xff, ",")
			if len(ips) > 0 {
				clientIP := strings.TrimSpace(ips[0])
				// Validate it's a real IP, not garbage
				if net.ParseIP(clientIP) != nil {
					return clientIP
				}
			}
		}

		// Check X-Real-IP header
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			clientIP := strings.TrimSpace(xri)
			if net.ParseIP(clientIP) != nil {
				return clientIP
			}
		}
	}

	return remoteIP
}
