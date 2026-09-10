package main

import (
	"sync"
	"time"

	"github.com/ptudor/sigillum-dnssec/validator/internal/dns"
)

// AnchorsStore manages the root trust anchors with thread-safe access
type AnchorsStore struct {
	mu       sync.RWMutex
	anchors  *dns.RootAnchors
	loadedAt time.Time
	path     string
	url      string
	// cachePath is the last-known-good cache (RDAYBLUEX-011): every usable,
	// pinned document fetched from url is persisted here atomically, and it
	// is read before the network on later loads. Empty disables caching.
	cachePath string
	cacheErr  error
}

// NewAnchorsStore creates a new anchors store
func NewAnchorsStore(path, url string) *AnchorsStore {
	return &AnchorsStore{
		path: path,
		url:  url,
	}
}

// SetCachePath sets the last-known-good cache file; empty disables it.
func (s *AnchorsStore) SetCachePath(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cachePath = path
}

// Load loads or reloads the trust anchors in the offline-capable order: the
// operator's file, the last-known-good cache, then the URL — persisting a
// usable fetched document to the cache (RDAYBLUEX-011). A failed load —
// every source missing, malformed or unusable — leaves the last successfully
// loaded set and its load time untouched (RA6X-041): the store keeps serving
// the last-known-good anchors, and because activation dates are re-evaluated
// at every use (GetActivePinnedAnchors), an anchor that has since expired is
// not trusted merely to preserve availability; readiness reports the gap. A
// cache write failure never fails the load; it is kept in CacheError.
func (s *AnchorsStore) Load() error {
	s.mu.RLock()
	path, cachePath, url := s.path, s.cachePath, s.url
	s.mu.RUnlock()

	anchors, fetched, err := dns.LoadAnchorsWithCache(path, cachePath, url)
	if err != nil {
		return err
	}
	s.adopt(anchors, fetched)
	return nil
}

// Refresh re-reads the operator's file or, absent a usable one, fetches the
// URL and persists a usable document to the cache. Unlike Load it never
// re-reads the cache: the store already holds what the cache held, and the
// point of a refresh is newer material. A failed refresh keeps the current
// set.
func (s *AnchorsStore) Refresh() error {
	s.mu.RLock()
	path, url := s.path, s.url
	s.mu.RUnlock()

	anchors, fetched, err := dns.LoadAnchorsWithCache(path, "", url)
	if err != nil {
		return err
	}
	s.adopt(anchors, fetched)
	return nil
}

// adopt installs a validated set and, when it was fetched, persists it.
func (s *AnchorsStore) adopt(anchors *dns.RootAnchors, fetched []byte) {
	var cacheErr error
	s.mu.RLock()
	cachePath := s.cachePath
	s.mu.RUnlock()
	if fetched != nil && cachePath != "" {
		cacheErr = dns.WriteAnchorCache(cachePath, fetched)
	}

	s.mu.Lock()
	s.anchors = anchors
	s.loadedAt = time.Now()
	if fetched != nil && cachePath != "" {
		s.cacheErr = cacheErr
	}
	s.mu.Unlock()
}

// CacheError reports the outcome of the most recent cache write: nil when it
// succeeded or no fetched document has been written yet.
func (s *AnchorsStore) CacheError() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cacheErr
}

// Get returns the current anchors
func (s *AnchorsStore) Get() *dns.RootAnchors {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.anchors
}

// LoadedAt returns when the anchors were loaded
func (s *AnchorsStore) LoadedAt() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadedAt
}

// Age returns the age of the loaded anchors
func (s *AnchorsStore) Age() time.Duration {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.loadedAt.IsZero() {
		return 0
	}
	return time.Since(s.loadedAt)
}

// IsStale returns true if anchors are older than the given duration
func (s *AnchorsStore) IsStale(maxAge time.Duration) bool {
	return s.Age() > maxAge
}
