package main

import (
	"sync"
	"time"

	"github.com/ptudor/dnssec-validator/internal/dns"
)

// AnchorsStore manages the root trust anchors with thread-safe access
type AnchorsStore struct {
	mu        sync.RWMutex
	anchors   *dns.RootAnchors
	loadedAt  time.Time
	path      string
	url       string
}

// NewAnchorsStore creates a new anchors store
func NewAnchorsStore(path, url string) *AnchorsStore {
	return &AnchorsStore{
		path: path,
		url:  url,
	}
}

// Load loads or reloads the trust anchors
func (s *AnchorsStore) Load() error {
	anchors, err := dns.LoadAnchorsWithFallback(s.path, s.url)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.anchors = anchors
	s.loadedAt = time.Now()
	s.mu.Unlock()

	return nil
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
