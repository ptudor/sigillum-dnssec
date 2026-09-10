package main

import (
	"math"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/validator/internal/dns"
)

// R-055: the root-anchor age must be NaN before any successful load, reflect real
// elapsed time at read (scrape) time, and never reset after a failed refresh.
func TestR055_RootAnchorAgeSemantics(t *testing.T) {
	// The built-in anchor document (RDAYBLUEX-011) would satisfy this load;
	// disable it so the fallback behaviour under test is reached.
	t.Cleanup(dns.SetEmbeddedAnchorsForTest([]byte(`{"zone":".","anchors":[]}`)))
	store := NewAnchorsStore("/nonexistent/anchors.json", "http://nonexistent.invalid")

	ageFn := func() float64 {
		la := store.LoadedAt()
		if la.IsZero() {
			return math.NaN()
		}
		return time.Since(la).Seconds()
	}

	// Never loaded → NaN, not zero.
	if !math.IsNaN(ageFn()) {
		t.Fatalf("age must be NaN before any successful load, got %v", ageFn())
	}

	// Simulate a successful load two hours ago.
	store.mu.Lock()
	store.anchors = &dns.RootAnchors{Anchors: []dns.Anchor{{KeyTag: 20326}}}
	store.loadedAt = time.Now().Add(-2 * time.Hour)
	store.mu.Unlock()

	if age := ageFn(); age < 3600 {
		t.Fatalf("age should reflect ~2h since load, got %v seconds", age)
	}

	// A failed refresh must NOT reset the loaded timestamp.
	before := store.LoadedAt()
	if err := store.Load(); err == nil {
		t.Fatal("expected the failed load to error (nonexistent file+url)")
	}
	if !store.LoadedAt().Equal(before) {
		t.Fatal("a failed refresh must not reset loadedAt (age must keep growing)")
	}
}
