package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/validate"
)

// RDAYBLUEX-025: the dashboard validation caches are scoped to the daemon
// generation. A result computed under generation A is never served for
// generation B, an A computation still in flight when B is published cannot
// fill B's entry, per-zone entries of superseded generations and expired
// entries are evicted, and within a generation the 30-second single-flight
// cache still holds.

func TestRDAYBLUEX025_AggregateCacheIsGenerationScoped(t *testing.T) {
	c := &validationCache{}
	var computes int32
	mk := func(tag string) func() *validate.ValidateOutput {
		return func() *validate.ValidateOutput {
			atomic.AddInt32(&computes, 1)
			return &validate.ValidateOutput{Zones: map[string]*validate.ValidationResult{tag: {}}}
		}
	}
	// Generation 1 primes the cache.
	if out := c.get(1, mk("A"), time.Minute, time.Second); out == nil || out.Zones["A"] == nil {
		t.Fatal("generation 1 must compute A")
	}
	if out := c.get(1, mk("A2"), time.Minute, time.Second); out.Zones["A"] == nil || atomic.LoadInt32(&computes) != 1 {
		t.Fatal("within a generation the cached result is served")
	}
	// Generation 2 must not see A.
	out := c.get(2, mk("B"), time.Minute, time.Second)
	if out == nil || out.Zones["B"] == nil || out.Zones["A"] != nil {
		t.Fatalf("generation 2 must compute its own result, got %+v", out)
	}
	if atomic.LoadInt32(&computes) != 2 {
		t.Fatalf("expected 2 computations, got %d", computes)
	}
}

// An in-flight generation-1 computation released after generation 2 became
// active must not populate generation 2's slot.
func TestRDAYBLUEX025_InFlightOldGenerationCannotFillNew(t *testing.T) {
	c := &validationCache{}
	release := make(chan struct{})
	slow := func() *validate.ValidateOutput {
		<-release
		return &validate.ValidateOutput{Zones: map[string]*validate.ValidationResult{"OLD": {}}}
	}
	// Start the old computation; the caller times out quickly (nil on a cold start).
	if out := c.get(1, slow, time.Minute, 20*time.Millisecond); out != nil {
		t.Fatal("cold start past the wait budget returns nil")
	}
	// Generation 2 is published; a request computes B.
	fast := func() *validate.ValidateOutput {
		return &validate.ValidateOutput{Zones: map[string]*validate.ValidationResult{"NEW": {}}}
	}
	if out := c.get(2, fast, time.Minute, time.Second); out == nil || out.Zones["NEW"] == nil {
		t.Fatal("generation 2 must compute B despite the old in-flight run")
	}
	close(release)
	time.Sleep(50 * time.Millisecond) // let the old goroutine finish
	out := c.get(2, fast, time.Minute, time.Second)
	if out == nil || out.Zones["NEW"] == nil || out.Zones["OLD"] != nil {
		t.Fatalf("the old completion must not have replaced generation 2's result: %+v", out)
	}
}

func TestRDAYBLUEX025_PerZoneCacheGenerationScopedAndBounded(t *testing.T) {
	c := &zoneValidationCache{byZone: map[string]*zoneValEntry{}}
	var computes int32
	compute := func() *validate.ValidationResult {
		atomic.AddInt32(&computes, 1)
		return &validate.ValidationResult{}
	}
	// Generation 1: entries for two zones.
	c.get(1, "a.example", compute, time.Minute, time.Second)
	c.get(1, "b.example", compute, time.Minute, time.Second)
	if len(c.byZone) != 2 || atomic.LoadInt32(&computes) != 2 {
		t.Fatalf("two entries expected, got %d entries / %d computes", len(c.byZone), computes)
	}
	// Generation 2 (b.example removed from the zone set): the first lookup
	// evicts every old entry and recomputes for the new generation.
	c.get(2, "a.example", compute, time.Minute, time.Second)
	if _, stale := c.byZone["b.example"]; stale || len(c.byZone) != 1 {
		t.Fatalf("a reload must evict superseded entries, got %v", c.byZone)
	}
	if atomic.LoadInt32(&computes) != 3 {
		t.Fatalf("generation 2 must recompute a.example, got %d computes", computes)
	}

	// Within a generation, remove/re-add churn is bounded: expired entries
	// are swept on lookup.
	c2 := &zoneValidationCache{byZone: map[string]*zoneValEntry{}}
	for i := 0; i < 200; i++ {
		c2.get(1, fmt.Sprintf("z%d.example", i), compute, time.Millisecond, time.Second)
		time.Sleep(time.Millisecond)
	}
	if n := len(c2.byZone); n > 3 {
		t.Fatalf("expired per-zone entries must be swept; %d entries remain", n)
	}

	// An in-flight old-generation computation cannot fill the new generation.
	c3 := &zoneValidationCache{byZone: map[string]*zoneValEntry{}}
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		c3.get(1, "x.example", func() *validate.ValidationResult { <-release; return &validate.ValidationResult{Domain: "OLD"} }, time.Minute, 10*time.Millisecond)
	}()
	wg.Wait()
	got := c3.get(2, "x.example", func() *validate.ValidationResult { return &validate.ValidationResult{Domain: "NEW"} }, time.Minute, time.Second)
	if got == nil || got.Domain != "NEW" {
		t.Fatalf("generation 2 must compute its own entry, got %+v", got)
	}
	close(release)
	time.Sleep(50 * time.Millisecond)
	got = c3.get(2, "x.example", func() *validate.ValidationResult { return &validate.ValidationResult{Domain: "NEW2"} }, time.Minute, time.Second)
	if got == nil || got.Domain != "NEW" {
		t.Fatalf("the old completion must not have replaced generation 2's entry: %+v", got)
	}
}
