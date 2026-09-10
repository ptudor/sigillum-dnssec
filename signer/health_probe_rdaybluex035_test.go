//go:build !windows

package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RDAYBLUEX-035: health requests no longer drive unthrottled filesystem
// mutation. Directory write probes are single-flighted and cached for a short
// interval, invalidated on reload and on a real write failure, and remote
// health requests are rate limited.

// countingProbe wraps the real probe and counts calls per directory.
type countingProbe struct {
	mu    sync.Mutex
	calls map[string]int
	fail  map[string]error
}

func installCountingProbe(t *testing.T) *countingProbe {
	t.Helper()
	cp := &countingProbe{calls: map[string]int{}, fail: map[string]error{}}
	orig, origInterval := dirProbeFn, healthProbeInterval
	dirProbeFn = func(dir string) error {
		cp.mu.Lock()
		cp.calls[dir]++
		err := cp.fail[dir]
		cp.mu.Unlock()
		if err != nil {
			return err
		}
		return checkDirWritable(dir)
	}
	t.Cleanup(func() { dirProbeFn, healthProbeInterval = orig, origInterval })
	return cp
}

func (cp *countingProbe) count(dir string) int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	return cp.calls[dir]
}

func (cp *countingProbe) total() int {
	cp.mu.Lock()
	defer cp.mu.Unlock()
	n := 0
	for _, c := range cp.calls {
		n += c
	}
	return n
}

func healthDaemon(t *testing.T) (*Daemon, *config.Config, *statepkg.State, http.Handler) {
	t.Helper()
	d, cfg, state, domain := signableZoneDaemon(t)
	cfg.LoadedAt = time.Now().UTC()
	// A ready zone so only the probes decide health.
	zs := state.GetZone(domain)
	state.Mutate(func() {
		zs.LastSigned = time.Now()
		zs.SignaturesExp = time.Now().Add(24 * time.Hour)
		zs.PublishedAt = time.Now()
		zs.PublishedGenerationSignedAt = zs.LastSigned
	})
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterHealthHandlersWithDaemon(mux, d)
	return d, cfg, state, mux
}

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	return rr
}

func TestRDAYBLUEX035_ProbesAreSingleFlightedAndCached(t *testing.T) {
	cp := installCountingProbe(t)
	healthProbeInterval = time.Minute
	_, cfg, _, h := healthDaemon(t)

	var wg sync.WaitGroup
	var codes sync.Map
	for i := 0; i < 300; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			path := "/health"
			if i%2 == 1 {
				path = "/healthz"
			}
			rr := get(h, path)
			codes.Store(i, rr.Code)
		}(i)
	}
	wg.Wait()
	for _, dir := range []string{cfg.OutputDir, cfg.DataDir, cfg.KeysDir()} {
		if n := cp.count(dir); n != 1 {
			t.Fatalf("directory %s must be probed once per interval across 300 concurrent requests, got %d", dir, n)
		}
	}
	codes.Range(func(_, v any) bool {
		if v.(int) != http.StatusOK {
			t.Fatalf("every caller must get a consistent healthy result, got %d", v.(int))
		}
		return true
	})
	// Within the interval, further requests reuse the cache.
	for i := 0; i < 20; i++ {
		get(h, "/health")
	}
	if cp.total() != 3 {
		t.Fatalf("no further probes inside the interval, total %d", cp.total())
	}
}

func TestRDAYBLUEX035_ExpiryReprobesAndReportsUnhealthy(t *testing.T) {
	cp := installCountingProbe(t)
	healthProbeInterval = 40 * time.Millisecond
	_, cfg, _, h := healthDaemon(t)
	if rr := get(h, "/healthz"); rr.Code != http.StatusOK {
		t.Fatalf("healthy first, got %d", rr.Code)
	}
	// The data directory becomes unwritable after the cached result expires.
	cp.mu.Lock()
	cp.fail[cfg.DataDir] = errors.New("simulated permission change")
	cp.mu.Unlock()
	if rr := get(h, "/healthz"); rr.Code != http.StatusOK {
		t.Fatal("inside the interval the cached healthy result is served")
	}
	time.Sleep(60 * time.Millisecond)
	if rr := get(h, "/health"); rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("after expiry the next probe must report the failure, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestRDAYBLUEX035_ReloadAndWriteFailureInvalidate(t *testing.T) {
	cp := installCountingProbe(t)
	healthProbeInterval = time.Minute
	d, cfg, _, h := healthDaemon(t)
	get(h, "/health")
	if cp.total() != 3 {
		t.Fatalf("expected 3 probes, got %d", cp.total())
	}

	// Reload: the next request re-probes.
	newCfg := *cfg
	newCfg.Zones = map[string]config.ZoneConfig{}
	for k, v := range cfg.Zones {
		newCfg.Zones[k] = v
	}
	newState, err := statepkg.LoadState(cfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Reload(&newCfg, newState); err != nil {
		t.Fatal(err)
	}
	get(h, "/healthz")
	if cp.total() != 5 {
		t.Fatalf("a reload must invalidate the cache (2 more probes for /healthz), got %d", cp.total())
	}

	// A real write failure (a signing cycle whose state save fails)
	// invalidates too.
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not restrict root")
	}
	before := cp.total()
	_, restore := failNextDaemonSave(t, newState, cfg.StatePath())
	d.signAllZones()
	restore()
	get(h, "/healthz")
	if cp.total() != before+2 {
		t.Fatalf("a failed state save must invalidate the cache, probes %d -> %d", before, cp.total())
	}
}

func TestRDAYBLUEX035_RemoteModeIsRateLimited(t *testing.T) {
	installCountingProbe(t)
	healthProbeInterval = time.Minute
	origRate, origBurst := healthRemoteRate, healthRemoteBurst
	healthRemoteRate, healthRemoteBurst = 1, 5
	t.Cleanup(func() { healthRemoteRate, healthRemoteBurst = origRate, origBurst })

	// Loopback default: never limited.
	_, _, _, h := healthDaemon(t)
	for i := 0; i < 50; i++ {
		if rr := get(h, "/healthz"); rr.Code == http.StatusTooManyRequests {
			t.Fatal("the loopback default must not be rate limited")
		}
	}

	// Deliberately exposed listener: bounded.
	_, cfg, _, h := healthDaemon(t)
	cfg.Health.AllowRemote = true
	limited := 0
	for i := 0; i < 50; i++ {
		rr := get(h, "/health")
		if rr.Code == http.StatusTooManyRequests {
			limited++
			if rr.Header().Get("Retry-After") == "" {
				t.Fatal("a limited response carries Retry-After")
			}
		}
	}
	if limited == 0 {
		t.Fatal("remote health requests beyond the burst must be limited")
	}
	if limited > 46 {
		t.Fatalf("the burst must be admitted, %d limited of 50", limited)
	}
}

func TestRDAYBLUEX035_InFlightProbeIsSharedNotDuplicated(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	orig, origInterval := dirProbeFn, healthProbeInterval
	dirProbeFn = func(dir string) error {
		calls.Add(1)
		<-release
		return nil
	}
	healthProbeInterval = time.Minute
	t.Cleanup(func() { dirProbeFn, healthProbeInterval = orig, origInterval })
	c := newDirProbeCache()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := c.probe("/some/dir"); err != nil {
				t.Errorf("probe: %v", err)
			}
		}()
	}
	time.Sleep(30 * time.Millisecond)
	close(release)
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("50 concurrent callers must share one in-flight probe, got %d", calls.Load())
	}
	// An invalidation during a probe discards its result.
	release = make(chan struct{})
	dirProbeFn = func(dir string) error { calls.Add(1); <-release; return nil }
	done := make(chan struct{})
	go func() { _ = c.probe("/other"); close(done) }()
	time.Sleep(20 * time.Millisecond)
	c.invalidate()
	close(release)
	<-done
	before := calls.Load()
	release = make(chan struct{})
	close(release)
	_ = c.probe("/other")
	if calls.Load() != before+1 {
		t.Fatal("a probe that completed after an invalidation must not be served from the cache")
	}
}
