package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"

	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
)

// RA6X-040: startup reads go through a guarded snapshot and Reload is
// serialized until the daemon has published its ready state. Run with -race.

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// The review's exact probe: the signing loop started directly while Reload
// swaps the config repeatedly. With readiness published, the loop's initial
// interval must come from a guarded snapshot.
func TestRA6X040_SigningLoopStartVersusReload(t *testing.T) {
	d, cfg, state, _ := signableZoneDaemon(t)
	d.markReady()
	d.wg.Add(1)
	go d.runSigningLoop()
	for i := 0; i < 20; i++ {
		c := *cfg
		c.PollInterval = config.Duration{Duration: time.Duration(i+1) * time.Minute}
		d.Reload(&c, state)
	}
	d.cancel()
	d.wg.Wait()
}

// Reloads delivered during Run's startup sequence wait for readiness instead
// of racing the startup reads; shutdown after startup drains cleanly.
func TestRA6X040_ReloadDuringStartupIsSerialized(t *testing.T) {
	d, cfg, state, _ := signableZoneDaemon(t)
	cfg.Health.Listen = freePort(t)
	cfg.Web.Enabled = false
	cfg.PollInterval = config.Duration{Duration: time.Hour}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 10; i++ {
			c := *cfg
			c.PollInterval = config.Duration{Duration: time.Duration(i+2) * time.Hour}
			d.Reload(&c, state) // blocks until Run publishes readiness
		}
	}()
	runErr := make(chan error, 1)
	go func() { runErr <- d.Run() }()

	select {
	case <-d.ready:
	case <-time.After(10 * time.Second):
		t.Fatal("Run never published readiness")
	}
	wg.Wait()
	d.Shutdown()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after shutdown")
	}
	// A reload after shutdown is ignored, not blocked.
	done := make(chan struct{})
	go func() { d.Reload(cfg, state); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Reload after shutdown must return immediately")
	}
}

// Shutdown delivered before Run reaches its workers: Run returns without
// starting the signing loop or the heartbeat, and a failed startup wakes any
// waiting Reload.
func TestRA6X040_ShutdownBeforeStartupStartsNothing(t *testing.T) {
	d, cfg, state, _ := signableZoneDaemon(t)
	cfg.Health.Listen = freePort(t)
	d.Shutdown()
	if err := d.Run(); err != nil {
		t.Fatalf("Run after shutdown must return cleanly: %v", err)
	}
	if d.lastSigningRun.Load() != 0 {
		t.Fatal("the signing loop must not run after shutdown")
	}
	// Failed startup (port in use) wakes a pending Reload.
	d2, cfg2, state2, _ := signableZoneDaemon(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg2.Health.Listen = ln.Addr().String()
	done := make(chan struct{})
	go func() { d2.Reload(cfg2, state2); close(done) }()
	if err := d2.Run(); err == nil {
		t.Fatal("Run must fail on a bound port")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a Reload waiting on a failed startup must be released")
	}
	_ = state
	_ = statepkg.NewState
}

// The serialization guard itself, asserted directly rather than through a
// timing race (RA6X-040 verification): while a startup is in progress, Reload
// must block until Run publishes readiness. The concurrency tests above cannot
// detect the guard's removal — the config swap is mutex-protected either way,
// so -race stays quiet and every assertion still holds — but removing it lets
// Run start the heartbeat client from a snapshot Reload has already replaced,
// which is what TestRA6X040_ReloadWaitsForReadiness and the heartbeat test
// below pin down.
func TestRA6X040_ReloadWaitsForReadiness(t *testing.T) {
	d, cfg, state, _ := signableZoneDaemon(t)

	// A startup is in progress but readiness has not been published.
	d.starting.Store(true)

	returned := make(chan struct{})
	go func() {
		d.Reload(cfg, state)
		close(returned)
	}()

	select {
	case <-returned:
		t.Fatal("Reload returned while a startup was in progress; it must wait for readiness so Run's startup snapshot cannot be swapped underneath it")
	case <-time.After(250 * time.Millisecond):
	}

	d.markReady()

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("Reload did not return after readiness was published")
	}
}

// The heartbeat client Run starts must be the one Shutdown stops. Run starts
// the client captured in its startup snapshot; if a Reload lands between the
// snapshot and that Start, the daemon starts a client it no longer references
// and Shutdown stops a different one — the started client never sends its
// "stopping" heartbeat and its loops are never joined. The readiness guard is
// what makes that interleaving impossible.
//
// This asserts the invariant (every started client is also stopped, and the
// last heartbeat after shutdown is "stopping") rather than reliably producing
// the bad interleaving: the window is too small to hit on demand without a
// seam inside Run. TestRA6X040_ReloadWaitsForReadiness is the deterministic
// check on the guard itself.
func TestRA6X040_StartedHeartbeatIsTheOneShutdownStops(t *testing.T) {
	d, cfg, state, _ := signableZoneDaemon(t)

	var mu sync.Mutex
	var actions []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		mu.Lock()
		actions = append(actions, r.PostFormValue("action"))
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	hb := config.HeartbeatConfig{
		Enabled:         true,
		URL:             srv.URL,
		APIKey:          "synthetic-not-a-real-key",
		App:             "sigillum-signer-test",
		InstanceID:      "ra6x040",
		IntervalMinutes: 60,
		AllowInsecure:   true,
	}
	cfg.Heartbeat = hb
	cfg.Health.Listen = freePort(t)
	cfg.Web.Enabled = false
	cfg.PollInterval = config.Duration{Duration: time.Hour}
	d.cfg = cfg
	d.heartbeat = NewHeartbeatClient(&cfg.Heartbeat)

	runErr := make(chan error, 1)
	go func() { runErr <- d.Run() }()

	// Deliver a reload concurrently with the startup sequence.
	reloaded := make(chan struct{})
	go func() {
		c := *cfg
		c.PollInterval = config.Duration{Duration: 2 * time.Hour}
		d.Reload(&c, state)
		close(reloaded)
	}()

	select {
	case <-d.ready:
	case <-time.After(10 * time.Second):
		t.Fatal("Run never published readiness")
	}
	<-reloaded
	d.Shutdown()
	select {
	case err := <-runErr:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not return after shutdown")
	}

	mu.Lock()
	got := append([]string(nil), actions...)
	mu.Unlock()

	var starts, stops int
	for _, a := range got {
		switch a {
		case "starting":
			starts++
		case "stopping":
			stops++
		}
	}
	if starts == 0 {
		t.Fatalf("no starting heartbeat was sent; actions=%v", got)
	}
	if starts != stops {
		t.Fatalf("every started heartbeat client must also be stopped: %d starting vs %d stopping (actions=%v)", starts, stops, got)
	}
	if len(got) == 0 || got[len(got)-1] != "stopping" {
		t.Fatalf("the last heartbeat after shutdown must be \"stopping\", got %v", got)
	}
}
