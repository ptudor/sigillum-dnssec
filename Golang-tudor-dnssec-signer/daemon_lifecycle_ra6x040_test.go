package main

import (
	"net"
	"sync"
	"testing"
	"time"

	statepkg "github.com/ptudor/dnssec-tudor/internal/state"

	"github.com/ptudor/dnssec-tudor/internal/config"
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
