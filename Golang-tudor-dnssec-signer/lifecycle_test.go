package main

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	signerpkg "github.com/ptudor/dnssec-tudor/internal/signer"

	"github.com/ptudor/dnssec-tudor/internal/dnssectest"
	statepkg "github.com/ptudor/dnssec-tudor/internal/state"

	"github.com/ptudor/dnssec-tudor/internal/config"
)

// signableZoneDaemon builds a daemon with one real, key-backed, signable zone.
func signableZoneDaemon(t *testing.T) (*Daemon, *config.Config, *statepkg.State, string) {
	t.Helper()
	dataDir := t.TempDir()
	cfg := dnssectest.Config(t, dataDir)
	domain := "lifecycle.example."
	zone := `$ORIGIN lifecycle.example.
$TTL 3600
@	IN	SOA	ns1.lifecycle.example. admin.lifecycle.example. (
				2024011501 3600 1800 604800 86400 )
@	IN	NS	ns1.lifecycle.example.
ns1	IN	A	192.0.2.1
www	IN	A	192.0.2.10
`
	zonePath := filepath.Join(dataDir, "lifecycle.zone")
	if err := os.WriteFile(zonePath, []byte(zone), 0644); err != nil {
		t.Fatal(err)
	}
	cfg.Zones[domain] = config.ZoneConfig{Path: zonePath}
	if err := signerpkg.EnsureDir(cfg.KeysDir()); err != nil {
		t.Fatal(err)
	}
	if err := signerpkg.EnsureDir(cfg.OutputDir); err != nil {
		t.Fatal(err)
	}
	state := statepkg.NewState(cfg.StatePath())
	keyGen := signerpkg.NewKeyGenerator(cfg)
	ksk, err := keyGen.GenerateKSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	zsk, err := keyGen.GenerateZSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	state.SetZone(domain, &statepkg.ZoneState{Path: zonePath, KSK: ksk, ZSK: zsk})
	return NewDaemon(cfg, state), cfg, state, domain
}

// R-018: the signing path reads the heartbeat/cfg/state via the locked snapshot,
// and Reload swaps them under the same lock. Run with `go test -race`: a concurrent
// signing loop and Reload must not race. (Pre-fix, checkAndSignZone read d.heartbeat
// unlocked while Reload reassigned it — the detector flagged it.)
func TestDaemon_SignReloadRace(t *testing.T) {
	d, cfg, _, domain := signableZoneDaemon(t)
	// Distinct keys held so each reloaded state can keep signing the zone.
	zoneState := d.state.GetZone(domain)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 25; i++ {
			d.signAllZonesSafe()
		}
		close(done)
	}()
	for i := 0; i < 25; i++ {
		ns := statepkg.NewState(cfg.StatePath())
		ns.SetZone(domain, zoneState.Clone())
		d.Reload(cfg, ns)
	}
	<-done
}

// R-019 (part 1): a signing cycle that observes a cancelled context stops before
// iterating the remaining zones instead of signing them all.
func TestSignAllZones_StopsOnShutdown(t *testing.T) {
	d, _, state, domain := signableZoneDaemon(t)

	// Cancel before the cycle: the per-zone ctx check must break the loop before
	// SignZone runs, so LastSigned stays zero (the zone is never signed).
	d.cancel()
	d.signAllZones()

	if zs := state.GetZone(domain); !zs.LastSigned.IsZero() {
		t.Errorf("zone was signed despite shutdown; LastSigned=%v (R-019 ctx check missing)", zs.LastSigned)
	}
}

// R-020: if shutdown is signalled before runWebServer stores d.server, Run must
// still return (the web goroutine must not start serving on a cancelled daemon
// and leave wg.Wait() hanging).
func TestDaemon_ShutdownBeforeRun(t *testing.T) {
	dataDir := t.TempDir()
	cfg := dnssectest.Config(t, dataDir)
	cfg.Web.Enabled = true
	cfg.Web.Listen = "127.0.0.1:0"
	cfg.Health.Listen = "127.0.0.1:0"
	cfg.Health.ShutdownTimeout = config.Duration{Duration: 2 * time.Second}
	d := NewDaemon(cfg, statepkg.NewState(cfg.StatePath()))

	// Cancel the daemon context before Run starts serving.
	d.Shutdown()

	done := make(chan error, 1)
	go func() { done <- d.Run() }()

	select {
	case <-done:
		// returned promptly — good
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after Shutdown-before-Run (R-020 hang)")
	}
}

// R-021: a failed initial bind of the always-on health listener is fatal — Run
// returns a non-nil error (process exits non-zero) instead of logging and
// signing headlessly. This also gives implicit double-start protection.
func TestDaemon_HealthBindFatal(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	cfg := dnssectest.Config(t, t.TempDir())
	cfg.Health.Listen = occupied.Addr().String() // already in use
	d := NewDaemon(cfg, statepkg.NewState(cfg.StatePath()))

	err = d.Run()
	if err == nil {
		t.Fatal("Run must fail when the health port is already bound (R-021)")
	}
	if !strings.Contains(err.Error(), "health listen") {
		t.Errorf("error should name the health listener, got: %v", err)
	}
}

// R-021: same fatal treatment for the web listener when web is enabled.
func TestDaemon_WebBindFatal(t *testing.T) {
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	cfg := dnssectest.Config(t, t.TempDir())
	cfg.Health.Listen = "127.0.0.1:0" // free
	cfg.Web.Enabled = true
	cfg.Web.Listen = occupied.Addr().String() // already in use
	d := NewDaemon(cfg, statepkg.NewState(cfg.StatePath()))

	err = d.Run()
	if err == nil {
		t.Fatal("Run must fail when the web port is already bound (R-021)")
	}
	if !strings.Contains(err.Error(), "web listen") {
		t.Errorf("error should name the web listener, got: %v", err)
	}
}

// R-026: a daemon-path hook goroutine is tracked on the WaitGroup, so waiting on
// it blocks until the hook actually finishes — this is what keeps a shutdown from
// killing the final nsd-control reload.
func TestExecuteHook_WaitGroupTracked(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "hook-ran")
	hooks := &config.HooksConfig{PostSign: "touch " + marker, Shell: true}

	var wg sync.WaitGroup
	if err := firePostSignHooks(hooks, dir, []SignedZoneRef{{Domain: "x."}}, &wg, nil); err != nil {
		t.Fatal(err)
	}
	wg.Wait() // must not return until the tracked goroutine is Done

	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("hook marker missing after wg.Wait() — hook not tracked/awaited: %v", err)
	}
}

// R-026: the batched (coalesced) hook is likewise tracked.
func TestExecuteBatchHook_WaitGroupTracked(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "batch-hook-ran")
	hooks := &config.HooksConfig{PostSign: "touch " + marker, Shell: true, CoalescePostSign: true}

	var wg sync.WaitGroup
	if err := firePostSignHooks(hooks, dir, []SignedZoneRef{{Domain: "a."}, {Domain: "b."}}, &wg, nil); err != nil {
		t.Fatal(err)
	}
	wg.Wait()

	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("batch hook marker missing after wg.Wait(): %v", err)
	}
}
