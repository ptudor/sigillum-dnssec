//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
	signerpkg "github.com/ptudor/sigillum-dnssec/signer/internal/signer"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RDAYBLUEX-013: a configured post-sign hook is the deployment mechanism in
// every mode but the publication AUTHORITY only in effective hook mode. In
// probe mode the every-authoritative-server serial probe alone confirms; in
// immediate mode the atomic write already did and a later hook result moves
// nothing.

// fakeProber is a deterministic publicationProber.
type fakeProber struct {
	mu     sync.Mutex
	served bool
	err    error
	calls  int
}

func (f *fakeProber) ProbePublishedSerial(domain string, serial uint32) (bool, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return false, "", f.err
	}
	if !f.served {
		return false, fmt.Sprintf("one server still serves an older serial than %d", serial), nil
	}
	return true, fmt.Sprintf("serial %d served everywhere", serial), nil
}

func (f *fakeProber) set(served bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.served = served
}

func installFakeProber(t *testing.T, f *fakeProber) {
	t.Helper()
	orig := newPublicationProber
	newPublicationProber = func(*config.Config, *statepkg.State) publicationProber { return f }
	t.Cleanup(func() { newPublicationProber = orig })
}

// epochZone is a zone whose serial is a unix epoch, as serial_policy = "epoch"
// (required by probe mode) demands.
func epochZone(domain string) string {
	return "$ORIGIN " + domain + "\n$TTL 3600\n" +
		"@\tIN\tSOA\tns1." + domain + " admin." + domain + " 1700000000 3600 1800 604800 86400\n" +
		"@\tIN\tNS\tns1." + domain + "\nns1\tIN\tA\t192.0.2.1\nwww\tIN\tA\t192.0.2.10\n"
}

// modeDaemon builds a signable daemon under an explicit publication mode.
func modeDaemon(t *testing.T, publication string, hook []string) (*Daemon, *config.Config, *statepkg.State, string) {
	t.Helper()
	dataDir := t.TempDir()
	cfg := dnssectest.Config(t, dataDir)
	cfg.DNSSEC.Publication = publication
	cfg.DNSSEC.SerialPolicy = "epoch"
	cfg.Hooks.PostSignCmd = hook
	domain := "mode.example."
	zonePath := filepath.Join(dataDir, "mode.zone")
	if err := os.WriteFile(zonePath, []byte(epochZone(domain)), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg.Zones[domain] = config.ZoneConfig{Path: zonePath}
	for _, dir := range []string{cfg.KeysDir(), cfg.OutputDir} {
		if err := signerpkg.EnsureDir(dir); err != nil {
			t.Fatal(err)
		}
	}
	state := statepkg.NewState(cfg.StatePath())
	kg := signerpkg.NewKeyGenerator(cfg)
	ksk, err := kg.GenerateKSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	zsk, err := kg.GenerateZSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	state.SetZone(domain, &statepkg.ZoneState{Path: zonePath, KSK: ksk, ZSK: zsk})
	return NewDaemon(cfg, state), cfg, state, domain
}

// Explicit probe mode with a SUCCEEDING hook and a probe that does not yet
// confirm: publication stays pending, no rollover phase advances, and the
// probe (not the hook) eventually confirms.
func TestRDAYBLUEX013_Daemon_ProbeMode_HookNeverConfirms(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "hook-ran")
	d, cfg, state, domain := modeDaemon(t, config.PublicationProbe, []string{"/bin/sh", "-c", "touch " + marker})
	prober := &fakeProber{served: false}
	installFakeProber(t, prober)
	fastRollover(cfg)
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	rm := signerpkg.NewRolloverManager(cfg, state)
	zs := state.GetZone(domain)
	zs.ZSK.Expires = time.Now().UTC()
	if err := rm.CheckZSKRollover(domain); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2500 * time.Millisecond)
	for time.Now().Before(deadline) {
		d.signAllZones()
		d.hookWG.Wait()
		time.Sleep(300 * time.Millisecond)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("the hook must still run as the deployment mechanism")
	}
	zs = state.GetZone(domain)
	if !zs.PendingPublication || !zs.PublishedAt.IsZero() {
		t.Fatalf("a successful hook must not confirm publication in probe mode (pending=%v published=%v)", zs.PendingPublication, zs.PublishedAt)
	}
	if hasErrorPrefix(zs.Errors, statepkg.OpDeployment) {
		t.Fatalf("a successful hook must not record a deployment error: %v", zs.Errors)
	}
	if zs.Rollover == nil || zs.Rollover.State != statepkg.ZSKRolloverStatePrePublish {
		t.Fatalf("no rollover phase may advance on an unconfirmed publication, got %+v", zs.Rollover)
	}
	if prober.calls == 0 {
		t.Fatal("the probe must have been consulted")
	}

	// Every authoritative server now serves the published serial.
	prober.set(true)
	d.signAllZones()
	d.hookWG.Wait()
	zs = state.GetZone(domain)
	if zs.PendingPublication || zs.PublishedAt.IsZero() {
		t.Fatalf("the probe must confirm publication (pending=%v published=%v)", zs.PendingPublication, zs.PublishedAt)
	}
	time.Sleep(1200 * time.Millisecond)
	d.signAllZones()
	d.hookWG.Wait()
	if got := state.GetZone(domain).Rollover.State; got != statepkg.ZSKRolloverStateSigning {
		t.Fatalf("after probe-confirmed publication plus the cache-safe wait the phase must advance, got %q", got)
	}
}

// Explicit immediate mode with a hook: PublishedAt is set exactly by signing,
// a completed hook does not move it, and a failed hook neither un-publishes
// the generation nor leaves it pending — it only records a deployment error
// that a later successful hook clears.
func TestRDAYBLUEX013_Daemon_ImmediateMode_HookIsNotTheAuthority(t *testing.T) {
	d, cfg, state, domain := modeDaemon(t, config.PublicationImmediate, []string{"/bin/sh", "-c", "sleep 0.3; exit 0"})
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	d.signAllZones()
	zs := state.GetZone(domain)
	signed := zs.LastSigned
	if zs.PendingPublication || !zs.PublishedAt.Equal(signed) || !zs.PublishedGenerationSignedAt.Equal(signed) {
		t.Fatalf("immediate mode: signing itself must confirm (pending=%v published=%v signed=%v)", zs.PendingPublication, zs.PublishedAt, signed)
	}
	d.hookWG.Wait() // the hook finishes after the write
	zs = state.GetZone(domain)
	if !zs.PublishedAt.Equal(signed) || !zs.PublishedGenerationSignedAt.Equal(signed) {
		t.Fatalf("hook completion must not move the publication timestamps (published %v, signed %v)", zs.PublishedAt, signed)
	}
	horizon := zs.DNSKEYCacheHorizon

	// The hook fails on the next generation.
	cfg.Hooks.PostSignCmd = []string{"/bin/sh", "-c", "exit 1"}
	appendZoneRecord(t, cfg.Zones[domain].Path, "mail\tIN\tA\t192.0.2.25")
	d.signAllZones()
	d.hookWG.Wait()
	zs = state.GetZone(domain)
	if !zs.LastSigned.After(signed) {
		t.Fatal("the zone must have been re-signed")
	}
	if zs.PendingPublication || !zs.PublishedAt.Equal(zs.LastSigned) {
		t.Fatalf("a failed hook must not convert a published generation back to pending (pending=%v published=%v signed=%v)", zs.PendingPublication, zs.PublishedAt, zs.LastSigned)
	}
	if !hasErrorPrefix(zs.Errors, statepkg.OpDeployment) {
		t.Fatalf("the failed deployment step must be visible as a deployment error: %v", zs.Errors)
	}
	if zs.DNSKEYCacheHorizon.Before(horizon) {
		t.Fatal("cache horizons never move backwards")
	}
	disk, err := statepkg.LoadState(cfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if disk.GetZone(domain).PendingPublication || !hasErrorPrefix(disk.GetZone(domain).Errors, statepkg.OpDeployment) {
		t.Fatalf("the persisted state must agree: %+v", disk.GetZone(domain))
	}

	// A later successful hook clears the deployment error and still moves
	// no publication timestamp.
	cfg.Hooks.PostSignCmd = []string{"/bin/sh", "-c", "exit 0"}
	appendZoneRecord(t, cfg.Zones[domain].Path, "ftp\tIN\tA\t192.0.2.26")
	d.signAllZones()
	d.hookWG.Wait()
	zs = state.GetZone(domain)
	if hasErrorPrefix(zs.Errors, statepkg.OpDeployment) {
		t.Fatalf("a successful hook must clear the deployment error: %v", zs.Errors)
	}
	if !zs.PublishedAt.Equal(zs.LastSigned) || zs.PendingPublication {
		t.Fatalf("publication is still owned by the write: %+v", zs)
	}
}

// Hook mode keeps its contract: failure leaves the zone pending with a
// deployment error and the retry confirms.
func TestRDAYBLUEX013_Daemon_HookMode_Unchanged(t *testing.T) {
	d, cfg, state, domain := modeDaemon(t, config.PublicationHook, []string{"/bin/sh", "-c", "exit 1"})
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	d.signAllZones()
	d.hookWG.Wait()
	zs := state.GetZone(domain)
	if !zs.PendingPublication || !hasErrorPrefix(zs.Errors, statepkg.OpDeployment) {
		t.Fatalf("hook mode: a failed hook leaves the zone pending with a deployment error: %+v", zs)
	}
	cfg.Hooks.PostSignCmd = []string{"/bin/sh", "-c", "exit 0"}
	d.signAllZones() // retries the pending deployment without re-signing
	d.hookWG.Wait()
	zs = state.GetZone(domain)
	if zs.PendingPublication || zs.PublishedAt.IsZero() || hasErrorPrefix(zs.Errors, statepkg.OpDeployment) {
		t.Fatalf("hook mode: a successful hook confirms and clears the error: %+v", zs)
	}
}

// The CLI helper reports "served" by mode.
func TestRDAYBLUEX013_CLI_RunPostSignHookByMode(t *testing.T) {
	t.Run("immediate: failing hook records the error but does not block", func(t *testing.T) {
		_, cfg, state, domain := modeDaemon(t, config.PublicationImmediate, []string{"/bin/sh", "-c", "exit 1"})
		if err := signerpkg.NewSigner(cfg, state).SignZone(domain); err != nil {
			t.Fatal(err)
		}
		if !runPostSignHook(cfg, state, domain, cfg.Zones[domain].Path) {
			t.Fatal("immediate mode: the write is the publication; a failed hook must not report the zone as unpublished")
		}
		zs := state.GetZone(domain)
		if zs.PendingPublication || zs.PublishedAt.IsZero() || !hasErrorPrefix(zs.Errors, statepkg.OpDeployment) {
			t.Fatalf("immediate mode after a failed hook: %+v", zs)
		}
		disk, _ := statepkg.LoadState(cfg.StatePath())
		if !hasErrorPrefix(disk.GetZone(domain).Errors, statepkg.OpDeployment) {
			t.Fatal("the deployment error must be persisted")
		}
	})
	t.Run("probe: successful hook does not confirm; the probe does", func(t *testing.T) {
		_, cfg, state, domain := modeDaemon(t, config.PublicationProbe, []string{"/bin/sh", "-c", "exit 0"})
		prober := &fakeProber{served: false}
		installFakeProber(t, prober)
		if err := signerpkg.NewSigner(cfg, state).SignZone(domain); err != nil {
			t.Fatal(err)
		}
		if runPostSignHook(cfg, state, domain, cfg.Zones[domain].Path) {
			t.Fatal("probe mode: a successful hook must not report the zone as served while the probe fails")
		}
		zs := state.GetZone(domain)
		if !zs.PendingPublication || !zs.PublishedAt.IsZero() {
			t.Fatalf("probe mode: the zone must stay pending: %+v", zs)
		}
		if prober.calls != 1 {
			t.Fatalf("the probe must have run once, got %d", prober.calls)
		}
		prober.set(true)
		if !runPostSignHook(cfg, state, domain, cfg.Zones[domain].Path) {
			t.Fatal("probe mode: the probe confirming must report the zone as served")
		}
		zs = state.GetZone(domain)
		if zs.PendingPublication || zs.PublishedAt.IsZero() {
			t.Fatalf("probe mode: confirmed by the probe: %+v", zs)
		}
		disk, _ := statepkg.LoadState(cfg.StatePath())
		if disk.GetZone(domain).PendingPublication {
			t.Fatal("the confirmation must be persisted")
		}
	})
	t.Run("probe: failing hook, probe confirms anyway", func(t *testing.T) {
		_, cfg, state, domain := modeDaemon(t, config.PublicationProbe, []string{"/bin/sh", "-c", "exit 1"})
		installFakeProber(t, &fakeProber{served: true})
		if err := signerpkg.NewSigner(cfg, state).SignZone(domain); err != nil {
			t.Fatal(err)
		}
		if !runPostSignHook(cfg, state, domain, cfg.Zones[domain].Path) {
			t.Fatal("probe mode: the probe is the authority even when the hook failed")
		}
		zs := state.GetZone(domain)
		if zs.PendingPublication || !hasErrorPrefix(zs.Errors, statepkg.OpDeployment) {
			t.Fatalf("probe mode: confirmed, with the hook failure recorded: %+v", zs)
		}
	})
	t.Run("hook: success confirms, failure leaves pending", func(t *testing.T) {
		_, cfg, state, domain := modeDaemon(t, config.PublicationHook, []string{"/bin/sh", "-c", "exit 0"})
		if err := signerpkg.NewSigner(cfg, state).SignZone(domain); err != nil {
			t.Fatal(err)
		}
		if !runPostSignHook(cfg, state, domain, cfg.Zones[domain].Path) || state.GetZone(domain).PendingPublication {
			t.Fatal("hook mode: a successful hook confirms")
		}
		cfg.Hooks.PostSignCmd = []string{"/bin/sh", "-c", "exit 1"}
		zs := state.GetZone(domain)
		state.Mutate(func() { zs.ForceResign = true })
		if err := signerpkg.NewSigner(cfg, state).SignZone(domain); err != nil {
			t.Fatal(err)
		}
		if runPostSignHook(cfg, state, domain, cfg.Zones[domain].Path) || !state.GetZone(domain).PendingPublication {
			t.Fatal("hook mode: a failed hook leaves the zone pending")
		}
	})
}

// A one-shot `sign` in probe mode confirms through the probe, not the hook,
// including zones left pending by an earlier run.
func TestRDAYBLUEX013_CLISign_ProbeMode(t *testing.T) {
	dir := t.TempDir()
	local := dnssectest.Config(t, dir)
	for _, d := range []string{local.KeysDir(), local.OutputDir} {
		if err := signerpkg.EnsureDir(d); err != nil {
			t.Fatal(err)
		}
	}
	domain := "probe.example"
	zonePath := filepath.Join(dir, domain+".zone")
	if err := os.WriteFile(zonePath, []byte(epochZone(domain+".")), 0o644); err != nil {
		t.Fatal(err)
	}
	cfgTOML := fmt.Sprintf("output_dir = %q\ndata_dir = %q\n\n[dnssec]\npublication = \"probe\"\nserial_policy = \"epoch\"\n\n[hooks]\npost_sign_cmd = [\"/bin/sh\", \"-c\", \"exit 0\"]\n\n[zones.%q]\npath = %q\n",
		local.OutputDir, dir, domain, zonePath)
	cfgPath := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(cfgPath, []byte(cfgTOML), 0o600); err != nil {
		t.Fatal(err)
	}
	st := statepkg.NewState(local.StatePath())
	kg := signerpkg.NewKeyGenerator(local)
	ksk, err := kg.GenerateKSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	zsk, err := kg.GenerateZSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	st.SetZone(domain, &statepkg.ZoneState{Path: zonePath, KSK: ksk, ZSK: zsk})
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
	orig := configPath
	configPath = cfgPath
	t.Cleanup(func() { configPath = orig })
	prober := &fakeProber{served: false}
	installFakeProber(t, prober)

	if err := runSign(nil, nil); err != nil {
		t.Fatalf("sign: %v", err)
	}
	disk, err := statepkg.LoadState(local.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	zs := disk.GetZone(domain)
	if zs.LastSigned.IsZero() {
		t.Fatal("the zone must have been signed")
	}
	if !zs.PendingPublication || !zs.PublishedAt.IsZero() {
		t.Fatalf("probe mode `sign`: a successful hook must not confirm: %+v", zs)
	}
	if prober.calls == 0 {
		t.Fatal("`sign` must run the probe")
	}

	// A later run with nothing to sign still probes the pending generation.
	prober.set(true)
	if err := runSign(nil, nil); err != nil {
		t.Fatalf("second sign: %v", err)
	}
	disk, _ = statepkg.LoadState(local.StatePath())
	zs = disk.GetZone(domain)
	if zs.PendingPublication || zs.PublishedAt.IsZero() {
		t.Fatalf("the probe must confirm the pending generation on a later `sign`: %+v", zs)
	}
	if !strings.HasSuffix(zs.Path, domain+".zone") {
		t.Fatalf("unexpected zone path %q", zs.Path)
	}
}
