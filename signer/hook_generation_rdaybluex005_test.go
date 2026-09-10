//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RDAYBLUEX-005: an asynchronous hook completion is bound to the daemon
// generation, domain configuration, output path and exact signed generation
// it was launched for. A completion whose identity no longer matches — a
// reload happened, the zone was removed or re-added, the output path moved,
// or the zone was re-signed — is logged and discarded; it neither confirms
// nor fails anything in the newer generation.

// blockingHookDaemon builds a hook-mode daemon whose hook blocks until the
// returned release file exists.
func blockingHookDaemon(t *testing.T) (*Daemon, *config.Config, *statepkg.State, string, string) {
	t.Helper()
	d, cfg, state, domain := signableZoneDaemon(t)
	cfg.LoadedAt = time.Now().UTC()
	release := filepath.Join(t.TempDir(), "release")
	cfg.Hooks.PostSignCmd = []string{"/bin/sh", "-c", "while [ ! -f " + release + " ]; do sleep 0.05; done; exit 0"}
	return d, cfg, state, domain, release
}

// reloadFromDisk performs a SIGHUP-style reload: a fresh config value and a
// state freshly loaded from disk.
func reloadFromDisk(t *testing.T, d *Daemon, cfg *config.Config, mutate func(*config.Config)) (*config.Config, *statepkg.State) {
	t.Helper()
	newCfg := *cfg
	newCfg.Zones = map[string]config.ZoneConfig{}
	for k, v := range cfg.Zones {
		newCfg.Zones[k] = v
	}
	newCfg.LoadedAt = time.Now().UTC()
	if mutate != nil {
		mutate(&newCfg)
	}
	newState, err := statepkg.LoadState(newCfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	d.Reload(&newCfg, newState)
	return &newCfg, newState
}

func releaseHooks(t *testing.T, d *Daemon, release string) {
	t.Helper()
	if err := os.WriteFile(release, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	d.hookWG.Wait()
}

func TestRDAYBLUEX005_StaleGenerationCompletionIsDiscarded(t *testing.T) {
	d, cfg, _, domain, release := blockingHookDaemon(t)
	if d.Generation() != 1 {
		t.Fatalf("a new daemon is generation 1, got %d", d.Generation())
	}

	d.signAllZones() // generation A signed, saved, pending; hook blocked
	_, stB := reloadFromDisk(t, d, cfg, nil)
	if d.Generation() != 2 {
		t.Fatalf("a reload publishes a new generation, got %d", d.Generation())
	}
	zsB := stB.GetZone(domain)
	if !zsB.PendingPublication {
		t.Fatal("B must start pending (A's hook has not completed)")
	}
	before := zsB.Clone()

	releaseHooks(t, d, release) // A completes successfully — for generation 1
	zsB = stB.GetZone(domain)
	if !zsB.PendingPublication || !zsB.PublishedAt.Equal(before.PublishedAt) ||
		!zsB.PublishedGenerationSignedAt.Equal(before.PublishedGenerationSignedAt) ||
		!zsB.DNSKEYCacheHorizon.Equal(before.DNSKEYCacheHorizon) || !zsB.RRSIGCacheHorizon.Equal(before.RRSIGCacheHorizon) ||
		zsB.ServedDNSKEYTTL != before.ServedDNSKEYTTL {
		t.Fatalf("a stale-generation completion must leave B untouched: before %+v after %+v", before, zsB)
	}
	disk, err := statepkg.LoadState(cfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if !disk.GetZone(domain).PendingPublication {
		t.Fatal("the stale completion must not be persisted as a confirmation")
	}

	// Complete B: its own cycle relaunches the pending deployment under
	// generation 2 and confirms exactly B.
	d.signAllZones()
	d.hookWG.Wait()
	zsB = stB.GetZone(domain)
	if zsB.PendingPublication || !zsB.PublishedGenerationSignedAt.Equal(zsB.LastSigned) {
		t.Fatalf("B must be confirmed by a generation-2 hook: %+v", zsB)
	}
	disk, _ = statepkg.LoadState(cfg.StatePath())
	if disk.GetZone(domain).PendingPublication {
		t.Fatal("B's confirmation must be persisted")
	}
}

// A stale FAILURE must not overwrite the newer generation's status either.
func TestRDAYBLUEX005_StaleFailureDoesNotTouchNewGeneration(t *testing.T) {
	d, cfg, _, domain := signableZoneDaemon(t)
	cfg.LoadedAt = time.Now().UTC()
	release := filepath.Join(t.TempDir(), "release")
	cfg.Hooks.PostSignCmd = []string{"/bin/sh", "-c", "while [ ! -f " + release + " ]; do sleep 0.05; done; exit 1"}
	d.signAllZones()
	_, stB := reloadFromDisk(t, d, cfg, func(c *config.Config) {
		c.Hooks.PostSignCmd = []string{"/bin/sh", "-c", "exit 0"}
	})
	releaseHooks(t, d, release) // A fails under generation 1
	if hasErrorPrefix(stB.GetZone(domain).Errors, statepkg.OpDeployment) {
		t.Fatalf("a stale failure must not record a deployment error in the new generation: %v", stB.GetZone(domain).Errors)
	}
	d.signAllZones() // B's own (healthy) hook confirms
	d.hookWG.Wait()
	if zs := stB.GetZone(domain); zs.PendingPublication || hasErrorPrefix(zs.Errors, statepkg.OpDeployment) {
		t.Fatalf("B must be confirmed cleanly: %+v", zs)
	}
}

func TestRDAYBLUEX005_RemovedAndReAddedDomain(t *testing.T) {
	d, cfg, _, domain, release := blockingHookDaemon(t)
	d.signAllZones() // A pending, hook blocked

	// The operator removes the zone (CLI) and reloads.
	cliState(t, cfg.DataDir, cfg.StatePath(), func(st *statepkg.State) { st.MarkRemoved(domain) })
	_, stB := reloadFromDisk(t, d, cfg, func(c *config.Config) { delete(c.Zones, domain) })
	releaseHooks(t, d, release)
	if stB.GetZone(domain) != nil {
		t.Fatal("a stale completion must not resurrect a removed zone")
	}
	disk, _ := statepkg.LoadState(cfg.StatePath())
	if disk.GetZone(domain) != nil {
		t.Fatal("nothing may be persisted for a removed zone")
	}

	// Re-added: a fresh record, signed under the new generation, pending.
	cliState(t, cfg.DataDir, cfg.StatePath(), func(st *statepkg.State) { st.ClearRemoved(domain) })
	_, stC := reloadFromDisk(t, d, cfg, nil)
	if err := os.Remove(release); err != nil {
		t.Fatal(err)
	}
	d.signAllZones() // re-initializes and signs C; hook blocked
	zsC := stC.GetZone(domain)
	if zsC == nil || !zsC.PendingPublication {
		t.Fatalf("the re-added zone must be signed and pending: %+v", zsC)
	}
	releaseHooks(t, d, release)
	if zsC = stC.GetZone(domain); zsC.PendingPublication || !zsC.PublishedGenerationSignedAt.Equal(zsC.LastSigned) {
		t.Fatalf("C is confirmed by its own hook: %+v", zsC)
	}
}

func TestRDAYBLUEX005_ChangedOutputPath(t *testing.T) {
	d, cfg, _, domain, release := blockingHookDaemon(t)
	d.signAllZones() // A pending, hook blocked (deploying <old output>/zone)
	newOut := t.TempDir()
	_, stB := reloadFromDisk(t, d, cfg, func(c *config.Config) { c.OutputDir = newOut })
	releaseHooks(t, d, release)
	if !stB.GetZone(domain).PendingPublication {
		t.Fatal("a completion that deployed the old output path must not confirm the new generation")
	}
}

// Same generation, newer signing: the completion for the superseded signing
// is discarded and only the newest signing is confirmed by its own hook.
func TestRDAYBLUEX005_NewerSigningSupersedesCompletion(t *testing.T) {
	d, cfg, state, domain, release := blockingHookDaemon(t)
	d.signAllZones() // A, hook blocked
	genA := state.GetZone(domain).LastSigned
	appendZoneRecord(t, cfg.Zones[domain].Path, "mail\tIN\tA\t192.0.2.25")
	d.signAllZones() // B signed and saved; its hook is blocked too
	genB := state.GetZone(domain).LastSigned
	if !genB.After(genA) {
		t.Fatal("B must be a newer signing")
	}
	releaseHooks(t, d, release) // both complete; A's identity no longer matches
	zs := state.GetZone(domain)
	if zs.PendingPublication || !zs.PublishedGenerationSignedAt.Equal(genB) {
		t.Fatalf("exactly B must be confirmed: %+v", zs)
	}
	disk, _ := statepkg.LoadState(cfg.StatePath())
	if dz := disk.GetZone(domain); dz.PendingPublication || !dz.PublishedGenerationSignedAt.Equal(genB) {
		t.Fatalf("B's confirmation must be persisted: %+v", dz)
	}
}
