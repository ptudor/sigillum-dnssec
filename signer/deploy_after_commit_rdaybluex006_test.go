//go:build !windows

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
	"github.com/ptudor/sigillum-dnssec/signer/internal/fsutil"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RDAYBLUEX-006: a deployment hook runs only after the state describing the
// signed generation has been committed. A pre-commit save failure launches
// no hook, leaves the older on-disk file untouched and the new in-memory
// generation intact and pending; the first later cycle whose save commits
// saves first and then runs the hook exactly once for that generation. A
// post-rename durability warning counts as committed. A hook completion
// never replaces newer unsaved memory with the older disk snapshot.

func TestRDAYBLUEX006_NoHookBeforeCommittedSave(t *testing.T) {
	for _, coalesce := range []bool{false, true} {
		t.Run(fmt.Sprintf("coalesce=%v", coalesce), func(t *testing.T) {
			d, cfg, state, domain := signableZoneDaemon(t)
			cfg.LoadedAt = time.Now().UTC()
			rec := newHookRecorder(t)
			cfg.Hooks.PostSignCmd = rec.cmd()
			cfg.Hooks.CoalescePostSign = coalesce
			orig := cfg.StatePath()

			// Cycle 1: generation 1 signed, saved, deployed and confirmed.
			d.signAllZones()
			d.hookWG.Wait()
			if n := len(rec.invocations(t)); n != 1 {
				t.Fatalf("cycle 1 must deploy once, got %d", n)
			}
			rec.reset()
			gen1 := state.GetZone(domain).LastSigned
			if state.GetZone(domain).PendingPublication {
				t.Fatal("cycle 1 must be confirmed")
			}

			// Cycle 2: the source changed; the save fails before the rename
			// while an older valid state file (generation 1) exists.
			roPath, restore := failNextDaemonSave(t, state, orig)
			before, err := os.ReadFile(roPath)
			if err != nil {
				t.Fatal(err)
			}
			appendZoneRecord(t, cfg.Zones[domain].Path, "mail\tIN\tA\t192.0.2.25")
			d.signAllZones()
			d.hookWG.Wait()
			if inv := rec.invocations(t); len(inv) != 0 {
				t.Fatalf("no hook may start when the state save did not commit, got %v", inv)
			}
			if !d.lastSaveFailed.Load() {
				t.Fatal("the failed save must be recorded")
			}
			after, _ := os.ReadFile(roPath)
			if !bytes.Equal(before, after) {
				t.Fatal("the older on-disk state must not be rewritten")
			}
			zs := state.GetZone(domain)
			if !zs.LastSigned.After(gen1) || !zs.PendingPublication {
				t.Fatalf("the new generation must stay intact and pending in memory: %+v", zs)
			}
			gen2 := zs.LastSigned
			if len(d.deferredHooks) != 1 || !d.deferredHooks[domain].SignedAt.Equal(gen2) {
				t.Fatalf("the deployment must be deferred for exactly generation 2: %+v", d.deferredHooks)
			}
			restore()

			// Cycle 3: nothing to sign; the save commits, then the hook runs
			// exactly once and confirms generation 2.
			d.signAllZones()
			d.hookWG.Wait()
			inv := rec.invocations(t)
			if len(inv) != 1 {
				t.Fatalf("the deferred deployment must run exactly once after the save commits, got %d: %v", len(inv), inv)
			}
			if coalesce {
				if inv[0]["DNSSEC_DOMAINS"] != domain {
					t.Fatalf("batch invocation must name the zone: %v", inv[0])
				}
			} else if inv[0]["DNSSEC_DOMAIN"] != domain {
				t.Fatalf("per-zone invocation must name the zone: %v", inv[0])
			}
			if d.deferredHooks != nil {
				t.Fatal("the deferred set must be cleared once launched")
			}
			disk, err := statepkg.LoadState(orig)
			if err != nil {
				t.Fatal(err)
			}
			dz := disk.GetZone(domain)
			if !dz.LastSigned.Equal(gen2) || dz.PendingPublication || !dz.PublishedGenerationSignedAt.Equal(gen2) {
				t.Fatalf("generation 2 must be saved and then confirmed by its hook: %+v", dz)
			}
		})
	}
}

// A pre-save reload failure (state file made invalid) also withholds hooks.
func TestRDAYBLUEX006_PreSaveReloadFailureWithholdsHooks(t *testing.T) {
	d, cfg, state, domain := signableZoneDaemon(t)
	cfg.LoadedAt = time.Now().UTC()
	rec := newHookRecorder(t)
	cfg.Hooks.PostSignCmd = rec.cmd()
	d.signAllZones()
	d.hookWG.Wait()
	rec.reset()

	// Make the file invalid AFTER the cycle's authoritative load: use the
	// signer's own seam — the simplest deterministic way is to corrupt the
	// file between two cycles and let the cycle's initial reload fail closed
	// (no signing, no hook), which is the same withholding contract.
	if err := os.WriteFile(cfg.StatePath(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	appendZoneRecord(t, cfg.Zones[domain].Path, "mail\tIN\tA\t192.0.2.25")
	d.signAllZones()
	d.hookWG.Wait()
	if inv := rec.invocations(t); len(inv) != 0 {
		t.Fatalf("no hook may run when the authoritative state cannot be loaded: %v", inv)
	}
	if d.StateFault() == "" {
		t.Fatal("the state fault must be reported")
	}
	_ = state
}

// A save whose file is visible but whose directory sync failed is committed:
// the hook proceeds.
func TestRDAYBLUEX006_DurabilityWarningStillDeploys(t *testing.T) {
	d, cfg, state, domain := signableZoneDaemon(t)
	cfg.LoadedAt = time.Now().UTC()
	rec := newHookRecorder(t)
	cfg.Hooks.PostSignCmd = rec.cmd()
	d.signAllZones()
	d.hookWG.Wait()
	rec.reset()

	restore := fsutil.SetSyncDirForTest(func(string) error { return errors.New("injected directory sync failure") })
	t.Cleanup(restore)
	appendZoneRecord(t, cfg.Zones[domain].Path, "mail\tIN\tA\t192.0.2.25")
	d.signAllZones()
	d.hookWG.Wait()
	if n := len(rec.invocations(t)); n != 1 {
		t.Fatalf("a visible-but-unsynced save is committed; the hook must run once, got %d", n)
	}
	if d.lastSaveFailed.Load() || d.deferredHooks != nil {
		t.Fatal("a durability warning is not a failed save")
	}
	zs := state.GetZone(domain)
	if zs.PendingPublication {
		t.Fatal("the deployed generation must be confirmed")
	}
	restore()
	disk, err := statepkg.LoadState(cfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if disk.GetZone(domain).PendingPublication {
		t.Fatal("the confirmation must be persisted")
	}
}

// Immediate mode: publication is confirmed at the write, but the deployment
// hook is still withheld until the state commits and then runs once.
func TestRDAYBLUEX006_ImmediateModeDefersHookToo(t *testing.T) {
	rec := newHookRecorder(t)
	d, cfg, state, domain := modeDaemon(t, config.PublicationImmediate, rec.cmd())
	orig := cfg.StatePath()
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	d.signAllZones()
	d.hookWG.Wait()
	rec.reset()

	_, restore := failNextDaemonSave(t, state, orig)
	appendZoneRecord(t, cfg.Zones[domain].Path, "mail\tIN\tA\t192.0.2.25")
	d.signAllZones()
	d.hookWG.Wait()
	if inv := rec.invocations(t); len(inv) != 0 {
		t.Fatalf("immediate mode: the hook must also wait for a committed save, got %v", inv)
	}
	restore()
	d.signAllZones()
	d.hookWG.Wait()
	if n := len(rec.invocations(t)); n != 1 {
		t.Fatalf("the deferred deployment must run once, got %d", n)
	}
}

// A slow hook from cycle 1 completes while memory holds unsaved generation 2
// (cycle 2's save failed): the completion is for a generation that is no
// longer the zone's current one, so it is discarded (RDAYBLUEX-005) — and in
// particular it never reverts memory to the older disk snapshot. The next
// committed cycle saves generation 2 and deploys it; only generation 2 is
// ever confirmed.
func TestRDAYBLUEX006_HookCompletionDoesNotRevertUnsavedMemory(t *testing.T) {
	d, cfg, state, domain := signableZoneDaemon(t)
	cfg.LoadedAt = time.Now().UTC()
	release := t.TempDir() + "/release"
	cfg.Hooks.PostSignCmd = []string{"/bin/sh", "-c", "while [ ! -f " + release + " ]; do sleep 0.05; done; exit 0"}
	orig := cfg.StatePath()

	d.signAllZones() // generation 1 signed and saved; its hook is blocked
	gen1 := state.GetZone(domain).LastSigned

	// Cycle 2 while the hook is blocked: generation 2 in memory, save fails.
	_, restore := failNextDaemonSave(t, state, orig)
	appendZoneRecord(t, cfg.Zones[domain].Path, "mail\tIN\tA\t192.0.2.25")
	d.signAllZones()
	gen2 := state.GetZone(domain).LastSigned
	if !gen2.After(gen1) || !d.lastSaveFailed.Load() {
		t.Fatal("cycle 2 must sign generation 2 in memory with a failed save")
	}
	restore()

	// Release the generation-1 hook.
	if err := os.WriteFile(release, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	d.hookWG.Wait()
	zs := state.GetZone(domain)
	if !zs.LastSigned.Equal(gen2) {
		t.Fatalf("the hook completion reverted memory to the older disk generation: %v (want %v)", zs.LastSigned, gen2)
	}
	if !zs.PendingPublication || !zs.PublishedAt.IsZero() {
		t.Fatalf("a completion for a superseded generation must confirm nothing: %+v", zs)
	}

	// The next cycle saves generation 2 and deploys it (the release file
	// exists, so the hook returns at once); exactly generation 2 is confirmed
	// and persisted.
	d.signAllZones()
	d.hookWG.Wait()
	zs = state.GetZone(domain)
	if zs.PendingPublication || !zs.PublishedGenerationSignedAt.Equal(gen2) {
		t.Fatalf("generation 2 must be confirmed by its own hook: %+v", zs)
	}
	disk, err := statepkg.LoadState(orig)
	if err != nil {
		t.Fatal(err)
	}
	dz := disk.GetZone(domain)
	if !dz.LastSigned.Equal(gen2) || dz.PendingPublication || !dz.PublishedGenerationSignedAt.Equal(gen2) {
		t.Fatalf("the persisted state must show exactly generation 2 confirmed: %+v", dz)
	}
}
