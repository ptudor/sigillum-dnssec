//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	statepkg "github.com/ptudor/dnssec-tudor/internal/state"
)

// RA6X-025: every CLI mutation committed under the process lock must survive
// the daemon's next save — warnings added or cleared, removals, and phase
// metadata that does not sign — and a removed zone must not be resurrected
// from a stale (pre-SIGHUP) configuration.

// cliState simulates a CLI command: load the authoritative state from disk
// under the lock, mutate, save.
func cliState(t *testing.T, dataDir, statePath string, mutate func(*statepkg.State)) {
	t.Helper()
	lock, err := acquireStateLock(dataDir, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.release()
	st, err := statepkg.LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	mutate(st)
	if err := st.Save(); err != nil {
		t.Fatal(err)
	}
}

func TestRA6X025_CLIMutationsSurviveDaemonCycles(t *testing.T) {
	d, cfg, state, domain := signableZoneDaemon(t)
	cfg.LoadedAt = time.Now().UTC()
	statePath := cfg.StatePath()

	// Cycle 1: the daemon signs and saves.
	d.signAllZones()
	disk, err := statepkg.LoadState(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if disk.GetZone(domain) == nil || disk.GetZone(domain).LastSigned.IsZero() {
		t.Fatal("cycle 1 must persist the signed zone")
	}

	// A CLI adds an urgent registrar warning (no signing, same LastSigned).
	cliState(t, cfg.DataDir, statePath, func(st *statepkg.State) {
		st.UpdateZone(domain, func(z *statepkg.ZoneState) { z.AddWarning("URGENT: registrar left zero DS") })
	})
	d.signAllZones() // cycle 2: nothing to sign, saves
	disk, _ = statepkg.LoadState(statePath)
	if !strings.Contains(strings.Join(disk.GetZone(domain).Warnings, "\n"), "URGENT") {
		t.Fatal("the CLI's warning was lost by the daemon's save")
	}
	if state.GetZone(domain) == nil || !strings.Contains(strings.Join(state.GetZone(domain).Warnings, "\n"), "URGENT") {
		t.Fatal("the daemon's memory must adopt the CLI's warning")
	}

	// The CLI clears the warning.
	cliState(t, cfg.DataDir, statePath, func(st *statepkg.State) {
		st.UpdateZone(domain, func(z *statepkg.ZoneState) { z.ClearStickyWarnings() })
	})
	d.signAllZones()
	disk, _ = statepkg.LoadState(statePath)
	if strings.Contains(strings.Join(disk.GetZone(domain).Warnings, "\n"), "URGENT") {
		t.Fatal("a warning cleared by the CLI reappeared after the daemon's save")
	}

	// A rollover-timestamp-only change with equal LastSigned.
	stamp := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	cliState(t, cfg.DataDir, statePath, func(st *statepkg.State) {
		st.UpdateZone(domain, func(z *statepkg.ZoneState) {
			z.Rollover = &statepkg.RolloverState{Type: "zsk", State: statepkg.ZSKRolloverStatePrePublish, OldKeyID: z.ZSK.ID, NewKeyID: z.ZSK.ID + 1, Started: stamp, PhaseFirstSigned: stamp}
		})
	})
	// The daemon's rollover check would need key files for the new ZSK; keep
	// the cycle to state handling by clearing the zone's config entry for this
	// step so nothing is signed.
	zoneCfg := cfg.Zones[domain]
	delete(cfg.Zones, domain)
	d.signAllZones()
	cfg.Zones[domain] = zoneCfg
	disk, _ = statepkg.LoadState(statePath)
	if r := disk.GetZone(domain).Rollover; r == nil || !r.PhaseFirstSigned.Equal(stamp) {
		t.Fatalf("rollover metadata set by the CLI must persist through the daemon's save: %+v", r)
	}
	cliState(t, cfg.DataDir, statePath, func(st *statepkg.State) {
		st.UpdateZone(domain, func(z *statepkg.ZoneState) { z.Rollover = nil })
	})

	// The CLI removes the zone while the daemon still holds the old
	// configuration listing it: the daemon must not re-create it.
	cliState(t, cfg.DataDir, statePath, func(st *statepkg.State) { st.MarkRemoved(domain) })
	d.signAllZones()
	disk, _ = statepkg.LoadState(statePath)
	if disk.GetZone(domain) != nil {
		t.Fatal("a removed zone was resurrected from the daemon's stale configuration")
	}
	if _, removed := disk.RemovedAt(domain); !removed {
		t.Fatal("the deletion marker must persist")
	}
	if state.GetZone(domain) != nil {
		t.Fatal("the daemon's memory must drop the removed zone")
	}

	// The operator re-adds the zone to the configuration and reloads AFTER the
	// removal: the daemon initializes it again and clears the marker.
	cfg.LoadedAt = time.Now().UTC().Add(time.Second)
	d.signAllZones()
	disk, _ = statepkg.LoadState(statePath)
	if disk.GetZone(domain) == nil {
		t.Fatal("a zone listed by a configuration loaded after its removal must be managed again")
	}
	if _, removed := disk.RemovedAt(domain); removed {
		t.Fatal("re-adding must clear the deletion marker")
	}
	if _, err := os.Stat(filepath.Join(cfg.OutputDir, domain+".zone.signed")); err != nil {
		t.Fatalf("re-added zone must be signed: %v", err)
	}
}

// After a failed save the daemon merges (keeping its newer results) instead of
// discarding them for older disk data.
func TestRA6X025_FailedSaveDoesNotDiscardNewerResults(t *testing.T) {
	d, cfg, state, domain := signableZoneDaemon(t)
	cfg.LoadedAt = time.Now().UTC()
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not restrict root")
	}
	// Make the save fail for one cycle: the state file lives in a read-only
	// directory (readable, so the cycle's authoritative load proceeds, but the
	// atomic save cannot create its temp file there).
	orig := cfg.StatePath()
	roDir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(roDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(orig)
	if err != nil {
		t.Fatal(err)
	}
	roPath := filepath.Join(roDir, "state.json")
	if err := os.WriteFile(roPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(roDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) })
	state.SetPath(roPath)
	d.signAllZones()
	signedAt := state.GetZone(domain).LastSigned
	if signedAt.IsZero() {
		t.Fatal("zone should have been signed in memory")
	}
	if !d.lastSaveFailed.Load() {
		t.Fatal("a failed save must be recorded")
	}
	state.SetPath(orig)
	d.signAllZones()
	disk, err := statepkg.LoadState(orig)
	if err != nil {
		t.Fatal(err)
	}
	if disk.GetZone(domain).LastSigned.Before(signedAt) {
		t.Fatal("newer unsaved signing results must not be replaced by older disk data")
	}
	if d.lastSaveFailed.Load() {
		t.Fatal("a successful save must clear the failed-save flag")
	}
}
