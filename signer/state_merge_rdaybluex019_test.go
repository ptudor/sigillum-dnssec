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

	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RDAYBLUEX-019: after a daemon pre-commit save failure, a CLI mutation
// persisted at the same LastSigned (an urgent registrar warning, an operation
// error) and the daemon's unsaved signing results must BOTH survive the
// daemon's next merge-and-save; a diagnostic the CLI later clears must not be
// resurrected.

// failNextDaemonSave retargets the state at a read-only copy so the next
// atomic save cannot create its temp file (pre-commit failure) while the
// cycle's authoritative load still succeeds. It returns the read-only copy's
// path and the restore function.
func failNextDaemonSave(t *testing.T, state *statepkg.State, orig string) (roPath string, restore func()) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not restrict root")
	}
	roDir := filepath.Join(t.TempDir(), "ro")
	if err := os.Mkdir(roDir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(orig)
	if err != nil {
		t.Fatal(err)
	}
	roPath = filepath.Join(roDir, "state.json")
	if err := os.WriteFile(roPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(roDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) })
	state.SetPath(roPath)
	return roPath, func() { state.SetPath(orig) }
}

// appendZoneRecord changes the unsigned zone (size and mtime) so the next
// cycle must re-sign it.
func appendZoneRecord(t *testing.T, path, record string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(record + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRDAYBLUEX019_CLIDiagnosticsSurviveDaemonSaveFailure(t *testing.T) {
	d, cfg, state, domain := signableZoneDaemon(t)
	cfg.LoadedAt = time.Now().UTC()
	orig := cfg.StatePath()

	// Cycle 1: signed and saved (generation 1).
	d.signAllZones()
	gen1 := state.GetZone(domain).LastSigned
	if gen1.IsZero() || d.lastSaveFailed.Load() {
		t.Fatal("cycle 1 must sign and save")
	}

	// Cycle 2: the source changed, the daemon signs generation 2 in memory,
	// and its save fails before the rename.
	_, restore := failNextDaemonSave(t, state, orig)
	appendZoneRecord(t, cfg.Zones[domain].Path, "mail\tIN\tA\t192.0.2.25")
	d.signAllZones()
	gen2 := state.GetZone(domain).LastSigned
	if !gen2.After(gen1) {
		t.Fatalf("cycle 2 must have re-signed in memory (gen1 %v, gen2 %v)", gen1, gen2)
	}
	if !d.lastSaveFailed.Load() {
		t.Fatal("the failed save must be recorded")
	}
	restore()

	// A CLI, under the lock, persists an urgent registrar warning and a
	// registrar operation error against the disk's generation 1.
	cliState(t, cfg.DataDir, orig, func(st *statepkg.State) {
		if !st.GetZone(domain).LastSigned.Equal(gen1) {
			t.Fatalf("the disk must still hold generation 1, got %v", st.GetZone(domain).LastSigned)
		}
		st.UpdateZone(domain, func(z *statepkg.ZoneState) {
			z.AddWarning("URGENT: registrar left zone with ZERO DS at parent")
			z.SetOperationError(statepkg.OpRegistrar, "push failed: 502")
		})
	})

	// Cycle 3: merge and save. Both sides must be on disk and in memory.
	d.signAllZones()
	if d.lastSaveFailed.Load() {
		t.Fatal("cycle 3 must save")
	}
	disk, err := statepkg.LoadState(orig)
	if err != nil {
		t.Fatal(err)
	}
	dz := disk.GetZone(domain)
	if dz.LastSigned.Before(gen2) {
		t.Fatalf("the daemon's unsaved generation 2 was lost: disk has %v", dz.LastSigned)
	}
	if !strings.Contains(strings.Join(dz.Warnings, "\n"), "URGENT: registrar left zone with ZERO DS") {
		t.Fatalf("the CLI's urgent warning was erased by the daemon's save: %v", dz.Warnings)
	}
	if !dz.HasOperationError(statepkg.OpRegistrar) {
		t.Fatalf("the CLI's registrar error was erased by the daemon's save: %v", dz.Errors)
	}
	mz := state.GetZone(domain)
	if !strings.Contains(strings.Join(mz.Warnings, "\n"), "URGENT") || !mz.HasOperationError(statepkg.OpRegistrar) {
		t.Fatalf("the daemon's memory must adopt the CLI's diagnostics: %v / %v", mz.Warnings, mz.Errors)
	}
	if dz.Revision == 0 {
		t.Fatal("the persisted zone must carry a revision")
	}

	// The CLI resolves the condition: clears the sticky warning and the
	// registrar error. The daemon (clean) adopts the removal and does not
	// resurrect either on its next save.
	cliState(t, cfg.DataDir, orig, func(st *statepkg.State) {
		st.UpdateZone(domain, func(z *statepkg.ZoneState) {
			z.ClearStickyWarnings()
			z.ClearOperationError(statepkg.OpRegistrar)
		})
	})
	d.signAllZones()
	disk, _ = statepkg.LoadState(orig)
	dz = disk.GetZone(domain)
	if strings.Contains(strings.Join(dz.Warnings, "\n"), "URGENT") || dz.HasOperationError(statepkg.OpRegistrar) {
		t.Fatalf("diagnostics cleared by the CLI were resurrected: %v / %v", dz.Warnings, dz.Errors)
	}

	// And again with the daemon dirty: the CLI clears while the daemon holds
	// unsaved work; the clear must still win and the unsaved work survive.
	cliState(t, cfg.DataDir, orig, func(st *statepkg.State) {
		st.UpdateZone(domain, func(z *statepkg.ZoneState) { z.AddWarning("URGENT: second") })
	})
	d.signAllZones() // adopts the warning, saves
	_, restore = failNextDaemonSave(t, state, orig)
	appendZoneRecord(t, cfg.Zones[domain].Path, "ftp\tIN\tA\t192.0.2.26")
	d.signAllZones() // generation 3 in memory, save fails
	gen3 := state.GetZone(domain).LastSigned
	restore()
	cliState(t, cfg.DataDir, orig, func(st *statepkg.State) {
		st.UpdateZone(domain, func(z *statepkg.ZoneState) { z.ClearStickyWarnings() })
	})
	d.signAllZones()
	disk, _ = statepkg.LoadState(orig)
	dz = disk.GetZone(domain)
	if dz.LastSigned.Before(gen3) {
		t.Fatalf("generation 3 lost: %v", dz.LastSigned)
	}
	if strings.Contains(strings.Join(dz.Warnings, "\n"), "URGENT: second") {
		t.Fatalf("a warning cleared by the CLI while the daemon was dirty was resurrected: %v", dz.Warnings)
	}
}

// Concurrent CLI mutations under the lock interleaved with daemon cycles:
// every CLI-added urgent warning must be on disk and in memory at the end,
// and the daemon's signing state must never regress. Run under -race.
func TestRDAYBLUEX019_ConcurrentCLIAndDaemonSequences(t *testing.T) {
	d, cfg, state, domain := signableZoneDaemon(t)
	cfg.LoadedAt = time.Now().UTC()
	path := cfg.StatePath()
	d.signAllZones()

	const n = 12
	errCh := make(chan error, n)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			msg := fmt.Sprintf("URGENT: %d", i)
			if err := cliMutate(cfg.DataDir, path, func(st *statepkg.State) {
				st.UpdateZone(domain, func(z *statepkg.ZoneState) { z.AddWarning(msg) })
			}); err != nil {
				errCh <- err
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			d.signAllZones()
			time.Sleep(20 * time.Millisecond)
		}
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}
	d.signAllZones()

	disk, err := statepkg.LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	dw := strings.Join(disk.GetZone(domain).Warnings, "\n")
	mw := strings.Join(state.GetZone(domain).Warnings, "\n")
	for i := 0; i < n; i++ {
		msg := fmt.Sprintf("URGENT: %d", i)
		if !strings.Contains(dw, msg+"\n") && !strings.HasSuffix(dw, msg) {
			t.Fatalf("warning %q lost on disk: %v", msg, disk.GetZone(domain).Warnings)
		}
		if !strings.Contains(mw, msg+"\n") && !strings.HasSuffix(mw, msg) {
			t.Fatalf("warning %q lost in memory: %v", msg, state.GetZone(domain).Warnings)
		}
	}
	if disk.GetZone(domain).LastSigned.IsZero() {
		t.Fatal("signing state lost")
	}
}

// cliMutate is cliState for goroutines (returns errors instead of failing).
func cliMutate(dataDir, statePath string, mutate func(*statepkg.State)) error {
	lock, err := acquireStateLock(dataDir, 5*time.Second)
	if err != nil {
		return err
	}
	defer lock.release()
	st, err := statepkg.LoadState(statePath)
	if err != nil {
		return err
	}
	mutate(st)
	return st.Save()
}
