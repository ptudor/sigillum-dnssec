//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RDAYBLUEX-004: data_dir is restart-required. A reload naming a different
// data_dir is rejected whole — the previous config/state snapshot and
// generation stay active and signing keeps reading and writing only the
// startup directory — while symlink-equivalent and relative/absolute-
// equivalent spellings of the same directory are accepted.

func TestRDAYBLUEX004_ReloadRejectsChangedDataDir(t *testing.T) {
	d, cfg, state, domain := signableZoneDaemon(t)
	cfg.LoadedAt = time.Now().UTC()
	d.signAllZones()
	if state.GetZone(domain).LastSigned.IsZero() {
		t.Fatal("initial sign expected")
	}

	other := t.TempDir()
	newCfg := *cfg
	newCfg.DataDir = other
	newCfg.Zones = map[string]config.ZoneConfig{domain: cfg.Zones[domain]}
	newState := statepkg.NewState(newCfg.StatePath())
	newState.SetZone(domain, state.GetZoneCopy(domain))

	err := d.Reload(&newCfg, newState)
	if !errors.Is(err, ErrDataDirChanged) {
		t.Fatalf("a reload changing data_dir must be rejected with ErrDataDirChanged, got %v", err)
	}
	if d.Generation() != 1 {
		t.Fatalf("a rejected reload must not publish a new generation, got %d", d.Generation())
	}
	curCfg, curState := d.current()
	if curCfg != cfg || curState != state {
		t.Fatal("the previous config/state snapshot must remain active")
	}

	// Subsequent signing reads and writes only the startup directory.
	appendZoneRecord(t, cfg.Zones[domain].Path, "mail\tIN\tA\t192.0.2.25")
	d.signAllZones()
	if _, err := os.Stat(cfg.StatePath()); err != nil {
		t.Fatalf("state must be written under the active data_dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(other, "state.json")); !os.IsNotExist(err) {
		t.Fatalf("nothing may be written under the rejected data_dir, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(other, "state.json.lock")); !os.IsNotExist(err) {
		t.Fatalf("the rejected data_dir must not even be locked, stat err=%v", err)
	}
	disk, err := statepkg.LoadState(cfg.StatePath())
	if err != nil {
		t.Fatal(err)
	}
	if !disk.GetZone(domain).LastSigned.Equal(state.GetZone(domain).LastSigned) {
		t.Fatal("the active state must have been persisted in the startup directory")
	}

	// A second instance cannot operate on the directory the daemon actively
	// uses: the lifetime lock on the startup directory still refuses it.
	lock, err := acquireInstanceLock(cfg.DataDir)
	if err != nil {
		t.Fatalf("instance lock for the active directory: %v", err)
	}
	defer lock.release()
	if _, err := acquireInstanceLock(cfg.DataDir); err == nil || !strings.Contains(err.Error(), "already holds") {
		t.Fatalf("a second instance on the active data_dir must be refused, got %v", err)
	}
}

// Harmless textual differences do not trigger a false migration.
func TestRDAYBLUEX004_EquivalentDataDirSpellingsAccepted(t *testing.T) {
	d, cfg, state, domain := signableZoneDaemon(t)
	cfg.LoadedAt = time.Now().UTC()
	d.signAllZones()

	link := filepath.Join(t.TempDir(), "data-link")
	if err := os.Symlink(cfg.DataDir, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	relative := filepath.Join(cfg.DataDir, "..", filepath.Base(cfg.DataDir))
	for _, spelling := range []string{link, relative, cfg.DataDir + string(filepath.Separator)} {
		newCfg := *cfg
		newCfg.DataDir = spelling
		newCfg.Zones = map[string]config.ZoneConfig{domain: cfg.Zones[domain]}
		newState, err := statepkg.LoadState(cfg.StatePath())
		if err != nil {
			t.Fatal(err)
		}
		before := d.Generation()
		if err := d.Reload(&newCfg, newState); err != nil {
			t.Fatalf("spelling %q of the same directory must be accepted: %v", spelling, err)
		}
		if d.Generation() != before+1 {
			t.Fatalf("an accepted reload publishes a new generation (%d → %d)", before, d.Generation())
		}
		curCfg, _ := d.current()
		if curCfg != &newCfg {
			t.Fatal("the accepted configuration must be active")
		}
	}
	_ = state
}

// A data_dir that does not exist cannot be proven equivalent and is rejected.
func TestRDAYBLUEX004_UnresolvableDataDirRejected(t *testing.T) {
	d, cfg, state, domain := signableZoneDaemon(t)
	cfg.LoadedAt = time.Now().UTC()
	newCfg := *cfg
	newCfg.DataDir = filepath.Join(t.TempDir(), "does-not-exist")
	newCfg.Zones = map[string]config.ZoneConfig{domain: cfg.Zones[domain]}
	if err := d.Reload(&newCfg, statepkg.NewState(newCfg.StatePath())); !errors.Is(err, ErrDataDirChanged) {
		t.Fatalf("an unresolvable data_dir must be rejected, got %v", err)
	}
	if _, cur := d.current(); cur != state {
		t.Fatal("state must remain active")
	}
}
