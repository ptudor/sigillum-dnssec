//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	statepkg "github.com/ptudor/dnssec-tudor/internal/state"
)

// registrarLockFixture writes a config (dynadot enabled, one opted-in zone)
// and a state.json with that zone managed, points the configPath global at it
// for the duration of the test, and returns the data dir.
func registrarLockFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	zonePath := filepath.Join(dir, "example.com.db")
	content := fmt.Sprintf(`output_dir = %q
data_dir = %q

[registrar.dynadot]
enabled = true
api_key = "test-fixture-key"
api_secret = "test-fixture-secret"

[zones."example.com"]
path = %q
registrar = "dynadot"
`, filepath.Join(dir, "signed"), dir, zonePath)
	if err := os.WriteFile(cfgPath, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	state := statepkg.NewState(filepath.Join(dir, "state.json"))
	state.SetZone("example.com", &statepkg.ZoneState{Path: zonePath})
	if err := state.Save(); err != nil {
		t.Fatal(err)
	}

	origConfigPath := configPath
	configPath = cfgPath
	t.Cleanup(func() { configPath = origConfigPath })
	return dir
}

// Item 8 (R-007 + R-032): the mutating registrar commands (`push`, `clear`)
// resolve through resolveRegistrarLocked, which must hold the cross-process
// state lock until the returned unlock runs — a second acquisition times out
// while it is held (TestStateLock_MutualExclusion pattern) and succeeds after
// unlock. The read-only resolveRegistrar must take no lock at all.
func TestResolveRegistrarLocked_HoldsStateLock(t *testing.T) {
	dir := registrarLockFixture(t)

	cfg, state, reg, unlock, err := resolveRegistrarLocked("example.com")
	if err != nil {
		t.Fatalf("resolveRegistrarLocked: %v", err)
	}
	if cfg == nil || state == nil {
		t.Fatal("resolveRegistrarLocked returned nil config/state")
	}
	if reg == nil || reg.Name() != "dynadot" {
		t.Fatalf("expected dynadot adapter, got %v", reg)
	}

	// While held, the push/clear span excludes the daemon and other CLIs.
	if l, err := acquireStateLock(dir, 200*time.Millisecond); err == nil {
		l.release()
		t.Fatal("state lock should be held between resolveRegistrarLocked and unlock")
	}

	unlock()

	l, err := acquireStateLock(dir, time.Second)
	if err != nil {
		t.Fatalf("acquire after unlock: %v", err)
	}
	l.release()

	// The read-only commands (get/verify) resolve unlocked: acquiring the
	// state lock must succeed while their config/state snapshot is live.
	if _, _, roReg, err := resolveRegistrar("example.com"); err != nil || roReg == nil {
		t.Fatalf("resolveRegistrar: reg=%v err=%v", roReg, err)
	}
	l2, err := acquireStateLock(dir, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("read-only resolveRegistrar must not hold the state lock: %v", err)
	}
	l2.release()
}

// Item 8: resolveRegistrarLocked must release the lock on its own error paths,
// or a failed `push`/`clear` would wedge the daemon's next signing cycle for
// the acquisition timeout.
func TestResolveRegistrarLocked_ReleasesLockOnError(t *testing.T) {
	dir := registrarLockFixture(t)

	if _, _, _, _, err := resolveRegistrarLocked("unmanaged.example.com"); err == nil {
		t.Fatal("expected error for an unmanaged domain")
	}

	l, err := acquireStateLock(dir, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("lock must be released after a resolveRegistrarLocked error: %v", err)
	}
	l.release()
}
