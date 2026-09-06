package main

import (
	"os"
	"path/filepath"
	"testing"

	signerpkg "github.com/ptudor/sigillum-dnssec/signer/internal/signer"

	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// R-011: a failed re-add must RESTORE the pre-existing signed output (a
// nameserver may still be serving it), not delete it.
func TestR011_UnwindRestoresPreExistingOutput(t *testing.T) {
	dir := t.TempDir()
	cfg := dnssectest.Config(t, dir)
	if err := os.MkdirAll(cfg.OutputDir, 0o755); err != nil {
		t.Fatal(err)
	}
	signedPath := filepath.Join(cfg.OutputDir, "example.com.zone.signed")
	const prev = "; previous signed zone that a nameserver is still serving\n"
	if err := os.WriteFile(signedPath, []byte(prev), 0o644); err != nil {
		t.Fatal(err)
	}
	// Simulate the failing add overwriting it with a new (to-be-rolled-back) version.
	if err := os.WriteFile(signedPath, []byte("NEW OUTPUT FROM FAILED ADD"), 0o644); err != nil {
		t.Fatal(err)
	}

	state := statepkg.NewState(cfg.StatePath())
	state.SetZone("example.com", &statepkg.ZoneState{Path: "/zones/example.com.db"})

	// origOutput was snapshotted BEFORE the overwrite; outputExisted=true.
	unwindAdd(cfg, state, "example.com", false, false, []byte(prev), true)

	got, err := os.ReadFile(signedPath)
	if err != nil {
		t.Fatalf("pre-existing output was deleted on rollback: %v", err)
	}
	if string(got) != prev {
		t.Fatalf("output not restored to the previous bytes: got %q", got)
	}
}

// R-011: a failed add of a truly-new zone (no predecessor output) removes the
// output this add created.
func TestR011_UnwindRemovesNewlyCreatedOutput(t *testing.T) {
	dir := t.TempDir()
	cfg := dnssectest.Config(t, dir)
	if err := os.MkdirAll(cfg.OutputDir, 0o755); err != nil {
		t.Fatal(err)
	}
	signedPath := filepath.Join(cfg.OutputDir, "new.example.zone.signed")
	if err := os.WriteFile(signedPath, []byte("output this add created"), 0o644); err != nil {
		t.Fatal(err)
	}
	state := statepkg.NewState(cfg.StatePath())
	state.SetZone("new.example", &statepkg.ZoneState{Path: "/zones/new.example.db"})

	unwindAdd(cfg, state, "new.example", false, false, nil, false)

	if signerpkg.FileExists(signedPath) {
		t.Fatal("newly-created output should be removed on rollback (no predecessor)")
	}
}
