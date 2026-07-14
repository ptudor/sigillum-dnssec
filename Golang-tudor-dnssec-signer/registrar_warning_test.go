package main

import (
	"path/filepath"
	"testing"

	statepkg "github.com/ptudor/dnssec-tudor/internal/state"
)

// TestRecordRegistrarWarning (R-032): an auto-publish failure must land in the
// zone's status warnings and be persisted, not just printed to stderr, so
// `status`/the dashboard reflect it. Also verifies dedup.
func TestRecordRegistrarWarning(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	state := statepkg.NewState(path)
	state.SetZone("example.com", &statepkg.ZoneState{Path: "/tmp/example.com.zone"})

	const msg = "registrar auto-publish failed: boom"
	recordRegistrarWarning(state, "example.com", msg)
	recordRegistrarWarning(state, "example.com", msg) // dedup: second call must not duplicate

	z := state.GetZoneCopy("example.com")
	if z == nil {
		t.Fatal("zone missing from state")
	}
	if len(z.Warnings) != 1 || z.Warnings[0] != msg {
		t.Fatalf("expected exactly one warning %q, got %v", msg, z.Warnings)
	}

	// The warning must survive a reload (it was persisted to disk).
	reloaded, err := statepkg.LoadState(path)
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	rz := reloaded.GetZoneCopy("example.com")
	if rz == nil || len(rz.Warnings) != 1 || rz.Warnings[0] != msg {
		t.Fatalf("warning not persisted across reload: %+v", rz)
	}
}
