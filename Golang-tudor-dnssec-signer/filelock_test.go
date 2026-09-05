//go:build !windows

package main

import (
	"path/filepath"
	"testing"
	"time"

	statepkg "github.com/ptudor/dnssec-tudor/internal/state"
)

// R-007: the advisory state lock is mutually exclusive across independent acquisitions.
func TestStateLock_MutualExclusion(t *testing.T) {
	dir := t.TempDir()
	l1, err := acquireStateLock(dir, time.Second)
	if err != nil {
		t.Fatalf("first acquire: %v", err)
	}
	// A second acquisition must block and time out while the first is held.
	if _, err := acquireStateLock(dir, 200*time.Millisecond); err == nil {
		t.Fatal("second acquire should have timed out while the lock was held")
	}
	l1.release()
	// After release, a fresh acquisition succeeds.
	l2, err := acquireStateLock(dir, time.Second)
	if err != nil {
		t.Fatalf("acquire after release: %v", err)
	}
	l2.release()
}

// R-007: ReloadFromDisk adopts a disk zone's rollover when LastSigned is not older, so the
// daemon's end-of-cycle Save doesn't revert a rollover a CLI command started mid-cycle.
func TestReloadFromDisk_AdoptsRolloverAtEqualLastSigned(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")
	ts := time.Now().UTC().Truncate(time.Second)

	disk := statepkg.NewState(statePath)
	disk.SetZone("example.com", &statepkg.ZoneState{
		Path: "/x", LastSigned: ts,
		KSK:      &statepkg.KeyState{ID: 2, Algorithm: "ED25519"},
		Rollover: &statepkg.RolloverState{Type: "ksk", State: statepkg.KSKRolloverStateDSAddWait, OldKeyID: 1, NewKeyID: 2, Started: ts},
	})
	if err := disk.Save(); err != nil {
		t.Fatal(err)
	}

	// Stale in-memory snapshot: same zone, same LastSigned, no rollover.
	mem := statepkg.NewState(statePath)
	mem.SetZone("example.com", &statepkg.ZoneState{Path: "/x", LastSigned: ts, KSK: &statepkg.KeyState{ID: 1, Algorithm: "ED25519"}})

	if err := mem.ReloadFromDisk(); err != nil {
		t.Fatal(err)
	}
	got := mem.GetZone("example.com")
	if got.Rollover == nil {
		t.Fatal("ReloadFromDisk should adopt the disk zone's rollover at equal LastSigned")
	}
	if got.Rollover.NewKeyID != 2 {
		t.Fatalf("adopted rollover NewKeyID = %d, want 2", got.Rollover.NewKeyID)
	}
}
