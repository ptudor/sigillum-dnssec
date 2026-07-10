//go:build !windows

package main

import (
	"path/filepath"
	"testing"
	"time"
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

	disk := NewState(statePath)
	disk.SetZone("example.com", &ZoneState{
		Path: "/x", LastSigned: ts,
		Rollover: &RolloverState{Type: "ksk", State: KSKRolloverStateDSAddWait, OldKeyID: 1, NewKeyID: 2, Started: ts},
	})
	if err := disk.Save(); err != nil {
		t.Fatal(err)
	}

	// Stale in-memory snapshot: same zone, same LastSigned, no rollover.
	mem := NewState(statePath)
	mem.SetZone("example.com", &ZoneState{Path: "/x", LastSigned: ts})

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

func TestRolloverEqual(t *testing.T) {
	a := &RolloverState{Type: "ksk", State: "ds_add_wait", OldKeyID: 1, NewKeyID: 2}
	b := &RolloverState{Type: "ksk", State: "ds_add_wait", OldKeyID: 1, NewKeyID: 2}
	if !rolloverEqual(a, b) {
		t.Fatal("identical rollovers must be equal")
	}
	if rolloverEqual(a, nil) {
		t.Fatal("nil vs non-nil must not be equal")
	}
	if !rolloverEqual(nil, nil) {
		t.Fatal("nil == nil")
	}
	if rolloverEqual(a, &RolloverState{Type: "zsk"}) {
		t.Fatal("different type must not be equal")
	}
}
