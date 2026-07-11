package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestStateSchemaRoundTrip (R-077): a fully-populated state — including the
// fields added by recent findings (source_mtime/source_size, rollover
// phase_started, force_resign) — survives a Save + LoadState round-trip.
func TestStateSchemaRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Now().UTC()

	orig := NewState(path)
	zs := &ZoneState{
		Path:            "/z/example.zone",
		Serial:          2024010101,
		PublishedSerial: 2024010102,
		LastSigned:      now,
		SourceModTime:   now.Add(-time.Hour),
		SourceSize:      4096,
		SignaturesExp:   now.Add(14 * 24 * time.Hour),
		KSK:             &KeyState{ID: 111, Algorithm: "ED25519", Created: now, Expires: now.Add(5 * 365 * 24 * time.Hour)},
		ZSK:             &KeyState{ID: 222, Algorithm: "ED25519", Created: now, Expires: now.Add(90 * 24 * time.Hour)},
		Rollover: &RolloverState{
			Type: "zsk", State: ZSKRolloverStatePrePublish,
			OldKeyID: 222, NewKeyID: 333,
			Started: now, PhaseStarted: now.Add(time.Minute), Action: "next step",
		},
		Warnings:    []string{"w1"},
		Errors:      []string{"e1"},
		ForceResign: true,
	}
	orig.SetZone("example.com", zs)
	if err := orig.Save(); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	got := loaded.GetZone("example.com")
	if got == nil {
		t.Fatal("zone missing after round-trip")
	}

	if got.Serial != zs.Serial || got.PublishedSerial != zs.PublishedSerial {
		t.Errorf("serials not preserved: %d/%d", got.Serial, got.PublishedSerial)
	}
	if got.SourceSize != zs.SourceSize || !got.SourceModTime.Equal(zs.SourceModTime) {
		t.Errorf("source mtime/size not preserved: %v/%d", got.SourceModTime, got.SourceSize)
	}
	if !got.ForceResign {
		t.Error("ForceResign not preserved")
	}
	if got.KSK == nil || got.KSK.ID != 111 || got.ZSK == nil || got.ZSK.ID != 222 {
		t.Errorf("keys not preserved: %+v / %+v", got.KSK, got.ZSK)
	}
	if got.Rollover == nil || got.Rollover.State != ZSKRolloverStatePrePublish ||
		!got.Rollover.PhaseStarted.Equal(zs.Rollover.PhaseStarted) {
		t.Errorf("rollover (incl. phase_started) not preserved: %+v", got.Rollover)
	}
	if len(got.Warnings) != 1 || len(got.Errors) != 1 {
		t.Errorf("warnings/errors not preserved: %v / %v", got.Warnings, got.Errors)
	}
}

// TestStateLoad_OldSchemaTolerant (R-077): a state.json written by an older
// version (no source_mtime/source_size/phase_started/force_resign) loads
// without error, with the new fields defaulting to zero.
func TestStateLoad_OldSchemaTolerant(t *testing.T) {
	oldJSON := `{
      "zones": {
        "example.com": {
          "path": "/z/example.zone",
          "serial": 2024010101,
          "last_signed": "2024-01-15T10:00:00Z",
          "signatures_expire": "2024-01-29T10:00:00Z",
          "ksk": {"id": 111, "algorithm": "ED25519", "created": "2023-01-15T00:00:00Z", "expires": "2028-01-15T00:00:00Z"},
          "zsk": {"id": 222, "algorithm": "ED25519", "created": "2024-01-01T00:00:00Z", "expires": "2024-04-01T00:00:00Z"}
        }
      }
    }`
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(oldJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadState(path)
	if err != nil {
		t.Fatalf("old-schema state must load without error: %v", err)
	}
	z := loaded.GetZone("example.com")
	if z == nil {
		t.Fatal("zone missing")
	}

	// Existing fields loaded.
	if z.Serial != 2024010101 || z.KSK == nil || z.KSK.ID != 111 {
		t.Errorf("existing fields not loaded: serial=%d ksk=%+v", z.Serial, z.KSK)
	}
	// New fields default to zero / nil.
	if !z.SourceModTime.IsZero() || z.SourceSize != 0 {
		t.Errorf("new source fields should be zero for old schema: %v/%d", z.SourceModTime, z.SourceSize)
	}
	if z.ForceResign {
		t.Error("ForceResign should default to false for old schema")
	}
	if z.Rollover != nil {
		t.Error("Rollover should be nil for old schema")
	}
}
