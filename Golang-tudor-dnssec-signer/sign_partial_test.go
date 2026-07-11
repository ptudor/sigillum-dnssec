package main

import (
	"os"
	"path/filepath"
	"testing"
)

// validZoneContent returns a minimal signable zone (SOA + apex NS + one A).
func validZoneContent(domain string) string {
	return "$ORIGIN " + domain + ".\n" +
		"$TTL 3600\n" +
		"@\tIN\tSOA\tns1." + domain + ". admin." + domain + ". 2024011501 3600 1800 604800 86400\n" +
		"@\tIN\tNS\tns1." + domain + ".\n" +
		"ns1\tIN\tA\t192.0.2.1\n"
}

// TestSignAll_ReturnsErrorOnPartialFailure (R-024): a zone that can't be signed
// must make SignAll return a non-nil error (so cron/CI see exit 1), while
// healthy zones are still signed and state is still saved.
func TestSignAll_ReturnsErrorOnPartialFailure(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)
	if err := ensureDir(cfg.KeysDir()); err != nil {
		t.Fatal(err)
	}
	if err := ensureDir(cfg.OutputDir); err != nil {
		t.Fatal(err)
	}

	good := "good.example"
	goodPath := filepath.Join(dataDir, good+".zone")
	if err := os.WriteFile(goodPath, []byte(validZoneContent(good)), 0644); err != nil {
		t.Fatal(err)
	}
	cfg.Zones[good] = ZoneConfig{Path: goodPath}

	// A zone whose file does not exist: key init succeeds but SignZone fails.
	bad := "bad.example"
	cfg.Zones[bad] = ZoneConfig{Path: filepath.Join(dataDir, "missing.zone")}

	state := NewState(cfg.StatePath())
	signer := NewSigner(cfg, state)

	err := signer.SignAll()
	if err == nil {
		t.Fatal("SignAll must return an error when a zone fails to sign (R-024)")
	}

	// The healthy zone must still have been signed.
	if _, statErr := os.Stat(filepath.Join(cfg.OutputDir, good+".zone.signed")); statErr != nil {
		t.Errorf("healthy zone should still be signed despite the failing one: %v", statErr)
	}
	// The failing zone's error must be recorded in state.
	if bz := state.GetZone(bad); bz == nil || len(bz.Errors) == 0 {
		t.Errorf("failing zone should have an error recorded, got: %+v", bz)
	}
}

// TestSignAll_AllHealthyExitsClean (R-024): with every zone healthy, SignAll
// returns nil.
func TestSignAll_AllHealthyExitsClean(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)
	if err := ensureDir(cfg.KeysDir()); err != nil {
		t.Fatal(err)
	}
	if err := ensureDir(cfg.OutputDir); err != nil {
		t.Fatal(err)
	}
	domain := "ok.example"
	zonePath := filepath.Join(dataDir, domain+".zone")
	if err := os.WriteFile(zonePath, []byte(validZoneContent(domain)), 0644); err != nil {
		t.Fatal(err)
	}
	cfg.Zones[domain] = ZoneConfig{Path: zonePath}

	state := NewState(cfg.StatePath())
	if err := NewSigner(cfg, state).SignAll(); err != nil {
		t.Fatalf("all-healthy SignAll must return nil, got: %v", err)
	}
}

// TestSignAll_RetriesKeylessPlaceholder (R-033): a keyless placeholder left by a
// prior failed init must not permanently disable key generation — the next
// SignAll re-runs recoverOrGenerateKeys and the zone gets keys and signs.
func TestSignAll_RetriesKeylessPlaceholder(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)
	if err := ensureDir(cfg.KeysDir()); err != nil {
		t.Fatal(err)
	}
	if err := ensureDir(cfg.OutputDir); err != nil {
		t.Fatal(err)
	}
	domain := "retry.example"
	zonePath := filepath.Join(dataDir, domain+".zone")
	if err := os.WriteFile(zonePath, []byte(validZoneContent(domain)), 0644); err != nil {
		t.Fatal(err)
	}
	cfg.Zones[domain] = ZoneConfig{Path: zonePath}

	state := NewState(cfg.StatePath())
	// Simulate a prior failed init: a keyless placeholder is in state.
	placeholder := &ZoneState{Path: zonePath}
	placeholder.AddError("keys dir was briefly unwritable")
	state.SetZone(domain, placeholder)

	if err := NewSigner(cfg, state).SignAll(); err != nil {
		t.Fatalf("SignAll: %v", err)
	}

	z := state.GetZone(domain)
	if z == nil || z.KSK == nil || z.ZSK == nil {
		t.Fatalf("keyless placeholder was not re-initialized (R-033); got: %+v", z)
	}
	if _, err := os.Stat(filepath.Join(cfg.OutputDir, domain+".zone.signed")); err != nil {
		t.Errorf("zone should be signed after re-init: %v", err)
	}
}

// TestStartAlgorithmRollover_NilKeysNoPanic (R-025): an algorithm rollover on a
// zone whose keys never initialized (keyless placeholder) must return a
// descriptive error, not panic on a nil KSK deref.
func TestStartAlgorithmRollover_NilKeysNoPanic(t *testing.T) {
	dataDir := t.TempDir()
	cfg := testConfig(t, dataDir)
	domain := "nokeys.example"

	state := NewState(cfg.StatePath())
	state.SetZone(domain, &ZoneState{Path: filepath.Join(dataDir, domain+".zone")}) // nil KSK/ZSK

	rm := NewRolloverManager(cfg, state)
	err := rm.StartAlgorithmRollover(domain, "ECDSAP256SHA256")
	if err == nil {
		t.Fatal("StartAlgorithmRollover must error on a keyless zone, not panic (R-025)")
	}
	if !contains(err.Error(), "no usable keys") {
		t.Errorf("error should explain the zone has no usable keys, got: %v", err)
	}
}
