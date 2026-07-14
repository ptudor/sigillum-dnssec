package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	signerpkg "github.com/ptudor/dnssec-tudor/internal/signer"

	"github.com/ptudor/dnssec-tudor/internal/dnssectest"
	statepkg "github.com/ptudor/dnssec-tudor/internal/state"

	"github.com/ptudor/dnssec-tudor/internal/config"
)

// TestNeedsSign_UsesSourceModTimeNotLastSigned (R-022 fidelity): change
// detection compares against the parse-time source mtime, so an edit whose mtime
// is after that reference but before LastSigned is still detected (the old
// LastSigned comparison would miss it).
func TestNeedsSign_UsesSourceModTimeNotLastSigned(t *testing.T) {
	dataDir := t.TempDir()
	cfg := dnssectest.Config(t, dataDir)
	if err := signerpkg.EnsureDir(cfg.KeysDir()); err != nil {
		t.Fatal(err)
	}
	domain := "fidelity.example"
	zonePath := filepath.Join(dataDir, domain+".zone")
	if err := os.WriteFile(zonePath, []byte(validZoneContent(domain)), 0644); err != nil {
		t.Fatal(err)
	}

	// t0 = parse-time reference; t1 = the edit (between t0 and t2); t2 = LastSigned.
	// t1 is well in the past so the quiescence re-stat doesn't apply.
	t0 := time.Now().Add(-1 * time.Hour)
	t1 := time.Now().Add(-30 * time.Minute)
	t2 := time.Now().Add(-10 * time.Minute)
	if err := os.Chtimes(zonePath, t1, t1); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(zonePath)
	if err != nil {
		t.Fatal(err)
	}

	state := statepkg.NewState(cfg.StatePath())
	keyGen := signerpkg.NewKeyGenerator(cfg)
	ksk, _ := keyGen.GenerateKSK(domain)
	zsk, _ := keyGen.GenerateZSK(domain)
	zs := &statepkg.ZoneState{
		Path:          zonePath,
		KSK:           ksk,
		ZSK:           zsk,
		SourceModTime: t0,
		SourceSize:    fi.Size(), // real size → size check is a no-op; mtime drives it
		LastSigned:    t2,
		SignaturesExp: time.Now().Add(10 * 24 * time.Hour), // not near expiry
	}
	state.SetZone(domain, zs)

	need, reason := signerpkg.NewSigner(cfg, state).NeedsSign(domain, zonePath, zs)
	if !need {
		t.Errorf("NeedsSign must detect an edit whose mtime > SourceModTime even when < LastSigned; got need=%v reason=%q", need, reason)
	}
}

// TestNeedsSign_DefersStillSettlingFile (R-022 quiescence): a source file that
// is still being written (mtime fresh and changing) is deferred rather than
// signed truncated.
func TestNeedsSign_DefersStillSettlingFile(t *testing.T) {
	dataDir := t.TempDir()
	cfg := dnssectest.Config(t, dataDir)
	if err := signerpkg.EnsureDir(cfg.KeysDir()); err != nil {
		t.Fatal(err)
	}
	domain := "settling.example"
	zonePath := filepath.Join(dataDir, domain+".zone")
	if err := os.WriteFile(zonePath, []byte(validZoneContent(domain)), 0644); err != nil {
		t.Fatal(err)
	}

	// Keep appending to the file so its size keeps changing across the
	// quiescence re-stat window.
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
			}
			if f, err := os.OpenFile(zonePath, os.O_APPEND|os.O_WRONLY, 0644); err == nil {
				f.WriteString("; still writing\n")
				f.Close()
			}
			time.Sleep(20 * time.Millisecond)
		}
	}()
	defer close(stop)

	state := statepkg.NewState(cfg.StatePath())
	keyGen := signerpkg.NewKeyGenerator(cfg)
	ksk, _ := keyGen.GenerateKSK(domain)
	zsk, _ := keyGen.GenerateZSK(domain)
	zs := &statepkg.ZoneState{
		Path:          zonePath,
		KSK:           ksk,
		ZSK:           zsk,
		SourceModTime: time.Now().Add(-1 * time.Hour), // so the fresh file reads as changed
		SignaturesExp: time.Now().Add(10 * 24 * time.Hour),
	}
	state.SetZone(domain, zs)

	need, _ := signerpkg.NewSigner(cfg, state).NeedsSign(domain, zonePath, zs)
	if need {
		t.Error("a still-being-written file should be deferred (need=false), not signed mid-write")
	}
}

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
	cfg := dnssectest.Config(t, dataDir)
	if err := signerpkg.EnsureDir(cfg.KeysDir()); err != nil {
		t.Fatal(err)
	}
	if err := signerpkg.EnsureDir(cfg.OutputDir); err != nil {
		t.Fatal(err)
	}

	good := "good.example"
	goodPath := filepath.Join(dataDir, good+".zone")
	if err := os.WriteFile(goodPath, []byte(validZoneContent(good)), 0644); err != nil {
		t.Fatal(err)
	}
	cfg.Zones[good] = config.ZoneConfig{Path: goodPath}

	// A zone whose file does not exist: key init succeeds but SignZone fails.
	bad := "bad.example"
	cfg.Zones[bad] = config.ZoneConfig{Path: filepath.Join(dataDir, "missing.zone")}

	state := statepkg.NewState(cfg.StatePath())
	signer := signerpkg.NewSigner(cfg, state)

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
	cfg := dnssectest.Config(t, dataDir)
	if err := signerpkg.EnsureDir(cfg.KeysDir()); err != nil {
		t.Fatal(err)
	}
	if err := signerpkg.EnsureDir(cfg.OutputDir); err != nil {
		t.Fatal(err)
	}
	domain := "ok.example"
	zonePath := filepath.Join(dataDir, domain+".zone")
	if err := os.WriteFile(zonePath, []byte(validZoneContent(domain)), 0644); err != nil {
		t.Fatal(err)
	}
	cfg.Zones[domain] = config.ZoneConfig{Path: zonePath}

	state := statepkg.NewState(cfg.StatePath())
	if err := signerpkg.NewSigner(cfg, state).SignAll(); err != nil {
		t.Fatalf("all-healthy SignAll must return nil, got: %v", err)
	}
}

// TestSignAll_RetriesKeylessPlaceholder (R-033): a keyless placeholder left by a
// prior failed init must not permanently disable key generation — the next
// SignAll re-runs RecoverOrGenerateKeys and the zone gets keys and signs.
func TestSignAll_RetriesKeylessPlaceholder(t *testing.T) {
	dataDir := t.TempDir()
	cfg := dnssectest.Config(t, dataDir)
	if err := signerpkg.EnsureDir(cfg.KeysDir()); err != nil {
		t.Fatal(err)
	}
	if err := signerpkg.EnsureDir(cfg.OutputDir); err != nil {
		t.Fatal(err)
	}
	domain := "retry.example"
	zonePath := filepath.Join(dataDir, domain+".zone")
	if err := os.WriteFile(zonePath, []byte(validZoneContent(domain)), 0644); err != nil {
		t.Fatal(err)
	}
	cfg.Zones[domain] = config.ZoneConfig{Path: zonePath}

	state := statepkg.NewState(cfg.StatePath())
	// Simulate a prior failed init: a keyless placeholder is in state.
	placeholder := &statepkg.ZoneState{Path: zonePath}
	placeholder.AddError("keys dir was briefly unwritable")
	state.SetZone(domain, placeholder)

	if err := signerpkg.NewSigner(cfg, state).SignAll(); err != nil {
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
	cfg := dnssectest.Config(t, dataDir)
	domain := "nokeys.example"

	state := statepkg.NewState(cfg.StatePath())
	state.SetZone(domain, &statepkg.ZoneState{Path: filepath.Join(dataDir, domain+".zone")}) // nil KSK/ZSK

	rm := signerpkg.NewRolloverManager(cfg, state)
	err := rm.StartAlgorithmRollover(domain, "ECDSAP256SHA256")
	if err == nil {
		t.Fatal("StartAlgorithmRollover must error on a keyless zone, not panic (R-025)")
	}
	if !contains(err.Error(), "no usable keys") {
		t.Errorf("error should explain the zone has no usable keys, got: %v", err)
	}
}
