package signer

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/ptudor/sigillum-dnssec/signer/internal/config"
	"github.com/ptudor/sigillum-dnssec/signer/internal/dnssectest"
	statepkg "github.com/ptudor/sigillum-dnssec/signer/internal/state"
)

// RDAYBLUEX-024 at the gates: a legacy zero parent DS TTL in a rollover
// record means the conservative 24h default, never "no wait"; an
// out-of-policy configured fallback cannot enter propagation as zero.

func rolloverZone(t *testing.T) (*RolloverManager, *config.Config, *statepkg.State, string) {
	t.Helper()
	dir := t.TempDir()
	cfg := dnssectest.Config(t, dir)
	if err := EnsureDir(cfg.KeysDir()); err != nil {
		t.Fatal(err)
	}
	domain := "ttl.example"
	kg := NewKeyGenerator(cfg)
	ksk, err := kg.GenerateKSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	zsk, err := kg.GenerateZSK(domain)
	if err != nil {
		t.Fatal(err)
	}
	state := statepkg.NewState(filepath.Join(dir, "state.json"))
	state.SetZone(domain, &statepkg.ZoneState{Path: "/z", KSK: ksk, ZSK: zsk})
	return NewRolloverManager(cfg, state), cfg, state, domain
}

func TestRDAYBLUEX024_LegacyZeroTTLWaitsTheDefault(t *testing.T) {
	rm, _, state, domain := rolloverZone(t)
	if err := rm.StartKSKRollover(domain); err != nil {
		t.Fatal(err)
	}
	zs := state.GetZone(domain)
	// A legacy record: propagation wait recorded with ParentDSTTL 0 and the
	// DS observed 23 hours ago.
	state.Mutate(func() {
		zs.Rollover.State = statepkg.KSKRolloverStateDSPropagation
		zs.Rollover.ParentDSTTL = 0
		zs.Rollover.DSObservedAt = time.Now().UTC().Add(-23 * time.Hour)
	})
	if err := rm.CheckKSKRollover(domain); err != nil {
		t.Fatal(err)
	}
	if zs.Rollover.State != statepkg.KSKRolloverStateDSPropagation {
		t.Fatalf("a zero TTL must wait the 24h default, not retire at once; got %q", zs.Rollover.State)
	}
	state.Mutate(func() { zs.Rollover.DSObservedAt = time.Now().UTC().Add(-25 * time.Hour) })
	if err := rm.CheckKSKRollover(domain); err != nil {
		t.Fatal(err)
	}
	if zs.Rollover.State != statepkg.KSKRolloverStateRetiring {
		t.Fatalf("after the default wait the old KSK retires; got %q", zs.Rollover.State)
	}
}

func TestRDAYBLUEX024_OutOfPolicyFallbackCannotEnterPropagationAsZero(t *testing.T) {
	rm, cfg, state, domain := rolloverZone(t)
	cfg.DNSSEC.ParentDSTTL = config.Duration{Duration: 500 * time.Millisecond} // bypasses Validate
	if err := rm.StartKSKRollover(domain); err != nil {
		t.Fatal(err)
	}
	if err := rm.CompleteKSKRollover(domain, time.Now().UTC(), 0); err != nil {
		t.Fatal(err)
	}
	r := state.GetZone(domain).Rollover
	if r.ParentDSTTL != 86400 {
		t.Fatalf("an out-of-policy fallback must not truncate to zero; recorded %d, want 86400", r.ParentDSTTL)
	}
	if err := rm.CheckKSKRollover(domain); err != nil {
		t.Fatal(err)
	}
	if r.State != statepkg.KSKRolloverStateDSPropagation {
		t.Fatalf("the old KSK must remain published until the full delay elapses, got %q", r.State)
	}
}

func TestRDAYBLUEX024_AlgorithmGateUsesEffectiveTTL(t *testing.T) {
	rm, _, state, domain := rolloverZone(t)
	if err := rm.StartAlgorithmRollover(domain, "ECDSAP256SHA256"); err != nil {
		t.Fatal(err)
	}
	zs := state.GetZone(domain)
	state.Mutate(func() {
		zs.Rollover.State = statepkg.AlgoRolloverStateDSPropagation
		zs.Rollover.ParentDSTTL = 0
		zs.Rollover.DSObservedAt = time.Now().UTC().Add(-2 * time.Hour)
	})
	if err := rm.CheckAlgorithmRollover(domain); err != nil {
		t.Fatal(err)
	}
	if zs.Rollover.State != statepkg.AlgoRolloverStateDSPropagation {
		t.Fatalf("a zero TTL must wait the 24h default before the old-DS-removal phase; got %q", zs.Rollover.State)
	}
}
