package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	signerpkg "github.com/ptudor/dnssec-tudor/internal/signer"

	statepkg "github.com/ptudor/dnssec-tudor/internal/state"

	"github.com/ptudor/dnssec-tudor/internal/config"
)

// R-039: an automatic ZSK rollover mints the new ZSK with the EXISTING ZSK's
// algorithm, not the (possibly-changed) config default.
func TestStartZSKRollover_KeepsExistingAlgorithm(t *testing.T) {
	_, cfg, state, domain := signableZoneDaemon(t)
	if cfg.DNSSEC.Algorithm != "ED25519" {
		t.Fatalf("precondition: expected ED25519 test zone, got %s", cfg.DNSSEC.Algorithm)
	}

	// Operator changes the global algorithm AFTER the zone was signed.
	cfg.DNSSEC.Algorithm = "ECDSAP256SHA256"

	// Force the ZSK into its pre-publish window so a rollover starts.
	zs := state.GetZone(domain)
	zs.ZSK.Expires = time.Now().UTC().Add(-time.Hour)

	rm := signerpkg.NewRolloverManager(cfg, state)
	if err := rm.CheckZSKRollover(domain); err != nil {
		t.Fatalf("CheckZSKRollover: %v", err)
	}
	if r := state.GetZone(domain).Rollover; r == nil || r.Type != "zsk" {
		t.Fatalf("expected a zsk rollover to start, got %+v", r)
	}

	// The newly-generated (live) ZSK must still be ED25519, matching the KSK,
	// not the changed config default.
	keyGen := signerpkg.NewKeyGenerator(cfg)
	newZSK, _, err := keyGen.LoadKeyPair(domain, "zsk")
	if err != nil {
		t.Fatalf("load new ZSK: %v", err)
	}
	if got := signerpkg.AlgorithmName(newZSK.Algorithm); got != "ED25519" {
		t.Errorf("new ZSK algorithm = %s, want ED25519 (R-039)", got)
	}
}

// R-011: the ZSK pre_publish→signing transition is gated on the phase actually
// being signed + a DNSKEY-TTL floor, not wall-time-since-start alone.
func TestZSKRollover_PhaseGating(t *testing.T) {
	_, cfg, state, domain := signableZoneDaemon(t)
	cfg.DNSSEC.DNSKEYTtl = 1 // TTL floor = 1s (fast for the test)
	rm := signerpkg.NewRolloverManager(cfg, state)

	zs := state.GetZone(domain)
	past := time.Now().UTC().Add(-30 * 24 * time.Hour)
	zs.Rollover = &statepkg.RolloverState{
		Type: "zsk", State: statepkg.ZSKRolloverStatePrePublish,
		OldKeyID: zs.ZSK.ID, NewKeyID: zs.ZSK.ID, Started: past,
	}
	// Not signed since the phase began (LastSigned older than Started).
	zs.LastSigned = past.Add(-time.Hour)

	if err := rm.CheckZSKRollover(domain); err != nil {
		t.Fatalf("CheckZSKRollover: %v", err)
	}
	if got := state.GetZone(domain).Rollover.State; got != statepkg.ZSKRolloverStatePrePublish {
		t.Fatalf("must NOT advance before the pre-published set was signed; state=%q (R-011)", got)
	}

	// Now the zone was signed in-phase and the TTL floor has elapsed.
	state.GetZone(domain).LastSigned = time.Now().UTC().Add(-10 * time.Second)
	if err := rm.CheckZSKRollover(domain); err != nil {
		t.Fatalf("CheckZSKRollover (2): %v", err)
	}
	if got := state.GetZone(domain).Rollover.State; got != statepkg.ZSKRolloverStateSigning {
		t.Fatalf("should advance to signing once published + TTL floor elapsed; state=%q (R-011)", got)
	}
	if state.GetZone(domain).Rollover.PhaseStarted.IsZero() {
		t.Error("PhaseStarted must be set on the switch to signing (R-011)")
	}
}

// R-041: a pending KSK rollover blocks the ZSK rollover; the zone must surface a
// warning instead of silently letting the ZSK age out.
func TestCheckZSKRollover_BlockedByKSKRolloverWarns(t *testing.T) {
	_, cfg, state, domain := signableZoneDaemon(t)
	rm := signerpkg.NewRolloverManager(cfg, state)

	zs := state.GetZone(domain)
	// A KSK rollover occupies the single Rollover slot...
	zs.Rollover = &statepkg.RolloverState{Type: "ksk", State: statepkg.KSKRolloverStateDSAddWait, OldKeyID: zs.KSK.ID, NewKeyID: 1, Started: time.Now().UTC()}
	// ...and the ZSK is due.
	zs.ZSK.Expires = time.Now().UTC().Add(-time.Hour)

	if err := rm.CheckZSKRollover(domain); err != nil {
		t.Fatalf("CheckZSKRollover: %v", err)
	}

	zs = state.GetZone(domain)
	if zs.Rollover.Type != "ksk" {
		t.Errorf("the KSK rollover must be untouched, got type %q", zs.Rollover.Type)
	}
	var found bool
	for _, w := range zs.Warnings {
		if strings.Contains(w, "blocked by the in-progress ksk rollover") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a warning that the ZSK rollover is blocked; warnings=%v (R-041)", zs.Warnings)
	}
}

// R-038: if the state Save fails during a KSK rollover start, the on-disk key
// rotation is rolled back and the in-memory rollover reverted, so state.json and
// the key files don't diverge.
func TestStartKSKRollover_RollsBackOnSaveFailure(t *testing.T) {
	_, cfg, state, domain := signableZoneDaemon(t)
	oldKSKID := state.GetZone(domain).KSK.ID

	// Force Save() to fail by pointing the state path into a nonexistent dir.
	state.SetPath(filepath.Join(t.TempDir(), "missing-subdir", "state.json"))

	rm := signerpkg.NewRolloverManager(cfg, state)
	if err := rm.StartKSKRollover(domain); err == nil {
		t.Fatal("StartKSKRollover should fail when the state Save fails")
	}

	// In-memory state reverted.
	zs := state.GetZone(domain)
	if zs.Rollover != nil {
		t.Error("in-memory rollover must be reverted after a failed save (R-038)")
	}
	if zs.KSK.ID != oldKSKID {
		t.Errorf("in-memory KSK must revert to old (id %d), got %d", oldKSKID, zs.KSK.ID)
	}

	// The live key files must be restored to the OLD key (not the new one).
	keyGen := signerpkg.NewKeyGenerator(cfg)
	liveKSK, err := keyGen.LoadPublicKey(domain, "ksk")
	if err != nil {
		t.Fatalf("load live KSK: %v", err)
	}
	if liveKSK.KeyTag() != oldKSKID {
		t.Errorf("live KSK file must be restored to old key (tag %d), got %d (R-038)", oldKSKID, liveKSK.KeyTag())
	}
}

// R-037: rollover completion refuses (does not retire the old KSK) when the new
// KSK's DS cannot be confirmed at the parent.
func TestVerifyNewKSKDSAtParent_UnreachableIsNotPresent(t *testing.T) {
	_, cfg, state, domain := signableZoneDaemon(t)
	// TEST-NET-1, guaranteed unroutable → the DS can't be confirmed.
	cfg.Validation.Resolver = "192.0.2.1:53"
	cfg.Validation.Timeout = config.Duration{Duration: 500 * time.Millisecond}

	present, _ := verifyNewKSKDSAtParent(cfg, state, domain)
	if present {
		t.Error("an unconfirmable parent DS must report not-present so completion refuses (R-037)")
	}
}
