package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	signerpkg "github.com/ptudor/dnssec-tudor/internal/signer"

	"github.com/ptudor/dnssec-tudor/internal/dnssectest"
	statepkg "github.com/ptudor/dnssec-tudor/internal/state"

	"github.com/miekg/dns"
	"github.com/ptudor/dnssec-tudor/internal/config"
)

// --- Item 4: ZSK rollover must not stall on frequently-edited zones ---

// A zone re-signed more often than the DNSKEY-TTL floor (e.g. an hourly-edited
// dynamic zone against the default 24h floor) must still advance its ZSK
// rollover: the floor measures from the phase's FIRST in-phase sign
// (PhaseFirstSigned), not the most recent one. Pre-fix, gate (c) compared
// against LastSigned and every fresh re-sign reset the clock — the rollover
// sat in pre_publish forever.
func TestZSKRollover_FrequentResignDoesNotStall(t *testing.T) {
	_, cfg, state, domain := signableZoneDaemon(t)
	cfg.DNSSEC.DNSKEYTtl = 3600 // 1h floor — far longer than the re-sign cadence
	rm := signerpkg.NewRolloverManager(cfg, state)

	now := time.Now().UTC()
	zs := state.GetZone(domain)
	zs.Rollover = &statepkg.RolloverState{
		Type: "zsk", State: statepkg.ZSKRolloverStatePrePublish,
		OldKeyID: zs.ZSK.ID, NewKeyID: zs.ZSK.ID,
		Started: now.Add(-3 * time.Hour),
	}
	// The pre-published key set was first signed 50 minutes into the phase.
	firstSign := now.Add(-50 * time.Minute)
	zs.LastSigned = firstSign

	// First check observing the in-phase sign: the publish time is stamped,
	// and the floor (measured from it) has not elapsed — no transition.
	if err := rm.CheckZSKRollover(domain); err != nil {
		t.Fatalf("CheckZSKRollover: %v", err)
	}
	zs = state.GetZone(domain)
	if got := zs.Rollover.State; got != statepkg.ZSKRolloverStatePrePublish {
		t.Fatalf("must not advance before the floor elapses from first publish; state=%q", got)
	}
	if !zs.Rollover.PhaseFirstSigned.Equal(firstSign) {
		t.Fatalf("PhaseFirstSigned must stamp the first in-phase sign: got %v, want %v",
			zs.Rollover.PhaseFirstSigned, firstSign)
	}

	// Frequent edits keep re-signing the zone; each check stays blocked (the
	// floor has not elapsed since FIRST publish) and the stamp is untouched.
	for _, age := range []time.Duration{30 * time.Minute, 10 * time.Minute, 10 * time.Second} {
		zs.LastSigned = now.Add(-age)
		if err := rm.CheckZSKRollover(domain); err != nil {
			t.Fatalf("CheckZSKRollover (re-sign %s ago): %v", age, err)
		}
		if got := state.GetZone(domain).Rollover.State; got != statepkg.ZSKRolloverStatePrePublish {
			t.Fatalf("must not advance before the floor elapses; state=%q", got)
		}
		if !state.GetZone(domain).Rollover.PhaseFirstSigned.Equal(firstSign) {
			t.Fatal("PhaseFirstSigned must not be re-stamped by later re-signs")
		}
	}

	// Time passes: the stamp is now older than the floor, while the zone keeps
	// being re-signed well inside it. Pre-fix (now - LastSigned >= floor) this
	// check never fired; now it must.
	zs.Rollover.PhaseFirstSigned = now.Add(-2 * time.Hour)
	zs.LastSigned = now.Add(-5 * time.Second)
	if err := rm.CheckZSKRollover(domain); err != nil {
		t.Fatalf("CheckZSKRollover (floor elapsed): %v", err)
	}
	zs = state.GetZone(domain)
	if got := zs.Rollover.State; got != statepkg.ZSKRolloverStateSigning {
		t.Fatalf("rollover stalled in pre_publish despite floor elapsed since first publish (Item 4); state=%q", got)
	}
	if zs.Rollover.PhaseStarted.IsZero() {
		t.Error("PhaseStarted must be set on the switch to signing (R-011)")
	}
	if !zs.Rollover.PhaseFirstSigned.IsZero() {
		t.Error("PhaseFirstSigned must be reset on the pre_publish→signing transition")
	}
}

// A RolloverState with phase_first_signed survives a Save + LoadState
// round-trip (mirrors TestStateSchemaRoundTrip for the new field).
func TestRolloverState_PhaseFirstSignedRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := time.Now().UTC()

	orig := statepkg.NewState(path)
	orig.SetZone("example.com", &statepkg.ZoneState{
		Path: "/z/example.zone",
		Rollover: &statepkg.RolloverState{
			Type: "zsk", State: statepkg.ZSKRolloverStatePrePublish,
			OldKeyID: 222, NewKeyID: 333,
			Started:          now,
			PhaseStarted:     now.Add(time.Minute),
			PhaseFirstSigned: now.Add(2 * time.Minute),
			Action:           "next step",
		},
	})
	if err := orig.Save(); err != nil {
		t.Fatal(err)
	}

	loaded, err := statepkg.LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	got := loaded.GetZone("example.com")
	if got == nil || got.Rollover == nil {
		t.Fatal("zone/rollover missing after round-trip")
	}
	if !got.Rollover.PhaseFirstSigned.Equal(now.Add(2 * time.Minute)) {
		t.Errorf("phase_first_signed not preserved: %v", got.Rollover.PhaseFirstSigned)
	}
}

// An old-schema state file whose rollover predates phase_first_signed loads
// without error, with the field defaulting to zero (it is then stamped at the
// first post-publish check — at most one poll interval late).
func TestRolloverState_OldSchemaNoPhaseFirstSigned(t *testing.T) {
	oldJSON := `{
      "zones": {
        "example.com": {
          "path": "/z/example.zone",
          "serial": 2024010101,
          "last_signed": "2024-01-15T10:00:00Z",
          "signatures_expire": "2024-01-29T10:00:00Z",
          "rollover": {
            "type": "zsk",
            "state": "pre_publish",
            "old_key_id": 222,
            "new_key_id": 333,
            "started": "2024-01-14T00:00:00Z",
            "action": "next step"
          }
        }
      }
    }`
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte(oldJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := statepkg.LoadState(path)
	if err != nil {
		t.Fatalf("old-schema state must load without error: %v", err)
	}
	z := loaded.GetZone("example.com")
	if z == nil || z.Rollover == nil {
		t.Fatal("zone/rollover missing")
	}
	if z.Rollover.State != statepkg.ZSKRolloverStatePrePublish || z.Rollover.NewKeyID != 333 {
		t.Errorf("existing rollover fields not loaded: %+v", z.Rollover)
	}
	if !z.Rollover.PhaseFirstSigned.IsZero() {
		t.Errorf("phase_first_signed must default to zero for old schema, got %v", z.Rollover.PhaseFirstSigned)
	}
}

// --- R-077 gap: signing→complete transition gates ---

// Drives the "signing" phase of handleZSKRolloverState through completion:
// it must NOT complete before the signing-phase dwell has elapsed, must NOT
// complete when the zone hasn't been signed after the switch, and once every
// gate passes it must complete — rollover cleared, re-sign forced, and the
// old ZSK dropped from the published DNSKEY RRset on the next sign.
func TestZSKRollover_SigningPhaseGating(t *testing.T) {
	_, cfg, state, domain := signableZoneDaemon(t)
	cfg.DNSSEC.DNSKEYTtl = 1                                                    // 1s TTL floor (fast for the test)
	cfg.DNSSEC.RolloverPrepublish = config.Duration{Duration: 61 * time.Second} // signing dwell =
	cfg.DNSSEC.RolloverSwitch = config.Duration{Duration: 1 * time.Second}      // prepublish - switch = 60s
	rm := signerpkg.NewRolloverManager(cfg, state)

	now := time.Now().UTC()
	zs := state.GetZone(domain)
	zs.Rollover = &statepkg.RolloverState{
		Type: "zsk", State: statepkg.ZSKRolloverStateSigning,
		OldKeyID: 11111, NewKeyID: zs.ZSK.ID,
		Started:      now.Add(-30 * 24 * time.Hour),
		PhaseStarted: now.Add(-time.Second), // switched just now: dwell (60s) NOT elapsed
		// Floor already satisfied, so the dwell gate is the only blocker.
		PhaseFirstSigned: now.Add(-10 * time.Second),
	}
	zs.LastSigned = now.Add(-500 * time.Millisecond) // signed after the switch

	// (1) Everything satisfied except the signing-phase dwell → no completion.
	if err := rm.CheckZSKRollover(domain); err != nil {
		t.Fatalf("CheckZSKRollover (dwell gate): %v", err)
	}
	if r := state.GetZone(domain).Rollover; r == nil || r.State != statepkg.ZSKRolloverStateSigning {
		t.Fatalf("must NOT complete before the signing-phase dwell elapses; rollover=%+v", r)
	}

	// (2) Dwell elapsed, but the zone was never signed after the switch → no
	// completion, and no first-signed stamp either.
	zs = state.GetZone(domain)
	zs.Rollover.PhaseStarted = now.Add(-2 * time.Hour)
	zs.Rollover.PhaseFirstSigned = time.Time{} // as reset at the switch
	zs.LastSigned = now.Add(-3 * time.Hour)    // before the switch
	if err := rm.CheckZSKRollover(domain); err != nil {
		t.Fatalf("CheckZSKRollover (unsigned gate): %v", err)
	}
	if r := state.GetZone(domain).Rollover; r == nil || r.State != statepkg.ZSKRolloverStateSigning {
		t.Fatalf("must NOT complete when the zone wasn't signed after the switch; rollover=%+v", r)
	}
	if !state.GetZone(domain).Rollover.PhaseFirstSigned.IsZero() {
		t.Error("PhaseFirstSigned must not be stamped while the in-phase sign is missing")
	}

	// (3) All gates pass: dwell elapsed, signed after the switch, floor elapsed
	// since that first sign → completes.
	zs = state.GetZone(domain)
	zs.LastSigned = now.Add(-90 * time.Minute) // after PhaseStarted (-2h)
	zs.AddWarning("stale rollover warning")
	if err := rm.CheckZSKRollover(domain); err != nil {
		t.Fatalf("CheckZSKRollover (complete): %v", err)
	}
	zs = state.GetZone(domain)
	if zs.Rollover != nil {
		t.Fatalf("rollover must be cleared on completion, got %+v", zs.Rollover)
	}
	if !zs.ForceResign {
		t.Error("completion must force a re-sign so the old ZSK is dropped")
	}
	if len(zs.Warnings) != 0 {
		t.Errorf("completion must clear warnings, got %v", zs.Warnings)
	}

	// The forced re-sign publishes a DNSKEY RRset without the old ZSK: exactly
	// one ZSK (the new one) and one KSK.
	if err := signerpkg.NewSigner(cfg, state).SignZone(domain); err != nil {
		t.Fatalf("SignZone after completion: %v", err)
	}
	f, err := os.Open(filepath.Join(cfg.OutputDir, domain+".zone.signed"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var zskCount, kskCount int
	zp := dns.NewZoneParser(f, dns.Fqdn(domain), "")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if dk, isDNSKEY := rr.(*dns.DNSKEY); isDNSKEY {
			switch dk.Flags {
			case 256:
				zskCount++
			case 257:
				kskCount++
			}
		}
	}
	if err := zp.Err(); err != nil {
		t.Fatalf("parsing signed zone: %v", err)
	}
	if zskCount != 1 || kskCount != 1 {
		t.Errorf("signed zone after completion must publish exactly one ZSK and one KSK (old ZSK dropped), got %d ZSK / %d KSK", zskCount, kskCount)
	}
}

// --- Item 13: a backup-exists skip must require BOTH halves of the pair ---

// backupKey: a crash between the .key and .private copies leaves a tag-named
// backup .key with no .private. A rollover-start retry must complete the pair
// from the live .private — not skip and let the caller overwrite the live
// .private's only copy.
func TestBackupKey_CompletesHalfWrittenBackup(t *testing.T) {
	dataDir := t.TempDir()
	cfg := dnssectest.Config(t, dataDir)
	if err := signerpkg.EnsureDir(cfg.KeysDir()); err != nil {
		t.Fatal(err)
	}
	kg := signerpkg.NewKeyGenerator(cfg)
	ksk, err := kg.GenerateKSK("example.com")
	if err != nil {
		t.Fatal(err)
	}
	rm := signerpkg.NewRolloverManager(cfg, statepkg.NewState(cfg.StatePath()))

	base := filepath.Join(cfg.KeysDir(), "example.com.ksk")
	backupBase := filepath.Join(cfg.KeysDir(), fmt.Sprintf("example.com.ksk.%d", ksk.ID))
	liveKey, err := os.ReadFile(base + ".key")
	if err != nil {
		t.Fatal(err)
	}
	livePriv, err := os.ReadFile(base + ".private")
	if err != nil {
		t.Fatal(err)
	}

	// Simulate the crash artifact: only the .key half of the backup landed.
	if err := os.WriteFile(backupBase+".key", liveKey, 0o644); err != nil {
		t.Fatal(err)
	}

	if err := rm.BackupKey("example.com", "ksk", ksk.ID); err != nil {
		t.Fatalf("backupKey must complete a half-written backup, not fail: %v", err)
	}

	// Both backup halves now exist, and the .private holds the live key's material.
	backupPriv, err := os.ReadFile(backupBase + ".private")
	if err != nil {
		t.Fatalf("backup .private was not completed (Item 13): %v", err)
	}
	if !bytes.Equal(backupPriv, livePriv) {
		t.Error("completed backup .private must hold the live private key material")
	}
	// The live pair is untouched.
	nowKey, _ := os.ReadFile(base + ".key")
	nowPriv, _ := os.ReadFile(base + ".private")
	if !bytes.Equal(nowKey, liveKey) || !bytes.Equal(nowPriv, livePriv) {
		t.Error("live key files must be untouched by the backup completion")
	}
	// The completed backup loads as a valid, corresponding pair.
	if _, _, err := kg.LoadKeyPairByID("example.com", "ksk", ksk.ID); err != nil {
		t.Errorf("completed backup pair must load: %v", err)
	}
}

// backupExistingKeyFiles (via its caller SaveKeyFiles / GenerateKSK): the
// same-key skip must first complete a half-written backup pair from the live
// .private, because the caller immediately overwrites the live files.
func TestBackupExistingKeyFiles_CompletesHalfWrittenBackup(t *testing.T) {
	dataDir := t.TempDir()
	cfg := dnssectest.Config(t, dataDir)
	kg := signerpkg.NewKeyGenerator(cfg)
	ksk, err := kg.GenerateKSK("example.com")
	if err != nil {
		t.Fatal(err)
	}

	base := filepath.Join(cfg.KeysDir(), "example.com.ksk")
	backupBase := filepath.Join(cfg.KeysDir(), fmt.Sprintf("example.com.ksk.%d", ksk.ID))
	origKey, err := os.ReadFile(base + ".key")
	if err != nil {
		t.Fatal(err)
	}
	origPriv, err := os.ReadFile(base + ".private")
	if err != nil {
		t.Fatal(err)
	}

	// Crash artifact: a tag-named backup holds the same .key but no .private.
	if err := os.WriteFile(backupBase+".key", origKey, 0o644); err != nil {
		t.Fatal(err)
	}

	// Overwrite the live pair via new key generation — the SaveKeyFiles seam.
	// Pre-fix this skipped the backup ("already backed up") and the overwrite
	// destroyed the only copy of the old .private.
	if _, err := kg.GenerateKSK("example.com"); err != nil {
		t.Fatalf("GenerateKSK over an existing key: %v", err)
	}

	backupKey, err := os.ReadFile(backupBase + ".key")
	if err != nil {
		t.Fatal(err)
	}
	backupPriv, err := os.ReadFile(backupBase + ".private")
	if err != nil {
		t.Fatalf("backup .private missing after overwrite — old private key lost (Item 13): %v", err)
	}
	if !bytes.Equal(backupKey, origKey) || !bytes.Equal(backupPriv, origPriv) {
		t.Error("backup pair must hold the OLD key's material after the overwrite")
	}
	// The completed backup loads as a valid, corresponding pair.
	if _, _, err := kg.LoadKeyPairByID("example.com", "ksk", ksk.ID); err != nil {
		t.Errorf("completed backup pair must load: %v", err)
	}
}

// --- Item 14: the daemon must re-initialize keyless placeholders ---

// A keyless placeholder (written by a failed cron `sign` init and merged into
// a running daemon via ReloadFromDisk) must be re-initialized by the daemon's
// signing cycle — mirroring SignAll (R-033) — instead of producing a
// key-loading error every cycle until a CLI `sign` heals it.
func TestDaemon_ReinitializesKeylessPlaceholder(t *testing.T) {
	d, cfg, state, domain := signableZoneDaemon(t)
	origKSKID := state.GetZone(domain).KSK.ID

	// Replace the healthy zone state with a keyless placeholder, as a prior
	// failed init would have left it.
	placeholder := &statepkg.ZoneState{Path: cfg.Zones[domain].Path}
	placeholder.AddError("keys dir was briefly unwritable")
	state.SetZone(domain, placeholder)

	d.signAllZones()

	z := state.GetZone(domain)
	if z == nil || z.KSK == nil || z.ZSK == nil {
		t.Fatalf("daemon did not re-initialize the keyless placeholder (Item 14); got %+v", z)
	}
	// The key files on disk survive, so recovery must preserve the DS chain of
	// trust — the recovered KSK is the original one, not a fresh mint.
	if z.KSK.ID != origKSKID {
		t.Errorf("recovered KSK id = %d, want the original %d (DS chain preserved)", z.KSK.ID, origKSKID)
	}
	if _, err := os.Stat(filepath.Join(cfg.OutputDir, domain+".zone.signed")); err != nil {
		t.Errorf("zone should be signed after re-init: %v", err)
	}
}
