package main

import (
	"bytes"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"
)

// RolloverManager handles key rollover operations
type RolloverManager struct {
	cfg   *Config
	state *State
}

// NewRolloverManager creates a new rollover manager
func NewRolloverManager(cfg *Config, state *State) *RolloverManager {
	return &RolloverManager{
		cfg:   cfg,
		state: state,
	}
}

// StartKSKRollover begins a KSK rollover for a domain
func (rm *RolloverManager) StartKSKRollover(domain string) error {
	zoneState := rm.state.GetZone(domain)
	if zoneState == nil {
		return fmt.Errorf("zone %s not found", domain)
	}

	if zoneState.Rollover != nil {
		return fmt.Errorf("rollover already in progress")
	}

	oldKSK := zoneState.KSK
	if oldKSK == nil {
		return fmt.Errorf("no existing KSK found")
	}

	slog.Info("[ROLLOVER] Starting KSK rollover", "domain", domain, "old_key_id", oldKSK.ID)

	// Generate new KSK
	keyGen := NewKeyGenerator(rm.cfg)

	// Save old KSK to backup file. A backup failure is FATAL (R-027): the rollover-signing
	// path and DS recovery both depend on the old KSK's backup, so proceeding without it
	// risks an unrecoverable SERVFAIL. Abort before generating the new key.
	if err := rm.backupKey(domain, "ksk", oldKSK.ID); err != nil {
		return fmt.Errorf("backing up old KSK before rollover: %w", err)
	}

	// Generate new KSK
	newKSK, err := keyGen.GenerateKSK(domain)
	if err != nil {
		return fmt.Errorf("generating new KSK: %w", err)
	}

	// Set up rollover state
	rm.state.Mutate(func() {
		zoneState.Rollover = &RolloverState{
			Type:     "ksk",
			State:    KSKRolloverStateDSAddWait,
			OldKeyID: oldKSK.ID,
			NewKeyID: newKSK.ID,
			Started:  time.Now().UTC(),
			Action:   fmt.Sprintf("Publish new DS record at registrar, then run: dnssec-tudor rollover complete %s", domain),
		}

		// Update KSK in state (zone will now be signed with both during rollover)
		zoneState.KSK = newKSK
		zoneState.ForceResign = true
	})

	RecordRolloverOperation(domain, "ksk", "start")
	if err := rm.state.Save(); err != nil {
		// R-038: the key files are already rotated (live = new KSK) but the state
		// did not persist. Revert the in-memory rollover and restore the old KSK
		// files so the next sign doesn't publish a KSK the parent DS doesn't
		// reference (→ SERVFAIL) with no rollover record to recover from.
		rm.state.Mutate(func() {
			zoneState.KSK = oldKSK
			zoneState.Rollover = nil
			zoneState.ForceResign = false
		})
		if rerr := rm.restoreKeyFromBackup(domain, "ksk", oldKSK.ID); rerr != nil {
			slog.Error("[ROLLOVER] CRITICAL: could not restore old KSK files after a failed rollover-start save; manual recovery required",
				"domain", domain, "save_error", err, "restore_error", rerr)
		}
		return fmt.Errorf("saving KSK rollover state (key rotation rolled back): %w", err)
	}
	return nil
}

// CompleteKSKRollover finalizes a KSK rollover
func (rm *RolloverManager) CompleteKSKRollover(domain string) error {
	zoneState := rm.state.GetZone(domain)
	if zoneState == nil {
		return fmt.Errorf("zone %s not found", domain)
	}

	if zoneState.Rollover == nil {
		return fmt.Errorf("no rollover in progress")
	}

	if zoneState.Rollover.Type != "ksk" {
		return fmt.Errorf("current rollover is not KSK type")
	}

	if zoneState.Rollover.State != KSKRolloverStateDSAddWait {
		return fmt.Errorf("rollover not in ds_add_wait state")
	}

	slog.Info("[ROLLOVER] Completing KSK rollover",
		"domain", domain,
		"old_key_id", zoneState.Rollover.OldKeyID,
		"new_key_id", zoneState.Rollover.NewKeyID)

	// Clear rollover state; the next sign drops the old KSK from the zone
	rm.state.Mutate(func() {
		zoneState.Rollover = nil
		zoneState.ForceResign = true
		zoneState.ClearTransientWarnings()
	})

	// Old key files remain on disk but are no longer used
	slog.Info("[ROLLOVER] KSK rollover completed",
		"domain", domain,
		"note", "Old key files remain on disk for safety. You may delete them after removing the old DS from your registrar.")

	RecordRolloverOperation(domain, "ksk", "complete")
	return rm.state.Save()
}

// CheckZSKRollover checks if ZSK rollover is needed and handles it automatically
func (rm *RolloverManager) CheckZSKRollover(domain string) error {
	zoneState := rm.state.GetZone(domain)
	if zoneState == nil || zoneState.ZSK == nil {
		return nil
	}

	now := time.Now().UTC()
	zsk := zoneState.ZSK

	// Get configurable rollover timing
	prepublishDays := rm.cfg.DNSSEC.RolloverPrepublish.Duration.Hours() / 24

	// ZSK rollover timeline:
	// - prepublish_days before expiry: pre-publish new ZSK
	// - switch_days after prepublish: switch to signing with new ZSK
	// - on expiry: remove old ZSK

	daysUntilExpiry := zsk.Expires.Sub(now).Hours() / 24

	// Check for existing ZSK rollover
	if zoneState.Rollover != nil && zoneState.Rollover.Type == "zsk" {
		return rm.handleZSKRolloverState(domain, zoneState)
	}

	// A KSK/algorithm rollover occupies the single Rollover slot, so an automatic
	// ZSK rollover cannot start while one is pending (a KSK rollover often sits in
	// ds_add_wait for days awaiting a manual parent-DS update). Surface a warning
	// when the ZSK is due rather than letting it silently age past its lifetime
	// with no signal (R-041).
	if zoneState.Rollover != nil {
		if daysUntilExpiry <= prepublishDays {
			rm.state.Mutate(func() {
				zoneState.AddWarning(fmt.Sprintf(
					"ZSK rollover is due (expires in ~%.0f days) but is blocked by the in-progress %s rollover; complete that rollover to resume automatic ZSK rollover",
					daysUntilExpiry, zoneState.Rollover.Type))
			})
			return rm.state.Save()
		}
		return nil
	}

	// Start a rollover once inside the prepublish window — including when
	// the ZSK is already past its expiry date (e.g. the daemon was down
	// across the window). The old `daysUntilExpiry > 0` guard meant an
	// expired ZSK never rolled at all: automation silently stopped and the
	// zone kept signing with the overdue key forever.
	if daysUntilExpiry <= prepublishDays {
		return rm.startZSKRollover(domain, zoneState)
	}

	return nil
}

func (rm *RolloverManager) startZSKRollover(domain string, zoneState *ZoneState) error {
	// Don't start if there's already a rollover in progress
	if zoneState.Rollover != nil {
		return nil
	}

	oldZSK := zoneState.ZSK
	slog.Info("[ROLLOVER] Starting automatic ZSK rollover", "domain", domain, "old_key_id", oldZSK.ID)

	// Backup old key. Fatal on failure (R-027): the pre-publish/signing phases load the
	// old ZSK from this backup, and a missing backup would drop it from the published
	// DNSKEY RRset while resolvers still hold its cached RRSIGs.
	if err := rm.backupKey(domain, "zsk", oldZSK.ID); err != nil {
		return fmt.Errorf("backing up old ZSK before rollover: %w", err)
	}

	// Generate the new ZSK with the EXISTING ZSK's algorithm, not the current
	// config default (R-039). If the operator changed [dnssec].algorithm after
	// the zone was signed, GenerateZSK would mint a new ZSK in the new algorithm
	// while the KSK stays the old one — an unintended algorithm mismatch that
	// must instead go through the dedicated `rollover algorithm` flow.
	keyGen := NewKeyGenerator(rm.cfg)
	newZSK, err := keyGen.GenerateZSKWithAlgorithm(domain, oldZSK.Algorithm)
	if err != nil {
		return fmt.Errorf("generating new ZSK: %w", err)
	}

	// Set up rollover state
	rm.state.Mutate(func() {
		zoneState.Rollover = &RolloverState{
			Type:     "zsk",
			State:    ZSKRolloverStatePrePublish,
			OldKeyID: oldZSK.ID,
			NewKeyID: newZSK.ID,
			Started:  time.Now().UTC(),
			Action:   fmt.Sprintf("Automatic: new ZSK is pre-published, will switch to signing in %s", humanizeRolloverDelay(rm.cfg.DNSSEC.RolloverSwitch.Duration)),
		}
		zoneState.ForceResign = true

		// Don't update zoneState.ZSK yet - we keep signing with old key during pre-publish
	})

	RecordRolloverOperation(domain, "zsk", "start")
	return rm.state.Save()
}

// humanizeRolloverDelay renders a rollover delay for the operator-facing Action
// string: whole days when >= a day, otherwise the raw duration (test configs use
// seconds). Built from the configured RolloverSwitch rather than a hardcoded
// "7 days" so the message tracks the actual config (R-014).
func humanizeRolloverDelay(d time.Duration) string {
	if d >= 24*time.Hour {
		return fmt.Sprintf("%.0f day(s)", d.Hours()/24)
	}
	return d.String()
}

// dnskeyTTLFloor is the minimum time that must elapse after a phase's DNSKEY
// RRset is published before the rollover advances, so resolvers have had time to
// (a) cache the pre-published key and (b) let cached RRSIGs by the retiring key
// age out. Uses the configured DNSKEY TTL, with a conservative 24h fallback when
// it is 0 (which means "use the SOA TTL"). R-011.
func (rm *RolloverManager) dnskeyTTLFloor() time.Duration {
	ttl := time.Duration(rm.cfg.DNSSEC.DNSKEYTtl) * time.Second
	if ttl <= 0 {
		return 24 * time.Hour
	}
	return ttl
}

func (rm *RolloverManager) handleZSKRolloverState(domain string, zoneState *ZoneState) error {
	rollover := zoneState.Rollover
	now := time.Now().UTC()

	switchDuration := rm.cfg.DNSSEC.RolloverSwitch.Duration
	prepublishDuration := rm.cfg.DNSSEC.RolloverPrepublish.Duration
	ttlFloor := rm.dnskeyTTLFloor()
	lastSigned := zoneState.LastSigned

	switch rollover.State {
	case ZSKRolloverStatePrePublish:
		// Advance to "signing" only when ALL of the following hold (R-011), rather
		// than on wall-time-since-start alone — otherwise a daemon that was down or
		// failing across the window collapses both transitions into consecutive
		// polls, signing with a key validators never cached:
		//  (1) the pre-publish phase has lasted at least the switch duration;
		//  (2) the pre-published DNSKEY RRset was actually signed after the phase
		//      began (LastSigned after phaseStart) — else the new ZSK was never
		//      published;
		//  (3) a DNSKEY-TTL floor has elapsed since the phase's key set was FIRST
		//      published (PhaseFirstSigned) — measured from the first in-phase
		//      sign, not the most recent one, so a zone re-signed more often than
		//      the floor (e.g. hourly edits vs the 24h fallback) still advances
		//      instead of stalling in pre_publish forever.
		phaseStart := rollover.Started
		if now.Sub(phaseStart) < switchDuration {
			return nil
		}
		if !lastSigned.After(phaseStart) {
			slog.Debug("[ROLLOVER] ZSK pre_publish: waiting for the pre-published key set to be signed", "domain", domain)
			return nil
		}
		if rollover.PhaseFirstSigned.IsZero() {
			// First check that observes the phase's key set signed: stamp the
			// publish time the TTL floor counts from and persist it. Old state
			// files without the field pick it up here — at most one poll
			// interval late, which is conservative.
			rm.state.Mutate(func() { rollover.PhaseFirstSigned = lastSigned })
			if err := rm.state.Save(); err != nil {
				return err
			}
		}
		if now.Sub(rollover.PhaseFirstSigned) < ttlFloor {
			slog.Debug("[ROLLOVER] ZSK pre_publish: waiting DNSKEY-TTL floor after publish", "domain", domain, "floor", ttlFloor.String())
			return nil
		}

		slog.Info("[ROLLOVER] ZSK rollover: switching to new key", "domain", domain, "new_key_id", rollover.NewKeyID)
		keyGen := NewKeyGenerator(rm.cfg)
		newZSK, _, err := keyGen.LoadKeyPair(domain, "zsk")
		if err != nil {
			return fmt.Errorf("loading new ZSK: %w", err)
		}
		rm.state.Mutate(func() {
			rollover.State = ZSKRolloverStateSigning
			rollover.PhaseStarted = now             // gate the signing phase from here (R-011)
			rollover.PhaseFirstSigned = time.Time{} // the signing phase stamps its own first sign
			rollover.Action = "Automatic: signing with new ZSK, old ZSK still published"
			zoneState.ZSK = &KeyState{
				ID: newZSK.KeyTag(),
				// Algorithm comes from the key itself — the config may
				// have changed since this key was generated.
				Algorithm:   AlgorithmName(newZSK.Algorithm),
				Created:     rollover.Started,
				Expires:     rollover.Started.Add(rm.cfg.GetZoneZSKLifetime(domain)),
				RolloverDue: rollover.Started.Add(time.Duration(float64(rm.cfg.GetZoneZSKLifetime(domain)) * 0.75)),
			}
			zoneState.ForceResign = true
		})
		return rm.state.Save()

	case ZSKRolloverStateSigning:
		// Complete only when ALL hold (R-011): the signing phase has dwelled long
		// enough, the new ZSK's signatures were actually published after the
		// switch, and the DNSKEY-TTL floor has elapsed since they were FIRST
		// published (PhaseFirstSigned, same rationale as pre_publish) — so
		// resolvers no longer hold old-ZSK RRSIGs cached when the old ZSK is
		// dropped.
		phaseStart := rollover.PhaseStarted
		if phaseStart.IsZero() {
			phaseStart = rollover.Started // old state files predating phase_started
		}
		signingDuration := prepublishDuration - switchDuration
		if signingDuration <= 0 {
			signingDuration = switchDuration // defensive; R-014 enforces switch < prepublish
		}
		if now.Sub(phaseStart) < signingDuration {
			return nil
		}
		if !lastSigned.After(phaseStart) {
			slog.Debug("[ROLLOVER] ZSK signing: waiting for the new ZSK's signatures to be published", "domain", domain)
			return nil
		}
		if rollover.PhaseFirstSigned.IsZero() {
			// First check that observes the new ZSK's signatures published:
			// stamp the point the TTL floor counts from and persist it.
			rm.state.Mutate(func() { rollover.PhaseFirstSigned = lastSigned })
			if err := rm.state.Save(); err != nil {
				return err
			}
		}
		if now.Sub(rollover.PhaseFirstSigned) < ttlFloor {
			slog.Debug("[ROLLOVER] ZSK signing: waiting DNSKEY-TTL floor before dropping old ZSK", "domain", domain, "floor", ttlFloor.String())
			return nil
		}

		slog.Info("[ROLLOVER] ZSK rollover: completing", "domain", domain)
		// Clear rollover state; the next sign drops the old ZSK from the
		// published DNSKEY RRset.
		rm.state.Mutate(func() {
			zoneState.Rollover = nil
			zoneState.ForceResign = true
			zoneState.ClearTransientWarnings()
		})
		RecordRolloverOperation(domain, "zsk", "complete")
		slog.Info("[ROLLOVER] ZSK rollover completed automatically", "domain", domain)
		return rm.state.Save()
	}

	return nil
}

func (rm *RolloverManager) backupKey(domain, keyType string, keyID uint16) error {
	// Create backup by renaming with key ID suffix
	keysDir := rm.cfg.KeysDir()
	baseName := filepath.Join(keysDir, fmt.Sprintf("%s.%s", domain, keyType))
	backupName := filepath.Join(keysDir, fmt.Sprintf("%s.%s.%d", domain, keyType, keyID))

	// Refuse to clobber an existing backup that holds DIFFERENT key material. A
	// key-tag collision (R-029) would otherwise overwrite another key's backup
	// under the same <type>.<tag> name, destroying the only copy of that key. An
	// identical existing backup is fine (idempotent re-backup).
	if existing, err := os.ReadFile(backupName + ".key"); err == nil {
		src, err := os.ReadFile(baseName + ".key")
		if err != nil {
			return fmt.Errorf("reading %s key for backup: %w", keyType, err)
		}
		if !bytes.Equal(existing, src) {
			return fmt.Errorf("backup %s already exists with different key material (key-tag collision?); refusing to overwrite", backupName+".key")
		}
		// The .key half matches — but a crash between the two copies below can
		// leave the backup without its .private. Treating that artifact as
		// "already backed up" would let the caller proceed to overwrite the live
		// .private, destroying its only copy. Complete the pair from the live
		// .private before declaring success.
		if !fileExists(backupName + ".private") {
			if err := copyFile(baseName+".private", backupName+".private"); err != nil {
				return fmt.Errorf("completing half-written %s backup (.key present, .private missing): %w", keyType, err)
			}
			slog.Warn("[ROLLOVER] Completed a half-written key backup with the live private key",
				"domain", domain, "type", keyType, "key_id", keyID, "backup", backupName)
		}
		return nil // already backed up with identical content
	}

	// Copy key file to backup (don't move, in case rollover fails)
	if err := copyFile(baseName+".key", backupName+".key"); err != nil {
		return err
	}
	if err := copyFile(baseName+".private", backupName+".private"); err != nil {
		return err
	}

	return nil
}

// restoreKeyFromBackup copies the tag-suffixed backup of a key back over the
// live key files, undoing an in-place rotation. Used to roll back a rollover
// start whose state Save failed, so state.json and the on-disk keys do not
// diverge into a published-key-without-matching-DS SERVFAIL (R-038).
func (rm *RolloverManager) restoreKeyFromBackup(domain, keyType string, keyID uint16) error {
	keysDir := rm.cfg.KeysDir()
	base := filepath.Join(keysDir, fmt.Sprintf("%s.%s", domain, keyType))
	backup := filepath.Join(keysDir, fmt.Sprintf("%s.%s.%d", domain, keyType, keyID))
	if err := copyFile(backup+".private", base+".private"); err != nil {
		return err
	}
	if err := copyFile(backup+".key", base+".key"); err != nil {
		return err
	}
	return nil
}

// GetRolloverStatus returns the current rollover status for a domain
func (rm *RolloverManager) GetRolloverStatus(domain string) *RolloverState {
	zoneState := rm.state.GetZone(domain)
	if zoneState == nil {
		return nil
	}
	return zoneState.Rollover
}

// StartAlgorithmRollover begins an algorithm rollover for a domain
// This generates new KSK and ZSK with the target algorithm and signs with both
func (rm *RolloverManager) StartAlgorithmRollover(domain, targetAlgorithm string) error {
	zoneState := rm.state.GetZone(domain)
	if zoneState == nil {
		return fmt.Errorf("zone %s not found", domain)
	}

	if zoneState.Rollover != nil {
		return fmt.Errorf("rollover already in progress")
	}

	// A zone whose key init previously failed can be present only as a keyless
	// placeholder (see SignAll / R-033). Guard against the nil deref the way the
	// KSK-rollover path does, so an algorithm rollover on such a zone returns a
	// descriptive error instead of panicking (R-025).
	if zoneState.KSK == nil || zoneState.ZSK == nil {
		return fmt.Errorf("zone %s has no usable keys (key initialization previously failed); fix the underlying issue and re-run `dnssec-tudor sign` before attempting an algorithm rollover", domain)
	}

	oldAlgorithm := zoneState.KSK.Algorithm
	if oldAlgorithm == targetAlgorithm {
		return fmt.Errorf("zone already using algorithm %s", targetAlgorithm)
	}
	// Capture the old key states for rollback if the state Save fails (R-038).
	oldKSKState := zoneState.KSK
	oldZSKState := zoneState.ZSK

	slog.Info("[ROLLOVER] Starting algorithm rollover",
		"domain", domain,
		"old_algorithm", oldAlgorithm,
		"new_algorithm", targetAlgorithm)

	// Backup old keys. Fatal on failure (R-027): an algorithm rollover must sign with both
	// old and new algorithm keys (RFC 6840 §5.11), so losing the old keys' backup would
	// emit a zone missing signatures for a signaled algorithm.
	if err := rm.backupKey(domain, "ksk", zoneState.KSK.ID); err != nil {
		return fmt.Errorf("backing up old KSK before algorithm rollover: %w", err)
	}
	if err := rm.backupKey(domain, "zsk", zoneState.ZSK.ID); err != nil {
		return fmt.Errorf("backing up old ZSK before algorithm rollover: %w", err)
	}

	// Generate new keys with target algorithm (using explicit algorithm to avoid race conditions)
	keyGen := NewKeyGenerator(rm.cfg)
	newKSK, err := keyGen.GenerateKSKWithAlgorithm(domain, targetAlgorithm)
	if err != nil {
		return fmt.Errorf("generating new KSK: %w", err)
	}
	newZSK, err := keyGen.GenerateZSKWithAlgorithm(domain, targetAlgorithm)
	if err != nil {
		return fmt.Errorf("generating new ZSK: %w", err)
	}

	// Set up rollover state
	rm.state.Mutate(func() {
		zoneState.Rollover = &RolloverState{
			Type:         "algorithm",
			State:        AlgoRolloverStateDSAddWait,
			OldKeyID:     zoneState.KSK.ID,
			NewKeyID:     newKSK.ID,
			OldZSKID:     zoneState.ZSK.ID,
			NewZSKID:     newZSK.ID,
			OldAlgorithm: oldAlgorithm,
			NewAlgorithm: targetAlgorithm,
			Started:      time.Now().UTC(),
			Action:       fmt.Sprintf("Publish new DS record (algorithm %s) at registrar, then run: dnssec-tudor rollover complete %s", targetAlgorithm, domain),
		}

		// Update keys to new algorithm (old keys are backed up and will be used during rollover)
		zoneState.KSK = newKSK
		zoneState.ZSK = newZSK
		zoneState.ForceResign = true
	})

	RecordRolloverOperation(domain, "algorithm", "start")
	if err := rm.state.Save(); err != nil {
		// R-038: both key pairs are already rotated on disk but the state did not
		// persist. Revert in-memory and restore the old KSK+ZSK files so the next
		// sign doesn't publish new-algorithm keys with no rollover record (the
		// parent DS still references the old algorithm → SERVFAIL).
		rm.state.Mutate(func() {
			zoneState.KSK = oldKSKState
			zoneState.ZSK = oldZSKState
			zoneState.Rollover = nil
			zoneState.ForceResign = false
		})
		var rerr error
		if e := rm.restoreKeyFromBackup(domain, "ksk", oldKSKState.ID); e != nil {
			rerr = e
		}
		if e := rm.restoreKeyFromBackup(domain, "zsk", oldZSKState.ID); e != nil {
			rerr = e
		}
		if rerr != nil {
			slog.Error("[ROLLOVER] CRITICAL: could not restore old key files after a failed algorithm-rollover-start save; manual recovery required",
				"domain", domain, "save_error", err, "restore_error", rerr)
		}
		return fmt.Errorf("saving algorithm rollover state (key rotation rolled back): %w", err)
	}
	return nil
}

// CompleteAlgorithmRollover finalizes an algorithm rollover
func (rm *RolloverManager) CompleteAlgorithmRollover(domain string) error {
	zoneState := rm.state.GetZone(domain)
	if zoneState == nil {
		return fmt.Errorf("zone %s not found", domain)
	}

	if zoneState.Rollover == nil {
		return fmt.Errorf("no rollover in progress")
	}

	if zoneState.Rollover.Type != "algorithm" {
		return fmt.Errorf("current rollover is not algorithm type")
	}

	slog.Info("[ROLLOVER] Completing algorithm rollover",
		"domain", domain,
		"old_algorithm", zoneState.Rollover.OldAlgorithm,
		"new_algorithm", zoneState.Rollover.NewAlgorithm)

	// Clear rollover state; the next sign drops the old-algorithm keys
	rm.state.Mutate(func() {
		zoneState.Rollover = nil
		zoneState.ForceResign = true
		zoneState.ClearTransientWarnings()
	})

	slog.Info("[ROLLOVER] Algorithm rollover completed",
		"domain", domain,
		"note", "Old key files remain on disk for safety. You may delete them after removing the old DS from your registrar.")

	RecordRolloverOperation(domain, "algorithm", "complete")
	return rm.state.Save()
}
