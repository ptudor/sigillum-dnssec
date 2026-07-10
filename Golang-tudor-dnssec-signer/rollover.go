package main

import (
	"fmt"
	"log/slog"
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
	return rm.state.Save()
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
		zoneState.ClearWarnings()
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

	// Generate new ZSK
	keyGen := NewKeyGenerator(rm.cfg)
	newZSK, err := keyGen.GenerateZSK(domain)
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
			Action:   "Automatic: new ZSK is pre-published, will switch to signing in 7 days",
		}
		zoneState.ForceResign = true

		// Don't update zoneState.ZSK yet - we keep signing with old key during pre-publish
	})

	RecordRolloverOperation(domain, "zsk", "start")
	return rm.state.Save()
}

func (rm *RolloverManager) handleZSKRolloverState(domain string, zoneState *ZoneState) error {
	rollover := zoneState.Rollover
	now := time.Now().UTC()
	daysSinceStart := now.Sub(rollover.Started).Hours() / 24

	// Get configurable timing
	switchDays := rm.cfg.DNSSEC.RolloverSwitch.Duration.Hours() / 24
	prepublishDays := rm.cfg.DNSSEC.RolloverPrepublish.Duration.Hours() / 24

	switch rollover.State {
	case ZSKRolloverStatePrePublish:
		// After switch_days, start signing with new key
		if daysSinceStart >= switchDays {
			slog.Info("[ROLLOVER] ZSK rollover: switching to new key", "domain", domain, "new_key_id", rollover.NewKeyID)

			// Load and update ZSK state
			keyGen := NewKeyGenerator(rm.cfg)
			newZSK, _, err := keyGen.LoadKeyPair(domain, "zsk")
			if err != nil {
				return fmt.Errorf("loading new ZSK: %w", err)
			}

			rm.state.Mutate(func() {
				rollover.State = ZSKRolloverStateSigning
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
		}

	case ZSKRolloverStateSigning:
		// After prepublish_days total, complete rollover
		if daysSinceStart >= prepublishDays {
			slog.Info("[ROLLOVER] ZSK rollover: completing", "domain", domain)

			// Clear rollover state; the next sign drops the old ZSK from
			// the published DNSKEY RRset.
			rm.state.Mutate(func() {
				zoneState.Rollover = nil
				zoneState.ForceResign = true
				zoneState.ClearWarnings()
			})

			RecordRolloverOperation(domain, "zsk", "complete")
			slog.Info("[ROLLOVER] ZSK rollover completed automatically", "domain", domain)
			return rm.state.Save()
		}
	}

	return nil
}

func (rm *RolloverManager) backupKey(domain, keyType string, keyID uint16) error {
	// Create backup by renaming with key ID suffix
	keysDir := rm.cfg.KeysDir()
	baseName := filepath.Join(keysDir, fmt.Sprintf("%s.%s", domain, keyType))
	backupName := filepath.Join(keysDir, fmt.Sprintf("%s.%s.%d", domain, keyType, keyID))

	// Copy key file to backup (don't move, in case rollover fails)
	if err := copyFile(baseName+".key", backupName+".key"); err != nil {
		return err
	}
	if err := copyFile(baseName+".private", backupName+".private"); err != nil {
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

	oldAlgorithm := zoneState.KSK.Algorithm
	if oldAlgorithm == targetAlgorithm {
		return fmt.Errorf("zone already using algorithm %s", targetAlgorithm)
	}

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
	return rm.state.Save()
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
		zoneState.ClearWarnings()
	})

	slog.Info("[ROLLOVER] Algorithm rollover completed",
		"domain", domain,
		"note", "Old key files remain on disk for safety. You may delete them after removing the old DS from your registrar.")

	RecordRolloverOperation(domain, "algorithm", "complete")
	return rm.state.Save()
}
