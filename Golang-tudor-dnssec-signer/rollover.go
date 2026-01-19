package main

import (
	"fmt"
	"log/slog"
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

	slog.Info("Starting KSK rollover", "domain", domain, "old_key_id", oldKSK.ID)

	// Generate new KSK
	keyGen := NewKeyGenerator(rm.cfg)

	// Save old KSK to backup file
	if err := rm.backupKey(domain, "ksk", oldKSK.ID); err != nil {
		slog.Warn("Failed to backup old KSK", "error", err)
	}

	// Generate new KSK
	newKSK, err := keyGen.GenerateKSK(domain)
	if err != nil {
		return fmt.Errorf("generating new KSK: %w", err)
	}

	// Set up rollover state
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

	slog.Info("Completing KSK rollover",
		"domain", domain,
		"old_key_id", zoneState.Rollover.OldKeyID,
		"new_key_id", zoneState.Rollover.NewKeyID)

	// Clear rollover state
	zoneState.Rollover = nil
	zoneState.ClearWarnings()

	// Old key files remain on disk but are no longer used
	slog.Info("KSK rollover completed",
		"domain", domain,
		"note", "Old key files remain on disk for safety. You may delete them after removing the old DS from your registrar.")

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

	// ZSK rollover timeline:
	// - 14 days before expiry: pre-publish new ZSK
	// - 7 days before expiry: switch to signing with new ZSK
	// - on expiry: remove old ZSK

	daysUntilExpiry := zsk.Expires.Sub(now).Hours() / 24

	// Check for existing ZSK rollover
	if zoneState.Rollover != nil && zoneState.Rollover.Type == "zsk" {
		return rm.handleZSKRolloverState(domain, zoneState)
	}

	// Start new rollover if within 14 days of expiry
	if daysUntilExpiry <= 14 && daysUntilExpiry > 0 {
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
	slog.Info("Starting automatic ZSK rollover", "domain", domain, "old_key_id", oldZSK.ID)

	// Backup old key
	if err := rm.backupKey(domain, "zsk", oldZSK.ID); err != nil {
		slog.Warn("Failed to backup old ZSK", "error", err)
	}

	// Generate new ZSK
	keyGen := NewKeyGenerator(rm.cfg)
	newZSK, err := keyGen.GenerateZSK(domain)
	if err != nil {
		return fmt.Errorf("generating new ZSK: %w", err)
	}

	// Set up rollover state
	zoneState.Rollover = &RolloverState{
		Type:     "zsk",
		State:    ZSKRolloverStatePrePublish,
		OldKeyID: oldZSK.ID,
		NewKeyID: newZSK.ID,
		Started:  time.Now().UTC(),
		Action:   "Automatic: new ZSK is pre-published, will switch to signing in 7 days",
	}

	// Don't update zoneState.ZSK yet - we keep signing with old key during pre-publish

	return rm.state.Save()
}

func (rm *RolloverManager) handleZSKRolloverState(domain string, zoneState *ZoneState) error {
	rollover := zoneState.Rollover
	now := time.Now().UTC()
	daysSinceStart := now.Sub(rollover.Started).Hours() / 24

	switch rollover.State {
	case ZSKRolloverStatePrePublish:
		// After 7 days, switch to signing with new key
		if daysSinceStart >= 7 {
			slog.Info("ZSK rollover: switching to new key", "domain", domain, "new_key_id", rollover.NewKeyID)
			rollover.State = ZSKRolloverStateSigning
			rollover.Action = "Automatic: signing with new ZSK, old ZSK still published"

			// Load and update ZSK state
			keyGen := NewKeyGenerator(rm.cfg)
			newZSK, _, err := keyGen.LoadKeyPair(domain, "zsk")
			if err != nil {
				return fmt.Errorf("loading new ZSK: %w", err)
			}

			zoneState.ZSK = &KeyState{
				ID:          newZSK.KeyTag(),
				Algorithm:   rm.cfg.DNSSEC.Algorithm,
				Created:     rollover.Started,
				Expires:     rollover.Started.Add(rm.cfg.GetZoneZSKLifetime(domain)),
				RolloverDue: rollover.Started.Add(time.Duration(float64(rm.cfg.GetZoneZSKLifetime(domain)) * 0.75)),
			}

			return rm.state.Save()
		}

	case ZSKRolloverStateSigning:
		// After another 7 days (14 total), complete rollover
		if daysSinceStart >= 14 {
			slog.Info("ZSK rollover: completing", "domain", domain)
			rollover.State = ZSKRolloverStateRetired

			// Clear rollover state
			zoneState.Rollover = nil
			zoneState.ClearWarnings()

			slog.Info("ZSK rollover completed automatically", "domain", domain)
			return rm.state.Save()
		}
	}

	return nil
}

func (rm *RolloverManager) backupKey(domain, keyType string, keyID uint16) error {
	// Create backup by renaming with key ID suffix
	keysDir := rm.cfg.KeysDir()
	baseName := fmt.Sprintf("%s/%s.%s", keysDir, domain, keyType)
	backupName := fmt.Sprintf("%s/%s.%s.%d", keysDir, domain, keyType, keyID)

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
