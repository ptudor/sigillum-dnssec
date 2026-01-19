package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// State represents the daemon's persistent state
type State struct {
	mu    sync.RWMutex
	path  string
	Zones map[string]*ZoneState `json:"zones"`
}

// ZoneState represents the state of a single zone
type ZoneState struct {
	Path          string         `json:"path"`
	Serial        uint32         `json:"serial"`
	LastSigned    time.Time      `json:"last_signed"`
	SignaturesExp time.Time      `json:"signatures_expire"`
	KSK           *KeyState      `json:"ksk,omitempty"`
	ZSK           *KeyState      `json:"zsk,omitempty"`
	Rollover      *RolloverState `json:"rollover,omitempty"`
	Warnings      []string       `json:"warnings,omitempty"`
	Errors        []string       `json:"errors,omitempty"`
}

// KeyState represents the state of a DNSSEC key
type KeyState struct {
	ID          uint16    `json:"id"`
	Algorithm   string    `json:"algorithm"`
	Created     time.Time `json:"created"`
	Expires     time.Time `json:"expires"`
	DSPublished bool      `json:"ds_published,omitempty"`
	RolloverDue time.Time `json:"rollover_due,omitempty"`
}

// RolloverState represents an in-progress key rollover
type RolloverState struct {
	Type         string    `json:"type"`                    // "ksk", "zsk", or "algorithm"
	State        string    `json:"state"`                   // State machine state
	OldKeyID     uint16    `json:"old_key_id"`              // Old KSK ID (or only key for KSK/ZSK rollover)
	NewKeyID     uint16    `json:"new_key_id"`              // New KSK ID
	OldZSKID     uint16    `json:"old_zsk_id,omitempty"`    // Old ZSK ID (for algorithm rollover)
	NewZSKID     uint16    `json:"new_zsk_id,omitempty"`    // New ZSK ID (for algorithm rollover)
	OldAlgorithm string    `json:"old_algorithm,omitempty"` // For algorithm rollover
	NewAlgorithm string    `json:"new_algorithm,omitempty"` // For algorithm rollover
	Started      time.Time `json:"started"`
	Action       string    `json:"action"` // Human-readable next step
}

// ZSK rollover states (automatic)
const (
	ZSKRolloverStateActive     = "active"      // Normal operation
	ZSKRolloverStatePrePublish = "pre_publish" // New ZSK published, old still signing
	ZSKRolloverStateSigning    = "signing"     // New ZSK signing, old still published
	ZSKRolloverStateRetired    = "retired"     // Old ZSK removed
)

// KSK rollover states (semi-automatic)
const (
	KSKRolloverStateActive       = "active"         // Normal operation
	KSKRolloverStateDSAddWait    = "ds_add_wait"    // Waiting for new DS at registrar
	KSKRolloverStateDSRemoveWait = "ds_remove_wait" // Waiting for old DS removal
	KSKRolloverStateComplete     = "complete"       // Rollover finished
)

// Algorithm rollover states (manual, requires DS update)
const (
	AlgoRolloverStateDSAddWait    = "algo_ds_add_wait"    // New algorithm keys published, waiting for DS
	AlgoRolloverStateDSRemoveWait = "algo_ds_remove_wait" // Signing with new only, waiting for old DS removal
)

// NewState creates a new empty state
func NewState(path string) *State {
	return &State{
		path:  path,
		Zones: make(map[string]*ZoneState),
	}
}

// LoadState loads state from a JSON file
func LoadState(path string) (*State, error) {
	state := NewState(path)

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// No state file yet, return empty state
		return state, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading state file: %w", err)
	}

	if err := json.Unmarshal(data, state); err != nil {
		return nil, fmt.Errorf("parsing state file: %w", err)
	}

	return state, nil
}

// Save persists the state to disk
func (s *State) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling state: %w", err)
	}

	// Write to temp file first, then rename for atomicity
	tempPath := s.path + ".tmp"
	if err := os.WriteFile(tempPath, data, 0644); err != nil {
		return fmt.Errorf("writing state file: %w", err)
	}

	if err := os.Rename(tempPath, s.path); err != nil {
		os.Remove(tempPath)
		return fmt.Errorf("renaming state file: %w", err)
	}

	return nil
}

// GetZone returns the state for a zone, or nil if not found
func (s *State) GetZone(domain string) *ZoneState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Zones[domain]
}

// SetZone updates the state for a zone
func (s *State) SetZone(domain string, zone *ZoneState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Zones[domain] = zone
}

// RemoveZone removes a zone from state
func (s *State) RemoveZone(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Zones, domain)
}

// Status returns the overall status for a zone
func (z *ZoneState) Status() string {
	if len(z.Errors) > 0 {
		return "error"
	}
	if z.Rollover != nil && z.Rollover.State != "" {
		return "action_required"
	}
	if len(z.Warnings) > 0 {
		return "warning"
	}
	return "healthy"
}

// StatusOutput represents the JSON output for the status command
type StatusOutput struct {
	Timestamp time.Time                    `json:"timestamp"`
	Zones     map[string]*ZoneStatusOutput `json:"zones"`
	Summary   StatusSummary                `json:"summary"`
}

// ZoneStatusOutput represents per-zone status in the output
type ZoneStatusOutput struct {
	Status        string         `json:"status"`
	Serial        uint32         `json:"serial,omitempty"`
	LastSigned    time.Time      `json:"last_signed,omitempty"`
	SignaturesExp time.Time      `json:"signatures_expire,omitempty"`
	KSK           *KeyState      `json:"ksk,omitempty"`
	ZSK           *KeyState      `json:"zsk,omitempty"`
	Rollover      *RolloverState `json:"rollover,omitempty"`
	Warnings      []string       `json:"warnings,omitempty"`
	Errors        []string       `json:"errors,omitempty"`
}

// StatusSummary provides a summary of all zones
type StatusSummary struct {
	Total          int `json:"total"`
	Healthy        int `json:"healthy"`
	ActionRequired int `json:"action_required"`
	Warning        int `json:"warning"`
	Errors         int `json:"errors"`
}

// ToStatusOutput converts the state to status output format
func (s *State) ToStatusOutput() *StatusOutput {
	s.mu.RLock()
	defer s.mu.RUnlock()

	output := &StatusOutput{
		Timestamp: time.Now().UTC(),
		Zones:     make(map[string]*ZoneStatusOutput),
	}

	for domain, zone := range s.Zones {
		status := zone.Status()
		output.Zones[domain] = &ZoneStatusOutput{
			Status:        status,
			Serial:        zone.Serial,
			LastSigned:    zone.LastSigned,
			SignaturesExp: zone.SignaturesExp,
			KSK:           zone.KSK,
			ZSK:           zone.ZSK,
			Rollover:      zone.Rollover,
			Warnings:      zone.Warnings,
			Errors:        zone.Errors,
		}

		output.Summary.Total++
		switch status {
		case "healthy":
			output.Summary.Healthy++
		case "action_required":
			output.Summary.ActionRequired++
		case "warning":
			output.Summary.Warning++
		case "error":
			output.Summary.Errors++
		}
	}

	return output
}

// ToJSON returns the status output as JSON
func (s *State) ToJSON() ([]byte, error) {
	output := s.ToStatusOutput()
	return json.MarshalIndent(output, "", "  ")
}

// AddWarning adds a warning to a zone
func (z *ZoneState) AddWarning(msg string) {
	for _, w := range z.Warnings {
		if w == msg {
			return // Already present
		}
	}
	z.Warnings = append(z.Warnings, msg)
}

// ClearWarnings removes all warnings from a zone
func (z *ZoneState) ClearWarnings() {
	z.Warnings = nil
}

// AddError adds an error to a zone
func (z *ZoneState) AddError(msg string) {
	for _, e := range z.Errors {
		if e == msg {
			return // Already present
		}
	}
	z.Errors = append(z.Errors, msg)
}

// ClearErrors removes all errors from a zone
func (z *ZoneState) ClearErrors() {
	z.Errors = nil
}
