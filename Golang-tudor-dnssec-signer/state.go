package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ptudor/dnssec-tudor/internal/fsutil"
)

// State represents the daemon's persistent state
type State struct {
	mu    sync.RWMutex
	path  string
	Zones map[string]*ZoneState `json:"zones"`
}

// ZoneState represents the state of a single zone
type ZoneState struct {
	Path   string `json:"path"`
	Serial uint32 `json:"serial"`
	// PublishedSerial is the SOA serial actually written to the signed
	// zone. Equal to Serial under serial_policy = "keep"; under "epoch" it
	// is bumped on every signing event so secondaries pick up refreshed
	// signatures. Serial keeps tracking the unsigned file for change
	// detection.
	PublishedSerial uint32    `json:"published_serial,omitempty"`
	LastSigned      time.Time `json:"last_signed"`
	// SourceModTime/SourceSize are the unsigned zone file's mtime and size
	// captured at PARSE time. They are the change-detection reference (NeedsSign
	// compares against these, not LastSigned): stamping the reference at parse
	// time means an edit that lands between parse and completion is still
	// detected next cycle, and it survives across LastSigned being set later
	// (R-022). Omitempty + absent-tolerant for state.json back-compat.
	SourceModTime time.Time `json:"source_mtime,omitempty"`
	SourceSize    int64     `json:"source_size,omitempty"`
	SignaturesExp time.Time `json:"signatures_expire"`
	// PublishedDNSKEYTTL is the TTL (seconds) of the DNSKEY RRset actually
	// published at the last sign. Rollover phase gating uses it so the cache-safe
	// wait matches what resolvers hold, even when dnskey_ttl = 0 and signing used
	// the (possibly larger) SOA TTL (R-006). Absent in old state (0) → callers fall
	// back to a conservative floor. Not decreased while a rollover is active.
	PublishedDNSKEYTTL uint32 `json:"published_dnskey_ttl,omitempty"`
	// PublishedMaxRRSIGTTL is the largest TTL (seconds) of any RRset signed at the
	// last sign. A data RRSIG inherits its RRset's TTL, so an old-ZSK signature can
	// remain cached this long — longer than the DNSKEY RRset. ZSK retirement waits
	// max(DNSKEY-TTL, this) so the old ZSK is not dropped while a cached
	// signature by it is still verifiable (R-007). Not decreased during a rollover.
	PublishedMaxRRSIGTTL uint32         `json:"published_max_rrsig_ttl,omitempty"`
	KSK                  *KeyState      `json:"ksk,omitempty"`
	ZSK                  *KeyState      `json:"zsk,omitempty"`
	Rollover             *RolloverState `json:"rollover,omitempty"`
	Warnings             []string       `json:"warnings,omitempty"`
	Errors               []string       `json:"errors,omitempty"`
	// ForceResign is set whenever a rollover transition changes which keys
	// must be published or used for signing, and cleared on the next
	// successful sign. It replaces the old "re-sign every cycle while a
	// rollover is in progress" behavior, which churned signatures (and
	// fired the post-sign hook) every poll interval for the days a KSK
	// rollover sits in ds_add_wait.
	ForceResign bool `json:"force_resign,omitempty"`
}

// clone returns a deep copy of the zone state. Readers outside the signing
// goroutine must work on a clone taken under the state lock — handing out
// the live pointer lets JSON encoders race against in-place mutation.
func (z *ZoneState) clone() *ZoneState {
	if z == nil {
		return nil
	}
	c := *z
	c.KSK = z.KSK.clone()
	c.ZSK = z.ZSK.clone()
	if z.Rollover != nil {
		r := *z.Rollover
		c.Rollover = &r
	}
	if z.Warnings != nil {
		c.Warnings = append([]string(nil), z.Warnings...)
	}
	if z.Errors != nil {
		c.Errors = append([]string(nil), z.Errors...)
	}
	return &c
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

// clone returns a copy of the key state (nil-safe).
func (k *KeyState) clone() *KeyState {
	if k == nil {
		return nil
	}
	c := *k
	return &c
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
	// PhaseStarted marks when the current phase began (set on the ZSK
	// pre_publish→signing transition). Zero on old state files / at rollover
	// start; callers fall back to Started. Used to gate ZSK phase transitions on
	// actual per-phase dwell time, not wall-time-since-start (R-011).
	PhaseStarted time.Time `json:"phase_started,omitempty"`
	// PhaseFirstSigned records the first LastSigned observed after the current
	// phase began — when the phase's DNSKEY RRset was first published. The
	// DNSKEY-TTL floor gate measures from here rather than from the most recent
	// sign: a zone re-signed more often than the floor (e.g. an hourly-edited
	// dynamic zone against the default 24h floor) would otherwise never satisfy
	// the gate and the rollover would stall in pre_publish/signing forever.
	// Zero on old state files and at each phase start; stamped on the first
	// rollover check that sees the phase signed (at most one poll interval
	// late), and reset on the pre_publish→signing transition.
	PhaseFirstSigned time.Time `json:"phase_first_signed,omitempty"`
	Action           string    `json:"action"` // Human-readable next step
}

// ZSK rollover states (automatic)
const (
	ZSKRolloverStateActive     = "active"      // Normal operation
	ZSKRolloverStatePrePublish = "pre_publish" // New ZSK published, old still signing
	ZSKRolloverStateSigning    = "signing"     // New ZSK signing, old still published
	ZSKRolloverStateRetired    = "retired"     // Old ZSK removed
)

// KSK rollover states (semi-automatic). There is no ds_remove_wait phase: once
// the operator confirms the new DS is live, `rollover complete` clears the
// rollover and the next sign drops the old KSK in one step.
const (
	KSKRolloverStateActive    = "active"      // Normal operation
	KSKRolloverStateDSAddWait = "ds_add_wait" // Waiting for new DS at registrar
	KSKRolloverStateComplete  = "complete"    // Rollover finished
)

// Algorithm rollover states (manual, requires DS update). Same single-step
// completion as KSK — no separate ds_remove_wait phase.
const (
	AlgoRolloverStateDSAddWait = "algo_ds_add_wait" // New algorithm keys published, waiting for DS
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

// ReloadFromDisk reloads the state from disk, merging any new zones added by CLI commands.
// This preserves zones added by CLI while keeping daemon's in-memory updates for managed zones.
func (s *State) ReloadFromDisk() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		// No state file yet, nothing to merge
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading state file: %w", err)
	}

	diskState := &State{Zones: make(map[string]*ZoneState)}
	if err := json.Unmarshal(data, diskState); err != nil {
		return fmt.Errorf("parsing state file: %w", err)
	}

	// Merge zones from disk:
	// - Add zones that only exist on disk (CLI additions via "add" command)
	// - Update zones where disk has a more recent signing (CLI "resign"/"sign"
	//   ran while daemon was running — adopt the fresher state so the daemon
	//   doesn't overwrite it with stale in-memory data on next Save)
	for domain, diskZone := range diskState.Zones {
		memZone, exists := s.Zones[domain]
		switch {
		case !exists:
			s.Zones[domain] = diskZone
		case diskZone.LastSigned.After(memZone.LastSigned):
			s.Zones[domain] = diskZone
		case !rolloverEqual(diskZone.Rollover, memZone.Rollover) && !diskZone.LastSigned.Before(memZone.LastSigned):
			// A CLI `rollover start/complete` mutated the rollover state without a newer
			// LastSigned; adopt it so the daemon's Save doesn't revert the rollover while
			// the key files on disk are already rotated (R-007).
			s.Zones[domain] = diskZone
		}
	}

	return nil
}

// rolloverEqual reports whether two rollover states are equivalent for merge purposes.
func rolloverEqual(a, b *RolloverState) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Type == b.Type && a.State == b.State &&
		a.OldKeyID == b.OldKeyID && a.NewKeyID == b.NewKeyID &&
		a.OldZSKID == b.OldZSKID && a.NewZSKID == b.NewZSKID
}

// Save persists the state to disk
func (s *State) Save() error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling state: %w", err)
	}

	// Write via a UNIQUE temp file, fsync, then rename for atomicity and durability. A
	// fixed "state.json.tmp" is shared by the daemon and any concurrent mutating CLI
	// command; concurrent Saves to the same temp corrupt or lose state (R-002). The atomic
	// helper preserves the target directory's uid/gid so `dnssec-tudor add` run as root
	// leaves a state.json the daemon user can still read, and fsyncs so a crash/power loss
	// can't leave a truncated file (R-040).
	if err := fsutil.WriteFileAtomicOwned(s.path, data, 0600); err != nil {
		return fmt.Errorf("writing state file: %w", err)
	}

	return nil
}

// GetZone returns the state for a zone, or nil if not found.
//
// Concurrency contract: the returned pointer may only be mutated from the
// signing goroutine (single writer), and every mutation must be wrapped in
// Mutate (or UpdateZone) so it happens under the state write lock. Read-only
// consumers on other goroutines (web handlers, validators) must use
// GetZoneCopy or ToStatusOutput, which take the read lock and deep-copy.
func (s *State) GetZone(domain string) *ZoneState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Zones[domain]
}

// ZoneNames returns the raw zone-name keys currently in state (RLock-protected).
// Used for canonical-identity conflict checks (R-029).
func (s *State) ZoneNames() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	names := make([]string, 0, len(s.Zones))
	for name := range s.Zones {
		names = append(names, name)
	}
	return names
}

// GetZoneCopy returns a deep copy of a zone's state, or nil if not found.
// Safe to read and serialize from any goroutine.
func (s *State) GetZoneCopy(domain string) *ZoneState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Zones[domain].clone()
}

// Mutate runs fn while holding the state write lock. The signing goroutine
// and the rollover manager mutate ZoneState fields through pointers obtained
// from GetZone; bracketing those writes here is what makes the deep-copying
// readers (GetZoneCopy, ToStatusOutput) actually race-free. fn must not call
// other State methods — that would self-deadlock.
func (s *State) Mutate(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn()
}

// UpdateZone applies a mutation function to a zone under the state write lock.
// This is the preferred method when the caller needs atomic read-modify-write.
func (s *State) UpdateZone(domain string, fn func(*ZoneState)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if zone, ok := s.Zones[domain]; ok {
		fn(zone)
	}
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

// Status returns the overall status for a zone.
//
// ZSK rollovers are fully automatic (pre-publish, no registrar interaction),
// so they do not count as action_required — flagging them paged operators
// for routine maintenance every 90 days. The rollover details stay visible
// in the status JSON either way.
func (z *ZoneState) Status() string {
	if len(z.Errors) > 0 {
		return "error"
	}
	if z.Rollover != nil && z.Rollover.State != "" && z.Rollover.Type != "zsk" {
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
	Status          string            `json:"status"`
	Serial          uint32            `json:"serial,omitempty"`
	PublishedSerial uint32            `json:"published_serial,omitempty"`
	LastSigned      time.Time         `json:"last_signed,omitempty"`
	SignaturesExp   time.Time         `json:"signatures_expire,omitempty"`
	KSK             *KeyState         `json:"ksk,omitempty"`
	ZSK             *KeyState         `json:"zsk,omitempty"`
	Rollover        *RolloverState    `json:"rollover,omitempty"`
	Warnings        []string          `json:"warnings,omitempty"`
	Errors          []string          `json:"errors,omitempty"`
	Validation      *ValidationResult `json:"validation,omitempty"`
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
		// Deep-copy so callers (web handlers, health checks) never hold
		// references into live state the signing goroutine mutates.
		zc := zone.clone()
		output.Zones[domain] = &ZoneStatusOutput{
			Status:          status,
			Serial:          zc.Serial,
			PublishedSerial: zc.PublishedSerial,
			LastSigned:      zc.LastSigned,
			SignaturesExp:   zc.SignaturesExp,
			KSK:             zc.KSK,
			ZSK:             zc.ZSK,
			Rollover:        zc.Rollover,
			Warnings:        zc.Warnings,
			Errors:          zc.Errors,
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

// ClearWarnings removes all warnings from a zone.
func (z *ZoneState) ClearWarnings() {
	z.Warnings = nil
}

// stickyWarningPrefix marks a warning that a routine signer/rollover operation
// must NOT clear — currently the registrar-critical "URGENT:" notices (e.g. a
// registrar replacement that left the parent with ZERO DS). Such a warning
// describes an external condition a successful sign does not resolve, and must
// survive until the specific operation that fixes it clears it (R-017).
const stickyWarningPrefix = "URGENT:"

// ClearTransientWarnings removes only the signer-owned (transient) warnings —
// expiry/rollover notices a successful sign or rollover completion actually
// refreshes — while preserving sticky (registrar-critical) warnings (R-017).
func (z *ZoneState) ClearTransientWarnings() {
	if len(z.Warnings) == 0 {
		return
	}
	kept := z.Warnings[:0:0]
	for _, w := range z.Warnings {
		if strings.HasPrefix(w, stickyWarningPrefix) {
			kept = append(kept, w)
		}
	}
	z.Warnings = kept
}

// ClearStickyWarnings removes the sticky (registrar-critical) warnings. Callers
// invoke this only after the resolving operation succeeds — e.g. a registrar
// read-back confirms the expected nonempty DS set (R-017).
func (z *ZoneState) ClearStickyWarnings() {
	if len(z.Warnings) == 0 {
		return
	}
	kept := z.Warnings[:0:0]
	for _, w := range z.Warnings {
		if !strings.HasPrefix(w, stickyWarningPrefix) {
			kept = append(kept, w)
		}
	}
	z.Warnings = kept
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
