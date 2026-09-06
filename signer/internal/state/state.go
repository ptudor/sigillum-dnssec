package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/ptudor/sigillum-dnssec/signer/internal/fsutil"
)

// ErrStateFileMissing is returned by ReloadFromDisk when the state file that
// existed at the last successful load is gone. A missing file is not an
// empty update: the daemon fails the cycle closed and the operator recovers
// explicitly (restore the file, or restart the daemon to rebuild state from
// the key files on disk) (RA6X-026).
var ErrStateFileMissing = errors.New("state file is missing")

// State represents the daemon's persistent state
type State struct {
	mu    sync.RWMutex
	path  string
	Zones map[string]*ZoneState `json:"zones"`
	// Removed holds deletion markers: zones a CLI `remove` took out of
	// management, keyed by zone name with the removal time. A daemon whose
	// in-memory configuration predates the removal must not re-initialize
	// such a zone from that stale configuration (RA6X-025); the marker is
	// cleared when the zone is added again, or when a configuration loaded
	// after the removal still lists the zone (the operator re-added it).
	Removed map[string]time.Time `json:"removed,omitempty"`
	// fileSeen records that the state file existed at the last successful
	// load or save, so a later disappearance is detected (RA6X-026).
	fileSeen bool
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
	PublishedMaxRRSIGTTL uint32 `json:"published_max_rrsig_ttl,omitempty"`
	// Publication tracking (RA6X-004). LastSigned only means the output file
	// was written; these record whether and when that generation was confirmed
	// served (hook success, an authoritative probe, or the immediate-mode
	// assumption). Rollover phase timers start from PublishedAt.
	PendingPublication          bool      `json:"pending_publication,omitempty"`
	PublishedAt                 time.Time `json:"published_at,omitempty"`
	PublishedGenerationSignedAt time.Time `json:"published_generation_signed_at,omitempty"`
	// ServedDNSKEYTTL/ServedMaxRRSIGTTL are the TTLs of the confirmed
	// generation; DNSKEYCacheHorizon/RRSIGCacheHorizon are the latest times a
	// resolver may still hold an earlier generation's DNSKEY RRset or data
	// signatures (RA6X-027): raised on every confirmation to
	// confirmation time + the previous generation's TTL, never lowered, so a
	// TTL decrease before a rollover cannot shorten the safety wait.
	ServedDNSKEYTTL    uint32         `json:"served_dnskey_ttl,omitempty"`
	ServedMaxRRSIGTTL  uint32         `json:"served_max_rrsig_ttl,omitempty"`
	DNSKEYCacheHorizon time.Time      `json:"dnskey_cache_horizon,omitempty"`
	RRSIGCacheHorizon  time.Time      `json:"rrsig_cache_horizon,omitempty"`
	KSK                *KeyState      `json:"ksk,omitempty"`
	ZSK                *KeyState      `json:"zsk,omitempty"`
	Rollover           *RolloverState `json:"rollover,omitempty"`
	Warnings           []string       `json:"warnings,omitempty"`
	Errors             []string       `json:"errors,omitempty"`
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
func (z *ZoneState) Clone() *ZoneState {
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
	// PhaseHorizon is the cache horizon snapshotted when the phase's key set
	// was first confirmed published (RA6X-027): the phase may advance only
	// after it, and later re-signs of the same set do not move it.
	PhaseHorizon time.Time `json:"phase_horizon,omitempty"`
	// KSK/algorithm retirement gates (RA6X-003): when the new DS was seen at
	// every parent server, the parent's DS TTL, and when the old DS was seen
	// gone at every parent server (algorithm rollover). Retirement of the key
	// the old DS set authenticated waits ParentDSTTL after the observation.
	DSObservedAt   time.Time `json:"ds_observed_at,omitempty"`
	ParentDSTTL    uint32    `json:"parent_ds_ttl,omitempty"`
	OldDSRemovedAt time.Time `json:"old_ds_removed_at,omitempty"`
	Action         string    `json:"action"` // Human-readable next step
}

// ConfirmPublication records that the generation signed at signedAt is
// confirmed served as of now (RA6X-004) and raises the cache horizons
// (RA6X-027): resolvers may hold the previously served generation until
// now + its TTL. A confirmation for a generation older than the one already
// confirmed is ignored.
func (z *ZoneState) ConfirmPublication(signedAt, now time.Time) {
	if signedAt.Before(z.PublishedGenerationSignedAt) {
		return
	}
	prevDNSKEY, prevRRSIG := z.ServedDNSKEYTTL, z.ServedMaxRRSIGTTL
	if prevDNSKEY == 0 {
		prevDNSKEY = z.PublishedDNSKEYTTL
	}
	if prevRRSIG == 0 {
		prevRRSIG = z.PublishedMaxRRSIGTTL
	}
	if h := now.Add(time.Duration(prevDNSKEY) * time.Second); h.After(z.DNSKEYCacheHorizon) {
		z.DNSKEYCacheHorizon = h
	}
	if h := now.Add(time.Duration(prevRRSIG) * time.Second); h.After(z.RRSIGCacheHorizon) {
		z.RRSIGCacheHorizon = h
	}
	z.ServedDNSKEYTTL = z.PublishedDNSKEYTTL
	z.ServedMaxRRSIGTTL = z.PublishedMaxRRSIGTTL
	z.PublishedAt = now
	z.PublishedGenerationSignedAt = signedAt
	if !z.LastSigned.After(signedAt) {
		z.PendingPublication = false
	}
}

// PublishedSince reports whether a generation signed after t has been
// confirmed served.
func (z *ZoneState) PublishedSince(t time.Time) bool {
	return z.PublishedGenerationSignedAt.After(t)
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
	// KSKRolloverStateDSPropagation: the new DS was seen at every parent
	// server; both KSKs stay published until the parent's DS TTL has elapsed
	// so no resolver still holds an old-only DS set (RA6X-003).
	KSKRolloverStateDSPropagation = "ds_propagation_wait"
	// KSKRolloverStateRetiring: the old KSK has been dropped from the zone;
	// the rollover ends once that generation is confirmed served.
	KSKRolloverStateRetiring = "retiring"
	KSKRolloverStateComplete = "complete" // Rollover finished
)

// Algorithm rollover states (manual, requires DS update). Same single-step
// completion as KSK — no separate ds_remove_wait phase.
const (
	AlgoRolloverStateDSAddWait = "algo_ds_add_wait" // New algorithm keys published, waiting for DS
	// AlgoRolloverStateDSPropagation: the new-algorithm DS was seen at every
	// parent server; wait the parent's DS TTL (RFC 6781 §4.1.4, RA6X-003).
	AlgoRolloverStateDSPropagation = "algo_ds_propagation_wait"
	// AlgoRolloverStateOldDSRemoval: the old-algorithm DS must disappear from
	// every parent server, then the parent's DS TTL must elapse, before the
	// old-algorithm keys and signatures may be dropped.
	AlgoRolloverStateOldDSRemoval = "algo_old_ds_removal_wait"
	// AlgoRolloverStateRetiring: the old-algorithm keys are gone from the
	// zone; the rollover ends once that generation is confirmed served.
	AlgoRolloverStateRetiring = "algo_retiring"
)

// NewState creates a new empty state
func NewState(path string) *State {
	return &State{
		path:  path,
		Zones: make(map[string]*ZoneState),
	}
}

// LoadState loads state from a JSON file. The document is validated and
// normalized before it is exposed (RA6X-036): a missing/null zone map becomes
// an empty map, while null zone entries, invalid names or paths, unsupported
// rollover type/phase combinations and inconsistent key identities are
// rejected with an actionable error. The file is never rewritten on failure.
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
	if err := state.validateAndNormalize(); err != nil {
		return nil, fmt.Errorf("state file %s is invalid (left unchanged): %w", path, err)
	}
	state.fileSeen = true

	return state, nil
}

// Validate checks the in-memory state against the persistence schema rules
// LoadState enforces (RA6X-036) and normalizes a nil zone map to an empty one.
func (s *State) Validate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.validateAndNormalize()
}

// validateAndNormalize is Validate without locking (caller holds the lock or
// owns the value exclusively).
func (s *State) validateAndNormalize() error {
	if s.Zones == nil {
		// {"zones": null} — explicitly allowed as "no zones" (RA6X-036).
		s.Zones = make(map[string]*ZoneState)
	}
	if s.Removed == nil {
		s.Removed = make(map[string]time.Time)
	}
	for name := range s.Removed {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("removal marker with an empty zone name")
		}
	}
	for name, zone := range s.Zones {
		if err := validateZoneEntry(name, zone); err != nil {
			return err
		}
	}
	return nil
}

// validateZoneEntry checks one persisted zone entry.
func validateZoneEntry(name string, z *ZoneState) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("zone entry with an empty name")
	}
	if _, ok := dns.IsDomainName(name); !ok {
		return fmt.Errorf("zone %q: not a valid domain name", name)
	}
	if z == nil {
		return fmt.Errorf("zone %q: null entry", name)
	}
	if strings.ContainsRune(z.Path, 0) {
		return fmt.Errorf("zone %q: path contains a NUL byte", name)
	}
	if !z.LastSigned.IsZero() && strings.TrimSpace(z.Path) == "" {
		return fmt.Errorf("zone %q: signed zone has an empty source path", name)
	}
	if err := validateKeyState("ksk", z.KSK); err != nil {
		return fmt.Errorf("zone %q: %w", name, err)
	}
	if err := validateKeyState("zsk", z.ZSK); err != nil {
		return fmt.Errorf("zone %q: %w", name, err)
	}
	if z.Rollover != nil {
		if err := validateRolloverState(z); err != nil {
			return fmt.Errorf("zone %q: %w", name, err)
		}
	}
	return nil
}

// validateKeyState checks a persisted key record (nil is allowed: a zone whose
// key initialization has not yet succeeded is a keyless placeholder).
func validateKeyState(role string, k *KeyState) error {
	if k == nil {
		return nil
	}
	if strings.TrimSpace(k.Algorithm) == "" {
		return fmt.Errorf("%s key %d has no algorithm", role, k.ID)
	}
	return nil
}

// validateRolloverState rejects rollover records the signer has no defined
// interpretation for (RA6X-036). Only the persisted phases are accepted, and
// the key identities the record names must agree with the zone's live keys:
// during a KSK or algorithm rollover the live KSK is the new key; during a
// ZSK pre-publish the live ZSK is still the old key; during ZSK signing it is
// the new key. Anything else is ambiguous and must not be signed through.
func validateRolloverState(z *ZoneState) error {
	r := z.Rollover
	switch {
	case r.Type == "ksk" && (r.State == KSKRolloverStateDSAddWait || r.State == KSKRolloverStateDSPropagation || r.State == KSKRolloverStateRetiring):
		if r.OldKeyID == r.NewKeyID {
			return fmt.Errorf("ksk rollover names the same key %d as old and new", r.OldKeyID)
		}
		if z.KSK == nil {
			return fmt.Errorf("ksk rollover recorded but the zone has no KSK")
		}
		if z.KSK.ID != r.NewKeyID {
			return fmt.Errorf("ksk rollover: live KSK %d is neither the new key %d the rollover expects", z.KSK.ID, r.NewKeyID)
		}
	case r.Type == "zsk" && r.State == ZSKRolloverStatePrePublish:
		if r.OldKeyID == r.NewKeyID {
			return fmt.Errorf("zsk rollover names the same key %d as old and new", r.OldKeyID)
		}
		if z.ZSK == nil {
			return fmt.Errorf("zsk rollover recorded but the zone has no ZSK")
		}
		if z.ZSK.ID != r.OldKeyID {
			return fmt.Errorf("zsk pre_publish: live ZSK %d is not the old key %d still expected to sign", z.ZSK.ID, r.OldKeyID)
		}
	case r.Type == "zsk" && r.State == ZSKRolloverStateSigning:
		if r.OldKeyID == r.NewKeyID {
			return fmt.Errorf("zsk rollover names the same key %d as old and new", r.OldKeyID)
		}
		if z.ZSK == nil {
			return fmt.Errorf("zsk rollover recorded but the zone has no ZSK")
		}
		if z.ZSK.ID != r.NewKeyID {
			return fmt.Errorf("zsk signing: live ZSK %d is not the new key %d expected to sign", z.ZSK.ID, r.NewKeyID)
		}
	case r.Type == "algorithm" && (r.State == AlgoRolloverStateDSAddWait || r.State == AlgoRolloverStateDSPropagation || r.State == AlgoRolloverStateOldDSRemoval || r.State == AlgoRolloverStateRetiring):
		if r.OldKeyID == r.NewKeyID || r.OldZSKID == r.NewZSKID {
			return fmt.Errorf("algorithm rollover names the same key as old and new (ksk %d/%d, zsk %d/%d)", r.OldKeyID, r.NewKeyID, r.OldZSKID, r.NewZSKID)
		}
		if strings.TrimSpace(r.OldAlgorithm) == "" || strings.TrimSpace(r.NewAlgorithm) == "" || r.OldAlgorithm == r.NewAlgorithm {
			return fmt.Errorf("algorithm rollover has invalid algorithms (old %q, new %q)", r.OldAlgorithm, r.NewAlgorithm)
		}
		if z.KSK == nil || z.ZSK == nil {
			return fmt.Errorf("algorithm rollover recorded but the zone lacks a KSK or ZSK")
		}
		if z.KSK.ID != r.NewKeyID || z.ZSK.ID != r.NewZSKID {
			return fmt.Errorf("algorithm rollover: live keys (ksk %d, zsk %d) are not the new keys (ksk %d, zsk %d)", z.KSK.ID, z.ZSK.ID, r.NewKeyID, r.NewZSKID)
		}
	default:
		return fmt.Errorf("unsupported rollover type/state %q/%q (no defined signing behaviour; refusing to guess)", r.Type, r.State)
	}
	return nil
}

// ReplaceFromDisk adopts the on-disk state WHOLESALE: every zone and removal
// marker in memory is replaced by the validated disk document. It is the
// authoritative reload a signing cycle performs under the process lock before
// mutating anything (RA6X-025): with the lock held, the disk carries every
// mutation any CLI command committed since the daemon's last save — warnings
// added or cleared, removals, phase metadata that did not sign — and none of
// the merge heuristics of ReloadFromDisk are needed. Callers must not use it
// while unsaved in-memory results exist (see ReloadFromDisk for that case).
// A missing file that existed at the last successful load/save is
// ErrStateFileMissing; an invalid document leaves memory untouched.
func (s *State) ReplaceFromDisk() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		if s.fileSeen {
			return fmt.Errorf("%w: %s existed at the last successful load and is gone; restore it, or restart the daemon to rebuild state from the key files if the removal was intentional", ErrStateFileMissing, s.path)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading state file: %w", err)
	}
	diskState := &State{Zones: make(map[string]*ZoneState)}
	if err := json.Unmarshal(data, diskState); err != nil {
		return fmt.Errorf("parsing state file: %w", err)
	}
	if err := diskState.validateAndNormalize(); err != nil {
		return fmt.Errorf("state file %s is invalid (left unchanged, in-memory state not replaced): %w", s.path, err)
	}
	s.Zones = diskState.Zones
	s.Removed = diskState.Removed
	s.fileSeen = true
	return nil
}

// MarkRemoved takes a zone out of management and records a deletion marker so
// a daemon holding a configuration that predates the removal does not
// re-create the zone from it (RA6X-025).
func (s *State) MarkRemoved(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Zones, domain)
	if s.Removed == nil {
		s.Removed = make(map[string]time.Time)
	}
	s.Removed[domain] = time.Now().UTC()
}

// ClearRemoved drops the deletion marker for a zone that is being managed again.
// RestoreRemoved re-establishes a removal marker with its original timestamp,
// undoing a ClearRemoved from a transaction that did not commit.
func (s *State) RestoreRemoved(domain string, at time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Removed == nil {
		s.Removed = make(map[string]time.Time)
	}
	s.Removed[domain] = at
}

func (s *State) ClearRemoved(domain string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Removed, domain)
}

// RemovedAt returns when a zone was removed by a CLI command, if a deletion
// marker exists for it.
func (s *State) RemovedAt(domain string) (time.Time, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.Removed[domain]
	return t, ok
}

// ReloadFromDisk reloads the state from disk, merging any new zones added by CLI commands.
// This preserves zones added by CLI while keeping daemon's in-memory updates for managed zones.
//
// The disk document is validated before anything is merged (RA6X-036); an
// unreadable or invalid file leaves the in-memory state untouched and returns
// an error the caller must treat as fail-closed (RA6X-026). A file that
// existed at the last successful load/save and is now missing returns
// ErrStateFileMissing rather than being treated as an empty update.
func (s *State) ReloadFromDisk() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		if s.fileSeen {
			return fmt.Errorf("%w: %s existed at the last successful load and is gone; restore it, or restart the daemon to rebuild state from the key files if the removal was intentional", ErrStateFileMissing, s.path)
		}
		// Never existed yet: a fresh start, nothing to merge.
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading state file: %w", err)
	}

	diskState := &State{Zones: make(map[string]*ZoneState)}
	if err := json.Unmarshal(data, diskState); err != nil {
		return fmt.Errorf("parsing state file: %w", err)
	}
	if err := diskState.validateAndNormalize(); err != nil {
		return fmt.Errorf("state file %s is invalid (left unchanged, in-memory state not merged): %w", s.path, err)
	}
	s.fileSeen = true

	// Deletion markers (RA6X-025): adopt the disk's markers, and drop a
	// marker for any zone that has since been re-added on disk. A zone the
	// disk no longer holds but memory does, with a disk marker newer than
	// memory's last signing, was removed by a CLI command: drop it.
	if s.Removed == nil {
		s.Removed = make(map[string]time.Time)
	}
	for domain, at := range diskState.Removed {
		if _, onDisk := diskState.Zones[domain]; onDisk {
			continue
		}
		if memZone, exists := s.Zones[domain]; exists {
			if memZone.LastSigned.After(at) {
				// Re-added and signed after the removal: the disk marker is stale.
				delete(s.Removed, domain)
				continue
			}
			delete(s.Zones, domain)
		}
		s.Removed[domain] = at
	}
	for domain := range s.Removed {
		if _, onDisk := diskState.Zones[domain]; onDisk {
			delete(s.Removed, domain)
		}
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
	s.markFileSeen()

	return nil
}

// markFileSeen records that the state file now exists on disk. Save holds the
// read lock, so the flag is set under its own short write lock afterwards.
func (s *State) markFileSeen() {
	s.mu.RUnlock()
	s.mu.Lock()
	s.fileSeen = true
	s.mu.Unlock()
	s.mu.RLock()
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
	return s.Zones[domain].Clone()
}

// Mutate runs fn while holding the state write lock. The signing goroutine
// and the rollover manager mutate ZoneState fields through pointers obtained
// from GetZone; bracketing those writes here is what makes the deep-copying
// readers (GetZoneCopy, SnapshotZones) actually race-free. fn must not call
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

// SetPath overrides the filesystem path this State persists to on Save.
// Production code sets the path once via NewState/LoadState; this lets a
// caller (notably the save-failure rollback tests) retarget a populated State
// at a different — possibly unwritable — location.
func (s *State) SetPath(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path
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
		if z.Rollover.NeedsOperator() {
			return "action_required"
		}
		return "warning" // an automatic safety wait is in progress
	}
	if len(z.Warnings) > 0 {
		return "warning"
	}
	return "healthy"
}

// NeedsOperator reports whether the rollover phase waits on an operator (a
// DS change at the registrar) rather than on an automatic timer or probe.
func (r *RolloverState) NeedsOperator() bool {
	switch r.State {
	case KSKRolloverStateDSAddWait, AlgoRolloverStateDSAddWait, AlgoRolloverStateOldDSRemoval:
		return true
	}
	return false
}

// SnapshotZones returns a deep-copied, point-in-time view of every zone's
// state under a single read lock, so a status reader never tears across the
// signing goroutine's concurrent mutations. Keys are zone names; values are
// clones safe to read and serialize from any goroutine. The presentation
// layer (the status/output DTOs) lives in the root package, above both state
// and the validator, and builds its output from this snapshot.
func (s *State) SnapshotZones() map[string]*ZoneState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]*ZoneState, len(s.Zones))
	for domain, zone := range s.Zones {
		out[domain] = zone.Clone()
	}
	return out
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

// Operation-scoped errors (RA6X-048). Every error a zone carries names the
// operation that produced it ("signing", "rollover", "init", "deployment"),
// so a successful repair of one operation clears exactly that operation's
// error and leaves the others — a registrar or deployment problem must not
// vanish because a later sign succeeded. The JSON shape is unchanged: errors
// stay strings, prefixed "<operation>: ".
const (
	OpSigning    = "signing"
	OpRollover   = "rollover"
	OpInit       = "init"
	OpDeployment = "deployment"
	OpRegistrar  = "registrar"
)

// SetOperationError records the current failure of one operation, replacing
// any earlier error of the same operation.
func (z *ZoneState) SetOperationError(op, msg string) {
	z.ClearOperationError(op)
	z.Errors = append(z.Errors, op+": "+msg)
}

// ClearOperationError removes the error recorded for one operation, if any.
func (z *ZoneState) ClearOperationError(op string) {
	if len(z.Errors) == 0 {
		return
	}
	kept := z.Errors[:0:0]
	for _, e := range z.Errors {
		if !strings.HasPrefix(e, op+": ") {
			kept = append(kept, e)
		}
	}
	z.Errors = kept
}

// HasOperationError reports whether an error is recorded for the operation.
func (z *ZoneState) HasOperationError(op string) bool {
	for _, e := range z.Errors {
		if strings.HasPrefix(e, op+": ") {
			return true
		}
	}
	return false
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
