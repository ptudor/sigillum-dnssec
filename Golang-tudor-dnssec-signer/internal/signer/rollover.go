package signer

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/ptudor/dnssec-tudor/internal/fsutil"
	"github.com/ptudor/dnssec-tudor/internal/metrics"
	statepkg "github.com/ptudor/dnssec-tudor/internal/state"

	"github.com/ptudor/dnssec-tudor/internal/config"
)

// ParentDSObservation is what a probe of every authoritative server of the
// parent zone reports about a set of KSKs' DS records (RA6X-003).
type ParentDSObservation struct {
	// PresentOnAll and AbsentOnAll are keyed by KSK key tag: the DS for that
	// key was seen on every parent server / on none of them.
	PresentOnAll map[uint16]bool
	AbsentOnAll  map[uint16]bool
	// TTL is the largest DS RRset TTL any parent server returned (0 if none).
	TTL uint32
	// Servers lists the parent servers that answered.
	Servers []string
}

// ParentDSProbe queries every authoritative server of the parent zone for the
// DS records of the given KSKs. The signer package cannot import the
// validator (import cycle), so the daemon and CLI inject one.
type ParentDSProbe interface {
	ProbeParentDS(domain string, ksks []*dns.DNSKEY) (ParentDSObservation, error)
}

// RolloverManager handles key rollover operations
type RolloverManager struct {
	cfg   *config.Config
	state *statepkg.State
	// probe answers parent-DS questions for automatic KSK/algorithm phase
	// advancement; nil means those phases wait until one is provided.
	probe ParentDSProbe
	// failpoint is a test-only fault-injection seam propagated to the key
	// generator's transaction steps (see keytx.go); nil in production.
	failpoint func(step string) error
}

// SetParentDSProbe installs the parent-DS probe used by CheckAlgorithmRollover.
func (rm *RolloverManager) SetParentDSProbe(p ParentDSProbe) { rm.probe = p }

// keyGen returns a KeyGenerator sharing this manager's fault-injection seam.
func (rm *RolloverManager) keyGen() *KeyGenerator {
	kg := NewKeyGenerator(rm.cfg)
	kg.failpoint = rm.failpoint
	return kg
}

// NewRolloverManager creates a new rollover manager
func NewRolloverManager(cfg *config.Config, state *statepkg.State) *RolloverManager {
	return &RolloverManager{
		cfg:   cfg,
		state: state,
	}
}

// StartKSKRollover begins a KSK rollover for a domain.
//
// The rollover is one recoverable transaction (RA6X-002): the old KSK's
// tag-named backup is verified first (RA6X-023), the replacement is staged and
// verified at its own tag-named slot without touching the live pair, the
// rollover record naming both generations is saved durably, and only then is
// the new pair activated over the live slot. A failure before the save leaves
// the old generation live with no record; a failure or crash after it is
// repaired deterministically by the next signing run, which re-activates the
// recorded generation from its tag-named copy.
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

	keyGen := rm.keyGen()

	// A verified backup of the old KSK is required before anything else (R-027,
	// RA6X-023): the rollover-signing path and DS recovery both load it by ID.
	if err := rm.BackupKey(domain, "ksk", oldKSK.ID); err != nil {
		return fmt.Errorf("backing up old KSK before rollover: %w", err)
	}

	// Stage the replacement with the EXISTING KSK's algorithm (RA6X-001), not
	// the current config default: an ordinary KSK rollover must never change
	// the zone's algorithm, or the retired old KSK leaves data signed only by
	// the old-algorithm ZSK behind a new-algorithm DS (RFC 6840 §5.11). Only
	// the explicit `rollover algorithm` flow introduces another algorithm. The
	// live pair is untouched until the record below is on disk.
	newKSK, err := keyGen.StageKSK(domain, oldKSK.Algorithm)
	if err != nil {
		return fmt.Errorf("generating new KSK: %w", err)
	}

	rm.state.Mutate(func() {
		zoneState.Rollover = &statepkg.RolloverState{
			Type:     "ksk",
			State:    statepkg.KSKRolloverStateDSAddWait,
			OldKeyID: oldKSK.ID,
			NewKeyID: newKSK.ID,
			Started:  time.Now().UTC(),
			Action:   fmt.Sprintf("Publish new DS record at registrar, then run: dnssec-tudor rollover complete %s", domain),
		}

		// Update KSK in state (zone will now be signed with both during rollover)
		zoneState.KSK = newKSK
		zoneState.ForceResign = true
	})

	metrics.RecordRolloverOperation(domain, "ksk", "start")
	if err := rm.state.Save(); err != nil {
		if !fsutil.IsCommitted(err) {
			// Nothing live has changed. Drop the in-memory record; the staged
			// pair stays on disk (key material is never deleted) and is reused
			// by a retry, since it is keyed by tag.
			rm.state.Mutate(func() {
				zoneState.KSK = oldKSK
				zoneState.Rollover = nil
				zoneState.ForceResign = false
			})
			return fmt.Errorf("saving KSK rollover state (no live key was changed; staged key %d left at %s): %w",
				newKSK.ID, keyGen.taggedBase(domain, "ksk", newKSK.ID), err)
		}
		// The rollover record IS on disk; only its durability is uncertain
		// (RA6X-049). Continue with activation against the visible record.
		slog.Warn("[ROLLOVER] rollover state saved but its durability across power loss is uncertain", "domain", domain, "error", err)
	}

	return rm.activateRecorded(domain, keyGen, "ksk", newKSK.ID)
}

// activateRecorded activates a generation the persisted state already names as
// live. A failure here leaves the record in place: the next signing run
// re-activates the tag-named copy (EnsureLiveKey), so the operator is told to
// sign rather than to retry the rollover.
func (rm *RolloverManager) activateRecorded(domain string, keyGen *KeyGenerator, keyType string, tag uint16) error {
	if err := keyGen.ActivateKeyPair(domain, keyType, tag); err != nil {
		return fmt.Errorf("activating new %s %d (the rollover is recorded; run `dnssec-tudor sign` to retry activation from %s): %w",
			strings.ToUpper(keyType), tag, keyGen.taggedBase(domain, keyType, tag), err)
	}
	return nil
}

// CompleteKSKRollover moves a KSK rollover from ds_add_wait into the DS
// propagation wait (RA6X-003): the caller has established that the new KSK's
// DS is present at every parent server (dsObservedAt) and knows the parent's
// DS TTL (parentDSTTL, seconds; the configured fallback when unobservable).
// Both KSKs keep signing until CheckKSKRollover retires the old one after
// that TTL — a resolver that fetched the old-only DS set just before the new
// DS appeared holds it that long, and would go bogus if the old KSK vanished
// from the DNSKEY RRset earlier. The old DS may be removed at the parent at
// any time from here on.
func (rm *RolloverManager) CompleteKSKRollover(domain string, dsObservedAt time.Time, parentDSTTL uint32) error {
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

	if zoneState.Rollover.State != statepkg.KSKRolloverStateDSAddWait {
		return fmt.Errorf("rollover not in ds_add_wait state (currently %s; retirement is automatic from here)", zoneState.Rollover.State)
	}
	if parentDSTTL == 0 {
		parentDSTTL = uint32(rm.cfg.ParentDSTTLFallback() / time.Second)
	}

	slog.Info("[ROLLOVER] KSK rollover: new DS present at the parent; waiting out the parent DS TTL before retiring the old KSK",
		"domain", domain,
		"old_key_id", zoneState.Rollover.OldKeyID,
		"new_key_id", zoneState.Rollover.NewKeyID,
		"retire_after", dsObservedAt.Add(time.Duration(parentDSTTL)*time.Second).Format(time.RFC3339))

	rm.state.Mutate(func() {
		r := zoneState.Rollover
		r.State = statepkg.KSKRolloverStateDSPropagation
		r.DSObservedAt = dsObservedAt.UTC()
		r.ParentDSTTL = parentDSTTL
		r.PhaseStarted = time.Now().UTC()
		r.Action = fmt.Sprintf("Automatic: both KSKs stay published until %s (parent DS TTL), then the old KSK is retired; the OLD DS may be removed at the registrar now",
			r.DSObservedAt.Add(time.Duration(parentDSTTL)*time.Second).Format(time.RFC3339))
		zoneState.ClearTransientWarnings()
	})
	metrics.RecordRolloverOperation(domain, "ksk", "ds_propagation")
	return rm.state.Save()
}

// CheckKSKRollover advances the automatic phases of a KSK rollover
// (RA6X-003): after the parent DS TTL has elapsed since the new DS was seen,
// the old KSK is dropped from the zone; once that generation is confirmed
// served (RA6X-004) the rollover is complete.
func (rm *RolloverManager) CheckKSKRollover(domain string) error {
	zoneState := rm.state.GetZone(domain)
	if zoneState == nil || zoneState.Rollover == nil || zoneState.Rollover.Type != "ksk" {
		return nil
	}
	r := zoneState.Rollover
	now := time.Now().UTC()
	switch r.State {
	case statepkg.KSKRolloverStateDSPropagation:
		retireAt := r.DSObservedAt.Add(time.Duration(r.ParentDSTTL) * time.Second)
		if now.Before(retireAt) {
			return nil
		}
		slog.Info("[ROLLOVER] KSK rollover: parent DS TTL elapsed; retiring the old KSK", "domain", domain, "old_key_id", r.OldKeyID)
		rm.state.Mutate(func() {
			r.State = statepkg.KSKRolloverStateRetiring
			r.PhaseStarted = now
			r.Action = "Automatic: old KSK removed from the zone; the rollover ends once that zone is confirmed served"
			zoneState.ForceResign = true
		})
		return rm.state.Save()
	case statepkg.KSKRolloverStateRetiring:
		if !zoneState.PublishedSince(r.PhaseStarted) {
			return nil
		}
		slog.Info("[ROLLOVER] KSK rollover completed", "domain", domain,
			"note", "Old key files remain on disk for safety. You may delete them after removing the old DS from your registrar.")
		rm.state.Mutate(func() {
			zoneState.Rollover = nil
			zoneState.ClearTransientWarnings()
		})
		metrics.RecordRolloverOperation(domain, "ksk", "complete")
		return rm.state.Save()
	}
	return nil
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

func (rm *RolloverManager) startZSKRollover(domain string, zoneState *statepkg.ZoneState) error {
	// Don't start if there's already a rollover in progress
	if zoneState.Rollover != nil {
		return nil
	}

	oldZSK := zoneState.ZSK
	slog.Info("[ROLLOVER] Starting automatic ZSK rollover", "domain", domain, "old_key_id", oldZSK.ID)

	// Verified backup of the old key first (R-027, RA6X-023): the pre-publish and
	// signing phases load the old ZSK from it by ID.
	if err := rm.BackupKey(domain, "zsk", oldZSK.ID); err != nil {
		return fmt.Errorf("backing up old ZSK before rollover: %w", err)
	}

	// Stage the new ZSK with the EXISTING ZSK's algorithm, not the current
	// config default (R-039). If the operator changed [dnssec].algorithm after
	// the zone was signed, the default would mint a new ZSK in the new algorithm
	// while the KSK stays the old one — an unintended algorithm mismatch that
	// must instead go through the dedicated `rollover algorithm` flow. The live
	// pair is untouched until the record below is on disk (RA6X-002).
	keyGen := rm.keyGen()
	newZSK, err := keyGen.StageZSK(domain, oldZSK.Algorithm)
	if err != nil {
		return fmt.Errorf("generating new ZSK: %w", err)
	}

	rm.state.Mutate(func() {
		zoneState.Rollover = &statepkg.RolloverState{
			Type:     "zsk",
			State:    statepkg.ZSKRolloverStatePrePublish,
			OldKeyID: oldZSK.ID,
			NewKeyID: newZSK.ID,
			Started:  time.Now().UTC(),
			Action:   fmt.Sprintf("Automatic: new ZSK is pre-published, will switch to signing in %s", humanizeRolloverDelay(rm.cfg.DNSSEC.RolloverSwitch.Duration)),
		}
		zoneState.ForceResign = true

		// Don't update zoneState.ZSK yet - we keep signing with old key during pre-publish
	})

	metrics.RecordRolloverOperation(domain, "zsk", "start")
	if err := rm.state.Save(); err != nil {
		if !fsutil.IsCommitted(err) {
			rm.state.Mutate(func() {
				zoneState.Rollover = nil
				zoneState.ForceResign = false
			})
			return fmt.Errorf("saving ZSK rollover state (no live key was changed; staged key %d left at %s): %w",
				newZSK.ID, keyGen.taggedBase(domain, "zsk", newZSK.ID), err)
		}
		slog.Warn("[ROLLOVER] rollover state saved but its durability across power loss is uncertain", "domain", domain, "error", err)
	}

	// The live ZSK slot holds the NEW key during pre-publish (signing loads the
	// old one by ID from its tag-named copy).
	return rm.activateRecorded(domain, keyGen, "zsk", newZSK.ID)
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
// age out. It uses the DNSKEY TTL ACTUALLY published for this zone (recorded at
// sign time in zoneState.PublishedDNSKEYTTL), so a zone whose dnskey_ttl = 0 and
// whose SOA TTL exceeds 24h is not advanced early against a hardcoded floor
// (R-006). Falls back to the configured TTL, then a conservative 24h, for old
// state that predates the recorded field.
func (rm *RolloverManager) dnskeyTTLFloor(zoneState *statepkg.ZoneState) time.Duration {
	var ttl time.Duration
	if zoneState != nil && zoneState.PublishedDNSKEYTTL > 0 {
		ttl = time.Duration(zoneState.PublishedDNSKEYTTL) * time.Second
	}
	if cfgTTL := time.Duration(rm.cfg.DNSSEC.DNSKEYTtl) * time.Second; cfgTTL > ttl {
		ttl = cfgTTL
	}
	if ttl <= 0 {
		return 24 * time.Hour
	}
	return ttl
}

// zskRetireFloor is the minimum time after a ZSK's signatures were first published
// in the signing phase before the old ZSK may be dropped: the larger of the
// DNSKEY-TTL floor (R-006) and the largest signed RRset TTL (R-007), since a data
// RRSIG by the retiring key stays cached for its RRset's TTL.
func (rm *RolloverManager) zskRetireFloor(zoneState *statepkg.ZoneState) time.Duration {
	floor := rm.dnskeyTTLFloor(zoneState)
	if zoneState != nil {
		if rrsig := time.Duration(zoneState.PublishedMaxRRSIGTTL) * time.Second; rrsig > floor {
			floor = rrsig
		}
	}
	return floor
}

func (rm *RolloverManager) handleZSKRolloverState(domain string, zoneState *statepkg.ZoneState) error {
	rollover := zoneState.Rollover
	now := time.Now().UTC()

	switchDuration := rm.cfg.DNSSEC.RolloverSwitch.Duration
	prepublishDuration := rm.cfg.DNSSEC.RolloverPrepublish.Duration

	// stampPhasePublication records, once per phase, when the phase's key set
	// was first CONFIRMED served (RA6X-004) and the cache horizon the phase
	// must wait out (RA6X-027): every earlier generation's horizon plus the
	// floor after this publication. Re-signs of the same set do not move it.
	stampPhasePublication := func(floor time.Duration, horizons ...time.Time) error {
		if !rollover.PhaseFirstSigned.IsZero() {
			return nil
		}
		published := zoneState.PublishedAt
		horizon := published.Add(floor)
		for _, h := range horizons {
			if h.After(horizon) {
				horizon = h
			}
		}
		rm.state.Mutate(func() {
			rollover.PhaseFirstSigned = published
			rollover.PhaseHorizon = horizon
		})
		return rm.state.Save()
	}

	switch rollover.State {
	case statepkg.ZSKRolloverStatePrePublish:
		// Advance to "signing" only when ALL of the following hold (R-011):
		//  (1) the pre-publish phase has lasted at least the switch duration;
		//  (2) a generation signed after the phase began has been CONFIRMED
		//      served (not merely written) — else the new ZSK was never published;
		//  (3) the cache horizon has passed: every DNSKEY RRset a resolver may
		//      still hold — including earlier, longer-TTL generations — has
		//      expired, measured from the phase's first confirmed publication.
		phaseStart := rollover.Started
		if now.Sub(phaseStart) < switchDuration {
			return nil
		}
		if !zoneState.PublishedSince(phaseStart) {
			slog.Debug("[ROLLOVER] ZSK pre_publish: waiting for the pre-published key set to be confirmed served", "domain", domain)
			return nil
		}
		if err := stampPhasePublication(rm.dnskeyTTLFloor(zoneState), zoneState.DNSKEYCacheHorizon); err != nil {
			return err
		}
		if now.Before(rollover.PhaseHorizon) {
			slog.Debug("[ROLLOVER] ZSK pre_publish: waiting for cached DNSKEY RRsets to expire", "domain", domain, "until", rollover.PhaseHorizon.Format(time.RFC3339))
			return nil
		}

		slog.Info("[ROLLOVER] ZSK rollover: switching to new key", "domain", domain, "new_key_id", rollover.NewKeyID)
		newZSK, _, err := rm.keyGen().EnsureLiveKey(domain, "zsk", rollover.NewKeyID)
		if err != nil {
			return fmt.Errorf("loading new ZSK: %w", err)
		}
		rm.state.Mutate(func() {
			rollover.State = statepkg.ZSKRolloverStateSigning
			rollover.PhaseStarted = now             // gate the signing phase from here (R-011)
			rollover.PhaseFirstSigned = time.Time{} // the signing phase stamps its own first publication
			rollover.PhaseHorizon = time.Time{}
			rollover.Action = "Automatic: signing with new ZSK, old ZSK still published"
			zoneState.ZSK = &statepkg.KeyState{
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

	case statepkg.ZSKRolloverStateSigning:
		// Complete only when ALL hold (R-011): the signing phase has dwelled long
		// enough, the new ZSK's signatures were CONFIRMED served after the switch,
		// and the cache horizon has passed — no resolver still holds a DNSKEY
		// RRset or a data/denial signature by the retiring ZSK (R-007, RA6X-027).
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
		if !zoneState.PublishedSince(phaseStart) {
			slog.Debug("[ROLLOVER] ZSK signing: waiting for the new ZSK's signatures to be confirmed served", "domain", domain)
			return nil
		}
		if err := stampPhasePublication(rm.zskRetireFloor(zoneState), zoneState.DNSKEYCacheHorizon, zoneState.RRSIGCacheHorizon); err != nil {
			return err
		}
		if now.Before(rollover.PhaseHorizon) {
			slog.Debug("[ROLLOVER] ZSK signing: waiting for cached signatures by the old ZSK to expire", "domain", domain, "until", rollover.PhaseHorizon.Format(time.RFC3339))
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
		metrics.RecordRolloverOperation(domain, "zsk", "complete")
		slog.Info("[ROLLOVER] ZSK rollover completed automatically", "domain", domain)
		return rm.state.Save()
	}

	return nil
}

// BackupKey guarantees a complete, verified tag-named copy of the live key for
// the role before a rollover replaces it (RA6X-023): both halves present and
// parseable, owner/role/algorithm as expected, the private half corresponding
// to the public one, and durably written. A missing or damaged private half is
// repaired atomically from the verified live pair with the damaged file set
// aside; a slot holding a different key (tag collision) is never overwritten.
// keyID is the identity the persisted state records for the live key; a live
// pair with any other tag is refused so a rollover never backs up — and then
// replaces — a key the state does not name (RA6X-002).
func (rm *RolloverManager) BackupKey(domain, keyType string, keyID uint16) error {
	live, err := rm.keyGen().ensureVerifiedBackup(domain, keyType)
	if err != nil {
		return err
	}
	if live.KeyTag() != keyID {
		return fmt.Errorf("live %s key for %s has key tag %d but the recorded state names key %d; refusing to roll over an unrecorded key (run `dnssec-tudor sign` to reconcile first)",
			keyType, domain, live.KeyTag(), keyID)
	}
	return nil
}

// GetRolloverStatus returns the current rollover status for a domain
func (rm *RolloverManager) GetRolloverStatus(domain string) *statepkg.RolloverState {
	zoneState := rm.state.GetZone(domain)
	if zoneState == nil {
		return nil
	}
	return zoneState.Rollover
}

// StartAlgorithmRollover begins an algorithm rollover for a domain: it
// generates a new KSK and ZSK with the target algorithm and signs with both
// algorithms until completion. Both new pairs form ONE transaction (RA6X-002):
// each is staged and verified before the single rollover record naming all
// four generations is saved, and neither live pair changes before that save. A
// failure staging the ZSK after the KSK leaves the old generation live and
// unrecorded; a failure or crash after the save is repaired by the next signing
// run, which re-activates whichever recorded pair is not yet live.
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
	oldKSKState := zoneState.KSK
	oldZSKState := zoneState.ZSK

	slog.Info("[ROLLOVER] Starting algorithm rollover",
		"domain", domain,
		"old_algorithm", oldAlgorithm,
		"new_algorithm", targetAlgorithm)

	// Verified backups of both old keys first (R-027, RA6X-023): an algorithm
	// rollover must sign with both old and new algorithm keys (RFC 6840 §5.11),
	// so losing either old key would emit a zone missing signatures for a
	// signaled algorithm.
	if err := rm.BackupKey(domain, "ksk", oldKSKState.ID); err != nil {
		return fmt.Errorf("backing up old KSK before algorithm rollover: %w", err)
	}
	if err := rm.BackupKey(domain, "zsk", oldZSKState.ID); err != nil {
		return fmt.Errorf("backing up old ZSK before algorithm rollover: %w", err)
	}

	// Stage both new pairs; nothing live changes until both are verified and the
	// record is saved.
	keyGen := rm.keyGen()
	newKSK, err := keyGen.StageKSK(domain, targetAlgorithm)
	if err != nil {
		return fmt.Errorf("generating new KSK: %w", err)
	}
	newZSK, err := keyGen.StageZSK(domain, targetAlgorithm)
	if err != nil {
		return fmt.Errorf("generating new ZSK (old keys remain live; staged KSK %d left at %s): %w",
			newKSK.ID, keyGen.taggedBase(domain, "ksk", newKSK.ID), err)
	}

	rm.state.Mutate(func() {
		zoneState.Rollover = &statepkg.RolloverState{
			Type:         "algorithm",
			State:        statepkg.AlgoRolloverStateDSAddWait,
			OldKeyID:     oldKSKState.ID,
			NewKeyID:     newKSK.ID,
			OldZSKID:     oldZSKState.ID,
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

	metrics.RecordRolloverOperation(domain, "algorithm", "start")
	if err := rm.state.Save(); err != nil {
		if !fsutil.IsCommitted(err) {
			rm.state.Mutate(func() {
				zoneState.KSK = oldKSKState
				zoneState.ZSK = oldZSKState
				zoneState.Rollover = nil
				zoneState.ForceResign = false
			})
			return fmt.Errorf("saving algorithm rollover state (no live key was changed; staged keys left at %s and %s): %w",
				keyGen.taggedBase(domain, "ksk", newKSK.ID), keyGen.taggedBase(domain, "zsk", newZSK.ID), err)
		}
		slog.Warn("[ROLLOVER] rollover state saved but its durability across power loss is uncertain", "domain", domain, "error", err)
	}

	if err := rm.activateRecorded(domain, keyGen, "ksk", newKSK.ID); err != nil {
		return err
	}
	return rm.activateRecorded(domain, keyGen, "zsk", newZSK.ID)
}

// CompleteAlgorithmRollover moves an algorithm rollover from
// algo_ds_add_wait into its safe retirement sequence (RFC 6781 §4.1.4,
// RA6X-003): the caller has established that the new-algorithm DS is present
// at every parent server. Both algorithms keep signing everything while
// CheckAlgorithmRollover waits out the parent DS TTL, waits for the
// old-algorithm DS to disappear from every parent server plus another DS
// TTL, and only then drops the old-algorithm keys and signatures.
func (rm *RolloverManager) CompleteAlgorithmRollover(domain string, dsObservedAt time.Time, parentDSTTL uint32) error {
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
	if zoneState.Rollover.State != statepkg.AlgoRolloverStateDSAddWait {
		return fmt.Errorf("rollover not in algo_ds_add_wait state (currently %s; retirement is automatic from here)", zoneState.Rollover.State)
	}
	if parentDSTTL == 0 {
		parentDSTTL = uint32(rm.cfg.ParentDSTTLFallback() / time.Second)
	}

	slog.Info("[ROLLOVER] Algorithm rollover: new DS present at the parent; waiting out the parent DS TTL",
		"domain", domain,
		"old_algorithm", zoneState.Rollover.OldAlgorithm,
		"new_algorithm", zoneState.Rollover.NewAlgorithm)

	rm.state.Mutate(func() {
		r := zoneState.Rollover
		r.State = statepkg.AlgoRolloverStateDSPropagation
		r.DSObservedAt = dsObservedAt.UTC()
		r.ParentDSTTL = parentDSTTL
		r.PhaseStarted = time.Now().UTC()
		r.Action = fmt.Sprintf("Automatic: both algorithms stay published until %s (parent DS TTL); then remove the OLD DS (algorithm %s) at the registrar",
			r.DSObservedAt.Add(time.Duration(parentDSTTL)*time.Second).Format(time.RFC3339), r.OldAlgorithm)
		zoneState.ClearTransientWarnings()
	})
	metrics.RecordRolloverOperation(domain, "algorithm", "ds_propagation")
	return rm.state.Save()
}

// CheckAlgorithmRollover advances the automatic phases of an algorithm
// rollover (RA6X-003). It needs a parent-DS probe to see the old DS gone.
func (rm *RolloverManager) CheckAlgorithmRollover(domain string) error {
	zoneState := rm.state.GetZone(domain)
	if zoneState == nil || zoneState.Rollover == nil || zoneState.Rollover.Type != "algorithm" {
		return nil
	}
	r := zoneState.Rollover
	now := time.Now().UTC()
	ttl := time.Duration(r.ParentDSTTL) * time.Second
	switch r.State {
	case statepkg.AlgoRolloverStateDSPropagation:
		if now.Before(r.DSObservedAt.Add(ttl)) {
			return nil
		}
		rm.state.Mutate(func() {
			r.State = statepkg.AlgoRolloverStateOldDSRemoval
			r.PhaseStarted = now
			r.Action = fmt.Sprintf("Remove the OLD DS record (algorithm %s, key tag %d) at your registrar; the old-algorithm keys are retired automatically one parent DS TTL after it is gone from every parent server", r.OldAlgorithm, r.OldKeyID)
		})
		return rm.state.Save()
	case statepkg.AlgoRolloverStateOldDSRemoval:
		if r.OldDSRemovedAt.IsZero() {
			if rm.probe == nil {
				return nil
			}
			oldKSK, err := rm.keyGen().LoadPublicKeyByID(domain, "ksk", r.OldKeyID)
			if err != nil {
				return fmt.Errorf("loading old KSK %d to probe its DS: %w", r.OldKeyID, err)
			}
			obs, err := rm.probe.ProbeParentDS(domain, []*dns.DNSKEY{oldKSK})
			if err != nil {
				slog.Debug("[ROLLOVER] algorithm rollover: parent DS probe failed; retrying next cycle", "domain", domain, "error", err)
				return nil
			}
			if !obs.AbsentOnAll[r.OldKeyID] {
				return nil
			}
			ttlSeen := obs.TTL
			if ttlSeen == 0 {
				ttlSeen = r.ParentDSTTL
			}
			slog.Info("[ROLLOVER] Algorithm rollover: old DS gone from every parent server; waiting out the parent DS TTL before retiring the old algorithm",
				"domain", domain, "retire_after", now.Add(time.Duration(ttlSeen)*time.Second).Format(time.RFC3339))
			rm.state.Mutate(func() {
				r.OldDSRemovedAt = now
				if ttlSeen > r.ParentDSTTL {
					r.ParentDSTTL = ttlSeen
				}
				r.Action = fmt.Sprintf("Automatic: old DS gone; old-algorithm keys are retired after %s", now.Add(time.Duration(r.ParentDSTTL)*time.Second).Format(time.RFC3339))
			})
			return rm.state.Save()
		}
		if now.Before(r.OldDSRemovedAt.Add(time.Duration(r.ParentDSTTL) * time.Second)) {
			return nil
		}
		slog.Info("[ROLLOVER] Algorithm rollover: retiring the old-algorithm keys", "domain", domain, "old_algorithm", r.OldAlgorithm)
		rm.state.Mutate(func() {
			r.State = statepkg.AlgoRolloverStateRetiring
			r.PhaseStarted = now
			r.Action = "Automatic: old-algorithm keys removed from the zone; the rollover ends once that zone is confirmed served"
			zoneState.ForceResign = true
		})
		return rm.state.Save()
	case statepkg.AlgoRolloverStateRetiring:
		if !zoneState.PublishedSince(r.PhaseStarted) {
			return nil
		}
		slog.Info("[ROLLOVER] Algorithm rollover completed", "domain", domain,
			"note", "Old key files remain on disk for safety. You may delete them after removing the old DS from your registrar.")
		rm.state.Mutate(func() {
			zoneState.Rollover = nil
			zoneState.ClearTransientWarnings()
		})
		metrics.RecordRolloverOperation(domain, "algorithm", "complete")
		return rm.state.Save()
	}
	return nil
}
