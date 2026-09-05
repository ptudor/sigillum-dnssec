package signer

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ptudor/dnssec-tudor/internal/metrics"
	statepkg "github.com/ptudor/dnssec-tudor/internal/state"

	"github.com/miekg/dns"
	"github.com/ptudor/dnssec-tudor/internal/config"
	"github.com/ptudor/dnssec-tudor/internal/fsutil"
)

// Signer handles DNSSEC signing operations
type Signer struct {
	cfg   *config.Config
	state *statepkg.State
	// mutateBeforeVerify is a test-only seam that rewrites the freshly signed
	// records before the self-verification gate, so a generator regression can
	// be driven through the real publication boundary; nil in production.
	mutateBeforeVerify func([]dns.RR) []dns.RR
	// afterSourceRead is a test-only seam invoked after the zone file's bytes
	// have been read and before the post-read consistency check, so a rewrite
	// racing the read can be simulated; nil in production.
	afterSourceRead func(path string)
}

// NewSigner creates a new signer
func NewSigner(cfg *config.Config, state *statepkg.State) *Signer {
	return &Signer{
		cfg:   cfg,
		state: state,
	}
}

// SignAll signs all configured zones. Per-zone failures are logged, recorded in
// the zone's Errors, and do not abort the loop (other zones keep signing); state
// is always saved. It returns a non-nil error when any zone failed to
// initialize or sign, so one-shot callers (cron/CI via `sign`) detect it by
// exit code (R-024).
func (s *Signer) SignAll() error {
	var total, failed int
	for domain, zoneCfg := range s.cfg.Zones {
		total++
		zoneState := s.state.GetZone(domain)

		// Initialize a zone that is absent, or present only as a keyless
		// placeholder from a prior failed init — recover existing keys from disk
		// first to preserve the DS chain of trust. Re-running the init branch for
		// a placeholder (nil KSK/ZSK) is what lets a transient first-sign failure
		// (e.g. keys dir briefly unwritable) be retried next cycle instead of
		// permanently disabling key generation for that zone (R-033). A recovery
		// failure is logged and attached to the zone as an error; the loop moves
		// on so other zones keep signing.
		if zoneState == nil || zoneState.KSK == nil || zoneState.ZSK == nil {
			keyGen := NewKeyGenerator(s.cfg)
			ksk, zsk, err := RecoverOrGenerateKeys(keyGen, domain)
			if err != nil {
				slog.Error("[SIGN] Cannot initialize zone; skipping", "domain", domain, "error", err)
				placeholder := &statepkg.ZoneState{Path: zoneCfg.Path}
				placeholder.AddError(err.Error())
				s.state.SetZone(domain, placeholder)
				failed++
				continue
			}
			zoneState = &statepkg.ZoneState{
				Path: zoneCfg.Path,
				KSK:  ksk,
				ZSK:  zsk,
			}
			s.state.SetZone(domain, zoneState)
		}

		if err := s.SignZone(domain); err != nil {
			slog.Error("[SIGN] Failed to sign zone", "domain", domain, "error", err)
			s.state.Mutate(func() { zoneState.AddError(err.Error()) })
			failed++
		} else {
			s.state.Mutate(zoneState.ClearErrors)
		}
	}

	if err := s.state.Save(); err != nil {
		return err
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d zones failed to sign", failed, total)
	}
	return nil
}

// SignZone signs a single zone
func (s *Signer) SignZone(domain string) error {
	startTime := time.Now()

	zoneState := s.state.GetZone(domain)
	if zoneState == nil {
		return fmt.Errorf("zone %s not in state", domain)
	}

	sourcePath := s.SourcePath(domain, zoneState)
	slog.Info("[SIGN] Signing zone", "domain", domain, "path", sourcePath)

	// Load keys - handling rollover scenarios
	keyGen := NewKeyGenerator(s.cfg)
	keys, err := s.loadKeysForSigning(domain, keyGen, zoneState)
	if err != nil {
		return fmt.Errorf("loading keys: %w", err)
	}

	res, err := s.prepareSignedZone(domain, zoneState, keys, sourcePath)
	if err != nil {
		return err
	}

	// Write signed zone
	outputPath := s.OutputPath(domain)
	durabilityUncertain := ""
	if err := s.writeSignedZone(domain, outputPath, res.records); err != nil {
		if !fsutil.IsCommitted(err) {
			return fmt.Errorf("writing signed zone: %w", err)
		}
		// The signed zone is visible and is the generation now being served;
		// only its durability across power loss is uncertain (RA6X-049).
		// Reconcile with the visible generation rather than rolling back.
		durabilityUncertain = fmt.Sprintf("signed zone written but its directory sync failed; durability across power loss uncertain: %v", err)
		slog.Warn("[SIGN] "+durabilityUncertain, "domain", domain, "path", outputPath)
	}

	s.recordSignedZone(domain, zoneState, res, durabilityUncertain)

	// Record successful signing metrics
	duration := time.Since(startTime).Seconds()
	metrics.RecordSigningOperation(domain, duration, true)

	slog.Info("[SIGN] Zone signed successfully", "domain", domain, "serial", res.serial, "published_serial", res.published, "output", outputPath, "duration_ms", int64(duration*1000))
	return nil
}

// OutputPath is the signed-zone path for a domain.
func (s *Signer) OutputPath(domain string) string {
	return filepath.Join(s.cfg.OutputDir, fmt.Sprintf("%s.zone.signed", domain))
}

// SourcePath is the unsigned zone file every signing entry point reads for a
// domain (RA6X-005): the path the active configuration names, falling back to
// the path recorded in state only for a zone the configuration does not list.
// Change detection (NeedsSign) and hook metadata use the same path, and the
// state's copy is updated only after a successful publication
// (recordSignedZone), so a path change that fails to parse keeps the prior
// source reference and the prior signed output.
func (s *Signer) SourcePath(domain string, zoneState *statepkg.ZoneState) string {
	if zc, ok := s.cfg.Zones[domain]; ok && zc.Path != "" {
		return zc.Path
	}
	if zoneState != nil {
		return zoneState.Path
	}
	return ""
}

// signedZone is a fully signed and self-verified zone that has not been
// written or recorded yet.
type signedZone struct {
	records     []dns.RR
	serial      uint32
	published   uint32
	sourcePath  string
	srcModTime  time.Time
	srcSize     int64
	dnskeyTTL   uint32
	maxRRSIGTTL uint32
}

// prepareSignedZone reads one consistent snapshot of the unsigned zone at
// sourcePath, computes the published serial, builds the DNSKEY RRset and
// denial chain, signs every RRset with keys and self-verifies the result. It
// touches no file and no state.
func (s *Signer) prepareSignedZone(domain string, zoneState *statepkg.ZoneState, keys *signingKeys, sourcePath string) (*signedZone, error) {
	// The snapshot's mtime/size become the change-detection reference (R-022):
	// they describe exactly the bytes that were parsed, so an edit that lands
	// after the read is still detected on the next NeedsSign.
	snap, err := s.readSourceSnapshot(domain, sourcePath)
	if err != nil {
		return nil, fmt.Errorf("parsing zone file: %w", err)
	}
	res := &signedZone{
		sourcePath: sourcePath,
		srcModTime: snap.modTime,
		srcSize:    snap.size,
		serial:     snap.serial,
	}
	records := snap.records
	serial := snap.serial

	// R-007: the largest TTL among the zone's authoritative RRsets. A data RRSIG
	// inherits its RRset's TTL, so an old-ZSK signature can outlive the DNSKEY RRset;
	// ZSK retirement gates on this so the old key is not dropped while one of its
	// cached signatures is still verifiable.
	for _, rr := range records {
		if t := rr.Header().Ttl; t > res.maxRRSIGTTL {
			res.maxRRSIGTTL = t
		}
	}

	// Compute the serial to publish and rewrite the SOA before anything is
	// signed — the SOA RRset's RRSIG covers the published serial.
	published, err := s.publishedSerial(domain, serial, zoneState)
	if err != nil {
		return nil, err
	}
	res.published = published
	if published != serial {
		setSOASerial(records, published)
	}

	// Extract SOA minimum TTL for NSEC/NSEC3 records (RFC 4035 §2.3)
	soaMinTTL := s.getSOAMinimumTTL(records)

	// Determine DNSKEY TTL: use config value or SOA TTL
	res.dnskeyTTL = s.cfg.DNSSEC.DNSKEYTtl
	if res.dnskeyTTL == 0 {
		res.dnskeyTTL = s.getSOATTL(records) // Use SOA record TTL as convention
	}

	// Add all DNSKEY records with appropriate TTL (may include rollover keys)
	for _, k := range keys.dnskeys {
		k.Hdr.Ttl = res.dnskeyTTL
		records = append(records, k)
	}

	// The immutable input snapshot (data + DNSKEY) and its canonical index,
	// shared by chain generation, signing and self-verification (RA6X-053).
	input := append([]dns.RR(nil), records...)
	model := newZoneModel(domain, input)

	// Generate NSEC/NSEC3 chain
	if s.cfg.DNSSEC.NSECVersion == "nsec3" {
		nsec3Records, err := s.generateNSEC3ChainWithModel(model, domain, records, soaMinTTL)
		if err != nil {
			return nil, fmt.Errorf("generating NSEC3 chain: %w", err)
		}
		records = append(records, nsec3Records...)
	} else {
		nsecRecords := s.generateNSECChainWithModel(model, domain, records, soaMinTTL)
		records = append(records, nsecRecords...)
	}

	// Sign all RRsets
	signedRecords, err := s.signRecordsWithModel(model, domain, records, keys)
	if err != nil {
		return nil, fmt.Errorf("signing records: %w", err)
	}
	if s.mutateBeforeVerify != nil {
		signedRecords = s.mutateBeforeVerify(signedRecords)
	}

	// R-001: self-verify the produced records before publishing. If signing produced
	// something internally inconsistent (an RRSIG that doesn't verify, an unsigned
	// authoritative RRset, a broken NSEC/NSEC3 chain), fail here so the previous signed
	// output keeps serving instead of shipping a zone that SERVFAILs at every resolver.
	if err := s.verifySignedZoneWithModel(model, domain, input, signedRecords, keys); err != nil {
		return nil, fmt.Errorf("post-sign verification failed (previous signed zone kept): %w", err)
	}
	res.records = signedRecords
	return res, nil
}

// recordSignedZone updates the zone state after a signed zone has been
// published, under the write lock so concurrent readers (web UI, health
// checks) never observe a half-updated zone.
func (s *Signer) recordSignedZone(domain string, zoneState *statepkg.ZoneState, res *signedZone, durabilityUncertain string) {
	now := time.Now().UTC()
	s.state.Mutate(func() {
		if res.sourcePath != "" {
			// The old source reference is replaced only now that the new
			// source has been parsed and published (RA6X-005).
			zoneState.Path = res.sourcePath
		}
		zoneState.Serial = res.serial
		zoneState.PublishedSerial = res.published
		zoneState.LastSigned = now
		if !res.srcModTime.IsZero() {
			zoneState.SourceModTime = res.srcModTime
			zoneState.SourceSize = res.srcSize
		}
		zoneState.SignaturesExp = now.Add(s.cfg.DNSSEC.SignatureValidity.Duration)
		zoneState.ForceResign = false
		// R-006: record the DNSKEY RRset TTL actually published (config value, or the
		// SOA TTL when dnskey_ttl = 0) so rollover phase gating waits for the TTL
		// resolvers really cache. Never shorten a previously-established wait while a
		// rollover is active — only raise it (a mid-phase SOA TTL decrease must not
		// let the phase advance early).
		if zoneState.Rollover == nil || res.dnskeyTTL > zoneState.PublishedDNSKEYTTL {
			zoneState.PublishedDNSKEYTTL = res.dnskeyTTL
		}
		if zoneState.Rollover == nil || res.maxRRSIGTTL > zoneState.PublishedMaxRRSIGTTL {
			zoneState.PublishedMaxRRSIGTTL = res.maxRRSIGTTL
		}
		zoneState.ClearTransientWarnings()
		if durabilityUncertain != "" {
			zoneState.AddWarning(durabilityUncertain)
		}

		// Check for upcoming rollovers
		s.checkRolloverWarnings(domain, zoneState)
	})
}

// StagedZone is a signed zone produced from explicit key pairs and written to
// a staging path, not yet published as the domain's signed output and not yet
// recorded in the zone state. Import uses it to prove the complete signed zone
// before any live artifact changes (RA6X-024).
type StagedZone struct {
	s         *Signer
	domain    string
	zoneState *statepkg.ZoneState
	res       *signedZone
	path      string
}

// StageZoneWithKeys signs zoneState's zone file with exactly the given KSK and
// ZSK pairs — nothing is loaded from the live key slots — and writes the result
// atomically to stagingPath. The pairs are validated for the domain and role and
// for private/public correspondence first. zoneState is only read.
func (s *Signer) StageZoneWithKeys(domain string, zoneState *statepkg.ZoneState, ksk *dns.DNSKEY, kskPriv []byte, zsk *dns.DNSKEY, zskPriv []byte, stagingPath string) (*StagedZone, error) {
	if err := ValidateKeyForImport(domain, "ksk", ksk, kskPriv); err != nil {
		return nil, err
	}
	if err := ValidateKeyForImport(domain, "zsk", zsk, zskPriv); err != nil {
		return nil, err
	}
	keys := &signingKeys{
		dnskeys:      []*dns.DNSKEY{ksk, zsk},
		signingKSKs:  []*dns.DNSKEY{ksk},
		signingKSKPs: [][]byte{kskPriv},
		signingZSKs:  []*dns.DNSKEY{zsk},
		signingZSKPs: [][]byte{zskPriv},
	}
	if err := keys.validateConsistency(); err != nil {
		return nil, fmt.Errorf("internal key state for %s: %w", domain, err)
	}
	res, err := s.prepareSignedZone(domain, zoneState, keys, s.SourcePath(domain, zoneState))
	if err != nil {
		return nil, err
	}
	if err := s.writeSignedZone(domain, stagingPath, res.records); err != nil && !fsutil.IsCommitted(err) {
		return nil, fmt.Errorf("writing staged signed zone: %w", err)
	}
	return &StagedZone{s: s, domain: domain, zoneState: zoneState, res: res, path: stagingPath}, nil
}

// Path is the staging file.
func (sz *StagedZone) Path() string { return sz.path }

// Publish moves the staged file over the domain's signed output atomically
// (same directory rename), syncs the directory and records the signing in the
// zone state. The caller is responsible for preserving any prior output.
func (sz *StagedZone) Publish() error {
	outputPath := sz.s.OutputPath(sz.domain)
	if err := os.Rename(sz.path, outputPath); err != nil {
		return fmt.Errorf("publishing staged signed zone: %w", err)
	}
	durabilityUncertain := ""
	if err := fsutil.SyncDir(filepath.Dir(outputPath)); err != nil {
		durabilityUncertain = fmt.Sprintf("signed zone written but its directory sync failed; durability across power loss uncertain: %v", err)
		slog.Warn("[SIGN] "+durabilityUncertain, "domain", sz.domain, "path", outputPath)
	}
	sz.s.recordSignedZone(sz.domain, sz.zoneState, sz.res, durabilityUncertain)
	metrics.RecordSigningOperation(sz.domain, 0, true)
	slog.Info("[SIGN] Zone signed successfully", "domain", sz.domain, "serial", sz.res.serial, "published_serial", sz.res.published, "output", outputPath)
	return nil
}

// Discard removes the staging file of a transaction that did not commit.
func (sz *StagedZone) Discard() {
	if err := os.Remove(sz.path); err != nil && !os.IsNotExist(err) {
		slog.Warn("[SIGN] could not remove staged signed zone", "path", sz.path, "error", err)
	}
}

// serialGt reports whether serial a is greater than b in RFC 1982 serial
// number arithmetic (the comparison DNS secondaries use for SOA serials).
func serialGt(a, b uint32) bool {
	return (a > b && a-b < 1<<31) || (a < b && b-a > 1<<31)
}

// epochSerialFloor is 2000-01-01T00:00:00Z. Serials below this are not
// plausible unix timestamps; serials above now+1d are date-format
// (YYYYMMDDnn) or future-clock values — both are rejected under the epoch
// policy because the published serial is derived from the current time and
// must never move backwards relative to the unsigned file.
const epochSerialFloor = 946684800

// publishedSerial returns the SOA serial to write into the signed zone.
//
// Policy "keep" (default) publishes the unsigned serial unchanged. Policy
// "epoch" publishes max(now, serial+1, lastPublished+1): every signing
// event — including signature refreshes and rollover phases that don't
// touch the unsigned file — produces a strictly larger serial, so AXFR/IXFR
// secondaries always transfer the refreshed signatures. Zones under the
// epoch policy MUST carry a unix epoch serial in the unsigned file (e.g.
// from `date +%s`); anything else is rejected here, which fails this zone's
// signing while the previously signed output keeps serving.
func (s *Signer) publishedSerial(domain string, serial uint32, zoneState *statepkg.ZoneState) (uint32, error) {
	if s.cfg.GetZoneSerialPolicy(domain) != "epoch" {
		return serial, nil
	}

	now := uint32(time.Now().Unix())
	if serial < epochSerialFloor || serial > now+86400 {
		return 0, fmt.Errorf(
			"zone %s: serial_policy \"epoch\" requires a unix epoch SOA serial in the unsigned zone, got %d (expected %d..%d); set the serial to epoch seconds, e.g. `date +%%s`",
			domain, serial, epochSerialFloor, now+86400)
	}

	next := now
	if !serialGt(next, serial) {
		next = serial + 1
	}
	if prev := zoneState.PublishedSerial; prev != 0 && !serialGt(next, prev) {
		next = prev + 1
	}
	return next, nil
}

// setSOASerial rewrites the serial on the zone's SOA record in place.
func setSOASerial(records []dns.RR, serial uint32) {
	for _, rr := range records {
		if soa, ok := rr.(*dns.SOA); ok {
			soa.Serial = serial
			return
		}
	}
}

// signingKeys holds all keys needed for signing, handling rollover scenarios
type signingKeys struct {
	dnskeys      []*dns.DNSKEY // All DNSKEYs to include in zone
	signingKSKs  []*dns.DNSKEY // KSKs to sign DNSKEY RRset with
	signingKSKPs [][]byte      // Private keys for signingKSKs
	signingZSKs  []*dns.DNSKEY // ZSKs to sign other RRsets (multiple for algorithm rollover)
	signingZSKPs [][]byte      // Private keys for signingZSKs
}

// validateConsistency enforces the load-bearing DNSSEC invariant: every
// signing key must also be present (by keytag) in the published DNSKEY
// RRset. A signer whose keytag isn't published produces RRSIGs that
// validating resolvers can't verify — the zone is bogus and SERVFAILs
// across every validator. Catching the inconsistency here, before
// signRecordsWithKeys runs, keeps the previous (working) signed zone in
// place rather than overwriting it with a broken one.
//
// This is a defense-in-depth check: the rollover branches in
// loadKeysForSigning are supposed to keep this invariant, but a missing
// "append to dnskeys" line in the ZSK pre-publish branch shipped a
// silent outage in production. The check pays for itself the first time
// a future rollover branch forgets the same line.
func (k *signingKeys) validateConsistency() error {
	published := make(map[uint16]struct{}, len(k.dnskeys))
	for _, dk := range k.dnskeys {
		published[dk.KeyTag()] = struct{}{}
	}
	for _, sk := range k.signingKSKs {
		if _, ok := published[sk.KeyTag()]; !ok {
			return fmt.Errorf("signing KSK keytag %d is not in the published DNSKEY RRset; signing would emit a bogus zone", sk.KeyTag())
		}
	}
	for _, sk := range k.signingZSKs {
		if _, ok := published[sk.KeyTag()]; !ok {
			return fmt.Errorf("signing ZSK keytag %d is not in the published DNSKEY RRset; signing would emit a bogus zone", sk.KeyTag())
		}
	}
	return nil
}

// loadKeysForSigning loads all keys needed, handling rollover scenarios
func (s *Signer) loadKeysForSigning(domain string, keyGen *KeyGenerator, zoneState *statepkg.ZoneState) (*signingKeys, error) {
	keys := &signingKeys{}

	// The persisted state names the generation each live slot must hold
	// (RA6X-002). Loading by role alone would accept whatever file is there —
	// after a rollover interrupted between its state save and its activation,
	// that is the wrong generation. EnsureLiveKey checks the live pair's tag
	// against the record and re-activates the recorded generation from its
	// tag-named copy when they differ, failing closed when it cannot.
	expectedKSK, expectedZSK, err := expectedLiveKeyTags(zoneState)
	if err != nil {
		return nil, err
	}

	// Load current KSK
	ksk, kskPriv, err := keyGen.EnsureLiveKey(domain, "ksk", expectedKSK)
	if err != nil {
		return nil, fmt.Errorf("loading KSK: %w", err)
	}
	keys.dnskeys = append(keys.dnskeys, ksk)
	keys.signingKSKs = append(keys.signingKSKs, ksk)
	keys.signingKSKPs = append(keys.signingKSKPs, kskPriv)

	// Load current ZSK
	zsk, zskPriv, err := keyGen.EnsureLiveKey(domain, "zsk", expectedZSK)
	if err != nil {
		return nil, fmt.Errorf("loading ZSK: %w", err)
	}
	keys.dnskeys = append(keys.dnskeys, zsk)
	keys.signingZSKs = append(keys.signingZSKs, zsk)
	keys.signingZSKPs = append(keys.signingZSKPs, zskPriv)

	// Handle rollover scenarios
	if zoneState.Rollover != nil {
		switch {
		case zoneState.Rollover.Type == "ksk" && zoneState.Rollover.State == statepkg.KSKRolloverStateDSAddWait:
			// KSK rollover: load old KSK too, sign with both. FATAL on failure (R-003):
			// during ds_add_wait the parent DS still references the old KSK, so publishing
			// a DNSKEY RRset without it makes every resolver validating via the old DS go
			// bogus. Failing keeps the previous good signed zone in place.
			oldKSK, oldKSKPriv, err := keyGen.LoadKeyPairByID(domain, "ksk", zoneState.Rollover.OldKeyID)
			if err != nil {
				return nil, fmt.Errorf("loading old KSK %d for rollover signing (if the rollover is complete and the old key is gone, run `dnssec-tudor rollover complete %s`): %w", zoneState.Rollover.OldKeyID, domain, err)
			}
			keys.dnskeys = append(keys.dnskeys, oldKSK)
			keys.signingKSKs = append(keys.signingKSKs, oldKSK)
			keys.signingKSKPs = append(keys.signingKSKPs, oldKSKPriv)
			slog.Info("[SIGN] KSK rollover: signing with both old and new KSK",
				"old_key_id", zoneState.Rollover.OldKeyID,
				"new_key_id", zoneState.Rollover.NewKeyID)

		case zoneState.Rollover.Type == "zsk" && zoneState.Rollover.State == statepkg.ZSKRolloverStatePrePublish:
			// ZSK pre-publish: publish BOTH old and new ZSK in the DNSKEY
			// RRset, but continue signing every non-DNSKEY RRset with the OLD
			// ZSK. The new ZSK is already in keys.dnskeys via the
			// EnsureLiveKey("zsk") call above (the live *.zsk.key slot holds
			// the NEW key during pre-publish; expectedLiveKeyTags names it
			// from Rollover.NewKeyID). Append the OLD ZSK so the
			// signing key's keytag actually appears in the published RRset
			// — without this, RRSIGs reference a DNSKEY that isn't there
			// and every validating resolver returns bogus.
			//
			// A load failure here is fatal. Falling back to signing-with-new
			// would defeat pre-publish (resolvers haven't cached the new key
			// yet) and emit a structurally-different signed zone than the
			// one operators are expecting from the rollover state. Returning
			// an error keeps the previously-emitted signed zone in place.
			oldZSK, oldZSKPriv, err := keyGen.LoadKeyPairByID(domain, "zsk", zoneState.Rollover.OldKeyID)
			if err != nil {
				return nil, fmt.Errorf("loading old ZSK %d for pre-publish: %w", zoneState.Rollover.OldKeyID, err)
			}
			keys.dnskeys = append(keys.dnskeys, oldZSK)
			keys.signingZSKs = []*dns.DNSKEY{oldZSK}
			keys.signingZSKPs = [][]byte{oldZSKPriv}
			slog.Info("[SIGN] ZSK rollover pre-publish: publishing both, signing with old",
				"old_key_id", zoneState.Rollover.OldKeyID,
				"new_key_id", zoneState.Rollover.NewKeyID)

		case zoneState.Rollover.Type == "zsk" && zoneState.Rollover.State == statepkg.ZSKRolloverStateSigning:
			// ZSK signing phase: publish the old ZSK (only the public half is needed) while
			// signing with the new one. FATAL on failure (R-003): dropping the old ZSK from
			// the published RRset while resolvers still hold its cached RRSIGs is bogus.
			oldZSK, err := keyGen.LoadPublicKeyByID(domain, "zsk", zoneState.Rollover.OldKeyID)
			if err != nil {
				return nil, fmt.Errorf("loading old ZSK %d for publish during rollover (if the rollover is complete and the old key is gone, run `dnssec-tudor rollover complete %s`): %w", zoneState.Rollover.OldKeyID, domain, err)
			}
			keys.dnskeys = append(keys.dnskeys, oldZSK)
			slog.Info("[SIGN] ZSK rollover signing: publishing both, signing with new",
				"old_key_id", zoneState.Rollover.OldKeyID,
				"new_key_id", zoneState.Rollover.NewKeyID)

		case zoneState.Rollover.Type == "algorithm" && zoneState.Rollover.State == statepkg.AlgoRolloverStateDSAddWait:
			// Algorithm rollover: publish and sign with BOTH algorithms' keys. FATAL on
			// failure (R-003): dropping an old-algorithm key mid-rollover leaves RRsets
			// unsigned for a signaled algorithm, violating RFC 4035 §2.2 / RFC 6840 §5.11.
			oldKSK, oldKSKPriv, err := keyGen.LoadKeyPairByID(domain, "ksk", zoneState.Rollover.OldKeyID)
			if err != nil {
				return nil, fmt.Errorf("loading old-algorithm KSK %d for rollover (if the rollover is complete and the old key is gone, run `dnssec-tudor rollover complete %s`): %w", zoneState.Rollover.OldKeyID, domain, err)
			}
			keys.dnskeys = append(keys.dnskeys, oldKSK)
			keys.signingKSKs = append(keys.signingKSKs, oldKSK)
			keys.signingKSKPs = append(keys.signingKSKPs, oldKSKPriv)

			// Load old ZSK using stored ID
			oldZSK, oldZSKPriv, err := keyGen.LoadKeyPairByID(domain, "zsk", zoneState.Rollover.OldZSKID)
			if err != nil {
				return nil, fmt.Errorf("loading old-algorithm ZSK %d for rollover (if the rollover is complete and the old key is gone, run `dnssec-tudor rollover complete %s`): %w", zoneState.Rollover.OldZSKID, domain, err)
			}
			keys.dnskeys = append(keys.dnskeys, oldZSK)
			keys.signingZSKs = append(keys.signingZSKs, oldZSK)
			keys.signingZSKPs = append(keys.signingZSKPs, oldZSKPriv)

			slog.Info("[SIGN] Algorithm rollover: signing with both algorithms",
				"old_algorithm", zoneState.Rollover.OldAlgorithm,
				"new_algorithm", zoneState.Rollover.NewAlgorithm)
		}
	}

	if err := keys.validateConsistency(); err != nil {
		return nil, fmt.Errorf("internal key state for %s: %w", domain, err)
	}
	if err := keys.validateAlgorithms(zoneState); err != nil {
		return nil, fmt.Errorf("key algorithms for %s: %w", domain, err)
	}
	return keys, nil
}

// validateAlgorithms rejects a key set whose members use different algorithms
// unless an explicit algorithm rollover is in progress (RA6X-001). Publishing
// a DNSKEY RRset that advertises an algorithm no key of the right role signs
// with produces an algorithm-incomplete zone (RFC 6840 §5.11); only the
// dedicated `rollover algorithm` flow may introduce a second algorithm, and it
// signs everything with both.
func (k *signingKeys) validateAlgorithms(zoneState *statepkg.ZoneState) error {
	if zoneState.Rollover != nil && zoneState.Rollover.Type == "algorithm" {
		return nil
	}
	if len(k.dnskeys) == 0 {
		return nil
	}
	alg := k.dnskeys[0].Algorithm
	for _, dk := range k.dnskeys[1:] {
		if dk.Algorithm != alg {
			return fmt.Errorf("live keys use different algorithms (%s key tag %d, %s key tag %d) with no algorithm rollover in progress; refusing to publish an algorithm-incomplete zone — use `dnssec-tudor rollover algorithm` to change algorithms",
				AlgorithmName(alg), k.dnskeys[0].KeyTag(), AlgorithmName(dk.Algorithm), dk.KeyTag())
		}
	}
	return nil
}

// expectedLiveKeyTags returns the key tags the live KSK and ZSK slots must hold
// according to the persisted zone state. The live KSK is always KeyState.ID.
// The live ZSK is KeyState.ID except during ZSK pre-publish, when the zone
// keeps signing with the old key (still KeyState.ID) while the live slot
// already holds the pre-published new key named by Rollover.NewKeyID.
func expectedLiveKeyTags(zoneState *statepkg.ZoneState) (ksk, zsk uint16, err error) {
	if zoneState.KSK == nil || zoneState.ZSK == nil {
		return 0, 0, fmt.Errorf("zone state names no KSK/ZSK to sign with")
	}
	ksk = zoneState.KSK.ID
	zsk = zoneState.ZSK.ID
	if r := zoneState.Rollover; r != nil && r.Type == "zsk" && r.State == statepkg.ZSKRolloverStatePrePublish {
		zsk = r.NewKeyID
	}
	return ksk, zsk, nil
}

const (
	// zoneWriteQuiescenceWindow: a source change whose mtime is this fresh is
	// treated as possibly still-being-written and re-checked before signing.
	zoneWriteQuiescenceWindow = 3 * time.Second
	// zoneWriteSettleDelay: how long to wait before the quiescence re-stat.
	zoneWriteSettleDelay = 750 * time.Millisecond
)

// NeedsSign checks if a zone needs to be signed
func (s *Signer) NeedsSign(domain, zonePath string, zoneState *statepkg.ZoneState) (bool, string) {
	// New zone - always sign
	if zoneState == nil {
		return true, "new zone"
	}

	// Check signature expiry first — this is the most critical check and must
	// never be skipped, even if the zone file is temporarily inaccessible.
	now := time.Now()
	if !zoneState.SignaturesExp.IsZero() {
		refreshTime := zoneState.SignaturesExp.Add(-s.cfg.DNSSEC.SignatureRefresh.Duration)
		if now.After(zoneState.SignaturesExp) {
			return true, "signatures EXPIRED"
		}
		if now.After(refreshTime) {
			return true, "signatures approaching expiry"
		}

		slog.Debug("[SIGN] Signatures still valid",
			"domain", domain,
			"expires", zoneState.SignaturesExp.Format(time.RFC3339),
			"refresh_at", refreshTime.Format(time.RFC3339))
	}

	// Check for rollover transitions. ForceResign is set by the rollover
	// manager whenever the key set that must be published/signed changes
	// (start, phase switch, completion) and cleared on successful sign.
	// The Started fallback covers a rollover begun while the zone had
	// never been signed with it (e.g. state restored from backup). The old
	// behavior — re-sign unconditionally while Rollover != nil — re-signed
	// (and fired the post-sign hook) every poll cycle for the entire days-
	// long ds_add_wait window of a KSK rollover.
	if zoneState.ForceResign {
		return true, "rollover state changed"
	}
	if zoneState.Rollover != nil && zoneState.LastSigned.Before(zoneState.Rollover.Started) {
		return true, "rollover in progress"
	}

	// RA6X-005: the configured source differs from the one the last signing
	// used. That is a forced sign regardless of the new file's mtime/size —
	// an older or same-size replacement must not be skipped until refresh.
	if zoneState.Path != "" && filepath.Clean(zonePath) != filepath.Clean(zoneState.Path) {
		return true, "source path changed"
	}

	// RA6X-035: state may look fresh while the published output is gone or
	// unusable (a partially restored output directory, a changed output_dir).
	// Presence and file type are checked, never the output's mtime.
	if !zoneState.LastSigned.IsZero() {
		if reason := s.outputUnusable(domain); reason != "" {
			return true, reason
		}
	}

	// Check zone file modification time
	info, err := os.Stat(zonePath)
	if err != nil {
		slog.Error("[SIGN] Cannot stat zone file", "domain", domain, "path", zonePath, "error", err)
		s.state.Mutate(func() {
			zoneState.AddError(fmt.Sprintf("zone file missing or inaccessible: %v", err))
		})
		return false, ""
	}

	// Change-detection reference: the source mtime/size captured at PARSE time
	// (R-022), NOT LastSigned. This catches an edit that landed between the last
	// parse and its LastSigned stamp. Old state has no source_mtime — fall back
	// to LastSigned so upgraded zones don't re-sign forever.
	changeRef := zoneState.SourceModTime
	if changeRef.IsZero() {
		changeRef = zoneState.LastSigned
	}
	slog.Debug("[SIGN] Checking zone mtime",
		"domain", domain,
		"file_mtime", info.ModTime().Format(time.RFC3339),
		"change_ref", changeRef.Format(time.RFC3339))

	sizeChanged := zoneState.SourceSize != 0 && info.Size() != zoneState.SourceSize
	if info.ModTime().After(changeRef) || sizeChanged {
		// Quiescence: a very recent change may still be mid-write (a generator
		// doing `> zone`, an editor save). Re-stat after a short delay; if the
		// mtime/size changed again the write is ongoing, so defer to the next
		// tick rather than sign a truncated file. Expiry/rollover signing above
		// is never deferred (R-022).
		if time.Since(info.ModTime()) < zoneWriteQuiescenceWindow {
			time.Sleep(zoneWriteSettleDelay)
			if info2, err2 := os.Stat(zonePath); err2 == nil &&
				(info2.ModTime() != info.ModTime() || info2.Size() != info.Size()) {
				slog.Debug("[SIGN] Zone file still settling; deferring to next tick", "domain", domain)
				return false, ""
			}
		}
		return true, "zone file modified"
	}

	// Steady state: the source is unchanged since it was last parsed, signatures
	// are not near expiry, and no rollover is pending. We deliberately do NOT
	// parse the file on every idle poll just to re-read an unchanged serial
	// (wasteful I/O/CPU at many zones, R-064). The only case this skips is a
	// content edit that preserves an older mtime/size (e.g. `cp -p` from a
	// backup); that is picked up at the next signature-refresh re-sign.
	return false, ""
}

func (s *Signer) parseZoneFile(domain, path string) ([]dns.RR, uint32, error) {
	snap, err := s.readSourceSnapshot(domain, path)
	if err != nil {
		return nil, 0, err
	}
	return snap.records, snap.serial, nil
}

// sourceSnapshot is one consistent read of an unsigned zone file: the parsed
// records and the metadata that describes exactly those bytes.
type sourceSnapshot struct {
	records []dns.RR
	serial  uint32
	modTime time.Time
	size    int64
}

// outputUnusable reports why the published output for a domain cannot be
// served: missing, unreadable or not a regular file. Empty when it is usable.
func (s *Signer) outputUnusable(domain string) string {
	info, err := os.Stat(s.OutputPath(domain))
	switch {
	case os.IsNotExist(err):
		return "signed output missing"
	case err != nil:
		return fmt.Sprintf("signed output unreadable: %v", err)
	case !info.Mode().IsRegular():
		return fmt.Sprintf("signed output is not a regular file (%s)", info.Mode().Type())
	}
	return ""
}

// readSourceSnapshot reads the unsigned zone through a single regular-file
// descriptor and parses exactly the bytes it read (RA6X-042). The file is
// opened without blocking so a FIFO or device cannot hang the signer holding
// the state lock; anything but a regular file is rejected. The descriptor is
// stat'ed before and after the read: a size or mtime change means a writer
// rewrote the file in place while it was being read, and the read is refused
// rather than published. A producer that replaces the file atomically (write
// to a temporary file, then rename) never trips this — the descriptor keeps
// the complete previous version and the next change check picks up the new
// one — which is the documented producer contract; metadata cannot prove a
// paused in-place writer's valid prefix is complete.
func (s *Signer) readSourceSnapshot(domain, path string) (*sourceSnapshot, error) {
	f, err := openSourceFile(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	before, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspecting zone file %s: %w", path, err)
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("zone file %s is not a regular file (%s); pipes, devices and directories are not supported as zone sources", path, before.Mode().Type())
	}

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("reading zone file %s: %w", path, err)
	}
	if s.afterSourceRead != nil {
		s.afterSourceRead(path)
	}
	after, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspecting zone file %s after read: %w", path, err)
	}
	if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) || int64(len(data)) != before.Size() {
		return nil, fmt.Errorf("zone file %s changed while it was being read (size %d→%d); a zone producer must replace the file atomically (write a temporary file, then rename it into place) — not signed, retried on the next check",
			path, before.Size(), after.Size())
	}

	var records []dns.RR
	var serial uint32

	// $INCLUDE is intentionally NOT enabled (SetIncludeAllowed stays false): the
	// signer manages one self-contained zone file per zone, and enabling
	// includes would add an arbitrary-file-read surface plus cwd-relative path
	// ambiguity for a daemon that may run from `/`. A zone using $INCLUDE fails
	// with miekg's clear "$INCLUDE directive not allowed" error naming the line;
	// the limitation is documented in CLAUDE.md (R-065). Inline the records.
	zp := dns.NewZoneParser(bytes.NewReader(data), dns.Fqdn(domain), path)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		records = append(records, rr)

		// Extract serial from SOA
		if soa, ok := rr.(*dns.SOA); ok {
			serial = soa.Serial
		}
	}

	if err := zp.Err(); err != nil {
		return nil, fmt.Errorf("parsing zone: %w", err)
	}

	// Strip any DNSSEC records the signer manages itself before validation and
	// chain generation (R-034), so an already-signed file fed by mistake is
	// re-signed cleanly instead of producing a duplicated/self-referential chain.
	records = stripInputDNSSEC(domain, records)

	// Validate zone structure
	if err := s.validateZone(domain, records); err != nil {
		return nil, fmt.Errorf("zone validation failed: %w", err)
	}

	return &sourceSnapshot{records: records, serial: serial, modTime: before.ModTime(), size: before.Size()}, nil
}

// stripInputDNSSEC removes DNSSEC records that the signer generates itself from a
// parsed input zone — stale RRSIG/NSEC/NSEC3/NSEC3PARAM and any apex DNSKEY — so
// re-signing produces a valid single chain rather than duplicating/conflicting
// with the input's records or signing a stray RRSIG RRset. DS records at
// delegations are legitimate and preserved. R-034.
func stripInputDNSSEC(domain string, records []dns.RR) []dns.RR {
	apex := canonicalName(domain)
	out := make([]dns.RR, 0, len(records))
	stripped := 0
	for _, rr := range records {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM:
			stripped++
			continue
		case dns.TypeDNSKEY:
			// The signer manages the apex DNSKEY RRset; drop any in the input.
			if canonicalName(rr.Header().Name) == apex {
				stripped++
				continue
			}
		}
		out = append(out, rr)
	}
	if stripped > 0 {
		slog.Warn("[SIGN] Stripped pre-existing DNSSEC records from input zone (the signer manages its own chain)",
			"domain", domain, "count", stripped)
	}
	return out
}

// validateZoneRecords is the single source of truth for the rules a zone must
// satisfy before signing: exactly one SOA at the apex, at least one NS at the
// apex, every owner at or below the apex (R-035), and the semantic owner/type
// constraints an authoritative server enforces when loading the output
// (RA6X-029): a CNAME is the only record at its owner apart from DNSSEC
// metadata, and there is only one; a DNAME is singular, never beside a CNAME,
// and nothing exists beneath it (RFC 6672 §2.4); a delegation point holds only
// NS, DS and glue A/AAAA; DS appears only at delegation points. Owners are
// compared by canonical wire identity (RA6X-028). Both the in-memory signing
// path (Signer.validateZone) and the file-based CLI path (ValidateZoneFile)
// call this so the rules can't drift between `add`/`import` and signing (R-075).
func validateZoneRecords(domain string, records []dns.RR) error {
	apex := dns.Fqdn(domain)
	m := newZoneModel(domain, records)

	var soaCount int
	for _, rr := range records {
		name := m.canon(rr)

		// Every authoritative owner name must be at or below the apex. An
		// out-of-zone owner (a typo, or the wrong file) would otherwise be signed
		// and inserted into the NSEC/NSEC3 chain, breaking canonical ordering and
		// the denial-of-existence proofs (the chain would "cover" names outside
		// the zone). Reject rather than emit a subtly broken zone (R-035).
		if !m.within(name) {
			return fmt.Errorf("record owner %s is not within zone %s", rr.Header().Name, apex)
		}
		if rr.Header().Rrtype == dns.TypeSOA {
			soaCount++
			if name != m.apex {
				return fmt.Errorf("SOA record at %s not at zone apex %s", rr.Header().Name, apex)
			}
		}
	}

	if soaCount == 0 {
		return fmt.Errorf("zone has no SOA record")
	}
	if soaCount > 1 {
		return fmt.Errorf("zone has %d SOA records (must have exactly 1)", soaCount)
	}
	if apexInfo := m.owners[m.apex]; apexInfo == nil || apexInfo.types[dns.TypeNS] == 0 {
		return fmt.Errorf("zone has no NS records at apex")
	}

	names := make([]string, 0, len(m.owners))
	for name := range m.owners {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool { return canonicalLess(names[i], names[j]) })
	for _, name := range names {
		oi := m.owners[name]
		if n := oi.types[dns.TypeCNAME]; n > 0 {
			if name == m.apex {
				return fmt.Errorf("CNAME at the zone apex %s cannot coexist with the SOA and NS records (RFC 1034 §3.6.2)", apex)
			}
			if n > 1 {
				return fmt.Errorf("owner %s has %d CNAME records; a CNAME must be the only CNAME at its owner (RFC 1034 §3.6.2)", name, n)
			}
			for t := range oi.types {
				if t != dns.TypeCNAME && !isDNSSECMetadataType(t) {
					return fmt.Errorf("owner %s has both CNAME and %s records; a CNAME must not coexist with other data (RFC 1034 §3.6.2)", name, dns.TypeToString[t])
				}
			}
		}
		if n := oi.types[dns.TypeDNAME]; n > 0 {
			if n > 1 {
				return fmt.Errorf("owner %s has %d DNAME records; only one is allowed (RFC 6672 §2.4)", name, n)
			}
			if oi.types[dns.TypeCNAME] > 0 {
				return fmt.Errorf("owner %s has both DNAME and CNAME records (RFC 6672 §2.4)", name)
			}
		}
		if dn, ok := m.occludingDNAME(name); ok {
			return fmt.Errorf("records at %s lie beneath the DNAME at %s; names beneath a DNAME must not exist (RFC 6672 §2.4)", name, dn)
		}
		if m.isDelegation(name) {
			for t := range oi.types {
				switch t {
				case dns.TypeNS, dns.TypeDS, dns.TypeA, dns.TypeAAAA, dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
				default:
					return fmt.Errorf("owner %s is a delegation point but holds %s records; only NS, DS and glue A/AAAA may appear at a zone cut (RFC 4035 §2.2)", name, dns.TypeToString[t])
				}
			}
		} else if oi.types[dns.TypeDS] > 0 {
			return fmt.Errorf("owner %s has DS records but is not a delegation point (no NS RRset); DS belongs only at a zone cut (RFC 4035 §2.4)", name)
		}
	}

	return nil
}

// isDNSSECMetadataType reports whether a type is DNSSEC metadata that may sit
// beside a CNAME (RFC 4035 §2.5): the signer generates these itself, and a
// previously signed file fed as input carries them.
func isDNSSECMetadataType(t uint16) bool {
	switch t {
	case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3:
		return true
	}
	return false
}

// validateZone performs sanity checks on a parsed zone.
func (s *Signer) validateZone(domain string, records []dns.RR) error {
	return validateZoneRecords(domain, records)
}

// ValidateZoneFile validates a zone file without requiring a full Signer. It
// checks that the file is parseable and satisfies the same structural rules as
// the signing path (shared via validateZoneRecords).
func ValidateZoneFile(domain, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening zone file: %w", err)
	}
	defer f.Close()

	apex := dns.Fqdn(domain)

	var records []dns.RR
	zp := dns.NewZoneParser(f, apex, path)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		records = append(records, rr)
	}
	if err := zp.Err(); err != nil {
		return fmt.Errorf("parsing zone file: %w", err)
	}

	return validateZoneRecords(domain, records)
}

// signRecordsWithKeys signs all RRsets using the provided keys, handling
// rollover scenarios. RRsets are formed by canonical owner identity (RA6X-028)
// so every spelling of one wire name is signed as one RRset.
func (s *Signer) signRecordsWithKeys(domain string, records []dns.RR, keys *signingKeys) ([]dns.RR, error) {
	return s.signRecordsWithModel(newZoneModel(domain, records), domain, records, keys)
}

func (s *Signer) signRecordsWithModel(m *zoneModel, domain string, records []dns.RR, keys *signingKeys) ([]dns.RR, error) {
	rrsets, _ := groupRRsets(records)
	keysInOrder := sortedRRsetKeys(rrsets)

	inception := time.Now().UTC().Add(-1 * time.Hour) // 1 hour in the past for clock skew
	expiration := time.Now().UTC().Add(s.cfg.DNSSEC.SignatureValidity.Duration)

	var signedRecords []dns.RR
	signedRecords = append(signedRecords, records...)

	// Sign each RRset
	for _, k := range keysInOrder {
		rrset := rrsets[k]
		if len(rrset) == 0 {
			continue
		}

		// RFC 4035 §2.2: data below a zone cut (glue and anything else occluded)
		// is not authoritative in this zone — never sign it; at a delegation
		// point the parent is authoritative only for DS and the NSEC record.
		if !m.signable(k.name, k.rrtype) {
			slog.Debug("[SIGN] Skipping signature for non-authoritative RRset", "name", k.name, "type", dns.TypeToString[k.rrtype])
			continue
		}

		// The signature covers the wire-format RRset (RFC 4034 §6.2): sign over
		// copies with the canonical owner so divergent spellings form one RRset.
		wire := canonicalRRset(rrset)
		if k.rrtype == dns.TypeDNSKEY {
			// DNSKEY RRset is signed with ALL KSKs (for rollover support)
			for i, ksk := range keys.signingKSKs {
				rrsig := s.createRRSIG(wire, ksk, domain, inception, expiration)
				if err := s.signRRSIG(rrsig, wire, ksk, keys.signingKSKPs[i]); err != nil {
					return nil, fmt.Errorf("signing DNSKEY RRset with key %d: %w", ksk.KeyTag(), err)
				}
				signedRecords = append(signedRecords, rrsig)
			}
		} else {
			// All other RRsets are signed with the ZSK(s)
			// Multiple ZSKs during algorithm rollover
			for i, zsk := range keys.signingZSKs {
				rrsig := s.createRRSIG(wire, zsk, domain, inception, expiration)
				if err := s.signRRSIG(rrsig, wire, zsk, keys.signingZSKPs[i]); err != nil {
					return nil, fmt.Errorf("signing RRset %s with key %d: %w", rrset[0].Header().Name, zsk.KeyTag(), err)
				}
				signedRecords = append(signedRecords, rrsig)
			}
		}
	}

	return signedRecords, nil
}

// sortedRRsetKeys returns RRset keys in a deterministic order.
func sortedRRsetKeys(rrsets map[rrsetKey][]dns.RR) []rrsetKey {
	keys := make([]rrsetKey, 0, len(rrsets))
	for k := range rrsets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].name != keys[j].name {
			return canonicalLess(keys[i].name, keys[j].name)
		}
		return keys[i].rrtype < keys[j].rrtype
	})
	return keys
}

// verifySignedZone self-verifies the freshly produced records before they are
// published (R-001). It works entirely in memory on the exact records that will
// be written. `input` is the immutable data snapshot (zone data plus the
// DNSKEY RRset) the chain and signatures were produced from; every expectation
// is derived from it, never from what the generator emitted (RA6X-056). Any
// inconsistency returns an error, which keeps the previous signed output
// serving rather than shipping a zone that SERVFAILs.
//
// Checks: (1) every RRSIG cryptographically verifies against a published DNSKEY
// of the matching key tag and algorithm over the canonical RRset; (2) every
// RRset of the input survives, every signable RRset has a verifying RRSIG, and
// for every algorithm in the published DNSKEY RRset a key of the appropriate
// role (KSK for DNSKEY, ZSK otherwise) signs it (RFC 6840 §5.11, RA6X-001);
// (3) the denial chain for the configured mode is exactly the expected one:
// one NSEC per authoritative owner (or one NSEC3 per authoritative owner and
// empty non-terminal, with consistent parameters matching the apex
// NSEC3PARAM), in canonical/hash order, closed, with the type bitmap the
// input data dictates, and no records of the other denial mode.
func (s *Signer) verifySignedZone(domain string, input, signedRecords []dns.RR, keys *signingKeys) error {
	return s.verifySignedZoneWithModel(newZoneModel(domain, input), domain, input, signedRecords, keys)
}

func (s *Signer) verifySignedZoneWithModel(m *zoneModel, domain string, input, signedRecords []dns.RR, keys *signingKeys) error {
	dnskeysByTag := make(map[uint16][]*dns.DNSKEY)
	algorithms := make(map[uint8]bool)
	for _, dk := range keys.dnskeys {
		dnskeysByTag[dk.KeyTag()] = append(dnskeysByTag[dk.KeyTag()], dk)
		algorithms[dk.Algorithm] = true
	}

	rrsets, rrsigs := groupRRsets(signedRecords)
	var nsecs []*dns.NSEC
	var nsec3s []*dns.NSEC3
	var nsec3params []*dns.NSEC3PARAM
	for _, rr := range signedRecords {
		switch v := rr.(type) {
		case *dns.NSEC:
			nsecs = append(nsecs, v)
		case *dns.NSEC3:
			nsec3s = append(nsec3s, v)
		case *dns.NSEC3PARAM:
			nsec3params = append(nsec3params, v)
		}
	}

	// (1) Every RRSIG must verify against a published DNSKEY. Remember which
	// algorithm and key role produced a verifying signature per RRset.
	const roleKSK, roleZSK = 1, 2
	covered := make(map[rrsetKey]map[uint8]int)
	for _, sig := range rrsigs {
		k := rrsetKey{canonicalName(sig.Hdr.Name), sig.TypeCovered}
		rrset := rrsets[k]
		if len(rrset) == 0 {
			return fmt.Errorf("RRSIG for %s %s covers no RRset in the signed zone", sig.Hdr.Name, dns.TypeToString[sig.TypeCovered])
		}
		wire := canonicalRRset(rrset)
		candidates := dnskeysByTag[sig.KeyTag]
		if len(candidates) == 0 {
			return fmt.Errorf("RRSIG for %s %s references keytag %d absent from the published DNSKEY RRset", sig.Hdr.Name, dns.TypeToString[sig.TypeCovered], sig.KeyTag)
		}
		var signer *dns.DNSKEY
		var lastErr error
		for _, dk := range candidates {
			if dk.Algorithm != sig.Algorithm {
				continue
			}
			if err := sig.Verify(dk, wire); err == nil {
				signer = dk
				break
			} else {
				lastErr = err
			}
		}
		if signer == nil {
			return fmt.Errorf("RRSIG for %s %s (keytag %d) does not verify against the published DNSKEY: %v", sig.Hdr.Name, dns.TypeToString[sig.TypeCovered], sig.KeyTag, lastErr)
		}
		if covered[k] == nil {
			covered[k] = make(map[uint8]int)
		}
		role := roleZSK
		if signer.Flags&1 == 1 {
			role = roleKSK
		}
		covered[k][sig.Algorithm] |= role
	}

	// (2) Every input RRset survives and every signable RRset is signed by every
	// published algorithm with the appropriate role.
	inputSets, _ := groupRRsets(input)
	for k, in := range inputSets {
		if len(rrsets[k]) < len(in) {
			return fmt.Errorf("RRset %s %s from the input is missing or incomplete in the signed zone", k.name, dns.TypeToString[k.rrtype])
		}
	}
	for _, k := range sortedRRsetKeys(rrsets) {
		if !m.signable(k.name, k.rrtype) {
			continue
		}
		if len(covered[k]) == 0 {
			return fmt.Errorf("authoritative RRset %s %s has no covering RRSIG", k.name, dns.TypeToString[k.rrtype])
		}
		want := roleZSK
		roleName := "ZSK"
		if k.rrtype == dns.TypeDNSKEY {
			want = roleKSK
			roleName = "KSK"
		}
		for alg := range algorithms {
			if covered[k][alg]&want == 0 {
				return fmt.Errorf("RRset %s %s is not signed by a %s of algorithm %s although the DNSKEY RRset advertises that algorithm (RFC 6840 §5.11)", k.name, dns.TypeToString[k.rrtype], roleName, AlgorithmName(alg))
			}
		}
	}

	// (3) The denial chain must be exactly the one the input dictates.
	if s.cfg.DNSSEC.NSECVersion == "nsec3" {
		if len(nsecs) > 0 {
			return fmt.Errorf("NSEC records present in an NSEC3-signed zone")
		}
		return verifyNSEC3Expectations(m, nsec3s, nsec3params, uint16(s.cfg.DNSSEC.NSEC3Iterations), s.cfg.DNSSEC.NSEC3Salt)
	}
	if len(nsec3s) > 0 || len(nsec3params) > 0 {
		return fmt.Errorf("NSEC3 records present in an NSEC-signed zone")
	}
	return verifyNSECExpectations(m, nsecs)
}

// verifyNSECExpectations checks an NSEC chain against the owners and types the
// input snapshot dictates (RFC 4035 §2.3): one NSEC per authoritative owner in
// canonical order, each pointing at the next (the last at the first), and a
// type bitmap equal to the data at the owner plus NSEC and RRSIG.
func verifyNSECExpectations(m *zoneModel, nsecs []*dns.NSEC) error {
	expected := m.authoritativeOwners()
	if len(nsecs) == 0 {
		return fmt.Errorf("NSEC chain is missing: expected %d NSEC records, found none", len(expected))
	}
	byOwner := make(map[string]*dns.NSEC, len(nsecs))
	for _, n := range nsecs {
		owner := canonicalName(n.Hdr.Name)
		if _, dup := byOwner[owner]; dup {
			return fmt.Errorf("NSEC chain has a duplicate owner %s", owner)
		}
		byOwner[owner] = n
	}
	// Membership first (the most actionable diagnostics), then order and bitmaps.
	for _, owner := range expected {
		if byOwner[owner] == nil {
			return fmt.Errorf("NSEC chain is missing the record for authoritative owner %s", owner)
		}
	}
	for owner := range byOwner {
		if m.owners[owner] == nil || m.isOccluded(owner) {
			return fmt.Errorf("NSEC chain has a record at %s, which is not an authoritative owner of the zone", owner)
		}
	}
	for i, owner := range expected {
		n := byOwner[owner]
		next := expected[(i+1)%len(expected)]
		if got := canonicalName(n.NextDomain); got != next {
			return fmt.Errorf("NSEC at %s points at %s, expected %s (canonical order)", owner, got, next)
		}
		if err := compareTypeBitmap(owner, n.TypeBitMap, m.denialTypes(owner, false)); err != nil {
			return err
		}
	}
	return nil
}

// verifyNSEC3Expectations checks an NSEC3 chain against the input snapshot
// (RFC 5155 §7.1): exactly one NSEC3PARAM at the apex carrying the configured
// parameters, every NSEC3 using the same parameters, one NSEC3 per
// authoritative owner and empty non-terminal (hashed with those parameters)
// and none other, in hash order and closed, each with the type bitmap the
// data at its owner dictates.
func verifyNSEC3Expectations(m *zoneModel, nsec3s []*dns.NSEC3, params []*dns.NSEC3PARAM, iterations uint16, salt string) error {
	salt = strings.ToUpper(salt)
	if salt == "" {
		salt = "-"
	}
	normSalt := func(v string) string {
		v = strings.ToUpper(v)
		if v == "" {
			return "-"
		}
		return v
	}
	if len(params) != 1 {
		return fmt.Errorf("expected exactly one NSEC3PARAM at the apex, found %d", len(params))
	}
	p := params[0]
	if canonicalName(p.Hdr.Name) != m.apex {
		return fmt.Errorf("NSEC3PARAM is at %s, not at the apex %s", p.Hdr.Name, m.apex)
	}
	if p.Hash != dns.SHA1 || p.Flags != 0 || p.Iterations != iterations || normSalt(p.Salt) != salt {
		return fmt.Errorf("NSEC3PARAM (hash %d, flags %d, iterations %d, salt %s) does not match the configured parameters (hash 1, flags 0, iterations %d, salt %s)", p.Hash, p.Flags, p.Iterations, normSalt(p.Salt), iterations, salt)
	}

	type expect struct {
		owner string
		hash  string
	}
	var expected []expect
	for _, owner := range append(m.authoritativeOwners(), m.emptyNonTerminals()...) {
		expected = append(expected, expect{owner: owner, hash: strings.ToUpper(dns.HashName(owner, dns.SHA1, iterations, strings.TrimSuffix(salt, "-")))})
	}
	sort.Slice(expected, func(i, j int) bool { return expected[i].hash < expected[j].hash })
	if len(nsec3s) == 0 {
		return fmt.Errorf("NSEC3 chain is missing: expected %d NSEC3 records, found none", len(expected))
	}

	byHash := make(map[string]*dns.NSEC3, len(nsec3s))
	for _, n := range nsec3s {
		labels := dns.SplitDomainName(n.Hdr.Name)
		if len(labels) < 2 || joinLabels(labels[1:]) != m.apex {
			return fmt.Errorf("NSEC3 owner %s is not <hash>.%s", n.Hdr.Name, m.apex)
		}
		if n.Hash != dns.SHA1 || n.Flags != 0 || n.Iterations != iterations || normSalt(n.Salt) != salt {
			return fmt.Errorf("NSEC3 at %s (hash %d, flags %d, iterations %d, salt %s) does not match the NSEC3PARAM parameters", n.Hdr.Name, n.Hash, n.Flags, n.Iterations, normSalt(n.Salt))
		}
		hash := strings.ToUpper(labels[0])
		if _, dup := byHash[hash]; dup {
			return fmt.Errorf("NSEC3 chain has a duplicate owner hash %s", hash)
		}
		byHash[hash] = n
	}
	hashToOwner := make(map[string]string, len(expected))
	for _, e := range expected {
		hashToOwner[e.hash] = e.owner
	}
	for _, e := range expected {
		if byHash[e.hash] == nil {
			return fmt.Errorf("NSEC3 chain is missing the record for %s (hash %s)", e.owner, e.hash)
		}
	}
	for hash := range byHash {
		if _, ok := hashToOwner[hash]; !ok {
			return fmt.Errorf("NSEC3 chain has a record for hash %s, which is not the hash of any authoritative owner or empty non-terminal", hash)
		}
	}
	for i, e := range expected {
		n := byHash[e.hash]
		next := expected[(i+1)%len(expected)].hash
		if got := strings.ToUpper(n.NextDomain); got != next {
			return fmt.Errorf("NSEC3 for %s points at %s, expected %s (hash order)", e.owner, got, next)
		}
		if err := compareTypeBitmap(e.owner, n.TypeBitMap, m.denialTypes(e.owner, true)); err != nil {
			return err
		}
	}
	return nil
}

// compareTypeBitmap requires a denial record's type bitmap to equal the
// expected set exactly.
func compareTypeBitmap(owner string, got, want []uint16) error {
	g := append([]uint16(nil), got...)
	sort.Slice(g, func(i, j int) bool { return g[i] < g[j] })
	if len(g) != len(want) {
		return fmt.Errorf("denial record for %s lists types %s, expected %s", owner, typeList(g), typeList(want))
	}
	for i := range g {
		if g[i] != want[i] {
			return fmt.Errorf("denial record for %s lists types %s, expected %s", owner, typeList(g), typeList(want))
		}
	}
	return nil
}

func typeList(types []uint16) string {
	names := make([]string, len(types))
	for i, t := range types {
		names[i] = dns.TypeToString[t]
		if names[i] == "" {
			names[i] = fmt.Sprintf("TYPE%d", t)
		}
	}
	return "[" + strings.Join(names, " ") + "]"
}

// createRRSIG creates an RRSIG record for signing
func (s *Signer) createRRSIG(rrset []dns.RR, signingKey *dns.DNSKEY, domain string, inception, expiration time.Time) *dns.RRSIG {
	name := rrset[0].Header().Name
	labels := dns.CountLabel(name)

	// RFC 4035 §5.3.1: For wildcards, the Labels field excludes the wildcard label
	// So *.example.com has 2 labels, not 3. Judged on the canonical spelling so
	// an escaped asterisk is a wildcard too (RA6X-028).
	if strings.HasPrefix(canonicalName(name), "*.") {
		labels--
	}

	return &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    rrset[0].Header().Ttl,
		},
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm:   signingKey.Algorithm,
		Labels:      uint8(labels),
		OrigTtl:     rrset[0].Header().Ttl,
		Expiration:  uint32(expiration.Unix()),
		Inception:   uint32(inception.Unix()),
		KeyTag:      signingKey.KeyTag(),
		SignerName:  dns.Fqdn(domain),
	}
}

func (s *Signer) signRRSIG(rrsig *dns.RRSIG, rrset []dns.RR, key *dns.DNSKEY, privateKey []byte) error {
	switch key.Algorithm {
	case dns.ED25519:
		// crypto/ed25519.Sign PANICS if the key is not exactly 64 bytes. BIND/ldns and
		// RFC 8080 store the ED25519 private key as a 32-byte seed, so accept both the
		// 32-byte seed (expand it) and the 64-byte expanded form (R-010).
		var edKey ed25519.PrivateKey
		switch len(privateKey) {
		case ed25519.SeedSize: // 32-byte seed
			edKey = ed25519.NewKeyFromSeed(privateKey)
		case ed25519.PrivateKeySize: // 64-byte expanded key: derive from its seed (RA6X-030)
			edKey = ed25519.NewKeyFromSeed(privateKey[:ed25519.SeedSize])
		default:
			return fmt.Errorf("invalid ED25519 private key length %d (want %d or %d)", len(privateKey), ed25519.SeedSize, ed25519.PrivateKeySize)
		}
		return rrsig.Sign(edKey, rrset)
	case dns.ECDSAP256SHA256:
		if len(privateKey) != 32 {
			return fmt.Errorf("invalid ECDSA P-256 private key length %d (want 32)", len(privateKey))
		}
		// Reconstruct ECDSA P-256 private key
		ecdsaKey := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P256(),
			},
			D: new(big.Int).SetBytes(privateKey),
		}
		ecdsaKey.PublicKey.X, ecdsaKey.PublicKey.Y = ecdsaKey.PublicKey.Curve.ScalarBaseMult(privateKey)
		return rrsig.Sign(ecdsaKey, rrset)
	case dns.ECDSAP384SHA384:
		if len(privateKey) != 48 {
			return fmt.Errorf("invalid ECDSA P-384 private key length %d (want 48)", len(privateKey))
		}
		// Reconstruct ECDSA P-384 private key
		ecdsaKey := &ecdsa.PrivateKey{
			PublicKey: ecdsa.PublicKey{
				Curve: elliptic.P384(),
			},
			D: new(big.Int).SetBytes(privateKey),
		}
		ecdsaKey.PublicKey.X, ecdsaKey.PublicKey.Y = ecdsaKey.PublicKey.Curve.ScalarBaseMult(privateKey)
		return rrsig.Sign(ecdsaKey, rrset)
	default:
		return fmt.Errorf("unsupported algorithm: %d", key.Algorithm)
	}
}

// getSOAMinimumTTL extracts the minimum TTL from the SOA record (RFC 4035 §2.3)
func (s *Signer) getSOAMinimumTTL(records []dns.RR) uint32 {
	for _, rr := range records {
		if soa, ok := rr.(*dns.SOA); ok {
			return soa.Minttl
		}
	}
	return 3600 // fallback
}

// getSOATTL extracts the TTL of the SOA record itself (for DNSKEY TTL convention)
func (s *Signer) getSOATTL(records []dns.RR) uint32 {
	for _, rr := range records {
		if _, ok := rr.(*dns.SOA); ok {
			return rr.Header().Ttl
		}
	}
	return 3600 // fallback
}

func (s *Signer) generateNSECChain(domain string, records []dns.RR, soaMinTTL uint32) []dns.RR {
	return s.generateNSECChainWithModel(newZoneModel(domain, records), domain, records, soaMinTTL)
}

func (s *Signer) generateNSECChainWithModel(m *zoneModel, domain string, records []dns.RR, soaMinTTL uint32) []dns.RR {
	// Collect unique owner names that hold authoritative data or a
	// delegation NS RRset. Occluded names (below a zone cut) get no NSEC
	// (RFC 4035 §2.3), and neither do empty non-terminals: an NSEC (plus
	// its RRSIG) MUST NOT be the only RRset at any owner name (RFC 4035
	// §2.3) — ENT nonexistence-of-data is proven by the covering NSEC of
	// the next existing descendant name. Owners are canonical wire
	// identities (RA6X-028), so every spelling of a name is one owner.
	names := make(map[string]bool)
	typesByName := make(map[string]map[uint16]bool)

	for _, rr := range records {
		name := canonicalName(rr.Header().Name)
		if m.isOccluded(name) {
			continue
		}
		names[name] = true
		if typesByName[name] == nil {
			typesByName[name] = make(map[uint16]bool)
		}
		typesByName[name][rr.Header().Rrtype] = true
	}

	// Sort names canonically (RFC 4034 §6.1)
	var sortedNames []string
	for name := range names {
		sortedNames = append(sortedNames, name)
	}
	sort.Slice(sortedNames, func(i, j int) bool {
		return canonicalLess(sortedNames[i], sortedNames[j])
	})

	// Create NSEC chain
	var nsecRecords []dns.RR
	for i, name := range sortedNames {
		nextName := sortedNames[(i+1)%len(sortedNames)]

		// Collect types for this name. At a delegation point the parent is
		// authoritative only for NS, DS (if present), NSEC, and the NSEC's
		// RRSIG — glue address records at the cut stay out of the bitmap
		// (RFC 4035 §2.3; compare the root zone's insecure delegations:
		// "NS RRSIG NSEC").
		var types []uint16
		if m.isDelegation(name) {
			types = append(types, dns.TypeNS)
			if typesByName[name][dns.TypeDS] {
				types = append(types, dns.TypeDS)
			}
		} else {
			for t := range typesByName[name] {
				types = append(types, t)
			}
		}

		// Every name in the chain owns this NSEC and its RRSIG.
		types = append(types, dns.TypeNSEC, dns.TypeRRSIG)
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })

		nsec := &dns.NSEC{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeNSEC,
				Class:  dns.ClassINET,
				Ttl:    soaMinTTL, // RFC 4035 §2.3
			},
			NextDomain: nextName,
			TypeBitMap: types,
		}
		nsecRecords = append(nsecRecords, nsec)
	}

	return nsecRecords
}

// addEmptyNonTerminals adds empty non-terminal names (canonical) to the name set
func (s *Signer) addEmptyNonTerminals(names map[string]bool, typesByName map[string]map[uint16]bool, apex string) {
	// Collect all names first to avoid modifying map while iterating
	var allNames []string
	for name := range names {
		allNames = append(allNames, name)
	}
	apexLabels := dns.SplitDomainName(canonicalName(apex))

	for _, name := range allNames {
		// Walk up the tree to apex, adding empty non-terminals
		labels := dns.SplitDomainName(name)
		for i := 1; i < len(labels)-len(apexLabels); i++ {
			parent := joinLabels(labels[i:])
			if !names[parent] {
				names[parent] = true
				typesByName[parent] = make(map[uint16]bool) // Empty
			}
		}
	}
}

// canonicalLabelBytes converts a presentation-format DNS label to its
// canonical wire-format octets (RFC 4034 §6.1): decimal `\DDD` and `\X` escapes
// are resolved to the raw bytes they denote, and ASCII A–Z is lowercased. This
// must be done on the unescaped octets — comparing presentation strings
// mis-orders names containing escaped octets relative to wire order (R-066).
func canonicalLabelBytes(label string) []byte {
	out := make([]byte, 0, len(label))
	for i := 0; i < len(label); i++ {
		b := label[i]
		if b == '\\' && i+1 < len(label) {
			// \DDD decimal escape (exactly three digits) or \X single-char escape.
			if i+3 < len(label) &&
				label[i+1] >= '0' && label[i+1] <= '9' &&
				label[i+2] >= '0' && label[i+2] <= '9' &&
				label[i+3] >= '0' && label[i+3] <= '9' {
				b = byte((int(label[i+1]-'0')*100 + int(label[i+2]-'0')*10 + int(label[i+3]-'0')))
				i += 3
			} else {
				b = label[i+1]
				i++
			}
		}
		if b >= 'A' && b <= 'Z' {
			b += 32 // lowercase ASCII per canonical form
		}
		out = append(out, b)
	}
	return out
}

// canonicalLess compares two domain names in canonical order (RFC 4034 §6.1):
// right-to-left, label by label, each label compared as canonical wire-format
// octets (see canonicalLabelBytes) so escaped-octet owner names order correctly.
func canonicalLess(a, b string) bool {
	aLabels := dns.SplitDomainName(a)
	bLabels := dns.SplitDomainName(b)

	for i := 0; ; i++ {
		aIdx := len(aLabels) - 1 - i
		bIdx := len(bLabels) - 1 - i

		if aIdx < 0 && bIdx < 0 {
			return false // Equal
		}
		if aIdx < 0 {
			return true // Shorter name (fewer labels) comes first
		}
		if bIdx < 0 {
			return false
		}

		switch bytes.Compare(canonicalLabelBytes(aLabels[aIdx]), canonicalLabelBytes(bLabels[bIdx])) {
		case -1:
			return true
		case 1:
			return false
		}
		// Labels equal, continue to the next-more-significant label.
	}
}

func (s *Signer) generateNSEC3Chain(domain string, records []dns.RR, soaMinTTL uint32) ([]dns.RR, error) {
	return s.generateNSEC3ChainWithModel(newZoneModel(domain, records), domain, records, soaMinTTL)
}

func (s *Signer) generateNSEC3ChainWithModel(m *zoneModel, domain string, records []dns.RR, soaMinTTL uint32) ([]dns.RR, error) {
	// NSEC3 parameters
	iterations := uint16(s.cfg.DNSSEC.NSEC3Iterations)
	salt := s.cfg.DNSSEC.NSEC3Salt
	apex := m.apex

	// Collect unique owner names and their types. Occluded names (below a
	// zone cut) get no NSEC3 (RFC 5155 §7.1 covers only names with
	// authoritative data or at delegation points). Owners are canonical wire
	// identities (RA6X-028).
	names := make(map[string]bool)
	typesByName := make(map[string]map[uint16]bool)

	for _, rr := range records {
		name := canonicalName(rr.Header().Name)
		if m.isOccluded(name) {
			continue
		}
		names[name] = true
		if typesByName[name] == nil {
			typesByName[name] = make(map[uint16]bool)
		}
		typesByName[name][rr.Header().Rrtype] = true
	}

	// The NSEC3PARAM record (appended below) lives at the apex, so the
	// apex bitmap must list it (RFC 5155 §7.1).
	if typesByName[apex] != nil {
		typesByName[apex][dns.TypeNSEC3PARAM] = true
	}

	// Add empty non-terminals (RFC 5155 §7.1)
	s.addEmptyNonTerminals(names, typesByName, apex)

	// Hash all names
	type hashedName struct {
		original string
		hashed   string
	}
	var hashedNames []hashedName

	for name := range names {
		hashed := dns.HashName(name, dns.SHA1, iterations, salt)
		hashedNames = append(hashedNames, hashedName{original: name, hashed: hashed})
	}

	// Sort by hash
	sort.Slice(hashedNames, func(i, j int) bool {
		return hashedNames[i].hashed < hashedNames[j].hashed
	})

	// Create NSEC3 records
	var nsec3Records []dns.RR

	// Add NSEC3PARAM at zone apex
	nsec3param := &dns.NSEC3PARAM{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(domain),
			Rrtype: dns.TypeNSEC3PARAM,
			Class:  dns.ClassINET,
			Ttl:    0, // RFC 5155 §4.2: SHOULD be zero
		},
		Hash:       dns.SHA1,
		Flags:      0,
		Iterations: iterations,
		Salt:       salt,
		SaltLength: uint8(len(salt) / 2), // Salt is hex encoded
	}
	nsec3Records = append(nsec3Records, nsec3param)

	// Create NSEC3 chain
	for i, hn := range hashedNames {
		nextHash := hashedNames[(i+1)%len(hashedNames)].hashed

		// Collect types present at the *original* owner name (the NSEC3
		// record and its RRSIG live at the hashed name, so unlike NSEC they
		// never appear in their own bitmap). At a delegation point the
		// parent holds only NS and DS (glue stays out); the RRSIG bit is
		// set only when signed RRsets exist at the original name — i.e.
		// not at insecure delegations, and not at empty non-terminals,
		// which keep an empty bitmap (RFC 5155 §7.1).
		var types []uint16
		if m.isDelegation(hn.original) {
			types = append(types, dns.TypeNS)
			if typesByName[hn.original][dns.TypeDS] {
				types = append(types, dns.TypeDS, dns.TypeRRSIG)
			}
		} else if len(typesByName[hn.original]) > 0 {
			for t := range typesByName[hn.original] {
				types = append(types, t)
			}
			types = append(types, dns.TypeRRSIG)
		}
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })

		nsec3 := &dns.NSEC3{
			Hdr: dns.RR_Header{
				Name:   hn.hashed + "." + dns.Fqdn(domain),
				Rrtype: dns.TypeNSEC3,
				Class:  dns.ClassINET,
				Ttl:    soaMinTTL, // RFC 4035 §2.3
			},
			Hash:       dns.SHA1,
			Flags:      0,
			Iterations: iterations,
			Salt:       salt,
			SaltLength: uint8(len(salt) / 2),
			HashLength: 20, // SHA-1 produces 20 bytes
			NextDomain: nextHash,
			TypeBitMap: types,
		}
		nsec3Records = append(nsec3Records, nsec3)
	}

	return nsec3Records, nil
}

func (s *Signer) writeSignedZone(domain, path string, records []dns.RR) error {
	// Ensure output directory exists
	if err := EnsureDir(filepath.Dir(path)); err != nil {
		return err
	}

	// Sort records: SOA first, then NS, then others, with RRSIG after each RRset
	sortedRecords := sortZoneRecords(domain, records)

	// Write to a UNIQUE temp file in the output dir, then rename for atomicity. This
	// prevents NSD from picking up a partial zone if the process is killed mid-write.
	// A fixed "<path>.tmp" is shared by the daemon's signing loop and any concurrent CLI
	// sign of the same zone; both O_TRUNC the same file and interleave, so whichever
	// renames first publishes corrupted content (R-002). os.CreateTemp gives each writer
	// its own temp file. Mode 0644 so NSD (running as a different user) can read the
	// signed zone; explicit Chmod defeats a restrictive umask on the daemon process.
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tempPath := f.Name()
	if err = f.Chmod(0644); err != nil {
		f.Close()
		os.Remove(tempPath)
		return fmt.Errorf("chmod signed zone: %w", err)
	}
	defer func() {
		f.Close()
		// Clean up temp file on error (rename already happened on success)
		if err != nil {
			os.Remove(tempPath)
		}
	}()

	// Write header
	if _, err = fmt.Fprintf(f, "; Signed zone file for %s\n", domain); err != nil {
		return fmt.Errorf("writing zone header: %w", err)
	}
	if _, err = fmt.Fprintf(f, "; Generated by dnssec-tudor at %s\n", time.Now().UTC().Format(time.RFC3339)); err != nil {
		return fmt.Errorf("writing zone header: %w", err)
	}
	if _, err = fmt.Fprintf(f, "; DO NOT EDIT - this file is automatically generated\n\n"); err != nil {
		return fmt.Errorf("writing zone header: %w", err)
	}

	if _, err = fmt.Fprintf(f, "$ORIGIN %s\n", dns.Fqdn(domain)); err != nil {
		return fmt.Errorf("writing zone origin: %w", err)
	}

	for _, rr := range sortedRecords {
		if _, err = fmt.Fprintln(f, rr.String()); err != nil {
			return fmt.Errorf("writing zone record: %w", err)
		}
	}

	// Flush to disk before rename
	if err = f.Sync(); err != nil {
		return fmt.Errorf("syncing signed zone: %w", err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("closing signed zone: %w", err)
	}

	if err = os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("renaming signed zone: %w", err)
	}

	// R-020: fsync the parent directory so the renamed signed zone survives a power
	// loss, matching the file-and-directory durability contract used for state/config
	// (writeFileAtomicOwned). Without this the directory entry can be lost after state
	// was saved with a new serial, leaving NeedsSign to trust state and decline to
	// recreate the missing output. A sync failure is reported as a durability
	// outcome: the signed zone is visible and stays the current generation (RA6X-049).
	if err := fsutil.SyncDir(filepath.Dir(path)); err != nil {
		return &fsutil.DurabilityError{Path: path, Err: err}
	}

	return nil
}

func sortZoneRecords(domain string, records []dns.RR) []dns.RR {
	// Group by name and type
	type rrKey struct {
		name   string
		rrtype uint16
	}

	groups := make(map[rrKey][]dns.RR)
	var keys []rrKey

	for _, rr := range records {
		key := rrKey{name: canonicalName(rr.Header().Name), rrtype: rr.Header().Rrtype}
		if _, exists := groups[key]; !exists {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], rr)
	}

	// Sort keys: apex first, then by name, then by type (SOA, NS, DNSKEY, then others).
	// Keys are canonical owner identities (RA6X-028), so a mixed-case zone key
	// in config (e.g. "Example.COM") still sorts apex-first (R-063).
	apex := canonicalName(domain)
	sort.Slice(keys, func(i, j int) bool {
		// Apex comes first
		iApex := keys[i].name == apex
		jApex := keys[j].name == apex
		if iApex != jApex {
			return iApex
		}

		// Within same name, sort by type
		if keys[i].name == keys[j].name {
			// Special ordering: SOA < NS < DNSKEY < others
			typeOrder := func(t uint16) int {
				switch t {
				case dns.TypeSOA:
					return 0
				case dns.TypeNS:
					return 1
				case dns.TypeDNSKEY:
					return 2
				case dns.TypeRRSIG:
					return 100 // RRSIG comes last
				default:
					return 50
				}
			}
			return typeOrder(keys[i].rrtype) < typeOrder(keys[j].rrtype)
		}

		return keys[i].name < keys[j].name
	})

	// Flatten
	var result []dns.RR
	for _, key := range keys {
		result = append(result, groups[key]...)
	}

	return result
}

func (s *Signer) checkRolloverWarnings(domain string, zoneState *statepkg.ZoneState) {
	now := time.Now().UTC()

	// Check KSK rollover due
	if zoneState.KSK != nil && now.After(zoneState.KSK.RolloverDue) {
		zoneState.AddWarning("KSK rollover due - run 'dnssec-tudor rollover start " + domain + "'")
	}

	// Check ZSK rollover (this is automatic, but warn if close)
	if zoneState.ZSK != nil {
		daysUntilExpiry := zoneState.ZSK.Expires.Sub(now).Hours() / 24
		if daysUntilExpiry < 14 && daysUntilExpiry > 0 {
			zoneState.AddWarning(fmt.Sprintf("ZSK expires in %.0f days (will auto-rollover)", daysUntilExpiry))
		}
	}
}
