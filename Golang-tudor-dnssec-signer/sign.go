package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Signer handles DNSSEC signing operations
type Signer struct {
	cfg   *Config
	state *State
}

// NewSigner creates a new signer
func NewSigner(cfg *Config, state *State) *Signer {
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
			ksk, zsk, err := recoverOrGenerateKeys(keyGen, domain)
			if err != nil {
				slog.Error("[SIGN] Cannot initialize zone; skipping", "domain", domain, "error", err)
				placeholder := &ZoneState{Path: zoneCfg.Path}
				placeholder.AddError(err.Error())
				s.state.SetZone(domain, placeholder)
				failed++
				continue
			}
			zoneState = &ZoneState{
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

	slog.Info("[SIGN] Signing zone", "domain", domain, "path", zoneState.Path)

	// Capture the source file's mtime/size at PARSE time so it becomes the
	// change-detection reference (R-022). Recording it here — not after signing —
	// means an edit that lands between this parse and the LastSigned stamp is
	// still detected on the next NeedsSign. A stat failure is non-fatal (the
	// parse below will surface a real read error); leave the reference untouched.
	var srcModTime time.Time
	var srcSize int64
	if fi, statErr := os.Stat(zoneState.Path); statErr == nil {
		srcModTime = fi.ModTime()
		srcSize = fi.Size()
	}

	// Parse the zone file
	records, serial, err := s.parseZoneFile(domain, zoneState.Path)
	if err != nil {
		return fmt.Errorf("parsing zone file: %w", err)
	}

	// Compute the serial to publish and rewrite the SOA before anything is
	// signed — the SOA RRset's RRSIG covers the published serial.
	published, err := s.publishedSerial(domain, serial, zoneState)
	if err != nil {
		return err
	}
	if published != serial {
		setSOASerial(records, published)
	}

	// Extract SOA minimum TTL for NSEC/NSEC3 records (RFC 4035 §2.3)
	soaMinTTL := s.getSOAMinimumTTL(records)

	// Load keys - handling rollover scenarios
	keyGen := NewKeyGenerator(s.cfg)
	keys, err := s.loadKeysForSigning(domain, keyGen, zoneState)
	if err != nil {
		return fmt.Errorf("loading keys: %w", err)
	}

	// Determine DNSKEY TTL: use config value or SOA TTL
	dnskeyTTL := s.cfg.DNSSEC.DNSKEYTtl
	if dnskeyTTL == 0 {
		dnskeyTTL = s.getSOATTL(records) // Use SOA record TTL as convention
	}

	// Add all DNSKEY records with appropriate TTL (may include rollover keys)
	for _, k := range keys.dnskeys {
		k.Hdr.Ttl = dnskeyTTL
		records = append(records, k)
	}

	// Generate NSEC/NSEC3 chain
	if s.cfg.DNSSEC.NSECVersion == "nsec3" {
		nsec3Records, err := s.generateNSEC3Chain(domain, records, soaMinTTL)
		if err != nil {
			return fmt.Errorf("generating NSEC3 chain: %w", err)
		}
		records = append(records, nsec3Records...)
	} else {
		nsecRecords := s.generateNSECChain(domain, records, soaMinTTL)
		records = append(records, nsecRecords...)
	}

	// Sign all RRsets
	signedRecords, err := s.signRecordsWithKeys(domain, records, keys)
	if err != nil {
		return fmt.Errorf("signing records: %w", err)
	}

	// R-001: self-verify the produced records before publishing. If signing produced
	// something internally inconsistent (an RRSIG that doesn't verify, an unsigned
	// authoritative RRset, a broken NSEC/NSEC3 chain), fail here so the previous signed
	// output keeps serving instead of shipping a zone that SERVFAILs at every resolver.
	if err := s.verifySignedZone(domain, signedRecords, keys); err != nil {
		return fmt.Errorf("post-sign verification failed (previous signed zone kept): %w", err)
	}

	// Write signed zone
	outputPath := filepath.Join(s.cfg.OutputDir, fmt.Sprintf("%s.zone.signed", domain))
	if err := s.writeSignedZone(domain, outputPath, signedRecords); err != nil {
		return fmt.Errorf("writing signed zone: %w", err)
	}

	// Update state under the write lock so concurrent readers (web UI,
	// health checks) never observe a half-updated zone.
	now := time.Now().UTC()
	s.state.Mutate(func() {
		zoneState.Serial = serial
		zoneState.PublishedSerial = published
		zoneState.LastSigned = now
		if !srcModTime.IsZero() {
			zoneState.SourceModTime = srcModTime
			zoneState.SourceSize = srcSize
		}
		zoneState.SignaturesExp = now.Add(s.cfg.DNSSEC.SignatureValidity.Duration)
		zoneState.ForceResign = false
		zoneState.ClearWarnings()

		// Check for upcoming rollovers
		s.checkRolloverWarnings(domain, zoneState)
	})

	// Record successful signing metrics
	duration := time.Since(startTime).Seconds()
	RecordSigningOperation(domain, duration, true)

	slog.Info("[SIGN] Zone signed successfully", "domain", domain, "serial", serial, "published_serial", published, "output", outputPath, "duration_ms", int64(duration*1000))
	return nil
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
func (s *Signer) publishedSerial(domain string, serial uint32, zoneState *ZoneState) (uint32, error) {
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
func (s *Signer) loadKeysForSigning(domain string, keyGen *KeyGenerator, zoneState *ZoneState) (*signingKeys, error) {
	keys := &signingKeys{}

	// Load current KSK
	ksk, kskPriv, err := keyGen.LoadKeyPair(domain, "ksk")
	if err != nil {
		return nil, fmt.Errorf("loading KSK: %w", err)
	}
	keys.dnskeys = append(keys.dnskeys, ksk)
	keys.signingKSKs = append(keys.signingKSKs, ksk)
	keys.signingKSKPs = append(keys.signingKSKPs, kskPriv)

	// Load current ZSK
	zsk, zskPriv, err := keyGen.LoadKeyPair(domain, "zsk")
	if err != nil {
		return nil, fmt.Errorf("loading ZSK: %w", err)
	}
	keys.dnskeys = append(keys.dnskeys, zsk)
	keys.signingZSKs = append(keys.signingZSKs, zsk)
	keys.signingZSKPs = append(keys.signingZSKPs, zskPriv)

	// Handle rollover scenarios
	if zoneState.Rollover != nil {
		switch {
		case zoneState.Rollover.Type == "ksk" && zoneState.Rollover.State == KSKRolloverStateDSAddWait:
			// KSK rollover: load old KSK too, sign with both. FATAL on failure (R-003):
			// during ds_add_wait the parent DS still references the old KSK, so publishing
			// a DNSKEY RRset without it makes every resolver validating via the old DS go
			// bogus. Failing keeps the previous good signed zone in place.
			oldKSK, oldKSKPriv, err := keyGen.loadKeyPairByID(domain, "ksk", zoneState.Rollover.OldKeyID)
			if err != nil {
				return nil, fmt.Errorf("loading old KSK %d for rollover signing (if the rollover is complete and the old key is gone, run `dnssec-tudor rollover complete %s`): %w", zoneState.Rollover.OldKeyID, domain, err)
			}
			keys.dnskeys = append(keys.dnskeys, oldKSK)
			keys.signingKSKs = append(keys.signingKSKs, oldKSK)
			keys.signingKSKPs = append(keys.signingKSKPs, oldKSKPriv)
			slog.Info("[SIGN] KSK rollover: signing with both old and new KSK",
				"old_key_id", zoneState.Rollover.OldKeyID,
				"new_key_id", zoneState.Rollover.NewKeyID)

		case zoneState.Rollover.Type == "zsk" && zoneState.Rollover.State == ZSKRolloverStatePrePublish:
			// ZSK pre-publish: publish BOTH old and new ZSK in the DNSKEY
			// RRset, but continue signing every non-DNSKEY RRset with the OLD
			// ZSK. The new ZSK is already in keys.dnskeys via the
			// LoadKeyPair("zsk") call above (saveKeyFiles renamed the old
			// key file aside when the rollover started, so the *.zsk.key
			// path now resolves to the new key). Append the OLD ZSK so the
			// signing key's keytag actually appears in the published RRset
			// — without this, RRSIGs reference a DNSKEY that isn't there
			// and every validating resolver returns bogus.
			//
			// A load failure here is fatal. Falling back to signing-with-new
			// would defeat pre-publish (resolvers haven't cached the new key
			// yet) and emit a structurally-different signed zone than the
			// one operators are expecting from the rollover state. Returning
			// an error keeps the previously-emitted signed zone in place.
			oldZSK, oldZSKPriv, err := keyGen.loadKeyPairByID(domain, "zsk", zoneState.Rollover.OldKeyID)
			if err != nil {
				return nil, fmt.Errorf("loading old ZSK %d for pre-publish: %w", zoneState.Rollover.OldKeyID, err)
			}
			keys.dnskeys = append(keys.dnskeys, oldZSK)
			keys.signingZSKs = []*dns.DNSKEY{oldZSK}
			keys.signingZSKPs = [][]byte{oldZSKPriv}
			slog.Info("[SIGN] ZSK rollover pre-publish: publishing both, signing with old",
				"old_key_id", zoneState.Rollover.OldKeyID,
				"new_key_id", zoneState.Rollover.NewKeyID)

		case zoneState.Rollover.Type == "zsk" && zoneState.Rollover.State == ZSKRolloverStateSigning:
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

		case zoneState.Rollover.Type == "algorithm" && zoneState.Rollover.State == AlgoRolloverStateDSAddWait:
			// Algorithm rollover: publish and sign with BOTH algorithms' keys. FATAL on
			// failure (R-003): dropping an old-algorithm key mid-rollover leaves RRsets
			// unsigned for a signaled algorithm, violating RFC 4035 §2.2 / RFC 6840 §5.11.
			oldKSK, oldKSKPriv, err := keyGen.loadKeyPairByID(domain, "ksk", zoneState.Rollover.OldKeyID)
			if err != nil {
				return nil, fmt.Errorf("loading old-algorithm KSK %d for rollover (if the rollover is complete and the old key is gone, run `dnssec-tudor rollover complete %s`): %w", zoneState.Rollover.OldKeyID, domain, err)
			}
			keys.dnskeys = append(keys.dnskeys, oldKSK)
			keys.signingKSKs = append(keys.signingKSKs, oldKSK)
			keys.signingKSKPs = append(keys.signingKSKPs, oldKSKPriv)

			// Load old ZSK using stored ID
			oldZSK, oldZSKPriv, err := keyGen.loadKeyPairByID(domain, "zsk", zoneState.Rollover.OldZSKID)
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
	return keys, nil
}

const (
	// zoneWriteQuiescenceWindow: a source change whose mtime is this fresh is
	// treated as possibly still-being-written and re-checked before signing.
	zoneWriteQuiescenceWindow = 3 * time.Second
	// zoneWriteSettleDelay: how long to wait before the quiescence re-stat.
	zoneWriteSettleDelay = 750 * time.Millisecond
)

// NeedsSign checks if a zone needs to be signed
func (s *Signer) NeedsSign(domain, zonePath string, zoneState *ZoneState) (bool, string) {
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
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	var records []dns.RR
	var serial uint32

	// $INCLUDE is intentionally NOT enabled (SetIncludeAllowed stays false): the
	// signer manages one self-contained zone file per zone, and enabling
	// includes would add an arbitrary-file-read surface plus cwd-relative path
	// ambiguity for a daemon that may run from `/`. A zone using $INCLUDE fails
	// with miekg's clear "$INCLUDE directive not allowed" error naming the line;
	// the limitation is documented in CLAUDE.md (R-065). Inline the records.
	zp := dns.NewZoneParser(f, dns.Fqdn(domain), path)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		records = append(records, rr)

		// Extract serial from SOA
		if soa, ok := rr.(*dns.SOA); ok {
			serial = soa.Serial
		}
	}

	if err := zp.Err(); err != nil {
		return nil, 0, fmt.Errorf("parsing zone: %w", err)
	}

	// Strip any DNSSEC records the signer manages itself before validation and
	// chain generation (R-034), so an already-signed file fed by mistake is
	// re-signed cleanly instead of producing a duplicated/self-referential chain.
	records = stripInputDNSSEC(domain, records)

	// Validate zone structure
	if err := s.validateZone(domain, records); err != nil {
		return nil, 0, fmt.Errorf("zone validation failed: %w", err)
	}

	return records, serial, nil
}

// stripInputDNSSEC removes DNSSEC records that the signer generates itself from a
// parsed input zone — stale RRSIG/NSEC/NSEC3/NSEC3PARAM and any apex DNSKEY — so
// re-signing produces a valid single chain rather than duplicating/conflicting
// with the input's records or signing a stray RRSIG RRset. DS records at
// delegations are legitimate and preserved. R-034.
func stripInputDNSSEC(domain string, records []dns.RR) []dns.RR {
	apexLower := strings.ToLower(dns.Fqdn(domain))
	out := make([]dns.RR, 0, len(records))
	stripped := 0
	for _, rr := range records {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG, dns.TypeNSEC, dns.TypeNSEC3, dns.TypeNSEC3PARAM:
			stripped++
			continue
		case dns.TypeDNSKEY:
			// The signer manages the apex DNSKEY RRset; drop any in the input.
			if strings.ToLower(rr.Header().Name) == apexLower {
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

// validateZoneRecords is the single source of truth for the structural sanity
// rules a zone must satisfy before signing: exactly one SOA at the apex, at
// least one NS at the apex, and every authoritative owner name at or below the
// apex (R-035). Both the in-memory signing path (Signer.validateZone) and the
// file-based CLI path (ValidateZoneFile) call this so the rules can't drift
// between `add`/`import` and signing (R-075).
func validateZoneRecords(domain string, records []dns.RR) error {
	apex := dns.Fqdn(domain)
	apexLower := strings.ToLower(apex)

	var soaCount int
	var nsAtApex bool

	for _, rr := range records {
		name := strings.ToLower(rr.Header().Name)

		// Every authoritative owner name must be at or below the apex. An
		// out-of-zone owner (a typo, or the wrong file) would otherwise be signed
		// and inserted into the NSEC/NSEC3 chain, breaking canonical ordering and
		// the denial-of-existence proofs (the chain would "cover" names outside
		// the zone). Reject rather than emit a subtly broken zone (R-035).
		if !dns.IsSubDomain(apex, rr.Header().Name) {
			return fmt.Errorf("record owner %s is not within zone %s", rr.Header().Name, apex)
		}

		switch rr.Header().Rrtype {
		case dns.TypeSOA:
			soaCount++
			if name != apexLower {
				return fmt.Errorf("SOA record at %s not at zone apex %s", name, apex)
			}
		case dns.TypeNS:
			if name == apexLower {
				nsAtApex = true
			}
		}
	}

	if soaCount == 0 {
		return fmt.Errorf("zone has no SOA record")
	}
	if soaCount > 1 {
		return fmt.Errorf("zone has %d SOA records (must have exactly 1)", soaCount)
	}
	if !nsAtApex {
		return fmt.Errorf("zone has no NS records at apex")
	}

	return nil
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

// delegationInfo holds information about delegation points in a zone
type delegationInfo struct {
	delegationPoints map[string]bool // lowercase FQDNs with NS records (not at apex)
}

// findDelegationPoints identifies delegation points (NS RRsets below the apex)
// per RFC 4035 §2.2
func (s *Signer) findDelegationPoints(domain string, records []dns.RR) *delegationInfo {
	apexLower := strings.ToLower(dns.Fqdn(domain))
	info := &delegationInfo{
		delegationPoints: make(map[string]bool),
	}

	for _, rr := range records {
		if rr.Header().Rrtype == dns.TypeNS {
			name := strings.ToLower(rr.Header().Name)
			if name != apexLower {
				info.delegationPoints[name] = true
			}
		}
	}

	if len(info.delegationPoints) > 0 {
		slog.Debug("[SIGN] Found delegation points", "count", len(info.delegationPoints))
	}

	return info
}

// isOccluded reports whether a (lowercase, fully-qualified) name sits
// strictly below a delegation point. Everything at such names — glue address
// records and any other stray data — is not authoritative in this zone:
// it is never signed and never appears in the NSEC/NSEC3 chain.
func (di *delegationInfo) isOccluded(name string) bool {
	for dp := range di.delegationPoints {
		if strings.HasSuffix(name, "."+dp) {
			return true
		}
	}
	return false
}

// signRecordsWithKeys signs all RRsets using the provided keys, handling rollover scenarios
func (s *Signer) signRecordsWithKeys(domain string, records []dns.RR, keys *signingKeys) ([]dns.RR, error) {
	// Find delegation points (RFC 4035 §2.2)
	delInfo := s.findDelegationPoints(domain, records)

	// Group records by RRset (name + type)
	rrsets := make(map[string][]dns.RR)
	for _, rr := range records {
		key := fmt.Sprintf("%s:%d", strings.ToLower(rr.Header().Name), rr.Header().Rrtype)
		rrsets[key] = append(rrsets[key], rr)
	}

	inception := time.Now().UTC().Add(-1 * time.Hour) // 1 hour in the past for clock skew
	expiration := time.Now().UTC().Add(s.cfg.DNSSEC.SignatureValidity.Duration)

	var signedRecords []dns.RR
	signedRecords = append(signedRecords, records...)

	// Sign each RRset
	for _, rrset := range rrsets {
		if len(rrset) == 0 {
			continue
		}

		name := strings.ToLower(rrset[0].Header().Name)
		rrtype := rrset[0].Header().Rrtype

		// RFC 4035 §2.2: data below a zone cut (glue and anything else
		// occluded) is not authoritative in this zone — never sign it.
		if delInfo.isOccluded(name) {
			slog.Debug("[SIGN] Skipping signature for occluded name", "name", name, "type", dns.TypeToString[rrtype])
			continue
		}

		// RFC 4035 §2.2: at a delegation point the parent is authoritative
		// only for DS and the NSEC record — the NS RRset and any glue
		// address records at the cut itself stay unsigned.
		if delInfo.delegationPoints[name] && rrtype != dns.TypeDS && rrtype != dns.TypeNSEC {
			slog.Debug("[SIGN] Skipping signature at delegation point", "name", name, "type", dns.TypeToString[rrtype])
			continue
		}

		if rrtype == dns.TypeDNSKEY {
			// DNSKEY RRset is signed with ALL KSKs (for rollover support)
			for i, ksk := range keys.signingKSKs {
				rrsig := s.createRRSIG(rrset, ksk, domain, inception, expiration)
				if err := s.signRRSIG(rrsig, rrset, ksk, keys.signingKSKPs[i]); err != nil {
					return nil, fmt.Errorf("signing DNSKEY RRset with key %d: %w", ksk.KeyTag(), err)
				}
				signedRecords = append(signedRecords, rrsig)
			}
		} else {
			// All other RRsets are signed with the ZSK(s)
			// Multiple ZSKs during algorithm rollover
			for i, zsk := range keys.signingZSKs {
				rrsig := s.createRRSIG(rrset, zsk, domain, inception, expiration)
				if err := s.signRRSIG(rrsig, rrset, zsk, keys.signingZSKPs[i]); err != nil {
					return nil, fmt.Errorf("signing RRset %s with key %d: %w", rrset[0].Header().Name, zsk.KeyTag(), err)
				}
				signedRecords = append(signedRecords, rrsig)
			}
		}
	}

	return signedRecords, nil
}

// verifySignedZone self-verifies the freshly produced records before they are published
// (R-001). It works entirely in-memory on the exact records that will be written, reusing
// the signer's own delegation model so verifier and signer share one view of what is
// authoritative (no differential parsing). Any inconsistency returns an error, which keeps
// the previous signed output serving rather than shipping a zone that SERVFAILs.
//
// Checks: (1) every RRSIG cryptographically verifies against a published DNSKEY of the
// matching keytag/algorithm (catches wrong Labels/OrigTtl, key mixups, corrupt sigs);
// (2) every non-occluded, non-delegation authoritative RRset (plus DS/NSEC at delegation
// points) has at least one covering RRSIG; (3) the NSEC/NSEC3 Next pointers form a single
// closed cycle over every emitted owner.
func (s *Signer) verifySignedZone(domain string, signedRecords []dns.RR, keys *signingKeys) error {
	delInfo := s.findDelegationPoints(domain, signedRecords)

	dnskeysByTag := make(map[uint16][]*dns.DNSKEY)
	for _, dk := range keys.dnskeys {
		dnskeysByTag[dk.KeyTag()] = append(dnskeysByTag[dk.KeyTag()], dk)
	}

	type rrsetKey struct {
		name   string
		rrtype uint16
	}
	rrsets := make(map[rrsetKey][]dns.RR)
	var rrsigs []*dns.RRSIG
	var nsecs []*dns.NSEC
	var nsec3s []*dns.NSEC3
	for _, rr := range signedRecords {
		if sig, ok := rr.(*dns.RRSIG); ok {
			rrsigs = append(rrsigs, sig)
			continue
		}
		name := strings.ToLower(rr.Header().Name)
		k := rrsetKey{name, rr.Header().Rrtype}
		rrsets[k] = append(rrsets[k], rr)
		switch v := rr.(type) {
		case *dns.NSEC:
			nsecs = append(nsecs, v)
		case *dns.NSEC3:
			nsec3s = append(nsec3s, v)
		}
	}

	// (1) Every RRSIG must verify against a published DNSKEY.
	covered := make(map[rrsetKey]bool)
	for _, sig := range rrsigs {
		k := rrsetKey{strings.ToLower(sig.Hdr.Name), sig.TypeCovered}
		rrset := rrsets[k]
		if len(rrset) == 0 {
			return fmt.Errorf("RRSIG for %s %s covers no RRset in the signed zone", sig.Hdr.Name, dns.TypeToString[sig.TypeCovered])
		}
		candidates := dnskeysByTag[sig.KeyTag]
		if len(candidates) == 0 {
			return fmt.Errorf("RRSIG for %s %s references keytag %d absent from the published DNSKEY RRset", sig.Hdr.Name, dns.TypeToString[sig.TypeCovered], sig.KeyTag)
		}
		verified := false
		var lastErr error
		for _, dk := range candidates {
			if dk.Algorithm != sig.Algorithm {
				continue
			}
			if err := sig.Verify(dk, rrset); err == nil {
				verified = true
				break
			} else {
				lastErr = err
			}
		}
		if !verified {
			return fmt.Errorf("RRSIG for %s %s (keytag %d) does not verify against the published DNSKEY: %v", sig.Hdr.Name, dns.TypeToString[sig.TypeCovered], sig.KeyTag, lastErr)
		}
		covered[k] = true
	}

	// (2) Every authoritative RRset must have a covering RRSIG. Mirror signRecordsWithKeys:
	// skip occluded names and, at a delegation point, everything but DS and NSEC.
	for k := range rrsets {
		if k.rrtype == dns.TypeRRSIG {
			continue
		}
		if delInfo.isOccluded(k.name) {
			continue
		}
		if delInfo.delegationPoints[k.name] && k.rrtype != dns.TypeDS && k.rrtype != dns.TypeNSEC {
			continue
		}
		if !covered[k] {
			return fmt.Errorf("authoritative RRset %s %s has no covering RRSIG", k.name, dns.TypeToString[k.rrtype])
		}
	}

	// (3) NSEC/NSEC3 chain must be a single closed cycle over every emitted owner.
	if len(nsecs) > 0 {
		if err := verifyNSECChainClosure(nsecs); err != nil {
			return err
		}
	}
	if len(nsec3s) > 0 {
		if err := verifyNSEC3ChainClosure(nsec3s); err != nil {
			return err
		}
	}

	return nil
}

// verifyNSECChainClosure asserts the NSEC Next pointers form one closed cycle.
func verifyNSECChainClosure(nsecs []*dns.NSEC) error {
	next := make(map[string]string, len(nsecs))
	for _, n := range nsecs {
		owner := strings.ToLower(dns.Fqdn(n.Hdr.Name))
		if _, dup := next[owner]; dup {
			return fmt.Errorf("NSEC chain has a duplicate owner %s", owner)
		}
		next[owner] = strings.ToLower(dns.Fqdn(n.NextDomain))
	}
	return walkDenialChain("NSEC", next)
}

// verifyNSEC3ChainClosure asserts the NSEC3 Next-hash pointers form one closed cycle over
// the hashed owner names (the first label of each NSEC3 owner).
func verifyNSEC3ChainClosure(nsec3s []*dns.NSEC3) error {
	next := make(map[string]string, len(nsec3s))
	for _, n := range nsec3s {
		labels := dns.SplitDomainName(n.Hdr.Name)
		if len(labels) == 0 {
			return fmt.Errorf("NSEC3 owner %s has no hash label", n.Hdr.Name)
		}
		owner := strings.ToUpper(labels[0])
		if _, dup := next[owner]; dup {
			return fmt.Errorf("NSEC3 chain has a duplicate owner hash %s", owner)
		}
		next[owner] = strings.ToUpper(n.NextDomain)
	}
	return walkDenialChain("NSEC3", next)
}

// walkDenialChain follows next pointers from a deterministic start and asserts every owner
// is visited exactly once and the chain closes back to the start (a single cycle).
func walkDenialChain(kind string, next map[string]string) error {
	total := len(next)
	if total == 0 {
		return nil
	}
	var start string
	for k := range next {
		if start == "" || k < start {
			start = k
		}
	}
	visited := make(map[string]bool, total)
	cur := start
	for i := 0; i < total; i++ {
		if visited[cur] {
			return fmt.Errorf("%s chain has a premature cycle at %s", kind, cur)
		}
		visited[cur] = true
		nxt, ok := next[cur]
		if !ok {
			return fmt.Errorf("%s chain: owner %s points at a name with no %s record (dangling)", kind, cur, kind)
		}
		cur = nxt
	}
	if cur != start {
		return fmt.Errorf("%s chain does not close: after %d hops from %s it ended at %s", kind, total, start, cur)
	}
	if len(visited) != total {
		return fmt.Errorf("%s chain does not cover all %d owners (visited %d)", kind, total, len(visited))
	}
	return nil
}

// createRRSIG creates an RRSIG record for signing
func (s *Signer) createRRSIG(rrset []dns.RR, signingKey *dns.DNSKEY, domain string, inception, expiration time.Time) *dns.RRSIG {
	name := rrset[0].Header().Name
	labels := dns.CountLabel(name)

	// RFC 4035 §5.3.1: For wildcards, the Labels field excludes the wildcard label
	// So *.example.com has 2 labels, not 3
	if strings.HasPrefix(name, "*.") {
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
		case ed25519.PrivateKeySize: // 64-byte expanded key
			edKey = ed25519.PrivateKey(privateKey)
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
	delInfo := s.findDelegationPoints(domain, records)

	// Collect unique owner names that hold authoritative data or a
	// delegation NS RRset. Occluded names (below a zone cut) get no NSEC
	// (RFC 4035 §2.3), and neither do empty non-terminals: an NSEC (plus
	// its RRSIG) MUST NOT be the only RRset at any owner name (RFC 4035
	// §2.3) — ENT nonexistence-of-data is proven by the covering NSEC of
	// the next existing descendant name.
	names := make(map[string]bool)
	typesByName := make(map[string]map[uint16]bool)

	for _, rr := range records {
		name := strings.ToLower(rr.Header().Name)
		if delInfo.isOccluded(name) {
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
		if delInfo.delegationPoints[name] {
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

// addEmptyNonTerminals adds empty non-terminal names to the name set
func (s *Signer) addEmptyNonTerminals(names map[string]bool, typesByName map[string]map[uint16]bool, apex string) {
	// Collect all names first to avoid modifying map while iterating
	var allNames []string
	for name := range names {
		allNames = append(allNames, name)
	}

	for _, name := range allNames {
		// Walk up the tree to apex, adding empty non-terminals
		labels := dns.SplitDomainName(name)
		apexLabels := dns.SplitDomainName(apex)

		for i := 1; i < len(labels)-len(apexLabels)+1; i++ {
			parent := strings.Join(labels[i:], ".") + "."
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
	// NSEC3 parameters
	iterations := uint16(s.cfg.DNSSEC.NSEC3Iterations)
	salt := s.cfg.DNSSEC.NSEC3Salt
	apex := dns.Fqdn(domain)
	apexLower := strings.ToLower(apex)

	delInfo := s.findDelegationPoints(domain, records)

	// Collect unique owner names and their types. Occluded names (below a
	// zone cut) get no NSEC3 (RFC 5155 §7.1 covers only names with
	// authoritative data or at delegation points).
	names := make(map[string]bool)
	typesByName := make(map[string]map[uint16]bool)

	for _, rr := range records {
		name := strings.ToLower(rr.Header().Name)
		if delInfo.isOccluded(name) {
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
	if typesByName[apexLower] != nil {
		typesByName[apexLower][dns.TypeNSEC3PARAM] = true
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
			Name:   apex,
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
		if delInfo.delegationPoints[hn.original] {
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
	if err := ensureDir(filepath.Dir(path)); err != nil {
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
		key := rrKey{name: strings.ToLower(rr.Header().Name), rrtype: rr.Header().Rrtype}
		if _, exists := groups[key]; !exists {
			keys = append(keys, key)
		}
		groups[key] = append(groups[key], rr)
	}

	// Sort keys: apex first, then by name, then by type (SOA, NS, DNSKEY, then others).
	// Lowercase the apex to match the lowercased key names above — otherwise a
	// mixed-case zone key in config (e.g. "Example.COM") breaks apex-first
	// ordering (R-063).
	apex := strings.ToLower(dns.Fqdn(domain))
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

func (s *Signer) checkRolloverWarnings(domain string, zoneState *ZoneState) {
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
