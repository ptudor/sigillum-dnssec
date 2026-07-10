package main

import (
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

// SignAll signs all configured zones
func (s *Signer) SignAll() error {
	for domain, zoneCfg := range s.cfg.Zones {
		zoneState := s.state.GetZone(domain)

		// Initialize zone if not in state — recover existing keys from disk
		// first to preserve the DS chain of trust. A recovery failure must
		// not abort the whole SignAll loop: log it, attach it to this zone
		// as an error, and move on so other zones keep signing.
		if zoneState == nil {
			keyGen := NewKeyGenerator(s.cfg)
			ksk, zsk, err := recoverOrGenerateKeys(keyGen, domain)
			if err != nil {
				slog.Error("[SIGN] Cannot initialize zone; skipping", "domain", domain, "error", err)
				placeholder := &ZoneState{Path: zoneCfg.Path}
				placeholder.AddError(err.Error())
				s.state.SetZone(domain, placeholder)
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
		} else {
			s.state.Mutate(zoneState.ClearErrors)
		}
	}

	return s.state.Save()
}

// SignZone signs a single zone
func (s *Signer) SignZone(domain string) error {
	startTime := time.Now()

	zoneState := s.state.GetZone(domain)
	if zoneState == nil {
		return fmt.Errorf("zone %s not in state", domain)
	}

	slog.Info("[SIGN] Signing zone", "domain", domain, "path", zoneState.Path)

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
			// KSK rollover: load old KSK too, sign with both
			oldKSK, oldKSKPriv, err := keyGen.loadKeyPairByID(domain, "ksk", zoneState.Rollover.OldKeyID)
			if err != nil {
				slog.Warn("[SIGN] Failed to load old KSK for rollover signing", "error", err)
			} else {
				keys.dnskeys = append(keys.dnskeys, oldKSK)
				keys.signingKSKs = append(keys.signingKSKs, oldKSK)
				keys.signingKSKPs = append(keys.signingKSKPs, oldKSKPriv)
				slog.Info("[SIGN] KSK rollover: signing with both old and new KSK",
					"old_key_id", zoneState.Rollover.OldKeyID,
					"new_key_id", zoneState.Rollover.NewKeyID)
			}

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
			// ZSK signing phase: load old ZSK for publishing, sign with new
			oldZSK, _, err := keyGen.loadKeyPairByID(domain, "zsk", zoneState.Rollover.OldKeyID)
			if err != nil {
				slog.Warn("[SIGN] Failed to load old ZSK for publish", "error", err)
			} else {
				keys.dnskeys = append(keys.dnskeys, oldZSK)
				slog.Info("[SIGN] ZSK rollover signing: publishing both, signing with new",
					"old_key_id", zoneState.Rollover.OldKeyID,
					"new_key_id", zoneState.Rollover.NewKeyID)
			}

		case zoneState.Rollover.Type == "algorithm" && zoneState.Rollover.State == AlgoRolloverStateDSAddWait:
			// Algorithm rollover: load old algorithm keys, publish and sign with both algorithms
			oldKSK, oldKSKPriv, err := keyGen.loadKeyPairByID(domain, "ksk", zoneState.Rollover.OldKeyID)
			if err != nil {
				slog.Warn("[SIGN] Failed to load old KSK for algorithm rollover", "error", err)
			} else {
				keys.dnskeys = append(keys.dnskeys, oldKSK)
				keys.signingKSKs = append(keys.signingKSKs, oldKSK)
				keys.signingKSKPs = append(keys.signingKSKPs, oldKSKPriv)
			}

			// Load old ZSK using stored ID
			oldZSK, oldZSKPriv, err := keyGen.loadKeyPairByID(domain, "zsk", zoneState.Rollover.OldZSKID)
			if err != nil {
				slog.Warn("[SIGN] Failed to load old ZSK for algorithm rollover", "error", err)
			} else {
				keys.dnskeys = append(keys.dnskeys, oldZSK)
				keys.signingZSKs = append(keys.signingZSKs, oldZSK)
				keys.signingZSKPs = append(keys.signingZSKPs, oldZSKPriv)
			}

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

	slog.Debug("[SIGN] Checking zone mtime",
		"domain", domain,
		"file_mtime", info.ModTime().Format(time.RFC3339),
		"last_signed", zoneState.LastSigned.Format(time.RFC3339))

	if info.ModTime().After(zoneState.LastSigned) {
		return true, "zone file modified"
	}

	// Check if serial changed
	_, serial, err := s.parseZoneFile(domain, zonePath)
	if err != nil {
		slog.Error("[SIGN] Failed to parse zone file for serial check", "domain", domain, "error", err)
		// File inaccessible but signatures are valid — skip
	} else if serial != zoneState.Serial {
		return true, fmt.Sprintf("serial changed: %d -> %d", zoneState.Serial, serial)
	} else {
		slog.Debug("[SIGN] Serial unchanged", "domain", domain, "serial", serial)
	}

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

	// Validate zone structure
	if err := s.validateZone(domain, records); err != nil {
		return nil, 0, fmt.Errorf("zone validation failed: %w", err)
	}

	return records, serial, nil
}

// validateZone performs sanity checks on a parsed zone
func (s *Signer) validateZone(domain string, records []dns.RR) error {
	apex := dns.Fqdn(domain)
	apexLower := strings.ToLower(apex)

	var soaCount int
	var nsAtApex bool

	for _, rr := range records {
		name := strings.ToLower(rr.Header().Name)

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

// ValidateZoneFile validates a zone file without requiring a full Signer.
// It checks that the file is parseable and contains required records (SOA, NS at apex).
func ValidateZoneFile(domain, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("opening zone file: %w", err)
	}
	defer f.Close()

	apex := dns.Fqdn(domain)
	apexLower := strings.ToLower(apex)

	var soaCount int
	var nsAtApex bool

	zp := dns.NewZoneParser(f, apex, path)
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		name := strings.ToLower(rr.Header().Name)
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

	if err := zp.Err(); err != nil {
		return fmt.Errorf("parsing zone file: %w", err)
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

// canonicalLess compares two domain names in canonical order (RFC 4034 §6.1)
func canonicalLess(a, b string) bool {
	// Compare labels from right to left
	aLabels := dns.SplitDomainName(strings.ToLower(a))
	bLabels := dns.SplitDomainName(strings.ToLower(b))

	// Compare from the end (rightmost label first)
	for i := 0; ; i++ {
		aIdx := len(aLabels) - 1 - i
		bIdx := len(bLabels) - 1 - i

		// If we've exhausted one name
		if aIdx < 0 && bIdx < 0 {
			return false // Equal
		}
		if aIdx < 0 {
			return true // Shorter name comes first
		}
		if bIdx < 0 {
			return false
		}

		// Compare labels
		if aLabels[aIdx] < bLabels[bIdx] {
			return true
		}
		if aLabels[aIdx] > bLabels[bIdx] {
			return false
		}
		// Labels equal, continue to next
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

	// Write to temp file first, then rename for atomicity.
	// This prevents NSD from picking up a partial zone if the process is killed mid-write.
	// Mode 0644 so NSD (running as a different user) can read the signed zone;
	// explicit Chmod defeats a restrictive umask on the daemon process.
	tempPath := path + ".tmp"
	f, err := os.OpenFile(tempPath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
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

	// Sort keys: apex first, then by name, then by type (SOA, NS, DNSKEY, then others)
	apex := dns.Fqdn(domain)
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
