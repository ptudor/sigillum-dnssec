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

		// Initialize zone if not in state
		if zoneState == nil {
			keyGen := NewKeyGenerator(s.cfg)
			ksk, err := keyGen.GenerateKSK(domain)
			if err != nil {
				return fmt.Errorf("generating KSK for %s: %w", domain, err)
			}
			zsk, err := keyGen.GenerateZSK(domain)
			if err != nil {
				return fmt.Errorf("generating ZSK for %s: %w", domain, err)
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
			zoneState.AddError(err.Error())
		} else {
			zoneState.ClearErrors()
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

	// Update state
	now := time.Now().UTC()
	zoneState.Serial = serial
	zoneState.LastSigned = now
	zoneState.SignaturesExp = now.Add(s.cfg.DNSSEC.SignatureValidity.Duration)
	zoneState.ClearWarnings()

	// Check for upcoming rollovers
	s.checkRolloverWarnings(domain, zoneState)

	// Record successful signing metrics
	duration := time.Since(startTime).Seconds()
	RecordSigningOperation(domain, duration, true)

	slog.Info("[SIGN] Zone signed successfully", "domain", domain, "serial", serial, "output", outputPath, "duration_ms", int64(duration*1000))
	return nil
}

// signingKeys holds all keys needed for signing, handling rollover scenarios
type signingKeys struct {
	dnskeys      []*dns.DNSKEY // All DNSKEYs to include in zone
	signingKSKs  []*dns.DNSKEY // KSKs to sign DNSKEY RRset with
	signingKSKPs [][]byte      // Private keys for signingKSKs
	signingZSKs  []*dns.DNSKEY // ZSKs to sign other RRsets (multiple for algorithm rollover)
	signingZSKPs [][]byte      // Private keys for signingZSKs
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
			// ZSK pre-publish: load old ZSK, publish both but sign with old
			oldZSK, oldZSKPriv, err := keyGen.loadKeyPairByID(domain, "zsk", zoneState.Rollover.OldKeyID)
			if err != nil {
				slog.Warn("[SIGN] Failed to load old ZSK for pre-publish", "error", err)
			} else {
				// Replace signing ZSK with old (keep new in dnskeys for publishing)
				keys.signingZSKs = []*dns.DNSKEY{oldZSK}
				keys.signingZSKPs = [][]byte{oldZSKPriv}
				slog.Info("[SIGN] ZSK rollover pre-publish: publishing both, signing with old",
					"old_key_id", zoneState.Rollover.OldKeyID,
					"new_key_id", zoneState.Rollover.NewKeyID)
			}

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

	return keys, nil
}

// NeedsSign checks if a zone needs to be signed
func (s *Signer) NeedsSign(domain, zonePath string, zoneState *ZoneState) (bool, string) {
	// New zone - always sign
	if zoneState == nil {
		return true, "new zone"
	}

	// Check zone file modification time
	info, err := os.Stat(zonePath)
	if err != nil {
		slog.Error("[SIGN] Cannot stat zone file", "domain", domain, "path", zonePath, "error", err)
		zoneState.AddError(fmt.Sprintf("zone file missing or inaccessible: %v", err))
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
		// Still check signature expiry even if parse fails
	} else if serial != zoneState.Serial {
		return true, fmt.Sprintf("serial changed: %d -> %d", zoneState.Serial, serial)
	} else {
		slog.Debug("[SIGN] Serial unchanged", "domain", domain, "serial", serial)
	}

	// Check signature expiry
	refreshTime := zoneState.SignaturesExp.Add(-s.cfg.DNSSEC.SignatureRefresh.Duration)
	if time.Now().After(refreshTime) {
		return true, "signatures approaching expiry"
	}

	slog.Debug("[SIGN] Signatures still valid",
		"domain", domain,
		"expires", zoneState.SignaturesExp.Format(time.RFC3339),
		"refresh_at", refreshTime.Format(time.RFC3339))

	// Check for active rollover
	if zoneState.Rollover != nil {
		return true, "rollover in progress"
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

// delegationInfo holds information about delegation points and glue records
type delegationInfo struct {
	delegationPoints map[string]bool // Names with NS records (not at apex)
	glueRecords      map[string]bool // A/AAAA records for NS targets at/below delegations
}

// findDelegationPoints identifies delegation points and glue records per RFC 4035 §2.2
func (s *Signer) findDelegationPoints(domain string, records []dns.RR) *delegationInfo {
	apex := dns.Fqdn(domain)
	info := &delegationInfo{
		delegationPoints: make(map[string]bool),
		glueRecords:      make(map[string]bool),
	}

	// First pass: find all NS records and their targets
	nsTargets := make(map[string]bool) // NS target names
	for _, rr := range records {
		if ns, ok := rr.(*dns.NS); ok {
			name := strings.ToLower(rr.Header().Name)
			// Delegation point = NS record not at apex
			if name != strings.ToLower(apex) {
				info.delegationPoints[name] = true
			}
			nsTargets[strings.ToLower(ns.Ns)] = true
		}
	}

	// Second pass: identify glue records
	// Glue = A/AAAA records for NS targets that are at or below a delegation point
	for _, rr := range records {
		rrtype := rr.Header().Rrtype
		if rrtype != dns.TypeA && rrtype != dns.TypeAAAA {
			continue
		}

		name := strings.ToLower(rr.Header().Name)
		// Is this name an NS target?
		if !nsTargets[name] {
			continue
		}

		// Is this name at or below a delegation point?
		for dp := range info.delegationPoints {
			if name == dp || strings.HasSuffix(name, "."+dp) {
				key := fmt.Sprintf("%s:%d", name, rrtype)
				info.glueRecords[key] = true
				break
			}
		}
	}

	if len(info.delegationPoints) > 0 {
		slog.Debug("[SIGN] Found delegation points", "count", len(info.delegationPoints))
	}

	return info
}

// signRecordsWithKeys signs all RRsets using the provided keys, handling rollover scenarios
func (s *Signer) signRecordsWithKeys(domain string, records []dns.RR, keys *signingKeys) ([]dns.RR, error) {
	apex := dns.Fqdn(domain)

	// Find delegation points and glue records (RFC 4035 §2.2)
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
	for rrsetKey, rrset := range rrsets {
		if len(rrset) == 0 {
			continue
		}

		name := strings.ToLower(rrset[0].Header().Name)
		rrtype := rrset[0].Header().Rrtype

		// RFC 4035 §2.2: Don't sign NS at delegation points (only sign at apex)
		if rrtype == dns.TypeNS && name != strings.ToLower(apex) {
			if delInfo.delegationPoints[name] {
				slog.Debug("[SIGN] Skipping NS signature at delegation point", "name", name)
				continue
			}
		}

		// RFC 4035 §2.2: Don't sign glue records (A/AAAA for NS targets below delegations)
		if delInfo.glueRecords[rrsetKey] {
			slog.Debug("[SIGN] Skipping glue record signature", "name", name, "type", dns.TypeToString[rrtype])
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
		return rrsig.Sign(ed25519.PrivateKey(privateKey), rrset)
	case dns.ECDSAP256SHA256:
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
	// Collect unique owner names
	names := make(map[string]bool)
	typesByName := make(map[string]map[uint16]bool)

	apex := dns.Fqdn(domain)
	apexLower := strings.ToLower(apex)

	// Track delegation points (NS records not at apex)
	delegationPoints := make(map[string]bool)

	for _, rr := range records {
		name := strings.ToLower(rr.Header().Name)
		names[name] = true
		if typesByName[name] == nil {
			typesByName[name] = make(map[uint16]bool)
		}
		typesByName[name][rr.Header().Rrtype] = true

		// Track delegation points
		if rr.Header().Rrtype == dns.TypeNS && name != apexLower {
			delegationPoints[name] = true
		}
	}

	// Add empty non-terminals (RFC 4035)
	s.addEmptyNonTerminals(names, typesByName, apex)

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

		// Collect types for this name
		var types []uint16
		for t := range typesByName[name] {
			types = append(types, t)
		}

		// NSEC always present
		types = append(types, dns.TypeNSEC)

		// RRSIG present except for:
		// - Empty non-terminals with no types (but NSEC gets signed, so RRSIG exists)
		// - Delegation points with only NS (no DS) - NS doesn't get signed
		if len(typesByName[name]) > 0 {
			// Check if this is a delegation point with only NS (no signed types)
			isDelegation := delegationPoints[name]
			hasDS := typesByName[name][dns.TypeDS]

			// At delegation points, only DS gets signed. If there's no DS, no RRSIG.
			if isDelegation && !hasDS {
				// Pure delegation point - only NS, which doesn't get signed
				// RRSIG NOT added
			} else {
				types = append(types, dns.TypeRRSIG)
			}
		} else {
			// Empty non-terminal - NSEC exists and gets signed
			types = append(types, dns.TypeRRSIG)
		}
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

	// Collect unique owner names and their types
	names := make(map[string]bool)
	typesByName := make(map[string]map[uint16]bool)

	// Track delegation points (NS records not at apex)
	delegationPoints := make(map[string]bool)

	for _, rr := range records {
		name := strings.ToLower(rr.Header().Name)
		names[name] = true
		if typesByName[name] == nil {
			typesByName[name] = make(map[uint16]bool)
		}
		typesByName[name][rr.Header().Rrtype] = true

		// Track delegation points
		if rr.Header().Rrtype == dns.TypeNS && name != apexLower {
			delegationPoints[name] = true
		}
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

		// Collect types - RFC 5155 §7.1: don't include RRSIG or NSEC3
		var types []uint16
		for t := range typesByName[hn.original] {
			types = append(types, t)
		}
		// Only add RRSIG to type bitmap if this name has signed RRsets
		// Empty non-terminals have empty type bitmaps (RFC 5155 §7.1)
		// Delegation points with only NS (no DS) have no signed RRsets
		if len(typesByName[hn.original]) > 0 {
			isDelegation := delegationPoints[hn.original]
			hasDS := typesByName[hn.original][dns.TypeDS]

			// At delegation points, only DS gets signed. If there's no DS, no RRSIG.
			if isDelegation && !hasDS {
				// Pure delegation point - only NS, which doesn't get signed
				// RRSIG NOT added
			} else {
				types = append(types, dns.TypeRRSIG)
			}
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
	tempPath := path + ".tmp"
	f, err := os.Create(tempPath)
	if err != nil {
		return err
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
