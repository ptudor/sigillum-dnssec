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
			slog.Error("Failed to sign zone", "domain", domain, "error", err)
			zoneState.AddError(err.Error())
		} else {
			zoneState.ClearErrors()
		}
	}

	return s.state.Save()
}

// SignZone signs a single zone
func (s *Signer) SignZone(domain string) error {
	zoneState := s.state.GetZone(domain)
	if zoneState == nil {
		return fmt.Errorf("zone %s not in state", domain)
	}

	slog.Info("Signing zone", "domain", domain, "path", zoneState.Path)

	// Parse the zone file
	records, serial, err := s.parseZoneFile(domain, zoneState.Path)
	if err != nil {
		return fmt.Errorf("parsing zone file: %w", err)
	}

	// Load keys - handling rollover scenarios
	keyGen := NewKeyGenerator(s.cfg)
	keys, err := s.loadKeysForSigning(domain, keyGen, zoneState)
	if err != nil {
		return fmt.Errorf("loading keys: %w", err)
	}

	// Add all DNSKEY records (may include rollover keys)
	for _, k := range keys.dnskeys {
		records = append(records, k)
	}

	// Generate NSEC/NSEC3 chain
	if s.cfg.DNSSEC.NSECVersion == "nsec3" {
		nsec3Records, err := s.generateNSEC3Chain(domain, records)
		if err != nil {
			return fmt.Errorf("generating NSEC3 chain: %w", err)
		}
		records = append(records, nsec3Records...)
	} else {
		nsecRecords := s.generateNSECChain(domain, records)
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

	slog.Info("Zone signed successfully", "domain", domain, "serial", serial, "output", outputPath)
	return nil
}

// signingKeys holds all keys needed for signing, handling rollover scenarios
type signingKeys struct {
	dnskeys      []*dns.DNSKEY // All DNSKEYs to include in zone
	signingKSKs  []*dns.DNSKEY // KSKs to sign DNSKEY RRset with
	signingKSKPs [][]byte      // Private keys for signingKSKs
	signingZSK   *dns.DNSKEY   // ZSK to sign other RRsets
	signingZSKP  []byte        // Private key for ZSK
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
	keys.signingZSK = zsk
	keys.signingZSKP = zskPriv

	// Handle rollover scenarios
	if zoneState.Rollover != nil {
		switch {
		case zoneState.Rollover.Type == "ksk" && zoneState.Rollover.State == KSKRolloverStateDSAddWait:
			// KSK rollover: load old KSK too, sign with both
			oldKSK, oldKSKPriv, err := keyGen.loadKeyPairByID(domain, "ksk", zoneState.Rollover.OldKeyID)
			if err != nil {
				slog.Warn("Failed to load old KSK for rollover signing", "error", err)
			} else {
				keys.dnskeys = append(keys.dnskeys, oldKSK)
				keys.signingKSKs = append(keys.signingKSKs, oldKSK)
				keys.signingKSKPs = append(keys.signingKSKPs, oldKSKPriv)
				slog.Info("KSK rollover: signing with both old and new KSK",
					"old_key_id", zoneState.Rollover.OldKeyID,
					"new_key_id", zoneState.Rollover.NewKeyID)
			}

		case zoneState.Rollover.Type == "zsk" && zoneState.Rollover.State == ZSKRolloverStatePrePublish:
			// ZSK pre-publish: load old ZSK, publish both but sign with old
			oldZSK, oldZSKPriv, err := keyGen.loadKeyPairByID(domain, "zsk", zoneState.Rollover.OldKeyID)
			if err != nil {
				slog.Warn("Failed to load old ZSK for pre-publish", "error", err)
			} else {
				// Keep old ZSK for signing
				keys.signingZSK = oldZSK
				keys.signingZSKP = oldZSKPriv
				slog.Info("ZSK rollover pre-publish: publishing both, signing with old",
					"old_key_id", zoneState.Rollover.OldKeyID,
					"new_key_id", zoneState.Rollover.NewKeyID)
			}

		case zoneState.Rollover.Type == "zsk" && zoneState.Rollover.State == ZSKRolloverStateSigning:
			// ZSK signing phase: load old ZSK for publishing, sign with new
			oldZSK, _, err := keyGen.loadKeyPairByID(domain, "zsk", zoneState.Rollover.OldKeyID)
			if err != nil {
				slog.Warn("Failed to load old ZSK for publish", "error", err)
			} else {
				keys.dnskeys = append(keys.dnskeys, oldZSK)
				slog.Info("ZSK rollover signing: publishing both, signing with new",
					"old_key_id", zoneState.Rollover.OldKeyID,
					"new_key_id", zoneState.Rollover.NewKeyID)
			}
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
		return false, ""
	}

	if info.ModTime().After(zoneState.LastSigned) {
		return true, "zone file modified"
	}

	// Check if serial changed
	_, serial, err := s.parseZoneFile(domain, zonePath)
	if err == nil && serial != zoneState.Serial {
		return true, fmt.Sprintf("serial changed: %d -> %d", zoneState.Serial, serial)
	}

	// Check signature expiry
	refreshTime := zoneState.SignaturesExp.Add(-s.cfg.DNSSEC.SignatureRefresh.Duration)
	if time.Now().After(refreshTime) {
		return true, "signatures approaching expiry"
	}

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

	return records, serial, nil
}

// signRecordsWithKeys signs all RRsets using the provided keys, handling rollover scenarios
func (s *Signer) signRecordsWithKeys(domain string, records []dns.RR, keys *signingKeys) ([]dns.RR, error) {
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

		rrtype := rrset[0].Header().Rrtype

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
			// All other RRsets are signed with the ZSK
			rrsig := s.createRRSIG(rrset, keys.signingZSK, domain, inception, expiration)
			if err := s.signRRSIG(rrsig, rrset, keys.signingZSK, keys.signingZSKP); err != nil {
				return nil, fmt.Errorf("signing RRset %s: %w", rrset[0].Header().Name, err)
			}
			signedRecords = append(signedRecords, rrsig)
		}
	}

	return signedRecords, nil
}

// createRRSIG creates an RRSIG record for signing
func (s *Signer) createRRSIG(rrset []dns.RR, signingKey *dns.DNSKEY, domain string, inception, expiration time.Time) *dns.RRSIG {
	return &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   rrset[0].Header().Name,
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    rrset[0].Header().Ttl,
		},
		TypeCovered: rrset[0].Header().Rrtype,
		Algorithm:   signingKey.Algorithm,
		Labels:      uint8(dns.CountLabel(rrset[0].Header().Name)),
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

func (s *Signer) generateNSECChain(domain string, records []dns.RR) []dns.RR {
	// Collect unique owner names
	names := make(map[string]bool)
	typesByName := make(map[string]map[uint16]bool)

	for _, rr := range records {
		name := strings.ToLower(rr.Header().Name)
		names[name] = true
		if typesByName[name] == nil {
			typesByName[name] = make(map[uint16]bool)
		}
		typesByName[name][rr.Header().Rrtype] = true
	}

	// Sort names canonically
	var sortedNames []string
	for name := range names {
		sortedNames = append(sortedNames, name)
	}
	sort.Slice(sortedNames, func(i, j int) bool {
		return dns.CanonicalName(sortedNames[i]) < dns.CanonicalName(sortedNames[j])
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
		types = append(types, dns.TypeNSEC)
		types = append(types, dns.TypeRRSIG)
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })

		nsec := &dns.NSEC{
			Hdr: dns.RR_Header{
				Name:   name,
				Rrtype: dns.TypeNSEC,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			NextDomain: nextName,
			TypeBitMap: types,
		}
		nsecRecords = append(nsecRecords, nsec)
	}

	return nsecRecords
}

func (s *Signer) generateNSEC3Chain(domain string, records []dns.RR) ([]dns.RR, error) {
	// NSEC3 parameters
	iterations := uint16(s.cfg.DNSSEC.NSEC3Iterations)
	salt := s.cfg.DNSSEC.NSEC3Salt

	// Collect unique owner names and their types
	names := make(map[string]bool)
	typesByName := make(map[string]map[uint16]bool)

	for _, rr := range records {
		name := strings.ToLower(rr.Header().Name)
		names[name] = true
		if typesByName[name] == nil {
			typesByName[name] = make(map[uint16]bool)
		}
		typesByName[name][rr.Header().Rrtype] = true
	}

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
			Ttl:    0,
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

		// Collect types
		var types []uint16
		for t := range typesByName[hn.original] {
			types = append(types, t)
		}
		types = append(types, dns.TypeRRSIG)
		sort.Slice(types, func(i, j int) bool { return types[i] < types[j] })

		nsec3 := &dns.NSEC3{
			Hdr: dns.RR_Header{
				Name:   hn.hashed + "." + dns.Fqdn(domain),
				Rrtype: dns.TypeNSEC3,
				Class:  dns.ClassINET,
				Ttl:    3600,
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

	// Write to file
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Write header
	fmt.Fprintf(f, "; Signed zone file for %s\n", domain)
	fmt.Fprintf(f, "; Generated by dnssec-tudor at %s\n", time.Now().UTC().Format(time.RFC3339))
	fmt.Fprintf(f, "; DO NOT EDIT - this file is automatically generated\n\n")

	fmt.Fprintf(f, "$ORIGIN %s\n", dns.Fqdn(domain))

	for _, rr := range sortedRecords {
		fmt.Fprintln(f, rr.String())
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
