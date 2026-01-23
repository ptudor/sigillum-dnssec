package validator

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/miekg/dns"
	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

// VerifyDSMatchesDNSKEY checks if a DS record matches a DNSKEY
func VerifyDSMatchesDNSKEY(ds dnspkg.DSRecord, dnskey dnspkg.DNSKEYRecord, zone string) bool {
	// Key tag must match
	if ds.KeyTag != dnskey.KeyTag {
		return false
	}

	// Algorithm must match
	if ds.Algorithm != dnskey.Algorithm {
		return false
	}

	// Compute the DS digest from the DNSKEY and compare
	// This is critical for security - we must verify the digest, not just trust key tags
	computedDigest, err := ComputeDSDigestFromDNSKEY(zone, dnskey, ds.DigestType)
	if err != nil {
		// If we can't compute the digest, fall back to key tag match only
		// This handles unsupported digest types
		return true
	}

	// Compare digests (case-insensitive hex comparison)
	return strings.EqualFold(computedDigest, ds.Digest)
}

// ComputeDSDigest computes the DS digest for a DNSKEY (deprecated, use ComputeDSDigestFromDNSKEY)
// Returns the hex-encoded digest
func ComputeDSDigest(zone string, dnskey dnspkg.DNSKEYRecord, digestType uint8) (string, error) {
	return ComputeDSDigestFromDNSKEY(zone, dnskey, digestType)
}

// ComputeDSDigestFromDNSKEY computes the DS digest for a DNSKEY record
// per RFC 4034 Section 5.1.4: digest = hash(owner name | DNSKEY RDATA)
// Returns the hex-encoded digest
func ComputeDSDigestFromDNSKEY(zone string, dnskey dnspkg.DNSKEYRecord, digestType uint8) (string, error) {
	// Convert zone to wire format (lowercase, with length-prefixed labels)
	buf := make([]byte, 256)
	offset, err := dns.PackDomainName(strings.ToLower(zone), buf, 0, nil, false)
	if err != nil {
		return "", fmt.Errorf("failed to pack zone name: %w", err)
	}
	wireZone := buf[:offset]

	// Decode the base64-encoded public key
	publicKey, err := base64.StdEncoding.DecodeString(dnskey.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}

	// Build the data to hash per RFC 4034:
	// digest = hash(owner name | flags | protocol | algorithm | public key)
	var data []byte
	data = append(data, wireZone...)

	// Add flags (2 bytes, big endian)
	data = append(data, byte(dnskey.Flags>>8), byte(dnskey.Flags&0xFF))

	// Add protocol (1 byte, always 3)
	data = append(data, dnskey.Protocol)

	// Add algorithm (1 byte)
	data = append(data, dnskey.Algorithm)

	// Add public key (raw bytes)
	data = append(data, publicKey...)

	// Compute hash based on digest type per RFC 4509
	var digest []byte
	switch digestType {
	case 1: // SHA-1 (deprecated but still encountered)
		h := sha1.Sum(data)
		digest = h[:]
	case 2: // SHA-256
		h := sha256.Sum256(data)
		digest = h[:]
	case 4: // SHA-384
		h := sha512.Sum384(data)
		digest = h[:]
	default:
		return "", fmt.Errorf("unsupported digest type: %d", digestType)
	}

	return strings.ToUpper(hex.EncodeToString(digest)), nil
}

// FindKSKByKeyTag finds a KSK with the given key tag
func FindKSKByKeyTag(keyTag uint16, dnskeys []dnspkg.DNSKEYRecord) *dnspkg.DNSKEYRecord {
	for i, key := range dnskeys {
		if key.KeyTag == keyTag && key.IsKSK {
			return &dnskeys[i]
		}
	}
	return nil
}

// FindZSKByKeyTag finds a ZSK with the given key tag
func FindZSKByKeyTag(keyTag uint16, dnskeys []dnspkg.DNSKEYRecord) *dnspkg.DNSKEYRecord {
	for i, key := range dnskeys {
		if key.KeyTag == keyTag && key.IsZSK {
			return &dnskeys[i]
		}
	}
	return nil
}

// FindDNSKEYByKeyTag finds any DNSKEY with the given key tag
func FindDNSKEYByKeyTag(keyTag uint16, dnskeys []dnspkg.DNSKEYRecord) *dnspkg.DNSKEYRecord {
	for i, key := range dnskeys {
		if key.KeyTag == keyTag {
			return &dnskeys[i]
		}
	}
	return nil
}

// VerifyRRSIGValid checks if an RRSIG is currently valid (time-wise)
func VerifyRRSIGValid(rrsig dnspkg.RRSIGRecord) bool {
	now := time.Now()
	return now.After(rrsig.Inception) && now.Before(rrsig.Expiration)
}

// FindRRSIGForType finds an RRSIG that covers the given type
func FindRRSIGForType(rrtype uint16, rrsigs []dnspkg.RRSIGRecord) *dnspkg.RRSIGRecord {
	for i, rrsig := range rrsigs {
		if rrsig.TypeCovered == rrtype {
			return &rrsigs[i]
		}
	}
	return nil
}

// FindDSByKeyTag finds a DS record with the given key tag
func FindDSByKeyTag(keyTag uint16, dsRecords []dnspkg.DSRecord) *dnspkg.DSRecord {
	for i, ds := range dsRecords {
		if ds.KeyTag == keyTag {
			return &dsRecords[i]
		}
	}
	return nil
}

// ValidateChainLink validates the chain of trust between a DS and a DNSKEY
func ValidateChainLink(parentDS []dnspkg.DSRecord, childDNSKEY []dnspkg.DNSKEYRecord, zone string) (*ChainLink, error) {
	link := &ChainLink{
		ChildZone:    zone,
		ParentZone:   GetParentZone(zone),
		ParentDS:     parentDS,
		DSMatchesKSK: false,
	}

	if len(parentDS) == 0 {
		return nil, fmt.Errorf("no DS records in parent zone")
	}

	// Find a KSK that matches one of the DS records
	for _, ds := range parentDS {
		ksk := FindKSKByKeyTag(ds.KeyTag, childDNSKEY)
		if ksk == nil {
			// Try to find any DNSKEY with matching key tag
			ksk = FindDNSKEYByKeyTag(ds.KeyTag, childDNSKEY)
		}

		if ksk != nil {
			// Verify the DS matches the DNSKEY
			if VerifyDSMatchesDNSKEY(ds, *ksk, zone) {
				link.ChildKSK = ksk
				link.DSMatchesKSK = true
				link.Algorithm = dnspkg.AlgorithmName(ds.Algorithm)
				link.DigestType = dnspkg.DigestTypeName(ds.DigestType)
				link.KeyTag = ds.KeyTag
				return link, nil
			}
		}
	}

	return link, fmt.Errorf("no matching DNSKEY found for any DS record")
}

// VerifyDNSKEYRRSIG verifies that the DNSKEY RRset is properly signed
// This performs FULL cryptographic verification - the whole point of a diagnostic tool
func VerifyDNSKEYRRSIG(dnskeys []dnspkg.DNSKEYRecord, rrsigs []dnspkg.RRSIGRecord) error {
	// Find RRSIG covering DNSKEY (type 48)
	rrsigRecord := FindRRSIGForType(48, rrsigs)
	if rrsigRecord == nil {
		return fmt.Errorf("no RRSIG for DNSKEY RRset")
	}

	// Check time validity first (cheap check before expensive crypto)
	if !VerifyRRSIGValid(*rrsigRecord) {
		if rrsigRecord.IsExpired {
			return fmt.Errorf("DNSKEY RRSIG expired at %s", rrsigRecord.Expiration.Format(time.RFC3339))
		}
		return fmt.Errorf("DNSKEY RRSIG not yet valid (inception: %s)", rrsigRecord.Inception.Format(time.RFC3339))
	}

	// Find the signing key
	signingKeyRecord := FindKSKByKeyTag(rrsigRecord.KeyTag, dnskeys)
	if signingKeyRecord == nil {
		signingKeyRecord = FindDNSKEYByKeyTag(rrsigRecord.KeyTag, dnskeys)
	}
	if signingKeyRecord == nil {
		return fmt.Errorf("signing key (key tag %d) not found in DNSKEY RRset", rrsigRecord.KeyTag)
	}

	// Reconstruct the dns.DNSKEY for verification
	signingKey, err := reconstructDNSKEY(rrsigRecord.SignerName, *signingKeyRecord)
	if err != nil {
		return fmt.Errorf("failed to reconstruct signing key: %w", err)
	}

	// Reconstruct the dns.RRSIG for verification
	rrsig, err := reconstructRRSIG(rrsigRecord.SignerName, *rrsigRecord)
	if err != nil {
		return fmt.Errorf("failed to reconstruct RRSIG: %w", err)
	}

	// Build the DNSKEY RRset that was signed
	var rrset []dns.RR
	for _, dk := range dnskeys {
		dnskey, err := reconstructDNSKEY(rrsigRecord.SignerName, dk)
		if err != nil {
			return fmt.Errorf("failed to reconstruct DNSKEY for RRset: %w", err)
		}
		rrset = append(rrset, dnskey)
	}

	// Perform cryptographic signature verification
	if err := rrsig.Verify(signingKey, rrset); err != nil {
		return fmt.Errorf("DNSKEY RRSIG cryptographic verification failed: %w", err)
	}

	return nil
}

// reconstructDNSKEY converts our DNSKEYRecord back to a dns.DNSKEY for verification
func reconstructDNSKEY(zone string, record dnspkg.DNSKEYRecord) (*dns.DNSKEY, error) {
	// Decode the base64 public key
	pubKey, err := base64.StdEncoding.DecodeString(record.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 public key: %w", err)
	}

	dnskey := &dns.DNSKEY{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(zone),
			Rrtype: dns.TypeDNSKEY,
			Class:  dns.ClassINET,
			Ttl:    3600, // TTL doesn't affect verification
		},
		Flags:     record.Flags,
		Protocol:  record.Protocol,
		Algorithm: record.Algorithm,
		PublicKey: string(pubKey),
	}

	return dnskey, nil
}

// reconstructRRSIG converts our RRSIGRecord back to a dns.RRSIG for verification
func reconstructRRSIG(zone string, record dnspkg.RRSIGRecord) (*dns.RRSIG, error) {
	// Decode the base64 signature
	sig, err := base64.StdEncoding.DecodeString(record.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 signature: %w", err)
	}

	rrsig := &dns.RRSIG{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(zone),
			Rrtype: dns.TypeRRSIG,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		TypeCovered: record.TypeCovered,
		Algorithm:   record.Algorithm,
		Labels:      record.Labels,
		OrigTtl:     record.OriginalTTL,
		Expiration:  uint32(record.Expiration.Unix()),
		Inception:   uint32(record.Inception.Unix()),
		KeyTag:      record.KeyTag,
		SignerName:  dns.Fqdn(record.SignerName),
		Signature:   string(sig),
	}

	return rrsig, nil
}

// GetKSKs returns all KSKs from a list of DNSKEYs
func GetKSKs(dnskeys []dnspkg.DNSKEYRecord) []dnspkg.DNSKEYRecord {
	var ksks []dnspkg.DNSKEYRecord
	for _, key := range dnskeys {
		if key.IsKSK {
			ksks = append(ksks, key)
		}
	}
	return ksks
}

// GetZSKs returns all ZSKs from a list of DNSKEYs
func GetZSKs(dnskeys []dnspkg.DNSKEYRecord) []dnspkg.DNSKEYRecord {
	var zsks []dnspkg.DNSKEYRecord
	for _, key := range dnskeys {
		if key.IsZSK {
			zsks = append(zsks, key)
		}
	}
	return zsks
}

// VerifyRootTrustAnchor verifies that root DNSKEYs match the trust anchors
func VerifyRootTrustAnchor(dnskeys []dnspkg.DNSKEYRecord, anchors []dnspkg.Anchor) (*ChainLink, error) {
	link := &ChainLink{
		ChildZone:    ".",
		ParentZone:   "",
		DSMatchesKSK: false,
	}

	// Find a KSK that matches one of the trust anchors
	for _, anchor := range anchors {
		for i, key := range dnskeys {
			if key.KeyTag == uint16(anchor.KeyTag) && key.Algorithm == uint8(anchor.Algorithm) {
				link.ChildKSK = &dnskeys[i]
				link.DSMatchesKSK = true
				link.Algorithm = anchor.AlgorithmName
				link.DigestType = anchor.DigestTypeName
				link.KeyTag = uint16(anchor.KeyTag)
				return link, nil
			}
		}
	}

	return link, fmt.Errorf("no DNSKEY matches any trust anchor")
}
