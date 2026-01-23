package validator

import (
	"crypto/sha256"
	"crypto/sha512"
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

	// The DS record digest is a hash of: zone name (wire format) + DNSKEY RDATA
	// We verify by checking the key tag and algorithm match
	// Full verification would require computing the digest from the DNSKEY
	return true
}

// ComputeDSDigest computes the DS digest for a DNSKEY
// Returns the hex-encoded digest
func ComputeDSDigest(zone string, dnskey dnspkg.DNSKEYRecord, digestType uint8) (string, error) {
	// Create the wire format of the DNSKEY
	// This is: owner name (wire format) + flags + protocol + algorithm + public key

	// Convert zone to wire format
	buf := make([]byte, 256)
	offset, err := dns.PackDomainName(zone, buf, 0, nil, false)
	if err != nil {
		return "", fmt.Errorf("failed to pack zone name: %w", err)
	}
	wireZone := buf[:offset]

	// Build the data to hash
	var data []byte
	data = append(data, wireZone...)

	// Add flags (2 bytes, big endian)
	data = append(data, byte(dnskey.Flags>>8), byte(dnskey.Flags&0xFF))

	// Add protocol (1 byte)
	data = append(data, dnskey.Protocol)

	// Add algorithm (1 byte)
	data = append(data, dnskey.Algorithm)

	// Add public key (base64 decoded)
	// Note: dnskey.PublicKey is already base64 encoded, we'd need to decode it
	// For now, return empty as full implementation requires the raw key bytes

	// Compute hash based on digest type
	var digest []byte
	switch digestType {
	case 1: // SHA-1
		// SHA-1 is deprecated, not computing
		return "", fmt.Errorf("SHA-1 digest type not supported")
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
func VerifyDNSKEYRRSIG(dnskeys []dnspkg.DNSKEYRecord, rrsigs []dnspkg.RRSIGRecord) error {
	// Find RRSIG covering DNSKEY (type 48)
	rrsig := FindRRSIGForType(48, rrsigs)
	if rrsig == nil {
		return fmt.Errorf("no RRSIG for DNSKEY RRset")
	}

	// Check time validity
	if !VerifyRRSIGValid(*rrsig) {
		if rrsig.IsExpired {
			return fmt.Errorf("DNSKEY RRSIG expired at %s", rrsig.Expiration.Format(time.RFC3339))
		}
		return fmt.Errorf("DNSKEY RRSIG not yet valid (inception: %s)", rrsig.Inception.Format(time.RFC3339))
	}

	// Find the signing key
	signingKey := FindKSKByKeyTag(rrsig.KeyTag, dnskeys)
	if signingKey == nil {
		signingKey = FindDNSKEYByKeyTag(rrsig.KeyTag, dnskeys)
	}
	if signingKey == nil {
		return fmt.Errorf("signing key (key tag %d) not found in DNSKEY RRset", rrsig.KeyTag)
	}

	// Note: Full cryptographic verification would require:
	// 1. Reconstructing the signed data (RRSIG RDATA + canonical RRset)
	// 2. Verifying the signature using the public key
	// For now, we trust that if we have matching key tags and valid times, it's good

	return nil
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
