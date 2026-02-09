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
		// Fail closed: if digest cannot be computed, DS cannot be considered valid.
		// This avoids accepting a chain link based on key tag/algorithm alone.
		return false
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

// ClockSkewTolerance is the allowed clock difference between validator and signer.
// RFC 4035 Section 5.3.1 recommends validators "allow for small timing errors"
// due to clock skew. 5 minutes is standard practice (BIND, Unbound, etc.)
const ClockSkewTolerance = 5 * time.Minute

// VerifyRRSIGValid checks if an RRSIG is currently valid (time-wise)
// Allows for clock skew per RFC 4035 Section 5.3.1
func VerifyRRSIGValid(rrsig dnspkg.RRSIGRecord) bool {
	now := time.Now()
	// Allow clock skew: inception can be up to 5 min in future,
	// expiration can be up to 5 min in past
	return now.After(rrsig.Inception.Add(-ClockSkewTolerance)) &&
		now.Before(rrsig.Expiration.Add(ClockSkewTolerance))
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

// ValidateChainLink validates the chain of trust between DS and DNSKEY records.
// Per RFC 6840 Section 5.11, if multiple algorithms are present in DS records,
// ALL algorithms MUST have at least one valid DS→DNSKEY chain for the zone to be secure.
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

	// Group DS records by algorithm (RFC 6840 §5.11 requirement)
	algorithmDS := make(map[uint8][]dnspkg.DSRecord)
	for _, ds := range parentDS {
		algorithmDS[ds.Algorithm] = append(algorithmDS[ds.Algorithm], ds)
	}

	// Each algorithm present MUST have at least one valid DS→DNSKEY match
	var firstValidKSK *dnspkg.DNSKEYRecord
	var validatedAlgorithms []uint8

	for alg, dsRecords := range algorithmDS {
		algValidated := false

		for _, ds := range dsRecords {
			// Find matching DNSKEY (prefer KSK, fall back to any key)
			ksk := FindKSKByKeyTag(ds.KeyTag, childDNSKEY)
			if ksk == nil {
				ksk = FindDNSKEYByKeyTag(ds.KeyTag, childDNSKEY)
			}

			if ksk != nil && VerifyDSMatchesDNSKEY(ds, *ksk, zone) {
				algValidated = true
				if firstValidKSK == nil {
					firstValidKSK = ksk
					link.Algorithm = dnspkg.AlgorithmName(ds.Algorithm)
					link.DigestType = dnspkg.DigestTypeName(ds.DigestType)
					link.KeyTag = ds.KeyTag
				}
				break // This algorithm validated, move to next
			}
		}

		if algValidated {
			validatedAlgorithms = append(validatedAlgorithms, alg)
		} else {
			// Algorithm present in DS but no valid DNSKEY = BOGUS per RFC 6840
			return link, fmt.Errorf("algorithm %d (%s) has DS but no matching DNSKEY (RFC 6840 §5.11)",
				alg, dnspkg.AlgorithmName(alg))
		}
	}

	if firstValidKSK == nil {
		return link, fmt.Errorf("no matching DNSKEY found for any DS record")
	}

	link.ChildKSK = firstValidKSK
	link.DSMatchesKSK = true
	return link, nil
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

// VerifyRRsetRRSIGFromResponse performs full cryptographic verification of an RRset
// using the raw DNS response bytes and a trusted signing DNSKEY.
func VerifyRRsetRRSIGFromResponse(rawResponse []byte, typeCovered uint16, signingKeyRecord dnspkg.DNSKEYRecord, keyTag uint16) (int, error) {
	if len(rawResponse) == 0 {
		return 0, fmt.Errorf("raw DNS response unavailable")
	}

	var msg dns.Msg
	if err := msg.Unpack(rawResponse); err != nil {
		return 0, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	rrsetByOwner := make(map[string][]dns.RR)
	candidates := make([]*dns.RRSIG, 0)
	allRRs := append(msg.Answer, msg.Ns...)
	allRRs = append(allRRs, msg.Extra...)

	for _, rr := range allRRs {
		switch v := rr.(type) {
		case *dns.RRSIG:
			if v.TypeCovered == typeCovered && v.KeyTag == keyTag {
				candidates = append(candidates, v)
			}
		default:
			if rr.Header().Rrtype == typeCovered {
				owner := strings.ToLower(rr.Header().Name)
				rrsetByOwner[owner] = append(rrsetByOwner[owner], rr)
			}
		}
	}

	if len(candidates) == 0 {
		return 0, fmt.Errorf("no RRSIG found in response for type %d with key tag %d", typeCovered, keyTag)
	}

	var lastErr error
	for _, sig := range candidates {
		owner := strings.ToLower(sig.Hdr.Name)
		rrset := rrsetByOwner[owner]
		if len(rrset) == 0 {
			lastErr = fmt.Errorf("no RRset found for owner %s and type %d", sig.Hdr.Name, typeCovered)
			continue
		}

		signingKey, err := reconstructDNSKEY(sig.SignerName, signingKeyRecord)
		if err != nil {
			lastErr = fmt.Errorf("failed to reconstruct signing key: %w", err)
			continue
		}

		if err := sig.Verify(signingKey, rrset); err != nil {
			lastErr = fmt.Errorf("cryptographic RRset verification failed: %w", err)
			continue
		}

		return len(rrset), nil
	}

	if lastErr != nil {
		return 0, lastErr
	}
	return 0, fmt.Errorf("no verifiable RRSIG candidate for type %d", typeCovered)
}

// reconstructDNSKEY converts our DNSKEYRecord back to a dns.DNSKEY for verification
func reconstructDNSKEY(zone string, record dnspkg.DNSKEYRecord) (*dns.DNSKEY, error) {
	// miekg/dns Verify() expects PublicKey as base64 - it decodes internally
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
		PublicKey: record.PublicKey, // Already base64, Verify() decodes internally
	}

	return dnskey, nil
}

// reconstructRRSIG converts our RRSIGRecord back to a dns.RRSIG for verification
func reconstructRRSIG(zone string, record dnspkg.RRSIGRecord) (*dns.RRSIG, error) {
	// miekg/dns Verify() expects Signature as base64 - it decodes internally
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
		Signature:   record.Signature, // Already base64, Verify() decodes internally
	}

	return rrsig, nil
}

// DetectWildcardSynthesis checks if an RRSIG indicates wildcard synthesis.
// Per RFC 4034 Section 3.1.3, if the owner name has more labels than the
// RRSIG Labels field, the response was synthesized from a wildcard.
// Returns the wildcard source (e.g., "*.example.com.") or empty string.
func DetectWildcardSynthesis(ownerName string, rrsig dnspkg.RRSIGRecord) string {
	ownerLabels := GetZoneLabels(ownerName)

	// Labels field in RRSIG is the number of labels in the original owner name
	// (excluding the "*" label for wildcards and excluding the root label)
	if ownerLabels > int(rrsig.Labels) {
		// Response was synthesized from a wildcard
		// Reconstruct the wildcard: take last N labels and prepend "*"
		normalized := NormalizeDomain(ownerName)
		labels := strings.Split(strings.TrimSuffix(normalized, "."), ".")

		if int(rrsig.Labels) < len(labels) {
			// Get the last 'Labels' labels
			wildcardLabels := labels[len(labels)-int(rrsig.Labels):]
			return "*." + strings.Join(wildcardLabels, ".") + "."
		}
	}
	return ""
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
// by computing and comparing DS digests, not just key tags (which can collide per RFC 4034 Appendix B)
func VerifyRootTrustAnchor(dnskeys []dnspkg.DNSKEYRecord, anchors []dnspkg.Anchor) (*ChainLink, error) {
	link := &ChainLink{
		ChildZone:    ".",
		ParentZone:   "",
		DSMatchesKSK: false,
	}

	// For each anchor, find a DNSKEY and verify digest matches
	for _, anchor := range anchors {
		for i, key := range dnskeys {
			// Quick filter by key tag and algorithm
			if key.KeyTag != uint16(anchor.KeyTag) || key.Algorithm != uint8(anchor.Algorithm) {
				continue
			}

			// CRITICAL: Verify the digest, don't trust key tag alone
			// Key tags are not unique - two different keys can have the same tag
			computedDigest, err := ComputeDSDigestFromDNSKEY(".", key, uint8(anchor.DigestType))
			if err != nil {
				// Can't verify this key, try next
				continue
			}

			// Compare digests (case-insensitive)
			if strings.EqualFold(computedDigest, anchor.Digest) {
				link.ChildKSK = &dnskeys[i]
				link.DSMatchesKSK = true
				link.Algorithm = anchor.AlgorithmName
				link.DigestType = anchor.DigestTypeName
				link.KeyTag = uint16(anchor.KeyTag)
				return link, nil
			}
			// Key tag matched but digest didn't - possible collision, try next key
		}
	}

	return link, fmt.Errorf("no DNSKEY matches any trust anchor (digest verification failed)")
}
