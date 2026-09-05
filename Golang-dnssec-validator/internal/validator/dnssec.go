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

// EligibleKeysByKeyTag returns every DNSKEY carrying keyTag that is eligible to
// verify signatures (R-043 eligibility). A key tag is only a 16-bit hint that can
// collide (RFC 4034 Appendix B / RFC 6840), so callers MUST try each returned
// candidate cryptographically rather than trusting the first (R-044).
func EligibleKeysByKeyTag(keyTag uint16, dnskeys []dnspkg.DNSKEYRecord) []dnspkg.DNSKEYRecord {
	var out []dnspkg.DNSKEYRecord
	for _, k := range dnskeys {
		if k.KeyTag == keyTag && k.EligibleForVerification() {
			out = append(out, k)
		}
	}
	return out
}

// VerifyRRsetRRSIGFromResponseAnyKey tries each candidate signing key in turn and
// returns as soon as one produces a valid signature over the RRset. This makes
// verification robust to key-tag collisions (R-044): the RRSIG names a tag, but
// several eligible keys may share it and only one actually signed. Candidates
// must already be R-043-eligible.
func VerifyRRsetRRSIGFromResponseAnyKey(rawResponse []byte, typeCovered uint16, candidates []dnspkg.DNSKEYRecord, keyTag uint16, expectedOwner string, answerOnly bool) (int, error) {
	if len(candidates) == 0 {
		return 0, fmt.Errorf("no eligible signing key (tag %d) available", keyTag)
	}
	var lastErr error
	for _, key := range candidates {
		count, err := VerifyRRsetRRSIGFromResponse(rawResponse, typeCovered, key, keyTag, expectedOwner, answerOnly)
		if err == nil {
			return count, nil
		}
		lastErr = err
	}
	return 0, lastErr
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

// FindRRSIGsForType returns every RRSIG covering the given type, in response
// order. A zone mid-rollover (double-signature algorithm or KSK rollover) or
// signed by legacy tooling legitimately serves several RRSIGs over one RRset,
// and RFC 4035 §5.3.3 accepts the RRset if ANY of them validates — callers
// verifying signatures must consider them all, not stop at the first.
func FindRRSIGsForType(rrtype uint16, rrsigs []dnspkg.RRSIGRecord) []dnspkg.RRSIGRecord {
	var covering []dnspkg.RRSIGRecord
	for _, rrsig := range rrsigs {
		if rrsig.TypeCovered == rrtype {
			covering = append(covering, rrsig)
		}
	}
	return covering
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
// Per RFC 6840 Section 5.11 a validator accepts the delegation when ANY single DS
// exactly matches a DNSKEY (and the later DNSKEY-RRSIG check succeeds); it must NOT
// require every DS algorithm to have a working path (R-032). Algorithms whose DS has
// no matching DNSKEY are recorded as diagnostics, not treated as bogus — that keeps
// legitimate algorithm rollovers and heterogeneous validator capabilities working.
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

	// R-032: accept the delegation as soon as ANY single DS exactly matches an
	// eligible DNSKEY. RFC 6840 §5.11 does not require every DS algorithm to have a
	// working path; requiring that breaks algorithm rollovers and heterogeneous
	// validators. Key tags collide, so try every eligible same-tag DNSKEY (R-043/R-044).
	var firstValidKSK *dnspkg.DNSKEYRecord
	for _, ds := range parentDS {
		for i := range childDNSKEY {
			if childDNSKEY[i].KeyTag != ds.KeyTag || !childDNSKEY[i].EligibleForVerification() {
				continue
			}
			if VerifyDSMatchesDNSKEY(ds, childDNSKEY[i], zone) {
				firstValidKSK = &childDNSKEY[i]
				link.Algorithm = dnspkg.AlgorithmName(ds.Algorithm)
				link.DigestType = dnspkg.DigestTypeName(ds.DigestType)
				link.KeyTag = ds.KeyTag
				break
			}
		}
		if firstValidKSK != nil {
			break
		}
	}

	if firstValidKSK == nil {
		return link, fmt.Errorf("no matching DNSKEY found for any DS record")
	}

	link.ChildKSK = firstValidKSK
	link.DSMatchesKSK = true
	return link, nil
}

// CollectDSMatchedKeys returns every child DNSKEY whose digest matches one of the
// parent's DS records (RFC 4034 §5.1.4). These are the only keys the parent's DS
// authenticates; the DNSKEY RRset MUST be signed by one of them for the zone to be
// secure (RFC 4035 §5.2). Returned in DNSKEY-slice order with duplicates removed.
func CollectDSMatchedKeys(parentDS []dnspkg.DSRecord, childDNSKEY []dnspkg.DNSKEYRecord, zone string) []dnspkg.DNSKEYRecord {
	matched := make([]dnspkg.DNSKEYRecord, 0)
	seen := make(map[int]bool)
	for _, ds := range parentDS {
		for i := range childDNSKEY {
			if seen[i] {
				continue
			}
			if childDNSKEY[i].KeyTag != ds.KeyTag {
				continue
			}
			// R-043: a DS must not authenticate a non-zone/invalid-protocol key.
			if !childDNSKEY[i].EligibleForVerification() {
				continue
			}
			if VerifyDSMatchesDNSKEY(ds, childDNSKEY[i], zone) {
				matched = append(matched, childDNSKEY[i])
				seen[i] = true
			}
		}
	}
	return matched
}

// CollectAnchorMatchedKeys returns every root DNSKEY whose computed DS digest matches
// an authoritative PINNED trust anchor. These are the anchor-authenticated keys for
// the root zone; the root DNSKEY RRset must be signed by one of them.
//
// The pinned-anchor filter is applied here, at the final trust decision, and not
// only in VerifyRootTrustAnchor: a loaded anchor document that keeps the genuine
// pinned anchor and adds an attacker's entry would otherwise pass the existential
// root check and then let the attacker's key authenticate the DNSKEY RRset
// (RA6X-008). Unpinned anchors never contribute a key.
func CollectAnchorMatchedKeys(dnskeys []dnspkg.DNSKEYRecord, anchors []dnspkg.Anchor) []dnspkg.DNSKEYRecord {
	matched := make([]dnspkg.DNSKEYRecord, 0)
	seen := make(map[int]bool)
	for _, anchor := range anchors {
		if !dnspkg.IsPinnedRootAnchor(anchor) {
			continue
		}
		for i := range dnskeys {
			if seen[i] {
				continue
			}
			if dnskeys[i].KeyTag != uint16(anchor.KeyTag) || dnskeys[i].Algorithm != uint8(anchor.Algorithm) {
				continue
			}
			// R-043: an anchor must not authenticate a non-zone/invalid-protocol
			// or revoked key.
			if !dnskeys[i].EligibleForVerification() {
				continue
			}
			computedDigest, err := ComputeDSDigestFromDNSKEY(".", dnskeys[i], uint8(anchor.DigestType))
			if err != nil {
				continue
			}
			if strings.EqualFold(computedDigest, anchor.Digest) {
				matched = append(matched, dnskeys[i])
				seen[i] = true
			}
		}
	}
	return matched
}

// VerifyDNSKEYRRSIGByKeys verifies that the DNSKEY RRset is signed by one of the
// parent/anchor-authenticated keys — not merely by some key that happens to be present
// in the RRset. This closes the RFC 4035 §5.2 binding: a rogue self-signed KSK added to
// the served RRset must not be able to authenticate the RRset. authenticatedKeys is the
// set produced by CollectDSMatchedKeys (non-root) or CollectAnchorMatchedKeys (root).
// This performs FULL cryptographic verification — the whole point of a diagnostic tool.
func VerifyDNSKEYRRSIGByKeys(dnskeys []dnspkg.DNSKEYRecord, rrsigs []dnspkg.RRSIGRecord, authenticatedKeys []dnspkg.DNSKEYRecord) error {
	// Find every RRSIG covering DNSKEY (type 48)
	covering := FindRRSIGsForType(dns.TypeDNSKEY, rrsigs)
	if len(covering) == 0 {
		return fmt.Errorf("no RRSIG for DNSKEY RRset")
	}

	if len(authenticatedKeys) == 0 {
		return fmt.Errorf("no parent-authenticated (DS/anchor-matched) key available to verify the DNSKEY RRset")
	}

	// RFC 4035 §5.3.3: the RRset is authenticated if ANY covering RRSIG verifies
	// under an authenticated key. A zone mid-rollover serves several RRSIGs; only
	// one needs to chain to the parent's DS.
	var errs []error
	for _, rrsigRecord := range covering {
		err := verifyDNSKEYRRSIGOne(dnskeys, rrsigRecord, authenticatedKeys)
		if err == nil {
			return nil
		}
		errs = append(errs, err)
	}

	if len(errs) == 1 {
		return errs[0]
	}
	parts := make([]string, len(errs))
	for i, err := range errs {
		parts[i] = fmt.Sprintf("key tag %d: %v", covering[i].KeyTag, err)
	}
	return fmt.Errorf("none of %d RRSIGs over the DNSKEY RRset verified under a parent-authenticated key: %s", len(errs), strings.Join(parts, "; "))
}

// verifyDNSKEYRRSIGOne checks a single RRSIG over the DNSKEY RRset: time
// validity, membership of the signing key in the parent/anchor-authenticated
// set (the RFC 4035 §5.2 binding — R-080), and full cryptographic verification.
func verifyDNSKEYRRSIGOne(dnskeys []dnspkg.DNSKEYRecord, rrsigRecord dnspkg.RRSIGRecord, authenticatedKeys []dnspkg.DNSKEYRecord) error {
	// Check time validity first (cheap check before expensive crypto)
	if !VerifyRRSIGValid(rrsigRecord) {
		if rrsigRecord.IsExpired {
			return fmt.Errorf("DNSKEY RRSIG expired at %s", rrsigRecord.Expiration.Format(time.RFC3339))
		}
		return fmt.Errorf("DNSKEY RRSIG not yet valid (inception: %s)", rrsigRecord.Inception.Format(time.RFC3339))
	}

	// The signing key MUST be one of the parent/anchor-authenticated keys. Requiring
	// membership here — rather than trusting the key named by the RRSIG — is what binds
	// the DNSKEY RRset to the parent's DS (RFC 4035 §5.2). Key tags collide, so try
	// EVERY authenticated key sharing the tag, not just the first (R-044).
	var candidates []dnspkg.DNSKEYRecord
	for i := range authenticatedKeys {
		if authenticatedKeys[i].KeyTag == rrsigRecord.KeyTag {
			candidates = append(candidates, authenticatedKeys[i])
		}
	}
	if len(candidates) == 0 {
		return fmt.Errorf("DNSKEY RRset is not signed by a parent-authenticated key (RRSIG key tag %d is not DS/anchor-matched)", rrsigRecord.KeyTag)
	}

	// Reconstruct the dns.RRSIG for verification
	rrsig, err := reconstructRRSIG(rrsigRecord.SignerName, rrsigRecord)
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

	// Perform cryptographic signature verification against each candidate key.
	var lastErr error
	for _, ck := range candidates {
		signingKey, err := reconstructDNSKEY(rrsigRecord.SignerName, ck)
		if err != nil {
			lastErr = fmt.Errorf("failed to reconstruct signing key: %w", err)
			continue
		}
		if err := rrsig.Verify(signingKey, rrset); err != nil {
			lastErr = fmt.Errorf("DNSKEY RRSIG cryptographic verification failed: %w", err)
			continue
		}
		return nil
	}
	return lastErr
}

// rrsigWireTimeValid reports whether a raw RRSIG is currently within its validity
// period, allowing ClockSkewTolerance — the same semantics as VerifyRRSIGValid.
// R-028 uses this to bind the time check to the exact signature being verified.
func rrsigWireTimeValid(sig *dns.RRSIG) bool {
	now := time.Now()
	inception := time.Unix(int64(sig.Inception), 0)
	expiration := time.Unix(int64(sig.Expiration), 0)
	return now.After(inception.Add(-ClockSkewTolerance)) && now.Before(expiration.Add(ClockSkewTolerance))
}

// VerifyRRsetRRSIGFromResponse performs full cryptographic verification of an RRset
// using the raw DNS response bytes and a trusted signing DNSKEY.
//
// R-027: when expectedOwner is non-empty the signed RRset must be owned by that
// name (DNS-canonical comparison), and when answerOnly is true only the Answer
// section is considered — so a valid RRset+RRSIG for a different owner replayed in
// Authority/Additional cannot authenticate the queried name. R-028: each candidate
// signature is checked for time validity AND cryptographic validity as one
// indivisible unit, so a valid-time-but-bad signature can never let a
// crypto-valid-but-expired signature slip through.
func VerifyRRsetRRSIGFromResponse(rawResponse []byte, typeCovered uint16, signingKeyRecord dnspkg.DNSKEYRecord, keyTag uint16, expectedOwner string, answerOnly bool) (int, error) {
	// A key handed in directly is the trusted key for this check; only its
	// tag-matching signatures can verify under it, which is what the keyTag
	// argument selected before the candidate engine took over (RA6X-007/009).
	if signingKeyRecord.KeyTag != keyTag {
		return 0, fmt.Errorf("signing key tag %d does not match requested RRSIG key tag %d", signingKeyRecord.KeyTag, keyTag)
	}
	verified, err := VerifyRRsetFromResponse(rawResponse, typeCovered, []dnspkg.DNSKEYRecord{signingKeyRecord}, expectedOwner, "", answerOnly)
	if err != nil {
		return 0, err
	}
	return len(verified.Records), nil
}

// VerifyDenialRRSIGFromResponse performs full cryptographic verification of EVERY
// RRset of the given type (NSEC = 47, NSEC3 = 50) found in a denial response.
//
// Authenticated denial of existence (RFC 4035 §5.4, RFC 5155 §8) is only sound if
// every NSEC/NSEC3 record contributing to the proof is covered by a valid RRSIG from
// the zone's keys. Verifying only one RRset would let a forged covering record ride
// alongside a single genuinely-signed record, so this fails closed: it requires that
// each distinct RRset owner has at least one RRSIG that both matches a supplied DNSKEY
// (by key tag) and verifies cryptographically. It returns the number of verified
// RRsets, or an error naming the first owner whose signature could not be verified.
func VerifyDenialRRSIGFromResponse(rawResponse []byte, typeCovered uint16, dnskeys []dnspkg.DNSKEYRecord) (int, error) {
	if len(rawResponse) == 0 {
		return 0, fmt.Errorf("raw DNS response unavailable")
	}

	var msg dns.Msg
	if err := msg.Unpack(rawResponse); err != nil {
		return 0, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	rrsetByOwner := make(map[string][]dns.RR)
	sigsByOwner := make(map[string][]*dns.RRSIG)

	// Denial records live in the Authority section (or Answer for a direct
	// NSEC/NSEC3 query); nothing in Additional is denial evidence (RA6X-007).
	allRRs := make([]dns.RR, 0, len(msg.Answer)+len(msg.Ns))
	allRRs = append(allRRs, msg.Answer...)
	allRRs = append(allRRs, msg.Ns...)

	for _, rr := range allRRs {
		switch v := rr.(type) {
		case *dns.RRSIG:
			if v.TypeCovered == typeCovered {
				owner := strings.ToLower(v.Hdr.Name)
				sigsByOwner[owner] = append(sigsByOwner[owner], v)
			}
		default:
			if rr.Header().Rrtype == typeCovered {
				owner := strings.ToLower(rr.Header().Name)
				rrsetByOwner[owner] = append(rrsetByOwner[owner], rr)
			}
		}
	}

	if len(rrsetByOwner) == 0 {
		return 0, fmt.Errorf("no records of type %d found in response", typeCovered)
	}

	verified := 0
	for owner, rrset := range rrsetByOwner {
		sigs := sigsByOwner[owner]
		if len(sigs) == 0 {
			return 0, fmt.Errorf("no RRSIG for %s RRset at %s", dnspkg.TypeName(typeCovered), owner)
		}

		ok := false
		var lastErr error
		for _, sig := range sigs {
			// R-028: a denial signature must be within its validity period; bind the
			// time check to THIS signature before doing its crypto. Expired
			// authenticated denial must not downgrade a delegation.
			if !rrsigWireTimeValid(sig) {
				lastErr = fmt.Errorf("%s RRSIG at %s (key tag %d) outside its validity period", dnspkg.TypeName(typeCovered), owner, sig.KeyTag)
				continue
			}
			// Try every eligible key sharing the tag (R-043/R-044): tags collide,
			// and only a zone key with protocol 3 (not revoked) may authenticate.
			cands := EligibleKeysByKeyTag(sig.KeyTag, dnskeys)
			if len(cands) == 0 {
				lastErr = fmt.Errorf("signing key (tag %d) not found in zone DNSKEY", sig.KeyTag)
				continue
			}
			for i := range cands {
				signingKey, err := reconstructDNSKEY(sig.SignerName, cands[i])
				if err != nil {
					lastErr = fmt.Errorf("failed to reconstruct signing key: %w", err)
					continue
				}
				if err := sig.Verify(signingKey, rrset); err != nil {
					lastErr = fmt.Errorf("cryptographic verification failed: %w", err)
					continue
				}
				ok = true
				break
			}
			if ok {
				break
			}
		}

		if !ok {
			return 0, fmt.Errorf("%s RRset at %s: %w", dnspkg.TypeName(typeCovered), owner, lastErr)
		}
		verified++
	}

	return verified, nil
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
		// R-024: only an authoritative pinned anchor may establish root trust.
		// A loaded anchor whose digest an attacker controls must never be used
		// as the root of trust, even if it cryptographically matches a served
		// (possibly forged) root DNSKEY.
		if !dnspkg.IsPinnedRootAnchor(anchor) {
			continue
		}
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
