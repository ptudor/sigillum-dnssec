// Package validator provides DNSSEC validation functionality.
// nsec.go implements NSEC and NSEC3 authenticated denial of existence validation
// per RFC 4033, RFC 4034, RFC 4035, and RFC 5155.
package validator

import (
	"bytes"
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/miekg/dns"
	dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

// NSECProof represents cryptographic proof of non-existence
type NSECProof struct {
	ProofType    string   `json:"proof_type"`    // "NSEC" or "NSEC3"
	ResponseType string   `json:"response_type"` // "NXDOMAIN" or "NODATA"
	Verified     bool     `json:"verified"`      // Cryptographic verification passed
	Records      []string `json:"records"`       // NSEC/NSEC3 records involved
	CoveringNSEC string   `json:"covering_nsec"` // The NSEC/NSEC3 that proves it
	Explanation  string   `json:"explanation"`
	Error        string   `json:"error,omitempty"`
}

// NSEC3HashAlgorithm constants per RFC 5155 Section 3.1.1
const (
	NSEC3HashSHA1 = 1 // Only defined algorithm as of RFC 5155
)

// base32ExtendedHex is the base32 encoding used by NSEC3 per RFC 4648 §7
// (base32hex without padding)
var base32ExtendedHex = base32.HexEncoding.WithPadding(base32.NoPadding)

// VerifyNSECDenialWithRRSIG verifies NSEC records prove non-existence with full RRSIG verification.
// Per RFC 4035 Section 5.4. rawResponse is the raw wire-format DNS response containing the NSEC
// records; it is required so the NSEC RRset signatures can be cryptographically verified before
// the proof is reported as verified.
func VerifyNSECDenialWithRRSIG(qname string, qtype uint16, nsecRecords []dnspkg.NSECRecord, rrsigs []dnspkg.RRSIGRecord, dnskeys []dnspkg.DNSKEYRecord, rawResponse []byte, rcode int) *NSECProof {
	proof := &NSECProof{
		ProofType: "NSEC",
		Records:   make([]string, 0),
	}

	if rcode == 3 { // NXDOMAIN
		proof.ResponseType = "NXDOMAIN"
	} else {
		proof.ResponseType = "NODATA"
	}

	if len(nsecRecords) == 0 {
		proof.Error = "no NSEC records in response"
		return proof
	}

	// Verify NSEC RRSIG first
	rrsigRecord := findRRSIGForType(47, rrsigs) // TypeNSEC = 47
	if rrsigRecord == nil {
		proof.Error = "no RRSIG for NSEC records"
		return proof
	}

	// Check RRSIG time validity
	if !verifyRRSIGTimeValid(*rrsigRecord) {
		if rrsigRecord.IsExpired {
			proof.Error = "NSEC RRSIG expired"
		} else {
			proof.Error = "NSEC RRSIG not yet valid"
		}
		return proof
	}

	// Find signing key (fast fail with a clear message before the cryptographic check)
	if signingKey := findDNSKEYByTag(rrsigRecord.KeyTag, dnskeys); signingKey == nil {
		proof.Error = "NSEC signing key not found"
		return proof
	}

	// Record the NSEC records for display
	for _, nsec := range nsecRecords {
		proof.Records = append(proof.Records, fmt.Sprintf("%s → %s [%v]", nsec.Owner, nsec.NextDomain, nsec.TypeBitmap))
	}

	// Cryptographically verify the NSEC RRsets in the response. This is the security-
	// critical step: key-tag/timestamp matching alone does not prove the denial is genuine.
	// The proof below consumes ONLY the records whose RRset verified (RA6X-007).
	verified, rejected, err := VerifyDenialRRsetsFromResponse(rawResponse, 47, dnskeys, "")
	if err != nil {
		proof.Error = fmt.Sprintf("NSEC RRSIG cryptographic verification failed: %v", err)
		return proof
	}

	// Verify the denial proof (ranges/type bitmap) over the authenticated records.
	basicProof, err := VerifyNSECDenial(qname, qtype, nsecRecordsFromVerified(verified), rcode)
	if err != nil {
		proof.Error = err.Error() + rejectedNote(rejected)
		return proof
	}
	if basicProof != nil {
		proof.CoveringNSEC = basicProof.CoveringNSEC
		proof.Explanation = basicProof.Explanation
	}

	proof.Verified = true
	return proof
}

// VerifyNSECDenial verifies NSEC records prove non-existence.
// Returns nil if no NSEC proof is found (not an error, just no proof).
// Per RFC 4035 Section 5.4.
func VerifyNSECDenial(qname string, qtype uint16, nsecRecords []dnspkg.NSECRecord, rcode int) (*NSECProof, error) {
	if len(nsecRecords) == 0 {
		return nil, nil // No NSEC records, no proof
	}

	qname = canonicalizeName(qname)

	// RFC 4035 §5.4: If the RCODE is NXDOMAIN, NSEC proves name doesn't exist
	if rcode == 3 { // NXDOMAIN
		return verifyNSECNXDOMAIN(qname, nsecRecords)
	}

	// Otherwise, this is a NODATA response (name exists, type doesn't)
	return verifyNSECNODATA(qname, qtype, nsecRecords)
}

// verifyNSECNXDOMAIN verifies NSEC proves the queried name doesn't exist.
// Per RFC 4035 §5.4 a complete NXDOMAIN proof needs TWO things: (1) an NSEC whose range
// covers qname (owner < qname < next), and (2) an NSEC that covers the wildcard
// "*.<closest-encloser>", proving no wildcard could have synthesized qname. A single
// covering NSEC is not sufficient — accepting it would let an incomplete/forged denial
// pass.
func verifyNSECNXDOMAIN(qname string, nsecRecords []dnspkg.NSECRecord) (*NSECProof, error) {
	// (1) An NSEC must cover qname.
	var covering *dnspkg.NSECRecord
	for i := range nsecRecords {
		owner := canonicalizeName(nsecRecords[i].Owner)
		next := canonicalizeName(nsecRecords[i].NextDomain)
		if canonicallyBetween(qname, owner, next) {
			covering = &nsecRecords[i]
			break
		}
	}
	if covering == nil {
		return nil, fmt.Errorf("no NSEC record proves %s doesn't exist", qname)
	}

	// (2) An NSEC must cover the wildcard at the closest encloser (RFC 4035 §5.4).
	ce := closestEncloserFromNSEC(qname, canonicalizeName(covering.Owner), canonicalizeName(covering.NextDomain))
	wildcard := wildcardName(ce)
	var wcOwner, wcNext string
	wildcardCovered := false
	for i := range nsecRecords {
		owner := canonicalizeName(nsecRecords[i].Owner)
		next := canonicalizeName(nsecRecords[i].NextDomain)
		if canonicallyBetween(wildcard, owner, next) {
			wildcardCovered = true
			wcOwner, wcNext = owner, next
			break
		}
	}
	if !wildcardCovered {
		return nil, fmt.Errorf("NXDOMAIN proof incomplete: no NSEC covers the wildcard %s (RFC 4035 §5.4)", wildcard)
	}

	return &NSECProof{
		ProofType:    "nxdomain",
		CoveringNSEC: fmt.Sprintf("%s -> %s", canonicalizeName(covering.Owner), canonicalizeName(covering.NextDomain)),
		Explanation: fmt.Sprintf("NSEC proves %s does not exist (covered by %s -> %s) and no wildcard %s exists (covered by %s -> %s)",
			qname, canonicalizeName(covering.Owner), canonicalizeName(covering.NextDomain), wildcard, wcOwner, wcNext),
	}, nil
}

// verifyNSECNODATA verifies NSEC proves the queried type doesn't exist for a name.
// Per RFC 4035 Section 5.4, an NSEC at the name without the type in bitmap proves NODATA.
func verifyNSECNODATA(qname string, qtype uint16, nsecRecords []dnspkg.NSECRecord) (*NSECProof, error) {
	typeName := dnspkg.TypeName(qtype)

	for _, nsec := range nsecRecords {
		owner := canonicalizeName(nsec.Owner)

		// If NSEC owner matches the query name
		if owner == qname {
			// RFC 6840 §4.3: a NODATA proof is invalid if the NSEC has the CNAME bit set —
			// a CNAME should have been returned and followed instead of a bare NODATA.
			if HasTypeInBitmap("CNAME", nsec.TypeBitmap) {
				return nil, fmt.Errorf("NSEC at %s has the CNAME bit set: a CNAME was expected, not NODATA for %s (RFC 6840 §4.3)", owner, typeName)
			}

			// R-030: an NSEC whose bitmap has NS but not SOA is a parent-side
			// delegation point (a referral), not an authoritative NODATA from the
			// child. Accepting it would let an unauthenticated zone-cut error turn a
			// signed parent referral into a false secure NODATA. Reject it.
			if HasTypeInBitmap("NS", nsec.TypeBitmap) && !HasTypeInBitmap("SOA", nsec.TypeBitmap) {
				return nil, fmt.Errorf("NSEC at %s is a delegation point (NS set, SOA clear): a parent referral, not authoritative NODATA for %s (R-030)", owner, typeName)
			}

			// Check if the queried type is NOT in the type bitmap
			typeFound := false
			for _, t := range nsec.TypeBitmap {
				if t == typeName {
					typeFound = true
					break
				}
			}

			if !typeFound {
				return &NSECProof{
					ProofType:    "nodata",
					CoveringNSEC: fmt.Sprintf("%s types: %v", owner, nsec.TypeBitmap),
					Explanation: fmt.Sprintf("NSEC at %s proves type %s does not exist (not in type bitmap)",
						owner, typeName),
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("no NSEC record proves type %s doesn't exist for %s", typeName, qname)
}

// VerifyNSEC3DenialWithRRSIG verifies NSEC3 records prove non-existence with full RRSIG verification.
// Per RFC 5155 Section 8. rawResponse is the raw wire-format DNS response containing the NSEC3
// records; it is required so the NSEC3 RRset signatures can be cryptographically verified before
// the proof is reported as verified.
func VerifyNSEC3DenialWithRRSIG(qname string, qtype uint16, nsec3Records []dnspkg.NSEC3Record, rrsigs []dnspkg.RRSIGRecord, dnskeys []dnspkg.DNSKEYRecord, zone string, rawResponse []byte, rcode int) *NSECProof {
	proof := &NSECProof{
		ProofType: "NSEC3",
		Records:   make([]string, 0),
	}

	if rcode == 3 { // NXDOMAIN
		proof.ResponseType = "NXDOMAIN"
	} else {
		proof.ResponseType = "NODATA"
	}

	if len(nsec3Records) == 0 {
		proof.Error = "no NSEC3 records in response"
		return proof
	}

	// RFC 9276: refuse excessive iteration counts before any hashing or the
	// (bounded, but still wasteful) RRSIG crypto below (R-088).
	if iters, over := nsec3IterationsOverCap(nsec3Records); over {
		proof.Error = fmt.Sprintf("NSEC3 iterations=%d exceeds RFC 9276 cap of %d; refusing (CPU-amplification DoS vector)", iters, NSEC3MaxRecommendedIterations)
		return proof
	}

	// Verify NSEC3 RRSIG first
	rrsigRecord := findRRSIGForType(50, rrsigs) // TypeNSEC3 = 50
	if rrsigRecord == nil {
		proof.Error = "no RRSIG for NSEC3 records"
		return proof
	}

	// Check RRSIG time validity
	if !verifyRRSIGTimeValid(*rrsigRecord) {
		if rrsigRecord.IsExpired {
			proof.Error = "NSEC3 RRSIG expired"
		} else {
			proof.Error = "NSEC3 RRSIG not yet valid"
		}
		return proof
	}

	// Find signing key (fast fail with a clear message before the cryptographic check)
	if signingKey := findDNSKEYByTag(rrsigRecord.KeyTag, dnskeys); signingKey == nil {
		proof.Error = "NSEC3 signing key not found"
		return proof
	}

	// Record the NSEC3 records for display
	for _, nsec3 := range nsec3Records {
		optOut := ""
		if nsec3.Flags&0x01 != 0 {
			optOut = " [opt-out]"
		}
		proof.Records = append(proof.Records, fmt.Sprintf("%s → %s [%v]%s", nsec3.HashedOwner, nsec3.NextHashed, nsec3.TypeBitmap, optOut))
	}

	// Cryptographically verify the NSEC3 RRsets in the response. This is the security-
	// critical step: key-tag/timestamp matching alone does not prove the denial is genuine.
	// The proof below consumes ONLY the records whose RRset verified (RA6X-007).
	verified, rejected, err := VerifyDenialRRsetsFromResponse(rawResponse, 50, dnskeys, "")
	if err != nil {
		proof.Error = fmt.Sprintf("NSEC3 RRSIG cryptographic verification failed: %v", err)
		return proof
	}

	// Verify the denial proof (hashes/ranges/type bitmap) over the authenticated records.
	basicProof, err := VerifyNSEC3Denial(qname, qtype, nsec3RecordsFromVerified(verified), zone, rcode)
	if err != nil {
		proof.Error = err.Error() + rejectedNote(rejected)
		return proof
	}
	if basicProof != nil {
		proof.CoveringNSEC = basicProof.CoveringNSEC
		proof.Explanation = basicProof.Explanation
	}

	proof.Verified = true
	return proof
}

// VerifyNSEC3Denial verifies NSEC3 records prove non-existence.
// Per RFC 5155 Section 8.
func VerifyNSEC3Denial(qname string, qtype uint16, nsec3Records []dnspkg.NSEC3Record, zone string, rcode int) (*NSECProof, error) {
	if len(nsec3Records) == 0 {
		return nil, nil // No NSEC3 records, no proof
	}

	// RFC 9276: refuse excessive iteration counts before hashing (R-088).
	if iters, over := nsec3IterationsOverCap(nsec3Records); over {
		return nil, fmt.Errorf("NSEC3 iterations=%d exceeds RFC 9276 cap of %d; refusing (CPU-amplification DoS vector)", iters, NSEC3MaxRecommendedIterations)
	}

	qname = canonicalizeName(qname)
	zone = canonicalizeName(zone)

	// R-037: records from different NSEC3 chains (differing hash algorithm,
	// iterations, or salt — e.g. a salt/parameter transition, or replayed records)
	// must never be combined into one logical proof. Partition by parameter tuple
	// and require the whole proof to come from a single internally-consistent chain;
	// try each chain independently so a valid transition response still verifies.
	var lastErr error
	for _, group := range groupNSEC3ByParams(nsec3Records) {
		params := group[0]
		if params.Algorithm != NSEC3HashSHA1 {
			lastErr = fmt.Errorf("unsupported NSEC3 hash algorithm: %d (only SHA-1 supported)", params.Algorithm)
			continue
		}
		salt, err := hexDecode(params.Salt)
		if err != nil {
			lastErr = fmt.Errorf("invalid NSEC3 salt: %w", err)
			continue
		}

		hashedQname := computeNSEC3Hash(qname, salt, params.Iterations)

		var proof *NSECProof
		if rcode == 3 { // NXDOMAIN
			proof, err = verifyNSEC3NXDOMAIN(hashedQname, qname, group)
		} else { // NODATA
			proof, err = verifyNSEC3NODATA(hashedQname, qname, qtype, group)
		}
		if err == nil && proof != nil {
			return proof, nil
		}
		if err != nil {
			lastErr = err
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("no internally-consistent NSEC3 chain proves the denial for %s", qname)
	}
	return nil, lastErr
}

// groupNSEC3ByParams partitions NSEC3 records into groups that share the same
// (hash algorithm, iterations, salt) tuple — one internally-consistent chain each.
// Group order follows first appearance so behavior is deterministic (R-037).
func groupNSEC3ByParams(records []dnspkg.NSEC3Record) [][]dnspkg.NSEC3Record {
	type paramKey struct {
		alg  uint8
		iter uint16
		salt string
	}
	order := make([]paramKey, 0)
	byKey := make(map[paramKey][]dnspkg.NSEC3Record)
	for _, r := range records {
		k := paramKey{r.Algorithm, r.Iterations, strings.ToUpper(r.Salt)}
		if _, ok := byKey[k]; !ok {
			order = append(order, k)
		}
		byKey[k] = append(byKey[k], r)
	}
	groups := make([][]dnspkg.NSEC3Record, 0, len(order))
	for _, k := range order {
		groups = append(groups, byKey[k])
	}
	return groups
}

// verifyNSEC3NXDOMAIN verifies NSEC3 proves the name doesn't exist.
// Per RFC 5155 §8.4 a complete NSEC3 NXDOMAIN proof needs THREE records: (1) an NSEC3 that
// matches the closest encloser, (2) an NSEC3 that covers the next closer name, and (3) an
// NSEC3 that covers the wildcard "*.<closest-encloser>". A single covering NSEC3 is not a
// sufficient proof. hashedQname is unused (closest-encloser hashing is done per ancestor).
func verifyNSEC3NXDOMAIN(hashedQname, qname string, nsec3Records []dnspkg.NSEC3Record) (*NSECProof, error) {
	_ = hashedQname
	params := nsec3Records[0]
	salt, err := hexDecode(params.Salt)
	if err != nil {
		return nil, fmt.Errorf("invalid NSEC3 salt: %w", err)
	}
	iter := params.Iterations

	// (1) Closest encloser: the longest ancestor of qname whose hash matches an NSEC3.
	qname = canonicalizeName(qname)
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	var ce, nextCloser string
	for drop := 1; drop <= len(labels); drop++ {
		candidate := lastNLabels(qname, len(labels)-drop)
		if nsec3Matches(computeNSEC3Hash(candidate, salt, iter), nsec3Records) {
			ce = candidate
			nextCloser = lastNLabels(qname, len(labels)-drop+1)
			break
		}
	}
	if ce == "" {
		return nil, fmt.Errorf("NSEC3 NXDOMAIN proof incomplete: no closest-encloser match for %s (RFC 5155 §8.4)", qname)
	}

	// (2) The next closer name must be covered.
	if !nsec3Covers(computeNSEC3Hash(nextCloser, salt, iter), nsec3Records) {
		return nil, fmt.Errorf("NSEC3 NXDOMAIN proof incomplete: next closer name %s not covered (RFC 5155 §8.4)", nextCloser)
	}

	// (3) The wildcard at the closest encloser must be covered.
	wildcard := wildcardName(ce)
	if !nsec3Covers(computeNSEC3Hash(wildcard, salt, iter), nsec3Records) {
		return nil, fmt.Errorf("NSEC3 NXDOMAIN proof incomplete: wildcard %s not covered (RFC 5155 §8.4)", wildcard)
	}

	return &NSECProof{
		ProofType:    "nxdomain",
		CoveringNSEC: fmt.Sprintf("NSEC3 closest encloser %s", ce),
		Explanation: fmt.Sprintf("NSEC3 proves %s does not exist: closest encloser %s matched, next closer %s covered, wildcard %s covered",
			qname, ce, nextCloser, wildcard),
	}, nil
}

// verifyNSEC3NODATA verifies NSEC3 proves the type doesn't exist.
// Per RFC 5155 Section 8.5.
func verifyNSEC3NODATA(hashedQname, qname string, qtype uint16, nsec3Records []dnspkg.NSEC3Record) (*NSECProof, error) {
	typeName := dnspkg.TypeName(qtype)

	for _, nsec3 := range nsec3Records {
		// NSEC3 owner hash should match the queried name's hash
		if strings.EqualFold(nsec3.HashedOwner, hashedQname) {
			// RFC 6840 §4.3: a NODATA proof is invalid if the NSEC3 has the CNAME bit set.
			if HasTypeInBitmap("CNAME", nsec3.TypeBitmap) {
				return nil, fmt.Errorf("NSEC3 at %s has the CNAME bit set: a CNAME was expected, not NODATA for %s (RFC 6840 §4.3)", nsec3.HashedOwner, typeName)
			}

			// R-030: an NSEC3 whose bitmap has NS but not SOA is a parent-side
			// delegation point (a referral), not an authoritative NODATA from the
			// child. Reject it so an unauthenticated zone-cut cannot become a false
			// secure NODATA. (An opt-out/unsigned-delegation NSEC3 is handled by the
			// NXDOMAIN/DS-absence paths, not here.)
			if HasTypeInBitmap("NS", nsec3.TypeBitmap) && !HasTypeInBitmap("SOA", nsec3.TypeBitmap) {
				return nil, fmt.Errorf("NSEC3 at %s is a delegation point (NS set, SOA clear): a parent referral, not authoritative NODATA for %s (R-030)", nsec3.HashedOwner, typeName)
			}

			// Check if qtype is NOT in type bitmap
			typeFound := false
			for _, t := range nsec3.TypeBitmap {
				if t == typeName {
					typeFound = true
					break
				}
			}

			if !typeFound {
				return &NSECProof{
					ProofType:    "nodata",
					CoveringNSEC: fmt.Sprintf("NSEC3 %s types: %v", nsec3.HashedOwner, nsec3.TypeBitmap),
					Explanation: fmt.Sprintf("NSEC3 at %s proves type %s does not exist for %s",
						nsec3.HashedOwner, typeName, qname),
				}, nil
			}
		}
	}

	return nil, fmt.Errorf("no NSEC3 record proves type %s doesn't exist for %s", typeName, qname)
}

// nsec3IterationsOverCap returns the first NSEC3 iteration count exceeding the
// RFC 9276 cap (NSEC3MaxRecommendedIterations). Iterations beyond the cap give
// no security benefit and force up to 65536 SHA-1 hashes per name — a CPU
// amplifier — so callers refuse the proof before any hashing is performed. R-088.
func nsec3IterationsOverCap(records []dnspkg.NSEC3Record) (uint16, bool) {
	for _, r := range records {
		if int(r.Iterations) > NSEC3MaxRecommendedIterations {
			return r.Iterations, true
		}
	}
	return 0, false
}

// computeNSEC3Hash computes the NSEC3 hash of a name per RFC 5155 Section 5.
// Hash = H(H(H(... H(name || salt) ...) || salt) || salt)
// where H is applied (iterations + 1) times.
func computeNSEC3Hash(name string, salt []byte, iterations uint16) string {
	// Step 1: Wire format of the name (lowercase labels with length prefixes)
	wireFormat := toWireFormat(canonicalizeName(name))

	// Step 2: Initial hash = H(name || salt)
	h := sha1.New()
	h.Write(wireFormat)
	h.Write(salt)
	digest := h.Sum(nil)

	// Step 3: Iterate hash(hash || salt)
	for i := uint16(0); i < iterations; i++ {
		h.Reset()
		h.Write(digest)
		h.Write(salt)
		digest = h.Sum(nil)
	}

	// Step 4: Encode as base32hex without padding (uppercase)
	return strings.ToUpper(base32ExtendedHex.EncodeToString(digest))
}

// toWireFormat converts a domain name to DNS wire format.
// E.g., "www.example.com." -> [3]www[7]example[3]com[0]
func toWireFormat(name string) []byte {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	if name == "" {
		return []byte{0} // Root
	}

	labels := strings.Split(name, ".")
	var result []byte
	for _, label := range labels {
		result = append(result, byte(len(label)))
		result = append(result, []byte(label)...)
	}
	result = append(result, 0) // Terminating zero
	return result
}

// canonicalizeName normalizes a domain name to lowercase with trailing dot.
func canonicalizeName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name != "" && !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

// canonicalLabelBytes returns the unescaped, lowercased octets of a single DNS
// label. RFC 4034 §6.1 canonical ordering compares the raw label octets, so
// escape sequences (\DDD decimal, \X single-char) must be resolved to the bytes
// they denote and ASCII A–Z lowercased BEFORE comparison — comparing presentation
// strings mis-orders names containing escaped octets relative to wire order (R-045).
func canonicalLabelBytes(label string) []byte {
	out := make([]byte, 0, len(label))
	for i := 0; i < len(label); i++ {
		b := label[i]
		if b == '\\' && i+1 < len(label) {
			if i+3 < len(label) &&
				label[i+1] >= '0' && label[i+1] <= '9' &&
				label[i+2] >= '0' && label[i+2] <= '9' &&
				label[i+3] >= '0' && label[i+3] <= '9' {
				b = byte(int(label[i+1]-'0')*100 + int(label[i+2]-'0')*10 + int(label[i+3]-'0'))
				i += 3
			} else {
				b = label[i+1]
				i++
			}
		}
		if b >= 'A' && b <= 'Z' {
			b += 32
		}
		out = append(out, b)
	}
	return out
}

// compareCanonicalNames compares two domain names in RFC 4034 §6.1 canonical
// order: right-to-left, label by label, each label compared as unescaped,
// lowercased wire octets. Returns -1, 0, or 1. (R-045)
func compareCanonicalNames(a, b string) int {
	aLabels := dns.SplitDomainName(a)
	bLabels := dns.SplitDomainName(b)
	for i := 0; ; i++ {
		aIdx := len(aLabels) - 1 - i
		bIdx := len(bLabels) - 1 - i
		if aIdx < 0 && bIdx < 0 {
			return 0
		}
		if aIdx < 0 {
			return -1 // shorter name (fewer labels) sorts first
		}
		if bIdx < 0 {
			return 1
		}
		switch bytes.Compare(canonicalLabelBytes(aLabels[aIdx]), canonicalLabelBytes(bLabels[bIdx])) {
		case -1:
			return -1
		case 1:
			return 1
		}
	}
}

// canonicallyBetween checks if name falls strictly between start and end in DNS
// canonical order (RFC 4034 §6.1), with exclusive endpoints.
func canonicallyBetween(name, start, end string) bool {
	switch compareCanonicalNames(start, end) {
	case -1:
		// Normal interval: start < name < end.
		return compareCanonicalNames(name, start) > 0 && compareCanonicalNames(name, end) < 0
	case 1:
		// Wrap-around at the zone's last owner: name > start OR name < end.
		return compareCanonicalNames(name, start) > 0 || compareCanonicalNames(name, end) < 0
	default:
		// start == end: a single-record chain whose next owner is itself covers the
		// entire namespace except the owner name (R-036).
		return compareCanonicalNames(name, start) != 0
	}
}

// hashBetween checks if a hash falls strictly between start and end in
// lexicographic (base32hex) order. Endpoints are exclusive.
func hashBetween(hash, start, end string) bool {
	hash = strings.ToUpper(hash)
	start = strings.ToUpper(start)
	end = strings.ToUpper(end)

	switch {
	case start < end:
		return hash > start && hash < end
	case start > end:
		// Wrap-around at zone boundary.
		return hash > start || hash < end
	default:
		// start == end: a single NSEC3 record whose next hash is itself covers the
		// whole hash space except its own hash (R-036).
		return hash != start
	}
}

// splitLabels splits a domain name into labels (right to left order).
func splitLabels(name string) []string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if name == "" {
		return nil
	}
	labels := strings.Split(name, ".")
	// Reverse to get right-to-left order
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return labels
}

// compareCanonical compares two label slices in canonical DNS order.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
// Per RFC 4034 Section 6.1.
func compareCanonical(a, b []string) int {
	minLen := len(a)
	if len(b) < minLen {
		minLen = len(b)
	}

	for i := 0; i < minLen; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}

	// All compared labels are equal, shorter name comes first
	if len(a) < len(b) {
		return -1
	}
	if len(a) > len(b) {
		return 1
	}
	return 0
}

// hexDecode decodes a hex string to bytes.
func hexDecode(s string) ([]byte, error) {
	if s == "" || s == "-" {
		return nil, nil // Empty salt
	}
	s = strings.ToLower(s)
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("invalid hex string length")
	}
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		var b byte
		for j := 0; j < 2; j++ {
			c := s[i+j]
			switch {
			case c >= '0' && c <= '9':
				b = b<<4 | (c - '0')
			case c >= 'a' && c <= 'f':
				b = b<<4 | (c - 'a' + 10)
			default:
				return nil, fmt.Errorf("invalid hex character: %c", c)
			}
		}
		result[i/2] = b
	}
	return result, nil
}

// VerifyWildcardDenial verifies the authenticated-denial half of a wildcard-synthesized
// answer: that the queried name has no exact (non-wildcard) match, so the wildcard
// expansion was legitimate. Per RFC 4035 §5.3.4 (NSEC) and RFC 5155 §8.8 (NSEC3).
//
// wildcardLabels is the RRSIG Labels field of the synthesized record, which equals the
// number of labels in the closest encloser. The returned proof has Verified=true only
// when a covering NSEC (for the NSEC case) or a covering NSEC3 for the next closer name
// (for the NSEC3 case) is present. The accompanying RRSIG signatures must be verified
// separately via VerifyDenialRRSIGFromResponse.
func VerifyWildcardDenial(qname string, wildcardLabels uint8, nsecRecords []dnspkg.NSECRecord, nsec3Records []dnspkg.NSEC3Record) *NSECProof {
	proof := &NSECProof{
		ProofType:    "wildcard",
		ResponseType: "WILDCARD",
		Records:      make([]string, 0),
	}

	qname = canonicalizeName(qname)

	if len(nsecRecords) > 0 {
		proof.ProofType = "NSEC"
		// The queried name must not exist as an explicit (non-wildcard) name: find an
		// NSEC whose canonical range covers it.
		for _, nsec := range nsecRecords {
			owner := canonicalizeName(nsec.Owner)
			next := canonicalizeName(nsec.NextDomain)
			proof.Records = append(proof.Records, fmt.Sprintf("%s → %s", owner, next))
			if canonicallyBetween(qname, owner, next) {
				proof.CoveringNSEC = fmt.Sprintf("%s -> %s", owner, next)
				proof.Explanation = fmt.Sprintf("NSEC proves %s has no exact match (falls between %s and %s); wildcard expansion is valid",
					qname, owner, next)
				proof.Verified = true
				return proof
			}
		}
		proof.Error = fmt.Sprintf("no NSEC proves %s has no exact match for the wildcard expansion", qname)
		return proof
	}

	if len(nsec3Records) > 0 {
		proof.ProofType = "NSEC3"
		params := nsec3Records[0]
		// RFC 9276: refuse excessive iteration counts before hashing (R-088).
		if iters, over := nsec3IterationsOverCap(nsec3Records); over {
			proof.Error = fmt.Sprintf("NSEC3 iterations=%d exceeds RFC 9276 cap of %d; refusing (CPU-amplification DoS vector)", iters, NSEC3MaxRecommendedIterations)
			return proof
		}
		if params.Algorithm != NSEC3HashSHA1 {
			proof.Error = fmt.Sprintf("unsupported NSEC3 hash algorithm: %d (only SHA-1 supported)", params.Algorithm)
			return proof
		}
		salt, err := hexDecode(params.Salt)
		if err != nil {
			proof.Error = fmt.Sprintf("invalid NSEC3 salt: %v", err)
			return proof
		}

		// Next closer name = one label longer than the closest encloser, toward QNAME.
		// A covering NSEC3 for it proves no closer match than the wildcard exists.
		nextCloser := lastNLabels(qname, int(wildcardLabels)+1)
		hashedNC := computeNSEC3Hash(nextCloser, salt, params.Iterations)

		for _, rec := range nsec3Records {
			proof.Records = append(proof.Records, fmt.Sprintf("%s → %s", rec.HashedOwner, rec.NextHashed))
			if hashBetween(hashedNC, rec.HashedOwner, rec.NextHashed) {
				proof.CoveringNSEC = fmt.Sprintf("NSEC3 %s -> %s", rec.HashedOwner, rec.NextHashed)
				proof.Explanation = fmt.Sprintf("NSEC3 covers next closer name %s (hash %s); wildcard expansion is valid",
					nextCloser, hashedNC)
				proof.Verified = true
				return proof
			}
		}
		proof.Error = fmt.Sprintf("no NSEC3 covers the next closer name %s for the wildcard expansion", nextCloser)
		return proof
	}

	proof.Error = "no NSEC/NSEC3 records accompany the wildcard answer"
	return proof
}

// lastNLabels returns the suffix of qname consisting of its rightmost n labels,
// as an FQDN. n <= 0 yields the root ("."); n >= the label count yields qname itself.
func lastNLabels(qname string, n int) string {
	qname = canonicalizeName(qname)
	if n <= 0 || qname == "." || qname == "" {
		return "."
	}
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	if n >= len(labels) {
		return qname
	}
	return strings.Join(labels[len(labels)-n:], ".") + "."
}

// commonSuffixLabels returns the longest run of whole trailing labels shared by a and b,
// as an FQDN (their deepest common ancestor). Labels are compared case-insensitively
// (splitLabels lowercases). Returns "." when nothing is shared.
func commonSuffixLabels(a, b string) string {
	al := splitLabels(a) // right-to-left: al[0] is the rightmost label
	bl := splitLabels(b)
	n := len(al)
	if len(bl) < n {
		n = len(bl)
	}
	i := 0
	for i < n && al[i] == bl[i] {
		i++
	}
	if i == 0 {
		return "."
	}
	suffix := make([]string, i)
	copy(suffix, al[:i])
	for l, r := 0, len(suffix)-1; l < r; l, r = l+1, r-1 {
		suffix[l], suffix[r] = suffix[r], suffix[l]
	}
	return strings.Join(suffix, ".") + "."
}

// closestEncloserFromNSEC derives the closest encloser of qname from an NSEC that covers
// it (RFC 7129 §5.3). The covering NSEC's owner and next name both provably exist, so the
// closest encloser — the deepest existing ancestor of qname — is the deeper of the two
// longest-common-ancestors of qname with those names.
func closestEncloserFromNSEC(qname, owner, next string) string {
	ceOwner := commonSuffixLabels(qname, owner)
	ceNext := commonSuffixLabels(qname, next)
	if GetZoneLabels(ceNext) > GetZoneLabels(ceOwner) {
		return ceNext
	}
	return ceOwner
}

// nsec3Matches reports whether any NSEC3 record's owner hash equals hash (the name exists).
func nsec3Matches(hash string, records []dnspkg.NSEC3Record) bool {
	for _, r := range records {
		if strings.EqualFold(r.HashedOwner, hash) {
			return true
		}
	}
	return false
}

// nsec3Covers reports whether any NSEC3 record's hash range covers hash (the name does not
// exist — it falls strictly between an owner hash and its next hash).
func nsec3Covers(hash string, records []dnspkg.NSEC3Record) bool {
	for _, r := range records {
		if hashBetween(hash, r.HashedOwner, r.NextHashed) {
			return true
		}
	}
	return false
}

// wildcardName returns "*.<encloser>" (or "*." for the root encloser).
func wildcardName(encloser string) string {
	if encloser == "." || encloser == "" {
		return "*."
	}
	return "*." + encloser
}

// HasTypeInBitmap checks if a type is present in the NSEC/NSEC3 type bitmap.
func HasTypeInBitmap(typeName string, bitmap []string) bool {
	for _, t := range bitmap {
		if t == typeName {
			return true
		}
	}
	return false
}

// findRRSIGForType finds an RRSIG covering a specific type
func findRRSIGForType(rrtype uint16, rrsigs []dnspkg.RRSIGRecord) *dnspkg.RRSIGRecord {
	for i, rrsig := range rrsigs {
		if rrsig.TypeCovered == rrtype {
			return &rrsigs[i]
		}
	}
	return nil
}

// verifyRRSIGTimeValid checks if an RRSIG is currently valid time-wise.
// Uses VerifyRRSIGValid for consistency with clock skew tolerance per RFC 4035 §5.3.1.
func verifyRRSIGTimeValid(rrsig dnspkg.RRSIGRecord) bool {
	return VerifyRRSIGValid(rrsig)
}

// findDNSKEYByTag finds a DNSKEY by its key tag
func findDNSKEYByTag(keyTag uint16, dnskeys []dnspkg.DNSKEYRecord) *dnspkg.DNSKEYRecord {
	for i, key := range dnskeys {
		if key.KeyTag == keyTag {
			return &dnskeys[i]
		}
	}
	return nil
}
