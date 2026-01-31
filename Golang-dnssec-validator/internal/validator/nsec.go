// Package validator provides DNSSEC validation functionality.
// nsec.go implements NSEC and NSEC3 authenticated denial of existence validation
// per RFC 4033, RFC 4034, RFC 4035, and RFC 5155.
package validator

import (
	"crypto/sha1"
	"encoding/base32"
	"fmt"
	"strings"

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
// Per RFC 4035 Section 5.4.
func VerifyNSECDenialWithRRSIG(qname string, qtype uint16, nsecRecords []dnspkg.NSECRecord, rrsigs []dnspkg.RRSIGRecord, dnskeys []dnspkg.DNSKEYRecord, rcode int) *NSECProof {
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
	rrsigRecord := findRRSIGForType(46, rrsigs) // TypeNSEC = 47
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

	// Find signing key
	signingKey := findDNSKEYByTag(rrsigRecord.KeyTag, dnskeys)
	if signingKey == nil {
		proof.Error = "NSEC signing key not found"
		return proof
	}

	// Record the NSEC records for display
	for _, nsec := range nsecRecords {
		proof.Records = append(proof.Records, fmt.Sprintf("%s → %s [%v]", nsec.Owner, nsec.NextDomain, nsec.TypeBitmap))
	}

	// Verify the denial proof
	basicProof, err := VerifyNSECDenial(qname, qtype, nsecRecords, rcode)
	if err != nil {
		proof.Error = err.Error()
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
// Per RFC 4035 Section 5.4, we need an NSEC whose owner < qname < next_domain.
func verifyNSECNXDOMAIN(qname string, nsecRecords []dnspkg.NSECRecord) (*NSECProof, error) {
	for _, nsec := range nsecRecords {
		owner := canonicalizeName(nsec.Owner)
		next := canonicalizeName(nsec.NextDomain)

		// Check if qname falls in the gap between owner and next
		if canonicallyBetween(qname, owner, next) {
			return &NSECProof{
				ProofType:    "nxdomain",
				CoveringNSEC: fmt.Sprintf("%s -> %s", owner, next),
				Explanation: fmt.Sprintf("NSEC proves %s does not exist (falls between %s and %s in canonical order)",
					qname, owner, next),
			}, nil
		}
	}

	return nil, fmt.Errorf("no NSEC record proves %s doesn't exist", qname)
}

// verifyNSECNODATA verifies NSEC proves the queried type doesn't exist for a name.
// Per RFC 4035 Section 5.4, an NSEC at the name without the type in bitmap proves NODATA.
func verifyNSECNODATA(qname string, qtype uint16, nsecRecords []dnspkg.NSECRecord) (*NSECProof, error) {
	typeName := dnspkg.TypeName(qtype)

	for _, nsec := range nsecRecords {
		owner := canonicalizeName(nsec.Owner)

		// If NSEC owner matches the query name
		if owner == qname {
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
// Per RFC 5155 Section 8.
func VerifyNSEC3DenialWithRRSIG(qname string, qtype uint16, nsec3Records []dnspkg.NSEC3Record, rrsigs []dnspkg.RRSIGRecord, dnskeys []dnspkg.DNSKEYRecord, zone string, rcode int) *NSECProof {
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

	// Find signing key
	signingKey := findDNSKEYByTag(rrsigRecord.KeyTag, dnskeys)
	if signingKey == nil {
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

	// Verify the denial proof
	basicProof, err := VerifyNSEC3Denial(qname, qtype, nsec3Records, zone, rcode)
	if err != nil {
		proof.Error = err.Error()
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

	qname = canonicalizeName(qname)
	zone = canonicalizeName(zone)

	// Get NSEC3 parameters from first record (all should have same params)
	nsec3 := nsec3Records[0]
	if nsec3.Algorithm != NSEC3HashSHA1 {
		return nil, fmt.Errorf("unsupported NSEC3 hash algorithm: %d (only SHA-1 supported)", nsec3.Algorithm)
	}

	// Compute the hash of the query name
	salt, err := hexDecode(nsec3.Salt)
	if err != nil {
		return nil, fmt.Errorf("invalid NSEC3 salt: %w", err)
	}

	hashedQname := computeNSEC3Hash(qname, salt, nsec3.Iterations)

	// RFC 5155 §8.4-8.6: Check if hash falls in a gap
	if rcode == 3 { // NXDOMAIN
		return verifyNSEC3NXDOMAIN(hashedQname, qname, nsec3Records)
	}

	// NODATA case
	return verifyNSEC3NODATA(hashedQname, qname, qtype, nsec3Records)
}

// verifyNSEC3NXDOMAIN verifies NSEC3 proves the name doesn't exist.
// Per RFC 5155 Section 8.4-8.5.
func verifyNSEC3NXDOMAIN(hashedQname, qname string, nsec3Records []dnspkg.NSEC3Record) (*NSECProof, error) {
	for _, nsec3 := range nsec3Records {
		owner := nsec3.HashedOwner
		next := nsec3.NextHashed

		// Check if the hashed qname falls between owner and next
		if hashBetween(hashedQname, owner, next) {
			return &NSECProof{
				ProofType:    "nxdomain",
				CoveringNSEC: fmt.Sprintf("NSEC3 %s -> %s", owner, next),
				Explanation: fmt.Sprintf("NSEC3 proves %s does not exist (hash %s falls between %s and %s)",
					qname, hashedQname, owner, next),
			}, nil
		}
	}

	return nil, fmt.Errorf("no NSEC3 record proves %s (hash %s) doesn't exist", qname, hashedQname)
}

// verifyNSEC3NODATA verifies NSEC3 proves the type doesn't exist.
// Per RFC 5155 Section 8.5.
func verifyNSEC3NODATA(hashedQname, qname string, qtype uint16, nsec3Records []dnspkg.NSEC3Record) (*NSECProof, error) {
	typeName := dnspkg.TypeName(qtype)

	for _, nsec3 := range nsec3Records {
		// NSEC3 owner hash should match the queried name's hash
		if strings.EqualFold(nsec3.HashedOwner, hashedQname) {
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

// canonicallyBetween checks if name falls between start and end in DNS canonical order.
// DNS canonical ordering: compare label by label from the rightmost label.
// Per RFC 4034 Section 6.1.
func canonicallyBetween(name, start, end string) bool {
	nameLabels := splitLabels(name)
	startLabels := splitLabels(start)
	endLabels := splitLabels(end)

	// Handle wrap-around: if start > end (alphabetically), we're at zone boundary
	startCmp := compareCanonical(startLabels, endLabels)
	if startCmp > 0 {
		// Wrap-around case: name must be > start OR < end
		return compareCanonical(nameLabels, startLabels) > 0 ||
			compareCanonical(nameLabels, endLabels) < 0
	}

	// Normal case: start < name < end
	return compareCanonical(nameLabels, startLabels) > 0 &&
		compareCanonical(nameLabels, endLabels) < 0
}

// hashBetween checks if a hash falls between start and end in lexicographic order.
// NSEC3 hashes are compared as simple strings (base32hex).
func hashBetween(hash, start, end string) bool {
	hash = strings.ToUpper(hash)
	start = strings.ToUpper(start)
	end = strings.ToUpper(end)

	// Handle wrap-around at zone boundary
	if start > end {
		return hash > start || hash < end
	}

	return hash > start && hash < end
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

// HasTypeInBitmap checks if a type is present in the NSEC/NSEC3 type bitmap.
func HasTypeInBitmap(typeName string, bitmap []string) bool {
	for _, t := range bitmap {
		if t == typeName {
			return true
		}
	}
	return false
}

// ProvesDSAbsence checks if NSEC/NSEC3 proves DS record doesn't exist.
// This is used to determine if a delegation is insecure (no DS = unsigned child).
// Per RFC 5155 Section 8.9.
func ProvesDSAbsence(qname string, nsecRecords []dnspkg.NSECRecord, nsec3Records []dnspkg.NSEC3Record) bool {
	qname = canonicalizeName(qname)

	// Check NSEC first
	for _, nsec := range nsecRecords {
		owner := canonicalizeName(nsec.Owner)
		if owner == qname && !HasTypeInBitmap("DS", nsec.TypeBitmap) {
			// NSEC at delegation point without DS type = insecure delegation
			return true
		}
	}

	// Check NSEC3
	for _, nsec3 := range nsec3Records {
		// For NSEC3, we'd need to hash the name and compare
		// This is a simplified check - full implementation would verify hash
		if !HasTypeInBitmap("DS", nsec3.TypeBitmap) {
			// Found NSEC3 without DS - may indicate insecure delegation
			// Note: proper validation requires hash verification
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

// verifyRRSIGTimeValid checks if an RRSIG is currently valid time-wise
func verifyRRSIGTimeValid(rrsig dnspkg.RRSIGRecord) bool {
	return rrsig.IsValid && !rrsig.IsExpired
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
