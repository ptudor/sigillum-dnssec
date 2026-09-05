// Package validator provides DNSSEC validation functionality.
// nsec.go implements NSEC and NSEC3 authenticated denial of existence validation
// per RFC 4033, RFC 4034, RFC 4035, RFC 5155, RFC 6840 and RFC 7129.
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
	// OptOut is set when the proof relies on an opt-out NSEC3 covering the
	// next closer name (RFC 5155 §6, §9.2). Such a proof is authenticated but
	// cannot exclude an unsigned delegation, so its conclusion is INSECURE,
	// never secure. It is reported separately from Verified (RA6X-012).
	OptOut bool `json:"opt_out,omitempty"`
	// ClosestEncloser and NextCloser record the exact names the proof was
	// built on (RFC 5155 §8.3, RFC 7129 §5.3), so the decision is auditable.
	ClosestEncloser string `json:"closest_encloser,omitempty"`
	NextCloser      string `json:"next_closer,omitempty"`
	// Ignored lists NSEC3 records that were present but could not take part
	// in any proof (unknown flag bits, unsupported hash algorithm, bad salt).
	Ignored []string `json:"ignored,omitempty"`
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
// the proof is reported as verified. zone is the zone whose keys dnskeys are: every NSEC used
// must be owned within it and signed by it (RA6X-016). Every covering RRSIG in the
// response is evaluated as a whole by the crypto layer; an expired or unknown-key
// signature does not stop a valid alternative from authenticating the RRset (RA6X-017).
func VerifyNSECDenialWithRRSIG(qname string, qtype uint16, nsecRecords []dnspkg.NSECRecord, dnskeys []dnspkg.DNSKEYRecord, zone string, rawResponse []byte, rcode int) *NSECProof {
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

	// Record the NSEC records for display
	for _, nsec := range nsecRecords {
		proof.Records = append(proof.Records, fmt.Sprintf("%s → %s [%v]", nsec.Owner, nsec.NextDomain, nsec.TypeBitmap))
	}

	// RA6X-010: a zone's denial records can only speak about names inside it.
	if err := qnameWithinZone(qname, zone); err != nil {
		proof.Error = err.Error()
		return proof
	}

	// Cryptographically verify the NSEC RRsets in the response. This is the security-
	// critical step: key-tag/timestamp matching alone does not prove the denial is genuine.
	// The proof below consumes ONLY the records whose RRset verified (RA6X-007).
	verified, rejected, err := VerifyDenialRRsetsFromResponse(rawResponse, 47, dnskeys, zone)
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
	proof.adopt(basicProof)

	proof.Verified = true
	return proof
}

// adopt copies the semantic outcome of a basic (non-crypto) proof onto p.
func (p *NSECProof) adopt(basic *NSECProof) {
	if basic == nil {
		return
	}
	p.CoveringNSEC = basic.CoveringNSEC
	p.Explanation = basic.Explanation
	p.OptOut = basic.OptOut
	p.ClosestEncloser = basic.ClosestEncloser
	p.NextCloser = basic.NextCloser
	if len(basic.Ignored) > 0 {
		p.Ignored = append(p.Ignored, basic.Ignored...)
	}
}

// qnameWithinZone reports an error when qname is not at or below zone: denial
// records of one zone cannot deny a name outside it (RA6X-010).
func qnameWithinZone(qname, zone string) error {
	if zone == "" {
		return nil
	}
	if !dns.IsSubDomain(dns.CanonicalName(zone), dns.CanonicalName(qname)) {
		return fmt.Errorf("%s is not within zone %s; this zone's denial records cannot deny it", qname, zone)
	}
	return nil
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

// nsecAncestorBoundary rejects a denial when an NSEC in the set shows that an
// ancestor of qname (below the apex) is a delegation point (NS set, SOA
// clear) or carries a DNAME: names below such a cut belong to the child zone
// or are redirected, so this zone's NSEC records cannot deny them (RFC 6840
// §4.1, RFC 4035 §5.4). This is what stops a replayed, genuinely signed
// parent-side record from producing a false NXDOMAIN/NODATA inside a child
// (RA6X-010).
func nsecAncestorBoundary(qname string, nsecRecords []dnspkg.NSECRecord) error {
	qname = canonicalizeName(qname)
	for _, nsec := range nsecRecords {
		owner := canonicalizeName(nsec.Owner)
		if owner == qname || !dns.IsSubDomain(owner, qname) {
			continue
		}
		if HasTypeInBitmap("DNAME", nsec.TypeBitmap) {
			return fmt.Errorf("NSEC at %s, an ancestor of %s, has the DNAME bit set: names below it are redirected and cannot be denied by this zone", owner, qname)
		}
		if HasTypeInBitmap("NS", nsec.TypeBitmap) && !HasTypeInBitmap("SOA", nsec.TypeBitmap) {
			return fmt.Errorf("NSEC at %s, an ancestor of %s, is a delegation point (NS set, SOA clear): this zone cannot deny names below the zone cut (RFC 6840 §4.1)", owner, qname)
		}
	}
	return nil
}

// nsecEndpointBelow reports whether an NSEC endpoint proves that name exists as
// an empty non-terminal: a next name that is a proper descendant of name means
// every ancestor of that next name — including name — exists (RFC 7129 §5.5).
func nsecEndpointBelow(name, endpoint string) bool {
	name = canonicalizeName(name)
	endpoint = canonicalizeName(endpoint)
	return endpoint != name && dns.IsSubDomain(name, endpoint)
}

// verifyNSECNXDOMAIN verifies NSEC proves the queried name doesn't exist.
// Per RFC 4035 §5.4 a complete NXDOMAIN proof needs TWO things: (1) an NSEC whose range
// covers qname (owner < qname < next), and (2) an NSEC that covers the wildcard
// "*.<closest-encloser>", proving no wildcard could have synthesized qname. A single
// covering NSEC is not sufficient — accepting it would let an incomplete/forged denial
// pass. Additionally (RA6X-010) an endpoint below qname proves qname exists as an
// empty non-terminal, and an ancestor delegation/DNAME means qname is not in this
// zone; both refute NXDOMAIN.
func verifyNSECNXDOMAIN(qname string, nsecRecords []dnspkg.NSECRecord) (*NSECProof, error) {
	qname = canonicalizeName(qname)

	if err := nsecAncestorBoundary(qname, nsecRecords); err != nil {
		return nil, err
	}

	// (1) An NSEC must cover qname.
	var covering *dnspkg.NSECRecord
	for i := range nsecRecords {
		owner := canonicalizeName(nsecRecords[i].Owner)
		next := canonicalizeName(nsecRecords[i].NextDomain)
		if owner == qname {
			return nil, fmt.Errorf("NSEC owned by %s proves the name exists; it cannot prove NXDOMAIN", qname)
		}
		if canonicallyBetween(qname, owner, next) {
			covering = &nsecRecords[i]
			break
		}
	}
	if covering == nil {
		return nil, fmt.Errorf("no NSEC record proves %s doesn't exist", qname)
	}
	owner := canonicalizeName(covering.Owner)
	next := canonicalizeName(covering.NextDomain)

	// RA6X-010: an endpoint below qname proves qname exists as an empty
	// non-terminal — the response should have been NODATA, not NXDOMAIN.
	if nsecEndpointBelow(qname, next) {
		return nil, fmt.Errorf("NSEC %s -> %s: the next name is below %s, which therefore exists as an empty non-terminal; NXDOMAIN is not proven (RFC 7129 §5.5)", owner, next, qname)
	}

	// (2) An NSEC must cover the wildcard at the closest encloser (RFC 4035 §5.4).
	ce := closestEncloserFromNSEC(qname, owner, next)
	if ce == qname {
		return nil, fmt.Errorf("NSEC %s -> %s proves %s exists; NXDOMAIN is not proven", owner, next, qname)
	}
	wildcard := wildcardName(ce)
	var wcOwner, wcNext string
	wildcardCovered := false
	for i := range nsecRecords {
		o := canonicalizeName(nsecRecords[i].Owner)
		n := canonicalizeName(nsecRecords[i].NextDomain)
		if o == wildcard {
			return nil, fmt.Errorf("NSEC owned by %s proves the wildcard exists; NXDOMAIN is not proven", wildcard)
		}
		if canonicallyBetween(wildcard, o, n) {
			wildcardCovered = true
			wcOwner, wcNext = o, n
			break
		}
	}
	if !wildcardCovered {
		return nil, fmt.Errorf("NXDOMAIN proof incomplete: no NSEC covers the wildcard %s (RFC 4035 §5.4)", wildcard)
	}

	return &NSECProof{
		ProofType:       "nxdomain",
		CoveringNSEC:    fmt.Sprintf("%s -> %s", owner, next),
		ClosestEncloser: ce,
		NextCloser:      nextCloserName(qname, ce),
		Explanation: fmt.Sprintf("NSEC proves %s does not exist (covered by %s -> %s) and no wildcard %s exists (covered by %s -> %s)",
			qname, owner, next, wildcard, wcOwner, wcNext),
	}, nil
}

// nextCloserName returns the ancestor of qname one label below ce (RFC 5155
// §1.3), or qname itself when ce is its parent.
func nextCloserName(qname, ce string) string {
	qname = canonicalizeName(qname)
	ce = canonicalizeName(ce)
	if ce == qname {
		return qname
	}
	n := GetZoneLabels(ce) + 1
	return lastNLabels(qname, n)
}

// verifyNSECNODATA verifies NSEC proves the queried type doesn't exist for a name.
// Per RFC 4035 Section 5.4, an NSEC at the name without the type in bitmap proves NODATA.
func verifyNSECNODATA(qname string, qtype uint16, nsecRecords []dnspkg.NSECRecord) (*NSECProof, error) {
	typeName := dnspkg.TypeName(qtype)
	qname = canonicalizeName(qname)

	// RA6X-010: an ancestor delegation/DNAME means qname is not served by this
	// zone; a parent-side NSEC cannot prove NODATA inside the child.
	if err := nsecAncestorBoundary(qname, nsecRecords); err != nil {
		return nil, err
	}

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
			if !HasTypeInBitmap(typeName, nsec.TypeBitmap) {
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
// the proof is reported as verified. Every covering RRSIG in the response is evaluated
// as a whole by the crypto layer; an expired or unknown-key signature does not stop a
// valid alternative from authenticating the RRset (RA6X-017).
func VerifyNSEC3DenialWithRRSIG(qname string, qtype uint16, nsec3Records []dnspkg.NSEC3Record, dnskeys []dnspkg.DNSKEYRecord, zone string, rawResponse []byte, rcode int) *NSECProof {
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

	// Record the NSEC3 records for display
	for _, nsec3 := range nsec3Records {
		optOut := ""
		if nsec3.Flags&0x01 != 0 {
			optOut = " [opt-out]"
		}
		proof.Records = append(proof.Records, fmt.Sprintf("%s → %s [%v]%s", nsec3.HashedOwner, nsec3.NextHashed, nsec3.TypeBitmap, optOut))
	}

	// RA6X-010/012: a zone's denial records can only speak about names inside it.
	if err := qnameWithinZone(qname, zone); err != nil {
		proof.Error = err.Error()
		return proof
	}

	// Cryptographically verify the NSEC3 RRsets in the response. This is the security-
	// critical step: key-tag/timestamp matching alone does not prove the denial is genuine.
	// The proof below consumes ONLY the records whose RRset verified (RA6X-007).
	verified, rejected, err := VerifyDenialRRsetsFromResponse(rawResponse, 50, dnskeys, zone)
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
	proof.adopt(basicProof)

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

	// R-037/RA6X-013: records from different NSEC3 chains (differing hash
	// algorithm, iterations, or salt — e.g. a salt/parameter transition, or
	// replayed records) must never be combined into one logical proof. Every
	// proof is evaluated within one internally-consistent chain; each chain is
	// tried independently so a valid transition response still verifies.
	chains, ignored, err := nsec3Chains(nsec3Records)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, chain := range chains {
		var proof *NSECProof
		if rcode == 3 { // NXDOMAIN
			proof, err = chain.nxdomain(qname)
		} else { // NODATA
			proof, err = chain.nodata(qname, qtype)
		}
		if err == nil && proof != nil {
			proof.Ignored = ignored
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

// nsec3Chain is one internally-consistent NSEC3 chain: every record shares
// the same hash algorithm, iteration count and decoded salt, so a hash
// computed with these parameters may be compared with every record's owner
// and next hash. Proof logic must only ever look inside one chain (RA6X-013).
type nsec3Chain struct {
	algorithm  uint8
	iterations uint16
	salt       []byte
	saltHex    string
	records    []dnspkg.NSEC3Record
}

// normalizeSalt returns the canonical presentation of an NSEC3 salt: upper-case
// hex, with the "no salt" spellings ("" and "-") unified.
func normalizeSalt(salt string) string {
	s := strings.ToUpper(strings.TrimSpace(salt))
	if s == "-" {
		return ""
	}
	return s
}

// nsec3UnknownFlags reports whether an NSEC3 record sets flag bits this
// validator does not understand. RFC 5155 §8.2: such records MUST be ignored.
func nsec3UnknownFlags(r dnspkg.NSEC3Record) bool {
	return r.Flags&^NSEC3FlagOptOut != 0
}

// newNSEC3Chain builds a chain from records that must all share one parameter
// tuple; it rejects a mixed set, an unsupported hash algorithm and a bad salt.
func newNSEC3Chain(records []dnspkg.NSEC3Record) (*nsec3Chain, error) {
	if len(records) == 0 {
		return nil, fmt.Errorf("no NSEC3 records")
	}
	first := records[0]
	if first.Algorithm != NSEC3HashSHA1 {
		return nil, fmt.Errorf("unsupported NSEC3 hash algorithm: %d (only SHA-1 supported)", first.Algorithm)
	}
	saltHex := normalizeSalt(first.Salt)
	salt, err := hexDecode(saltHex)
	if err != nil {
		return nil, fmt.Errorf("invalid NSEC3 salt: %w", err)
	}
	for _, r := range records[1:] {
		if r.Algorithm != first.Algorithm || r.Iterations != first.Iterations || normalizeSalt(r.Salt) != saltHex {
			return nil, fmt.Errorf("NSEC3 records span different chains (algorithm/iterations/salt differ); refusing to combine them")
		}
	}
	return &nsec3Chain{
		algorithm:  first.Algorithm,
		iterations: first.Iterations,
		salt:       salt,
		saltHex:    saltHex,
		records:    records,
	}, nil
}

// nsec3Chains partitions records into internally-consistent chains. Records
// with unknown flag bits are ignored (RFC 5155 §8.2) and reported; a group
// with an unsupported algorithm or bad salt is likewise reported rather than
// used. It fails only when no usable chain remains.
func nsec3Chains(records []dnspkg.NSEC3Record) ([]*nsec3Chain, []string, error) {
	usable := make([]dnspkg.NSEC3Record, 0, len(records))
	var ignored []string
	for _, r := range records {
		if nsec3UnknownFlags(r) {
			ignored = append(ignored, fmt.Sprintf("NSEC3 %s has unknown flag bits 0x%02x; ignored (RFC 5155 §8.2)", r.HashedOwner, r.Flags))
			continue
		}
		usable = append(usable, r)
	}
	chains := make([]*nsec3Chain, 0)
	var lastErr error
	for _, group := range groupNSEC3ByParams(usable) {
		chain, err := newNSEC3Chain(group)
		if err != nil {
			lastErr = err
			ignored = append(ignored, fmt.Sprintf("NSEC3 chain (iterations %d, salt %q): %v", group[0].Iterations, group[0].Salt, err))
			continue
		}
		chains = append(chains, chain)
	}
	if len(chains) == 0 {
		if lastErr == nil {
			lastErr = fmt.Errorf("no usable NSEC3 records: %s", strings.Join(ignored, "; "))
		}
		return nil, ignored, lastErr
	}
	return chains, ignored, nil
}

// hash computes the chain's NSEC3 hash of name.
func (c *nsec3Chain) hash(name string) string {
	return computeNSEC3Hash(name, c.salt, c.iterations)
}

// match returns the record whose owner hash equals hash (the name exists).
func (c *nsec3Chain) match(hash string) *dnspkg.NSEC3Record {
	for i := range c.records {
		if strings.EqualFold(c.records[i].HashedOwner, hash) {
			return &c.records[i]
		}
	}
	return nil
}

// cover returns the record whose hash interval strictly contains hash (the
// name does not exist in this chain's namespace).
func (c *nsec3Chain) cover(hash string) *dnspkg.NSEC3Record {
	for i := range c.records {
		if hashBetween(hash, c.records[i].HashedOwner, c.records[i].NextHashed) {
			return &c.records[i]
		}
	}
	return nil
}

// isOptOut reports whether an NSEC3 record has the Opt-Out flag set.
func isOptOut(r *dnspkg.NSEC3Record) bool {
	return r != nil && r.Flags&NSEC3FlagOptOut != 0
}

// nsec3RecordBoundary rejects a matching record that shows the matched name is
// a delegation point (NS set, SOA clear) or a DNAME owner: names below it are
// in the child zone or redirected, so this chain cannot deny them (RFC 5155
// §8.3, RFC 6840 §4.1) (RA6X-012).
func nsec3RecordBoundary(name string, r *dnspkg.NSEC3Record) error {
	if r == nil {
		return nil
	}
	if HasTypeInBitmap("DNAME", r.TypeBitmap) {
		return fmt.Errorf("NSEC3 matching %s has the DNAME bit set: names below it are redirected and cannot be denied by this zone", name)
	}
	if HasTypeInBitmap("NS", r.TypeBitmap) && !HasTypeInBitmap("SOA", r.TypeBitmap) {
		return fmt.Errorf("NSEC3 matching %s is a delegation point (NS set, SOA clear): this zone cannot deny names below the zone cut (RFC 5155 §8.3)", name)
	}
	return nil
}

// closestEncloser performs the RFC 5155 §8.3 closest-encloser proof for qname
// within this chain: the closest encloser is the longest ancestor of qname
// whose hash matches a record, and the next closer name (one label below it,
// toward qname) must be covered. The matched closest-encloser record must not
// be a delegation point or DNAME owner. It returns the exact records used.
func (c *nsec3Chain) closestEncloser(qname string) (ce, nextCloser string, ceRec, ncRec *dnspkg.NSEC3Record, err error) {
	qname = canonicalizeName(qname)
	labels := strings.Split(strings.TrimSuffix(qname, "."), ".")
	if qname == "." {
		labels = nil
	}
	for drop := 1; drop <= len(labels); drop++ {
		candidate := lastNLabels(qname, len(labels)-drop)
		if rec := c.match(c.hash(candidate)); rec != nil {
			ce = candidate
			ceRec = rec
			nextCloser = lastNLabels(qname, len(labels)-drop+1)
			break
		}
	}
	if ce == "" {
		return "", "", nil, nil, fmt.Errorf("NSEC3 proof incomplete: no closest-encloser match for %s (RFC 5155 §8.3)", qname)
	}
	if err := nsec3RecordBoundary(ce, ceRec); err != nil {
		return "", "", nil, nil, fmt.Errorf("closest encloser %s of %s: %v", ce, qname, err)
	}
	ncRec = c.cover(c.hash(nextCloser))
	if ncRec == nil {
		return "", "", nil, nil, fmt.Errorf("NSEC3 proof incomplete: next closer name %s not covered (RFC 5155 §8.3)", nextCloser)
	}
	return ce, nextCloser, ceRec, ncRec, nil
}

// nxdomain verifies the chain proves qname does not exist (RFC 5155 §8.4):
// closest-encloser proof plus a cover of the wildcard at the closest
// encloser. An opt-out cover of the next closer name is authenticated but
// only proves the name is absent OR an unsigned delegation, so the proof is
// marked OptOut and its conclusion is insecure (RFC 5155 §9.2) (RA6X-012).
func (c *nsec3Chain) nxdomain(qname string) (*NSECProof, error) {
	qname = canonicalizeName(qname)
	if c.match(c.hash(qname)) != nil {
		return nil, fmt.Errorf("NSEC3 matching %s proves the name exists; it cannot prove NXDOMAIN", qname)
	}
	ce, nextCloser, _, ncRec, err := c.closestEncloser(qname)
	if err != nil {
		return nil, fmt.Errorf("NSEC3 NXDOMAIN %v", err)
	}
	wildcard := wildcardName(ce)
	if c.match(c.hash(wildcard)) != nil {
		return nil, fmt.Errorf("NSEC3 matching wildcard %s proves it exists; NXDOMAIN is not proven", wildcard)
	}
	if c.cover(c.hash(wildcard)) == nil {
		return nil, fmt.Errorf("NSEC3 NXDOMAIN proof incomplete: wildcard %s not covered (RFC 5155 §8.4)", wildcard)
	}

	proof := &NSECProof{
		ProofType:       "nxdomain",
		CoveringNSEC:    fmt.Sprintf("NSEC3 closest encloser %s", ce),
		ClosestEncloser: ce,
		NextCloser:      nextCloser,
		Explanation: fmt.Sprintf("NSEC3 proves %s does not exist: closest encloser %s matched, next closer %s covered, wildcard %s covered",
			qname, ce, nextCloser, wildcard),
	}
	if isOptOut(ncRec) {
		proof.OptOut = true
		proof.Explanation += "; the next closer name is covered by an opt-out NSEC3, so an unsigned delegation may exist there: the conclusion is insecure, not secure (RFC 5155 §9.2)"
	}
	return proof, nil
}

// nodata verifies the chain proves qname exists without qtype (RFC 5155 §8.5).
func (c *nsec3Chain) nodata(qname string, qtype uint16) (*NSECProof, error) {
	qname = canonicalizeName(qname)
	return verifyNSEC3NODATAInChain(c, qname, qtype)
}

// groupNSEC3ByParams partitions NSEC3 records into groups that share the same
// (hash algorithm, iterations, salt) tuple — one internally-consistent chain each.
// Group order follows first appearance so behavior is deterministic (R-037).
// Equivalent empty salts ("" and "-") and hex case are normalized (RA6X-013).
func groupNSEC3ByParams(records []dnspkg.NSEC3Record) [][]dnspkg.NSEC3Record {
	type paramKey struct {
		alg  uint8
		iter uint16
		salt string
	}
	order := make([]paramKey, 0)
	byKey := make(map[paramKey][]dnspkg.NSEC3Record)
	for _, r := range records {
		k := paramKey{r.Algorithm, r.Iterations, normalizeSalt(r.Salt)}
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
// The records must all belong to one chain (RA6X-013).
func verifyNSEC3NXDOMAIN(hashedQname, qname string, nsec3Records []dnspkg.NSEC3Record) (*NSECProof, error) {
	_ = hashedQname
	chain, err := newNSEC3Chain(nsec3Records)
	if err != nil {
		return nil, err
	}
	return chain.nxdomain(qname)
}

// verifyNSEC3NODATA verifies NSEC3 proves the type doesn't exist.
// Per RFC 5155 Section 8.5. hashedQname is recomputed from the chain's own
// parameters so a caller cannot pair a hash from one chain with another
// chain's records (RA6X-013).
func verifyNSEC3NODATA(hashedQname, qname string, qtype uint16, nsec3Records []dnspkg.NSEC3Record) (*NSECProof, error) {
	_ = hashedQname
	chain, err := newNSEC3Chain(nsec3Records)
	if err != nil {
		return nil, err
	}
	return verifyNSEC3NODATAInChain(chain, canonicalizeName(qname), qtype)
}

// verifyNSEC3NODATAInChain is the RFC 5155 §8.5 NODATA proof within one chain.
func verifyNSEC3NODATAInChain(c *nsec3Chain, qname string, qtype uint16) (*NSECProof, error) {
	typeName := dnspkg.TypeName(qtype)
	hashedQname := c.hash(qname)

	if nsec3 := c.match(hashedQname); nsec3 != nil {
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

		if !HasTypeInBitmap(typeName, nsec3.TypeBitmap) {
			return &NSECProof{
				ProofType:       "nodata",
				CoveringNSEC:    fmt.Sprintf("NSEC3 %s types: %v", nsec3.HashedOwner, nsec3.TypeBitmap),
				ClosestEncloser: qname,
				Explanation: fmt.Sprintf("NSEC3 at %s proves type %s does not exist for %s",
					nsec3.HashedOwner, typeName, qname),
			}, nil
		}
		return nil, fmt.Errorf("NSEC3 at %s lists type %s: NODATA is not proven for %s", nsec3.HashedOwner, typeName, qname)
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
// number of labels in the closest encloser. The closest encloser the denial records
// prove must AGREE with the one the (authenticated) signature claims (RA6X-011): an
// NSEC that proves a closer ancestor exists blocks synthesis from the shallower
// wildcard, and a next closer name that exists likewise refutes it. Proofs crossing
// a delegation or DNAME boundary are rejected. The returned proof has Verified=true
// only for a consistent proof; for NSEC3 an opt-out cover of the next closer name is
// reported through OptOut, whose conclusion is insecure (RA6X-012). The accompanying
// RRSIG signatures must be verified separately via VerifyDenialRRsetsFromResponse;
// callers must pass only authenticated records.
func VerifyWildcardDenial(qname string, wildcardLabels uint8, nsecRecords []dnspkg.NSECRecord, nsec3Records []dnspkg.NSEC3Record) *NSECProof {
	proof := &NSECProof{
		ProofType:    "wildcard",
		ResponseType: "WILDCARD",
		Records:      make([]string, 0),
	}

	qname = canonicalizeName(qname)
	if int(wildcardLabels) >= GetZoneLabels(qname) {
		proof.Error = fmt.Sprintf("signature Labels %d does not describe a wildcard expansion of %s", wildcardLabels, qname)
		return proof
	}
	claimedCE := lastNLabels(qname, int(wildcardLabels))
	nextCloser := lastNLabels(qname, int(wildcardLabels)+1)
	proof.ClosestEncloser = claimedCE
	proof.NextCloser = nextCloser

	if len(nsecRecords) > 0 {
		proof.ProofType = "NSEC"
		if err := nsecAncestorBoundary(qname, nsecRecords); err != nil {
			proof.Error = err.Error()
			return proof
		}
		// The queried name must not exist as an explicit (non-wildcard) name: find an
		// NSEC whose canonical range covers it, and check that the closest encloser it
		// proves is the one the signature claims.
		for _, nsec := range nsecRecords {
			owner := canonicalizeName(nsec.Owner)
			next := canonicalizeName(nsec.NextDomain)
			proof.Records = append(proof.Records, fmt.Sprintf("%s → %s", owner, next))
			if owner == qname {
				proof.Error = fmt.Sprintf("NSEC owned by %s proves an exact match exists; wildcard expansion from %s is not valid", owner, wildcardName(claimedCE))
				return proof
			}
			if owner == nextCloser {
				proof.Error = fmt.Sprintf("NSEC owned by %s proves the next closer name exists, so the closest encloser of %s is deeper than %s claimed by the signature; wildcard expansion from %s is not valid (RFC 4035 §5.3.4)",
					owner, qname, claimedCE, wildcardName(claimedCE))
				return proof
			}
			if !canonicallyBetween(qname, owner, next) {
				continue
			}
			if nsecEndpointBelow(qname, next) {
				proof.Error = fmt.Sprintf("NSEC %s -> %s proves %s exists as an empty non-terminal; wildcard expansion is not valid", owner, next, qname)
				return proof
			}
			provenCE := closestEncloserFromNSEC(qname, owner, next)
			if provenCE != claimedCE {
				proof.Error = fmt.Sprintf("NSEC %s -> %s proves the closest encloser of %s is %s, but the signature claims expansion from %s (closest encloser %s); the proof and signature disagree (RFC 4035 §5.3.4)",
					owner, next, qname, provenCE, wildcardName(claimedCE), claimedCE)
				return proof
			}
			proof.CoveringNSEC = fmt.Sprintf("%s -> %s", owner, next)
			proof.Explanation = fmt.Sprintf("NSEC proves %s has no exact match (falls between %s and %s) with closest encloser %s; wildcard expansion from %s is valid",
				qname, owner, next, claimedCE, wildcardName(claimedCE))
			proof.Verified = true
			return proof
		}
		proof.Error = fmt.Sprintf("no NSEC proves %s has no exact match for the wildcard expansion", qname)
		return proof
	}

	if len(nsec3Records) > 0 {
		proof.ProofType = "NSEC3"
		// RFC 9276: refuse excessive iteration counts before hashing (R-088).
		if iters, over := nsec3IterationsOverCap(nsec3Records); over {
			proof.Error = fmt.Sprintf("NSEC3 iterations=%d exceeds RFC 9276 cap of %d; refusing (CPU-amplification DoS vector)", iters, NSEC3MaxRecommendedIterations)
			return proof
		}
		for _, rec := range nsec3Records {
			proof.Records = append(proof.Records, fmt.Sprintf("%s → %s", rec.HashedOwner, rec.NextHashed))
		}
		chains, ignored, err := nsec3Chains(nsec3Records)
		if err != nil {
			proof.Error = err.Error()
			return proof
		}
		proof.Ignored = ignored

		// RFC 5155 §8.8: the closest encloser is known from the signature; the
		// next closer name must be covered, within ONE chain (RA6X-013), and
		// neither the queried name nor the next closer may exist.
		var lastErr string
		for _, chain := range chains {
			if chain.match(chain.hash(qname)) != nil || chain.match(chain.hash(nextCloser)) != nil {
				lastErr = fmt.Sprintf("NSEC3 proves %s or its next closer name %s exists; wildcard expansion from %s is not valid", qname, nextCloser, wildcardName(claimedCE))
				continue
			}
			if err := nsec3RecordBoundary(claimedCE, chain.match(chain.hash(claimedCE))); err != nil {
				lastErr = fmt.Sprintf("closest encloser %s: %v", claimedCE, err)
				continue
			}
			ncRec := chain.cover(chain.hash(nextCloser))
			if ncRec == nil {
				lastErr = fmt.Sprintf("no NSEC3 covers the next closer name %s for the wildcard expansion", nextCloser)
				continue
			}
			proof.CoveringNSEC = fmt.Sprintf("NSEC3 %s -> %s", ncRec.HashedOwner, ncRec.NextHashed)
			proof.Explanation = fmt.Sprintf("NSEC3 covers next closer name %s (hash %s); wildcard expansion from %s is valid",
				nextCloser, chain.hash(nextCloser), wildcardName(claimedCE))
			if isOptOut(ncRec) {
				proof.OptOut = true
				proof.Explanation += "; the cover is an opt-out NSEC3, so an unsigned delegation may exist at the next closer name: the conclusion is insecure, not secure (RFC 5155 §9.2)"
			}
			proof.Verified = true
			return proof
		}
		if lastErr == "" {
			lastErr = fmt.Sprintf("no NSEC3 covers the next closer name %s for the wildcard expansion", nextCloser)
		}
		proof.Error = lastErr
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
