# RFC Compliance Fixes — Implementation Guide

## Task #1: Add Clock Skew Tolerance (RFC 4035 §5.3.1)

**Priority:** P0 — Critical (causes false validation failures)

**Current Code:** `internal/validator/dnssec.go:132-136`
```go
func VerifyRRSIGValid(rrsig dnspkg.RRSIGRecord) bool {
    now := time.Now()
    return now.After(rrsig.Inception) && now.Before(rrsig.Expiration)
}
```

**Solution:**
```go
// ClockSkewTolerance is the allowed clock difference between validator and signer.
// RFC 4035 Section 5.3.1 recommends allowing for timing errors.
// 5 minutes is standard practice in most validators (BIND, Unbound, etc.)
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
```

**Testing:**
- Create RRSIG with inception = now + 3 minutes → should be valid
- Create RRSIG with expiration = now - 3 minutes → should be valid
- Create RRSIG with inception = now + 10 minutes → should be invalid
- Create RRSIG with expiration = now - 10 minutes → should be invalid

---

## Task #2: Multi-Algorithm Validation (RFC 6840 §5.11)

**Priority:** P1 — Important (false positives during rollovers)

**Current Code:** `internal/validator/dnssec.go:158-193`

The function returns success on first matching DS/DNSKEY pair.

**Solution:**
```go
// ValidateChainLink validates the chain of trust between DS and DNSKEY records.
// Per RFC 6840 Section 5.11, if multiple algorithms are present, ALL must validate.
func ValidateChainLink(parentDS []dnspkg.DSRecord, childDNSKEY []dnspkg.DNSKEYRecord, zone string) (*ChainLink, error) {
    link := &ChainLink{
        ChildZone:  zone,
        ParentZone: GetParentZone(zone),
        ParentDS:   parentDS,
    }

    if len(parentDS) == 0 {
        return nil, fmt.Errorf("no DS records in parent zone")
    }

    // Group DS records by algorithm
    algorithmDS := make(map[uint8][]dnspkg.DSRecord)
    for _, ds := range parentDS {
        algorithmDS[ds.Algorithm] = append(algorithmDS[ds.Algorithm], ds)
    }

    // RFC 6840 §5.11: Each algorithm present MUST have at least one valid DS→DNSKEY chain
    var validatedAlgorithms []uint8
    var firstValidKSK *dnspkg.DNSKEYRecord

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
                break
            }
        }

        if algValidated {
            validatedAlgorithms = append(validatedAlgorithms, alg)
        } else {
            // Algorithm present in DS but no valid DNSKEY = BOGUS
            return link, fmt.Errorf("algorithm %d (%s) has DS but no matching DNSKEY",
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
```

**Testing:**
- Zone with DS for alg 8 and 13, DNSKEY for both → secure
- Zone with DS for alg 8 and 13, DNSKEY only for 8 → bogus
- Zone with DS for alg 8, DNSKEY for 8 and 13 → secure (extra DNSKEY OK)

---

## Task #3: Trust Anchor Digest Verification (RFC 4034 Appendix B)

**Priority:** P1 — Important (security weakness)

**Current Code:** `internal/validator/dnssec.go:326-349`

Only checks key tag and algorithm, not the actual digest.

**Solution:**
```go
// VerifyRootTrustAnchor verifies that root DNSKEYs match the trust anchors
// by computing and comparing DS digests, not just key tags (which can collide)
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
            computedDigest, err := ComputeDSDigestFromDNSKEY(".", key, uint8(anchor.DigestType))
            if err != nil {
                continue // Can't verify, try next
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
            // Key tag matched but digest didn't — possible collision or attack
        }
    }

    return link, fmt.Errorf("no DNSKEY matches any trust anchor (digest verification failed)")
}
```

**Testing:**
- Valid root DNSKEY → verified
- DNSKEY with same key tag but wrong public key → rejected
- DNSKEY with same key tag, algorithm, but tampered key → rejected

---

## Task #4: Wildcard Synthesis Detection (RFC 4034 §3.1.3)

**Priority:** P2 — Diagnostic enhancement

**Solution:** Add to result types and check during validation.

```go
// In internal/validator/result.go, add to ZoneResult:
type ZoneResult struct {
    // ... existing fields ...
    WildcardSource string `json:"wildcard_source,omitempty"` // If synthesized from wildcard
}

// In internal/validator/dnssec.go, add helper:

// DetectWildcardSynthesis checks if an RRSIG indicates wildcard synthesis.
// Per RFC 4034 §3.1.3, if owner name has more labels than RRSIG.Labels,
// the response was synthesized from a wildcard.
// Returns the wildcard source (e.g., "*.example.com.") or empty string.
func DetectWildcardSynthesis(ownerName string, rrsig dnspkg.RRSIGRecord) string {
    ownerLabels := GetZoneLabels(ownerName)

    // Labels field in RRSIG is the number of labels in the original owner name
    // (excluding the "*" label for wildcards)
    if ownerLabels > int(rrsig.Labels) {
        // Synthesized from wildcard
        // Reconstruct wildcard: take last N labels and prepend "*"
        labels := strings.Split(strings.TrimSuffix(NormalizeDomain(ownerName), "."), ".")
        if int(rrsig.Labels) < len(labels) {
            wildcardLabels := labels[len(labels)-int(rrsig.Labels):]
            return "*." + strings.Join(wildcardLabels, ".") + "."
        }
    }
    return ""
}
```

**Usage in validator.go:** After verifying RRSIG, check for wildcard:
```go
if rrsig := FindRRSIGForType(dns.TypeDNSKEY, result.RRSIG); rrsig != nil {
    if wildcard := DetectWildcardSynthesis(zone, *rrsig); wildcard != "" {
        result.WildcardSource = wildcard
        result.AddWarning(fmt.Sprintf("Response synthesized from wildcard %s", wildcard))
    }
}
```

---

## Task #5: NSEC/NSEC3 Authenticated Denial (RFC 4033 §5)

**Priority:** P2 — Core missing functionality

**Solution:** This is complex. Implement in phases.

**Phase 1: NSEC validation for NXDOMAIN**
```go
// In internal/validator/nsec.go (new file)

package validator

import (
    "strings"
    dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

// NSECProof represents proof of non-existence
type NSECProof struct {
    ProofType   string `json:"proof_type"` // "nxdomain", "nodata", "no_ds"
    CoveringRR  string `json:"covering_rr"` // The NSEC/NSEC3 that proves it
    Explanation string `json:"explanation"`
}

// VerifyNSECNXDOMAIN verifies NSEC proves a name doesn't exist.
// The queried name must fall canonically between NSEC owner and NextDomain.
func VerifyNSECNXDOMAIN(qname string, nsecRecords []dnspkg.NSECRecord) (*NSECProof, error) {
    qname = strings.ToLower(strings.TrimSuffix(qname, ".")) + "."

    for _, nsec := range nsecRecords {
        owner := strings.ToLower(nsec.NextDomain) // Note: need actual owner from RR header
        next := strings.ToLower(nsec.NextDomain)

        // Check if qname falls between owner and next in canonical order
        if canonicallyBetween(qname, owner, next) {
            return &NSECProof{
                ProofType:   "nxdomain",
                CoveringRR:  fmt.Sprintf("NSEC %s → %s", owner, next),
                Explanation: fmt.Sprintf("Name %s proven non-existent (falls between %s and %s)",
                    qname, owner, next),
            }, nil
        }
    }

    return nil, fmt.Errorf("no NSEC record proves %s doesn't exist", qname)
}

// VerifyNSECNODATA verifies NSEC proves a type doesn't exist for an existing name.
func VerifyNSECNODATA(qname string, qtype uint16, nsecRecords []dnspkg.NSECRecord) (*NSECProof, error) {
    qname = strings.ToLower(strings.TrimSuffix(qname, ".")) + "."
    typeName := dnspkg.TypeName(qtype)

    for _, nsec := range nsecRecords {
        // NSEC at qname should not include qtype in type bitmap
        // (Need owner from NSEC RR header for proper matching)
        for _, t := range nsec.TypeBitmap {
            if t == typeName {
                return nil, fmt.Errorf("NSEC shows type %s exists", typeName)
            }
        }
        return &NSECProof{
            ProofType:   "nodata",
            CoveringRR:  fmt.Sprintf("NSEC types: %v", nsec.TypeBitmap),
            Explanation: fmt.Sprintf("Type %s not in type bitmap for %s", typeName, qname),
        }, nil
    }

    return nil, fmt.Errorf("no NSEC record at %s", qname)
}

// canonicallyBetween checks if name falls between start and end in canonical DNS order
func canonicallyBetween(name, start, end string) bool {
    // DNS canonical ordering: compare label by label, right to left
    // This is a simplified version; full implementation needs proper label comparison
    return name > start && name < end
}
```

**Phase 2: NSEC3 validation** (more complex due to hashing)
```go
// VerifyNSEC3NXDOMAIN verifies NSEC3 proves a name doesn't exist
func VerifyNSEC3NXDOMAIN(qname string, nsec3Records []dnspkg.NSEC3Record, zone string) (*NSECProof, error) {
    // 1. Hash the qname using NSEC3 parameters (algorithm, iterations, salt)
    // 2. Find NSEC3 whose hash range covers the computed hash
    // 3. Verify the computed hash falls between NSEC3 owner hash and NextHashed

    // This requires computing NSEC3 hash:
    // hash = iterations times: hash(hash || name || salt)

    // Implementation deferred - this is complex
    return nil, fmt.Errorf("NSEC3 validation not yet implemented")
}
```

---

## Task #6: Algorithm Deprecation Warnings (RFC 8624)

**Priority:** P3 — User education

**Solution:** Add warning functions and call during validation.

```go
// In internal/validator/warnings.go (new file)

package validator

import (
    dnspkg "github.com/ptudor/dnssec-validator/internal/dns"
)

// RFC 8624 algorithm status
var deprecatedAlgorithms = map[uint8]string{
    5: "RSASHA1 (RFC 8624: MUST NOT use for signing, considered weak)",
    7: "RSASHA1-NSEC3-SHA1 (RFC 8624: MUST NOT use for signing, considered weak)",
}

var deprecatedDigestTypes = map[uint8]string{
    1: "SHA-1 (RFC 8624: MUST NOT use for signing, cryptographically weak)",
}

// CheckAlgorithmDeprecation returns warnings for deprecated algorithms
func CheckAlgorithmDeprecation(dnskeys []dnspkg.DNSKEYRecord) []string {
    var warnings []string
    seen := make(map[uint8]bool)

    for _, key := range dnskeys {
        if msg, deprecated := deprecatedAlgorithms[key.Algorithm]; deprecated && !seen[key.Algorithm] {
            warnings = append(warnings, fmt.Sprintf("Zone uses deprecated algorithm %d: %s",
                key.Algorithm, msg))
            seen[key.Algorithm] = true
        }
    }

    return warnings
}

// CheckDigestTypeDeprecation returns warnings for deprecated DS digest types
func CheckDigestTypeDeprecation(dsRecords []dnspkg.DSRecord) []string {
    var warnings []string
    seen := make(map[uint8]bool)

    for _, ds := range dsRecords {
        if msg, deprecated := deprecatedDigestTypes[ds.DigestType]; deprecated && !seen[ds.DigestType] {
            warnings = append(warnings, fmt.Sprintf("DS uses deprecated digest type %d: %s",
                ds.DigestType, msg))
            seen[ds.DigestType] = true
        }
    }

    return warnings
}
```

**Usage in validator.go:**
```go
// After retrieving DNSKEY
result.Warnings = append(result.Warnings, CheckAlgorithmDeprecation(result.DNSKEY)...)

// After retrieving DS
result.Warnings = append(result.Warnings, CheckDigestTypeDeprecation(result.DS)...)
```

---

## Task #7: NSEC3 Iteration Warnings (RFC 9276)

**Priority:** P3 — User education

**Solution:**
```go
// In internal/validator/warnings.go

const (
    // RFC 9276 Section 3.1: iterations SHOULD be 0, MUST NOT exceed 100
    NSEC3MaxRecommendedIterations = 100
    NSEC3IdealIterations          = 10
)

// CheckNSEC3Iterations returns warnings for excessive NSEC3 iterations
func CheckNSEC3Iterations(nsec3Records []dnspkg.NSEC3Record) []string {
    var warnings []string

    for _, nsec3 := range nsec3Records {
        if nsec3.Iterations > NSEC3MaxRecommendedIterations {
            warnings = append(warnings, fmt.Sprintf(
                "NSEC3 iterations=%d exceeds RFC 9276 maximum recommendation (≤%d); "+
                "high iterations are a DoS vector and provide no security benefit",
                nsec3.Iterations, NSEC3MaxRecommendedIterations))
            break // One warning is enough
        } else if nsec3.Iterations > NSEC3IdealIterations {
            warnings = append(warnings, fmt.Sprintf(
                "NSEC3 iterations=%d exceeds RFC 9276 ideal (≤%d); consider reducing",
                nsec3.Iterations, NSEC3IdealIterations))
            break
        }
    }

    return warnings
}
```

---

## Task #8: NSEC3 Opt-Out Interpretation (RFC 5155)

**Priority:** P3 — User education

**Solution:**
```go
// In internal/validator/warnings.go

// NSEC3 Flags
const NSEC3OptOutFlag = 0x01

// CheckNSEC3OptOut returns information about NSEC3 opt-out status
func CheckNSEC3OptOut(nsec3Records []dnspkg.NSEC3Record) (bool, string) {
    for _, nsec3 := range nsec3Records {
        if nsec3.Flags&NSEC3OptOutFlag != 0 {
            return true, "NSEC3 opt-out is enabled: insecure delegations may not be " +
                "cryptographically proven. This is common for large TLDs but means " +
                "unsigned child zones cannot be distinguished from non-existent names " +
                "using NSEC3 alone."
        }
    }
    return false, ""
}

// In ZoneResult, add field:
type ZoneResult struct {
    // ... existing fields ...
    NSEC3OptOut     bool   `json:"nsec3_opt_out,omitempty"`
    NSEC3OptOutNote string `json:"nsec3_opt_out_note,omitempty"`
}
```

---

## Task #9: DNSKEY Flag Handling Cleanup

**Priority:** P3 — Code clarity

**Current Code:** `internal/dns/query.go:111-117`
```go
IsKSK: v.Flags&0x0001 == 0x0001, // SEP bit
IsZSK: v.Flags&0x0100 == 0x0100, // Zone Key bit
// ...
dnskey.IsKSK = v.Flags == 257
dnskey.IsZSK = v.Flags == 256
```

**Solution:**
```go
// DNSKEY flag bits per RFC 4034 Section 2.1.1
const (
    // Bit 7: Zone Key flag - DNSKEY is a zone key (required for DNSSEC)
    DNSKEYFlagZoneKey = 1 << 8  // 256 in flags field

    // Bit 15: Secure Entry Point - key is intended for use as trust anchor
    // Conventionally indicates a KSK
    DNSKEYFlagSEP = 1 << 0      // 1 in flags field
)

// In parseResponse:
dnskey := DNSKEYRecord{
    Flags:     v.Flags,
    Protocol:  v.Protocol,
    Algorithm: v.Algorithm,
    PublicKey: base64.StdEncoding.EncodeToString([]byte(v.PublicKey)),
    KeyTag:    v.KeyTag(),
    // KSK: Zone Key (256) + SEP (1) = 257
    // ZSK: Zone Key (256) only = 256
    // Per RFC 4034, SEP is a hint; zone key bit is required for signing
    IsKSK: v.Flags == DNSKEYFlagZoneKey|DNSKEYFlagSEP, // 257
    IsZSK: v.Flags == DNSKEYFlagZoneKey,               // 256
}

// Note: Keys with other flag combinations (0, 1, etc.) are unusual but valid.
// They're neither KSK nor ZSK by convention but may still be used.
// The library handles them correctly for signature verification.
```

---

## Implementation Order

1. **Task #1** (Clock skew) — Simple fix, high impact
2. **Task #3** (Trust anchor digest) — Security fix, moderate complexity
3. **Task #9** (DNSKEY flags) — Code cleanup, simple
4. **Task #6** (Algorithm warnings) — New file, simple
5. **Task #7** (NSEC3 iterations) — Add to warnings file, simple
6. **Task #8** (Opt-out flag) — Add to warnings file, simple
7. **Task #2** (Multi-algorithm) — Moderate complexity, important
8. **Task #4** (Wildcard detection) — Moderate complexity
9. **Task #5** (NSEC/NSEC3 denial) — Complex, implement in phases

---

## Testing Requirements

Each fix should include tests:

```go
// Example test for clock skew (Task #1)
func TestVerifyRRSIGValidWithClockSkew(t *testing.T) {
    now := time.Now()

    tests := []struct {
        name       string
        inception  time.Time
        expiration time.Time
        want       bool
    }{
        {"valid normal", now.Add(-1*time.Hour), now.Add(1*time.Hour), true},
        {"valid inception in near future", now.Add(3*time.Minute), now.Add(1*time.Hour), true},
        {"valid expiration in near past", now.Add(-1*time.Hour), now.Add(-3*time.Minute), true},
        {"invalid inception too far future", now.Add(10*time.Minute), now.Add(1*time.Hour), false},
        {"invalid expiration too far past", now.Add(-1*time.Hour), now.Add(-10*time.Minute), false},
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            rrsig := dnspkg.RRSIGRecord{
                Inception:  tt.inception,
                Expiration: tt.expiration,
            }
            if got := VerifyRRSIGValid(rrsig); got != tt.want {
                t.Errorf("VerifyRRSIGValid() = %v, want %v", got, tt.want)
            }
        })
    }
}
```
