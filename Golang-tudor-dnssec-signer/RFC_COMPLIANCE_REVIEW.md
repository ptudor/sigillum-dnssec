# RFC Compliance Review: dnssec-tudor

**Reviewer perspective**: Skeptical RFC author who has seen too many broken DNSSEC implementations.

**Status**: Several issues identified that should be fixed before production use.

---

## CRITICAL ISSUES (Will break validation)

### 1. NSEC/NSEC3 TTL Must Match SOA Minimum (RFC 4035 §2.3)

**Current**: Hardcoded to 3600 seconds.

**RFC 4035 §2.3**: "The TTL value for any NSEC RR SHOULD be the same as the minimum TTL value field in the zone SOA RR."

**Impact**: Some validators may reject responses or cache incorrectly.

**Fix needed in sign.go**:
```go
// Get SOA minimum TTL for NSEC/NSEC3
var soaMinTTL uint32 = 3600 // fallback
for _, rr := range records {
    if soa, ok := rr.(*dns.SOA); ok {
        soaMinTTL = soa.Minttl
        break
    }
}
```

### 2. Empty Non-Terminals Missing from NSEC3 Chain (RFC 5155 §7.1)

**Current**: Only names with actual records are hashed.

**RFC 5155 §7.1**: "Each owner name within the zone that has authoritative RRsets MUST have a corresponding NSEC3 RR. Owner names for which the only RRsets are glue records... MUST NOT have NSEC3 RRs. **Empty non-terminals** (names that have no RRsets but have subdomains that do) MUST have NSEC3 RRs."

**Example**: If zone has `sub.example.com` but not `example.com` itself as a name with records, there's still an empty non-terminal at `example.com` that needs an NSEC3 record.

**Impact**: NXDOMAIN proofs may be incorrect, causing validation failures.

**Fix needed**: Build set of all names including empty non-terminals:
```go
// Add empty non-terminals
for name := range names {
    labels := dns.SplitDomainName(name)
    for i := 1; i < len(labels); i++ {
        parent := strings.Join(labels[i:], ".") + "."
        if !names[parent] {
            names[parent] = true
            // Empty non-terminal has no types
            typesByName[parent] = make(map[uint16]bool)
        }
    }
}
```

### 3. NSEC3 Type Bitmap Missing NSEC3 Type Itself

**Current**: NSEC3 records don't include NSEC3 in their type bitmap.

**RFC 5155 §7.1**: The type bitmap "MUST NOT include the type value for RRSIG or NSEC3."

**Wait, this is actually CORRECT** - my mistake. NSEC3 records should NOT include NSEC3 in the type bitmap. But they also shouldn't include RRSIG in the type bitmap per the RFC... let me check.

Actually, re-reading RFC 5155 §7.1: "The Type Bit Maps field of every NSEC3 RR in a signed zone MUST indicate the presence of all types present at the original owner name, except for the types solely contributed by an NSEC3 RR itself. That is, if an NSEC3 RR exists only to match an empty non-terminal node, the Type Bit Maps field MUST be empty."

**Current code adds RRSIG unconditionally**:
```go
types = append(types, dns.TypeRRSIG)
```

This is wrong for empty non-terminals!

---

## HIGH PRIORITY ISSUES (Interoperability problems)

### 4. Canonical DNS Name Ordering is Wrong (RFC 4034 §6.1)

**Current**:
```go
sort.Slice(sortedNames, func(i, j int) bool {
    return dns.CanonicalName(sortedNames[i]) < dns.CanonicalName(sortedNames[j])
})
```

**Problem**: `dns.CanonicalName()` lowercases the name, but canonical ordering per RFC 4034 §6.1 requires comparing labels right-to-left, not lexicographically comparing the full name.

**RFC 4034 §6.1**: "For the purposes of DNS security, owner names are ordered in canonical order by treating individual labels as unsigned left-justified octet strings. The absence of a octet sorts before a zero value octet, and upper case letters are treated as lower case letters."

**Example**: `a.example.com` should sort BEFORE `z.example.com`, but `example.com` should sort BEFORE both. Current lexicographic sort gets this wrong.

**Fix**: Use `dns.Compare()` or implement proper canonical ordering.

### 5. DNSKEY TTL Should Match Zone TTL Convention

**Current**: Hardcoded to 3600 in key generation.

**Best practice**: DNSKEY TTL should typically match the zone's TTL convention, often taken from the SOA or NS records.

### 6. RRSIG Original TTL Field (RFC 4034 §3.1.5)

**Current**: Uses the current TTL of the RRset.

**Concern**: If someone edits the zone file and changes a TTL, the original TTL in existing signatures won't match, potentially causing issues.

This is actually fine for fresh signing, but something to be aware of.

---

## MEDIUM PRIORITY ISSUES (Edge cases)

### 7. Wildcard Label Count (RFC 4035 §5.3.1)

**Current**:
```go
Labels: uint8(dns.CountLabel(rrset[0].Header().Name)),
```

**RFC 4035 §5.3.1**: "For each authoritative RRset in a signed zone, there MUST be at least one RRSIG record... The Labels field of every RRSIG RR MUST equal the number of labels in the RRset's owner name, excluding the root label and excluding the leftmost label if it is a wildcard."

**Impact**: Wildcard records (`*.example.com`) need special handling. The labels field should be 2, not 3.

**Fix**:
```go
labels := dns.CountLabel(rrset[0].Header().Name)
if strings.HasPrefix(rrset[0].Header().Name, "*.") {
    labels--
}
```

### 8. Delegation Points and Glue Records (RFC 4035 §2.2)

**Current**: Signs all records in zone file.

**RFC 4035 §2.2**: "A signed zone MUST include a DNSKEY RRset at the zone apex. A signed zone MAY have an NSEC RR at a delegation point. A signed zone SHOULD NOT include any RRSIG records for any NS or glue address records at a delegation point."

**Impact**: If zone file contains NS records for delegated subzones (delegation points), they should NOT be signed. Only the DS record (if any) should be signed.

### 9. NSEC3 Salt Encoding

**Current**:
```go
SaltLength: uint8(len(salt) / 2), // Salt is hex encoded
```

**Assumption**: Salt is hex-encoded in config. This should be documented clearly, and the code should validate it's valid hex.

---

## LOW PRIORITY ISSUES (Cosmetic/best practices)

### 10. NSEC3PARAM TTL (RFC 5155 §4.2)

**Current**: TTL = 0

**RFC 5155 §4.2**: "The NSEC3PARAM RR SHOULD have a TTL value of zero."

**Status**: ✅ Correct!

### 11. Key Rollover Timing Constants

**Current**: Hardcoded 14 days, 7 days for ZSK rollover phases.

**RFC 7583**: Provides guidance on timing that depends on TTLs, propagation delays, etc.

**Suggestion**: Make these configurable or compute based on signature validity and zone TTLs.

### 12. Algorithm Rollover Not Supported

**Current**: No support for algorithm rollover (e.g., RSA to ECDSA).

**Impact**: Users stuck on old algorithms can't migrate without manual intervention.

**Not critical for v1**, but worth noting.

---

## SUMMARY OF REQUIRED FIXES

| Priority | Issue | Effort |
|----------|-------|--------|
| CRITICAL | NSEC/NSEC3 TTL from SOA minimum | Small |
| CRITICAL | Empty non-terminals in NSEC3 | Medium |
| CRITICAL | NSEC3 type bitmap for ENTs | Small |
| HIGH | Canonical name ordering | Medium |
| MEDIUM | Wildcard label count | Small |
| MEDIUM | Don't sign at delegation points | Medium |

---

## TESTING RECOMMENDATIONS

Before going live:

1. **Verify with multiple validators**:
   ```bash
   ldns-verify-zone signed.zone
   validns -s signed.zone
   ```

2. **Test with online validators**:
   - https://dnsviz.net/
   - https://dnssec-debugger.verisignlabs.com/

3. **Test NXDOMAIN responses** with NSEC3:
   ```bash
   dig nonexistent.example.com @localhost +dnssec
   ```

4. **Test with real resolvers**:
   - Google (8.8.8.8) with +dnssec
   - Cloudflare (1.1.1.1) with +dnssec
   - Verify AD (Authenticated Data) flag is set

5. **Test wildcard expansion**:
   - If you have wildcards, verify they validate correctly

---

## CONCLUSION

The core signing logic is sound and uses miekg/dns correctly for the cryptographic operations. The main issues are around edge cases in NSEC/NSEC3 chain generation that could cause validation failures for NXDOMAIN responses or zones with complex structure.

**Recommendation**: Fix the CRITICAL issues before production use. The HIGH issues are important for correctness but may not cause immediate failures depending on zone structure.

---

*Review Date: 2026-01-19*
*Reviewer: Claude (playing skeptical RFC author)*
