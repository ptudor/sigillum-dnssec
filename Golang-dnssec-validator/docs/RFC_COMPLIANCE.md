# RFC Compliance Documentation

## DNSSEC Validator — Standards Conformance

This document tracks compliance with relevant IETF RFCs for DNS and DNSSEC.

---

## Core DNS Standards

### RFC 1034 / RFC 1035 — Domain Names

| Requirement | Section | Status | Notes |
|-------------|---------|--------|-------|
| Case-insensitive comparison | 1035 §2.3.3 | ✅ Compliant | `strings.ToLower()` used consistently |
| Label length ≤63 octets | 1035 §2.3.4 | ✅ Compliant | Validated in `handlers.go:247` |
| Total name ≤253 characters | 1035 §2.3.4 | ✅ Compliant | Validated in `handlers.go:235` |
| FQDN trailing dot handling | 1035 §3.1 | ✅ Compliant | Normalized throughout |
| Hyphen position rules | 1035 §2.3.1 | ✅ Compliant | Validated in `handlers.go:253-257` |

### RFC 6891 — EDNS0

| Requirement | Section | Status | Notes |
|-------------|---------|--------|-------|
| EDNS0 support | §6.2.3 | ✅ Compliant | 4096 byte buffer configured |
| DO (DNSSEC OK) bit | §6.1.4 | ✅ Compliant | Set in all queries |

### RFC 5966 — TCP for DNS

| Requirement | Section | Status | Notes |
|-------------|---------|--------|-------|
| TCP fallback on truncation | §4 | ✅ Compliant | Automatic retry in `query.go:56-62` |

---

## DNSSEC Standards

### RFC 4033 — DNSSEC Introduction

| Requirement | Section | Status | Notes |
|-------------|---------|--------|-------|
| Chain of trust validation | §5 | ✅ Compliant | Implemented root→target |
| Authenticated denial (NSEC) | §5 | ⚠️ Partial | Parsed but not validated |
| Authenticated denial (NSEC3) | §5 | ⚠️ Partial | Parsed but not validated |

### RFC 4034 — DNSSEC Resource Records

| Requirement | Section | Status | Notes |
|-------------|---------|--------|-------|
| DNSKEY flag interpretation | §2.1.1 | ✅ Compliant | Flags 256/257 correctly identified |
| DNSKEY protocol field = 3 | §2.1.2 | ✅ Compliant | Stored and displayed |
| DS digest computation | §5.1.4 | ✅ Compliant | Canonical wire format used |
| DS digest types (1,2,4) | §5.1.3 | ✅ Compliant | SHA-1, SHA-256, SHA-384 supported |
| RRSIG type covered | §3.1 | ✅ Compliant | Correctly parsed and matched |
| RRSIG labels field | §3.1.3 | ⚠️ Partial | Parsed but wildcard detection not implemented |
| RRSIG original TTL | §3.1.5 | ✅ Compliant | Used in verification |
| Key tag computation | §B.1 | ✅ Compliant | Via miekg/dns library |

### RFC 4035 — DNSSEC Protocol

| Requirement | Section | Status | Notes |
|-------------|---------|--------|-------|
| Signature verification | §5.3 | ✅ Compliant | Full cryptographic verification |
| Clock skew tolerance | §5.3.1 | ❌ Non-compliant | No tolerance implemented |
| Inception/expiration check | §5.3.1 | ✅ Compliant | Time bounds checked |
| Chain of trust walk | §5.2 | ✅ Compliant | Root anchors → target zone |
| Insecure delegation detection | §5.2 | ✅ Compliant | No DS = insecure |
| Bogus detection | §5.5 | ✅ Compliant | DS without matching DNSKEY = bogus |

### RFC 5155 — NSEC3

| Requirement | Section | Status | Notes |
|-------------|---------|--------|-------|
| NSEC3 parsing | §3 | ✅ Compliant | All fields captured |
| NSEC3 hash algorithm | §3.1 | ✅ Compliant | Algorithm field stored |
| NSEC3 opt-out flag | §6 | ⚠️ Partial | Flag parsed, not interpreted |
| NSEC3 iterations | §10.3 | ⚠️ No warning | High iteration counts not flagged |

### RFC 6840 — DNSSEC Clarifications

| Requirement | Section | Status | Notes |
|-------------|---------|--------|-------|
| Key tag collision handling | §5.10 | ⚠️ Partial | First match used; should verify digest |
| Multiple algorithm support | §5.11 | ❌ Non-compliant | Only one algorithm verified |
| Trust anchor rollover | §5.12 | ✅ Compliant | Multiple anchors supported |

### RFC 8624 — Algorithm Implementation Requirements

| Algorithm | Status per RFC | Our Support | Notes |
|-----------|----------------|-------------|-------|
| 5 (RSASHA1) | MUST NOT sign | ⚠️ No warning | Should warn on detection |
| 7 (RSASHA1-NSEC3-SHA1) | MUST NOT sign | ⚠️ No warning | Should warn on detection |
| 8 (RSASHA256) | MUST | ✅ Supported | |
| 10 (RSASHA512) | MAY | ✅ Supported | |
| 13 (ECDSAP256SHA256) | MUST | ✅ Supported | |
| 14 (ECDSAP384SHA384) | MAY | ✅ Supported | |
| 15 (ED25519) | RECOMMENDED | ✅ Supported | |
| 16 (ED448) | MAY | ✅ Supported | |

| Digest Type | Status per RFC | Our Support | Notes |
|-------------|----------------|-------------|-------|
| 1 (SHA-1) | MUST NOT sign | ⚠️ No warning | Should warn on detection |
| 2 (SHA-256) | MUST | ✅ Supported | |
| 4 (SHA-384) | MAY | ✅ Supported | |

### RFC 9276 — NSEC3 Guidance

| Requirement | Section | Status | Notes |
|-------------|---------|--------|-------|
| Iteration count ≤100 | §3.1 | ⚠️ No warning | Should flag excessive iterations |
| Salt length guidance | §3.1 | ⚠️ No warning | Not checked |

---

## Trust Anchor Standards

### RFC 5011 — Trust Anchor Update

| Requirement | Section | Status | Notes |
|-------------|---------|--------|-------|
| Automated updates | §2 | N/A | Uses external anchor file |
| Multiple anchor support | §6 | ✅ Compliant | Filters by validity dates |

---

## Compliance Summary

| Category | Compliant | Partial | Non-Compliant |
|----------|-----------|---------|---------------|
| Core DNS | 5 | 0 | 0 |
| DNSSEC Core | 12 | 4 | 2 |
| NSEC3 | 2 | 2 | 0 |
| Algorithms | 8 | 3 | 0 |
| **Total** | **27** | **9** | **2** |

---

## Known Issues Requiring Fix

### Critical (Causes Incorrect Results)

1. **No clock skew tolerance** — RFC 4035 §5.3.1 requires validators allow for timing errors
2. **Single algorithm verification** — RFC 6840 §5.11 requires ALL algorithms validate

### Important (Missing Diagnostics)

3. **Trust anchor digest not verified** — Only key tag checked, not DS digest
4. **No wildcard synthesis detection** — RRSIG Labels field unused
5. **No NSEC/NSEC3 proof validation** — Authenticated denial not verified

### Informational (User Warnings)

6. **No algorithm deprecation warnings** — RFC 8624 deprecated algorithms not flagged
7. **No NSEC3 iteration warnings** — RFC 9276 excessive iterations not flagged
8. **No NSEC3 opt-out interpretation** — Flag value not explained to user

---

## Version History

| Date | Version | Changes |
|------|---------|---------|
| 2026-01-23 | 1.0 | Initial compliance audit |
