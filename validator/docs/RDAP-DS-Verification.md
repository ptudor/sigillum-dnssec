# RDAP DS Record Verification

## Overview

The DNSSEC Validator includes an out-of-band DS record verification feature that queries RDAP (Registration Data Access Protocol) servers to compare DS records from two independent sources:

1. **DNS DS Records** - Retrieved from parent zone nameservers (the traditional source)
2. **RDAP DS Records** - Retrieved directly from the registry database via RDAP

This dual-source verification provides an additional layer of confidence in DNSSEC integrity.

## Why This Matters

### Different Data Sources

| Source | Path | Characteristics |
|--------|------|-----------------|
| **DNS** | Parent NS → Resolver → Client | Can be cached, potentially stale, subject to MITM if DNSSEC validation fails |
| **RDAP** | Registry DB → HTTPS → Client | Authoritative registry data, TLS-protected, typically real-time |

### What Matches Mean

| Match Result | Meaning | Concern Level |
|--------------|---------|---------------|
| **Full Match** | All DS records identical in both sources | None - good confirmation |
| **Partial Match** | Some DS records match, others differ | Medium - possible key rollover in progress |
| **No Match** | No DS records match between sources | High - investigate immediately |
| **RDAP Unsigned** | RDAP says no DS, but DNS has DS | High - registry/DNS desync |

### Common Causes of Mismatch

1. **Propagation Delay** - Registry updated but DNS hasn't propagated yet (usually resolves within hours)
2. **Key Rollover** - Domain is mid-rollover with old+new keys in transition
3. **Registry Sync Issue** - Backend problem at the registry
4. **DNS Cache Poisoning** - Malicious DS injection (rare but serious)
5. **Registrar Error** - DS records incorrectly submitted to registry

## Configuration

### Environment Variable

```bash
RDAP_BASE_URL=https://www.any53.com/rdap
```

### TOML Configuration

```toml
rdap_base_url = "https://www.any53.com/rdap"
```

### Default

If not configured, defaults to `https://www.any53.com/rdap` which is the local RDAP proxy that routes to authoritative RDAP servers worldwide.

### Disabling RDAP Verification

Set an empty value to disable:

```bash
RDAP_BASE_URL=""
```

## API Response

The `rdap_secure_dns` field appears in zone results for registrable domains (e.g., `example.com` but not `www.example.com` or `.com`):

```json
{
  "zone": "example.com.",
  "status": "secure",
  "ds": [
    {
      "key_tag": 2371,
      "algorithm": 13,
      "digest_type": 2,
      "digest": "32996839A6D808AFE3EB4A795A0E6A7A39A76FC52FF228B22B76F6D63826F2B9"
    }
  ],
  "rdap_secure_dns": {
    "delegation_signed": true,
    "ds_data": [
      {
        "key_tag": 2371,
        "algorithm": 13,
        "digest_type": 2,
        "digest": "32996839A6D808AFE3EB4A795A0E6A7A39A76FC52FF228B22B76F6D63826F2B9"
      }
    ],
    "ds_match": "full"
  }
}
```

### Match Result Values

| Value | Description |
|-------|-------------|
| `full` | All DS records match exactly |
| `partial` | Some records match, some differ |
| `none` | No matching DS records found |
| `no_rdap` | RDAP unavailable or domain not found in RDAP |
| `unsigned` | RDAP reports `delegationSigned: false` |

### Error Field

If RDAP query fails, the `error` field contains the reason:

```json
{
  "rdap_secure_dns": {
    "ds_match": "no_rdap",
    "error": "domain not found in RDAP"
  }
}
```

## Web UI

The web interface displays RDAP verification status on DS records:

- **RDAP ✓** (green) - DS record matches RDAP
- **RDAP ✗** (red) - DS record not found in RDAP
- **RDAP only** (yellow) - DS record exists in RDAP but not in DNS

A summary line below the DS records shows the overall RDAP status.

## Limitations

### Registrable Domain Detection

The current implementation uses a simple heuristic (2-label domains like `example.com`) rather than a full Public Suffix List. This means:

- Works correctly for standard TLDs: `example.com`, `example.net`, `example.org`
- May not work for complex TLDs: `example.co.uk`, `example.com.au`

### RDAP Coverage

Not all domains have RDAP data available:

- **gTLDs** (.com, .net, .org, etc.) - Generally good coverage
- **ccTLDs** - Varies by country; some don't support RDAP
- **New gTLDs** - Usually have RDAP support
- **Private/Internal zones** - No RDAP data

### Timing

RDAP queries add latency to validation. The query runs in parallel with other validation steps where possible, but may add 100-500ms depending on RDAP server response time.

## Technical Details

### RDAP Client

The RDAP client (`internal/rdap/client.go`):

- Uses the shared User-Agent: `TUDOR-DNSSEC-VALIDATOR/1.0 (ptudor.net)`
- Accepts `application/rdap+json` and `application/json`
- Treats HTTP 404 as "domain not found" (not an error)
- Uses the configured query timeout

### DS Comparison

DS records are compared by normalizing digests to uppercase and matching on:

- Key Tag
- Algorithm
- Digest Type
- Digest (hex string, case-insensitive)

### Integration Point

RDAP queries occur in `validateZone()` after:
1. DS records are fetched from parent zone
2. Chain of trust is validated

This ensures RDAP verification is purely informational and doesn't affect the core DNSSEC validation result.

## Related RFCs

- **RFC 9083** - JSON Responses for RDAP (secureDNS object in §5.3)
- **RFC 9082** - RDAP Query Format
- **RFC 7483** - Original RDAP JSON specification (obsoleted by RFC 9083)

## See Also

- [Golang-rdap-proxy-server](../../Golang-rdap-proxy-server/) - The RDAP proxy that routes queries to authoritative servers
- [IANA RDAP Bootstrap](https://data.iana.org/rdap/) - Bootstrap files for RDAP routing
