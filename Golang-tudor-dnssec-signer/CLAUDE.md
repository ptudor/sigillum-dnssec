# CLAUDE.md — dnssec-tudor

A minimal, opinionated DNSSEC signing daemon for sysadmins who just want zones signed.

## Project Philosophy

This tool exists because every DNSSEC solution is either:
- Overkill (OpenDNSSEC, PowerDNS) requiring databases, complex configs, HSM support
- Designed for DNS operators, not sysadmins with a colo box

**Target user:** A sysadmin with 10-50 domains on a single server, using NSD or similar authoritative-only nameserver that wants BIND-style zone files signed and doesn't want DNSSEC to become a part-time job.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    dnssec-tudor                         │
├─────────────────────────────────────────────────────────┤
│  Config: /etc/dnssec-tudor/config.toml                  │
│  Zones:  /etc/dnssec-tudor/zones/net/ptudor/zone.db     │
│  Keys:   /var/lib/dnssec-tudor/keys/                    │
│  Output: /var/lib/dnssec-tudor/signed/                  │
│  State:  /var/lib/dnssec-tudor/state.json               │
└─────────────────────────────────────────────────────────┘
           │                              │
           ▼                              ▼
    ┌─────────────┐               ┌──────────────┐
    │ NSD picks   │               │ Web UI shows │
    │ up signed   │               │ DS/DNSKEY    │
    │ zones       │               │ for registar │
    └─────────────┘               └──────────────┘
```

## Core Requirements

### What It Does

1. **Watches unsigned zone files** in a configured directory
2. **Generates keys** (KSK + ZSK) on first seeing a zone, with configurable lifetime (default: 3 years)
3. **Signs zones** automatically when:
   - Zone file changes (mtime or serial)
   - Signatures approaching expiry (resigns at 75% of signature lifetime)
   - Key rollover in progress
4. **Outputs signed zones** to a directory NSD can include
5. **Emits JSON to stdout** on demand (`--status`) or continuously (`--watch`)
6. **Serves a tiny web UI** (optional) showing:
   - Per-domain key status, DS records, DNSKEY records
   - Copy-pastable formats for common registrars
   - Rollover status and next actions needed

### What It Does NOT Do

- Talk to registrars (you copy-paste DS records yourself)
- Support NSEC3 opt-out or other complex configurations
- Manage your primary/secondary topology
- Support HSMs or PKCS#11
- Run as anything other than a single daemon on one machine

## Command Line Interface

```bash
# Run the daemon (foreground, logs to stderr, reloads on SIGHUP)
dnssec-tudor serve

# Run with web UI enabled
dnssec-tudor serve --web :8053

# One-shot: sign all zones, print status JSON to stdout, exit
dnssec-tudor sign

# Print status JSON to stdout
dnssec-tudor status
dnssec-tudor status --domain example.com

# Add a new domain (registers zone path, generates keys, signs)
# Zone file must already exist at the path
dnssec-tudor add example.com /etc/dnssec-tudor/zones/com/example/zone.db

# Remove a domain (does NOT delete keys, just stops managing)
dnssec-tudor remove example.com

# Key rollover commands
dnssec-tudor rollover start example.com    # Begin KSK or ZSK rollover
dnssec-tudor rollover status example.com   # Show rollover state
dnssec-tudor rollover complete example.com # Finalize after DS updated

# Export for registrar
dnssec-tudor ds example.com                # Print DS records
dnssec-tudor dnskey example.com            # Print DNSKEY records
```

## Configuration

```toml
# /etc/dnssec-tudor/config.toml

# Where to write signed zone files (flat: ptudor.net.zone.signed)
output_dir = "/var/lib/dnssec-tudor/signed"

# Where to store keys and state
data_dir = "/var/lib/dnssec-tudor"

# How often to check zones for changes (when running as daemon)
poll_interval = "5m"

# DNSSEC parameters
[dnssec]
algorithm = "ED25519"          # Smaller signatures, faster; fall back to ECDSAP256SHA256 if registrar doesn't support alg 15
ksk_lifetime = "3y"            # 1y, 3y, 5y — how long before rollover reminder
zsk_lifetime = "90d"           # ZSK rolls automatically, no registrar interaction
signature_validity = "14d"     # How long signatures are valid
signature_refresh = "3d"       # Re-sign when this much validity remains
nsec_version = "nsec3"         # "nsec" or "nsec3"

# Optional web UI
[web]
enabled = false
listen = "127.0.0.1:8053"
# No auth by default — bind to localhost and proxy if you need it

# Zone definitions — explicit paths, can be anywhere
# Supports hierarchical organization: zones/net/ptudor/zone.db
[zones.ptudor.net]
path = "/etc/dnssec-tudor/zones/net/ptudor/zone.db"

[zones.ptudor.com]
path = "/etc/dnssec-tudor/zones/com/ptudor/zone.db"
ksk_lifetime = "5y"  # Override: I'm extra lazy about this one

[zones.example.org]
path = "/srv/dns/org/example/zone.db"  # Can live anywhere

# Hook to run after signing (e.g., reload NSD)
[hooks]
post_sign = "systemctl reload nsd"
```

## JSON Output Schema

### Status Output (`dnssec-tudor status`)

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "zones": {
    "example.com": {
      "status": "healthy",
      "serial": 2024011501,
      "last_signed": "2024-01-15T10:00:00Z",
      "signatures_expire": "2024-01-29T10:00:00Z",
      "ksk": {
        "id": 12345,
        "algorithm": "ED25519",
        "created": "2023-01-15T00:00:00Z",
        "expires": "2026-01-15T00:00:00Z",
        "ds_published": true,
        "rollover_due": "2025-10-15T00:00:00Z"
      },
      "zsk": {
        "id": 67890,
        "algorithm": "ED25519",
        "created": "2024-01-01T00:00:00Z",
        "expires": "2024-04-01T00:00:00Z"
      },
      "warnings": [],
      "errors": []
    },
    "example.org": {
      "status": "action_required",
      "warnings": ["KSK rollover in progress — update DS at registrar"],
      "rollover": {
        "type": "ksk",
        "state": "ds_wait",
        "old_key_id": 11111,
        "new_key_id": 22222,
        "started": "2024-01-10T00:00:00Z",
        "action": "Publish new DS record at registrar, then run: dnssec-tudor rollover complete example.org"
      }
    }
  },
  "summary": {
    "total": 25,
    "healthy": 24,
    "action_required": 1,
    "errors": 0
  }
}
```

### Possible status values
- `healthy` — Everything fine, no action needed
- `action_required` — Human needs to do something (usually DS update)
- `warning` — Will need attention soon (approaching rollover)
- `error` — Something is broken

## Web UI Requirements

Single HTML page (embedded in binary), no JavaScript frameworks. Shows:

1. **Dashboard** — List of all zones with status badges
2. **Per-zone detail** — Click to expand:
   - Current KSK/ZSK key IDs and expiry
   - DS records in multiple formats (algorithm 2 and 4)
   - DNSKEY records
   - Copy buttons for each format
   - Rollover status if in progress

### Registrar-friendly DS formats

```
;; For registrars wanting digest type 2 (SHA-256)
example.com. IN DS 12345 15 2 E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CF

;; For registrars wanting just the fields
Key Tag: 12345
Algorithm: 15 (ED25519)  
Digest Type: 2 (SHA-256)
Digest: E2D3C916F6DEEAC73294E8268FB5885044A833FC5459588F4A9184CF
```

## Key Rollover Process

### ZSK Rollover (Automatic)
ZSK rolls use pre-publish method, fully automatic:
1. 14 days before ZSK expiry: Generate new ZSK, publish in zone
2. 7 days before expiry: Start signing with new ZSK
3. On expiry: Remove old ZSK

No human intervention required. Status JSON shows this happening.

### KSK Rollover (Semi-automatic)
KSK rolls require DS update at registrar:

```bash
# 1. Start rollover (generates new KSK, adds to zone)
$ dnssec-tudor rollover start example.com
New KSK generated. Both keys now in zone.
Update DS record at registrar. New DS:
  example.com. IN DS 22222 13 2 ABC123...

# 2. Wait for DS to propagate, then complete
$ dnssec-tudor rollover complete example.com
Old KSK removed. Rollover complete.
```

The daemon will remind you (in status output) if a rollover is pending.

## Directory Structure

```
/etc/dnssec-tudor/
├── config.toml
└── zones/                        # Hierarchical by TLD/domain
    ├── com/
    │   └── ptudor/
    │       └── zone.db           # Unsigned zone for ptudor.com
    ├── net/
    │   └── ptudor/
    │       └── zone.db           # Unsigned zone for ptudor.net
    └── org/
        └── example/
            └── zone.db

/var/lib/dnssec-tudor/
├── state.json                    # Daemon state, zone→path mappings, key metadata
├── keys/
│   ├── ptudor.com.ksk.private
│   ├── ptudor.com.ksk.key
│   ├── ptudor.com.zsk.private
│   ├── ptudor.com.zsk.key
│   ├── ptudor.net.ksk.private
│   └── ptudor.net.zsk.key
└── signed/                       # Flat output — NSD includes these
    ├── ptudor.com.zone.signed
    ├── ptudor.net.zone.signed
    └── example.org.zone.signed
```

Zone files can live anywhere — the path is explicit in config or provided via `dnssec-tudor add`. The hierarchical layout is a convention, not a requirement.

## NSD Integration

```
# /etc/nsd/nsd.conf
zone:
    name: "ptudor.com"
    zonefile: "/var/lib/dnssec-tudor/signed/ptudor.com.zone.signed"

zone:
    name: "ptudor.net"
    zonefile: "/var/lib/dnssec-tudor/signed/ptudor.net.zone.signed"
```

After signing, the daemon runs the `post_sign` hook (e.g., `nsd-control reload`).

## Implementation Notes

### Dependencies
- Use `miekg/dns` for zone parsing and DNSSEC operations
- Embed web UI with `embed` directive
- TOML config with `BurntSushi/toml` or `pelletier/go-toml`
- No database — state is a single JSON file

### Code Organization

```
cmd/
    dnssec-tudor/
        main.go           # CLI entry point (cobra or stdlib flag)
internal/
    config/
        config.go         # Config parsing
    zone/
        parse.go          # Zone file reading
        sign.go           # DNSSEC signing operations
    keys/
        generate.go       # Key generation
        storage.go        # Key file I/O
        rollover.go       # Rollover state machine
    state/
        state.go          # JSON state file
    daemon/
        daemon.go         # Main loop, file watching
        hooks.go          # Post-sign hooks
    web/
        server.go         # HTTP server
        handlers.go       # API endpoints
        ui/
            index.html    # Embedded web UI
```

### Error Handling Philosophy
- Never delete a key file automatically
- If signing fails, keep serving old signed zone
- Log errors to stderr, surface in status JSON
- Exit non-zero only on fatal startup errors

### Security Considerations
- Key files: 0600, owned by daemon user
- Don't serve web UI on public interface without proxy/auth
- Validate zone files before signing (catch syntax errors)

## Testing Strategy

1. **Unit tests** for zone parsing, signing, rollover state machine
2. **Integration test** with real zone files and temporary directories
3. **Manual testing checklist:**
   - [ ] Add a new zone via `dnssec-tudor add`, verify signed output
   - [ ] Modify zone file, verify re-sign and serial bump detection
   - [ ] Wait for signature refresh
   - [ ] ZSK auto-rollover
   - [ ] KSK manual rollover flow
   - [ ] Web UI displays correct DS records
   - [ ] NSD can load signed zones (`nsd-checkzone`)
   - [ ] `dig +dnssec` validates signatures
   - [ ] Verify hierarchical zone paths work (zones/net/ptudor/zone.db)

## Development Commands

```bash
# Build
go build -o dnssec-tudor ./cmd/dnssec-tudor

# Run tests
go test ./...

# Run with test config
./dnssec-tudor serve --config ./testdata/config.toml

# Quick iteration: sign and show status
./dnssec-tudor sign --config ./testdata/config.toml && ./dnssec-tudor status
```

## Future Considerations (Out of Scope for v1)

- Algorithm rollover (e.g., ED25519 to ECDSA fallback, or future post-quantum)
- CDS/CDNSKEY automatic DS publishing
- Prometheus metrics endpoint
- Multiple signing keys per algorithm
- TSIG for zone transfers

## References

- RFC 4033-4035: DNSSEC base specifications
- RFC 5155: NSEC3
- RFC 6781: DNSSEC operational practices
- RFC 7583: DNSSEC key rollover timing
- https://github.com/miekg/dns — Go DNS library
