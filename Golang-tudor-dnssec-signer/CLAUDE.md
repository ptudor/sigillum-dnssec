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
2. **Generates keys** (KSK + ZSK) on first seeing a zone, with configurable lifetime (default: 5 years)
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

- Support NSEC3 opt-out or other complex configurations
- Manage your primary/secondary topology
- Support HSMs or PKCS#11
- Run as anything other than a single daemon on one machine
- Process `$INCLUDE` directives in zone files — each zone must be a single
  self-contained file (a zone using `$INCLUDE` fails to parse with a clear
  "`$INCLUDE` directive not allowed" error). Inline the included records.

### What It Optionally Does (Registrar Integration)

Normally, updating the DS record at your registrar is a copy-paste job. For
registrars with a documented public API, an **opt-in** registrar module can
push/verify DS records automatically.

Supported registrars:

- **Dynadot** — via the `restful/v2` API (`GET`/`PUT`/`DELETE` on
  `/restful/v2/domains/{domain}/dnssec`). Requires an **API key** and an
  **API secret** issued under *Tools → API* in the Dynadot control panel.
  The key goes in the `Authorization: Bearer ...` header; the secret is
  the HMAC-SHA256 key for the required `X-Signature` header.

Design constraints:

- Registrar integration is **opt-in per zone** — a zone with no
  `registrar = "..."` line behaves exactly as before (copy-paste DS yourself).
- The signer never deletes old DS records unprompted. Removal happens only as
  part of a `rollover complete` that the operator explicitly runs.
- Failures to reach the registrar are logged and surfaced in status output,
  but never cause signing itself to fail. The zone keeps serving the old
  signed output.
- API keys live in the config file, which must be mode 0640 or stricter
  (root-owned, group-readable by the daemon user). They are never printed
  in logs or status output.

## Command Line Interface

```bash
# Run the daemon (foreground, logs to stderr, reloads on SIGHUP)
dnssec-tudor serve

# Run with web UI enabled (loopback only — the dashboard is unauthenticated;
# a non-loopback --web address is refused unless web.allow_remote = true)
dnssec-tudor serve --web 127.0.0.1:8053

# One-shot: sign all zones, print status JSON to stdout, exit
dnssec-tudor sign

# Print status JSON to stdout
dnssec-tudor status
dnssec-tudor status --domain example.com

# Add a new domain (registers zone path, generates keys, signs)
# Zone file must already exist at the path
dnssec-tudor add example.com /etc/dnssec-tudor/zones/com/example/zone.db

# Remove a domain: deletes it from state.json AND the config file (does NOT delete
# keys). A running daemon still holds the old config in memory until you SIGHUP it.
dnssec-tudor remove example.com

# Key rollover commands
dnssec-tudor rollover start example.com    # Begin KSK or ZSK rollover
dnssec-tudor rollover status example.com   # Show rollover state
dnssec-tudor rollover complete example.com # Finalize after DS updated

# Export for registrar
dnssec-tudor ds example.com                # Print DS records
dnssec-tudor dnskey example.com            # Print DNSKEY records

# Registrar API (opt-in; requires [registrar.*] config + zone "registrar" field)
dnssec-tudor registrar get example.com     # Show DS records currently at registrar
dnssec-tudor registrar push example.com    # Push expected DS records to registrar
dnssec-tudor registrar verify example.com  # Compare expected vs actual DS records
dnssec-tudor registrar clear example.com   # Remove all DS records at registrar
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
ksk_lifetime = "5y"            # 1y, 3y, 5y — how long before rollover reminder
zsk_lifetime = "90d"           # ZSK rolls automatically, no registrar interaction
signature_validity = "14d"     # How long signatures are valid
signature_refresh = "3d"       # Re-sign when this much validity remains
nsec_version = "nsec3"         # "nsec" or "nsec3"
# Serial handling for signed output. "keep" (default) passes the unsigned
# serial through unchanged. "epoch" publishes max(now, serial+1, last+1) on
# every signing event so AXFR/IXFR secondaries always pick up refreshed
# RRSIGs — zones under "epoch" MUST use unix epoch serials (`date +%s`) in
# the unsigned file; date-format serials (YYYYMMDDnn) are rejected at sign
# time. Per-zone override: serial_policy on the zone entry.
serial_policy = "keep"

# Optional web UI
[web]
enabled = false
listen = "127.0.0.1:8053"
# No auth by default — bind to localhost and proxy if you need it

# Optional registrar API integration. Each sub-section configures one registrar.
# Zones reference a registrar by its key (e.g. `registrar = "dynadot"`).
[registrar]
# digest_type is a [registrar]-level (registrar-agnostic) setting and MUST live
# under [registrar], NOT [registrar.dynadot]. Placing it under the sub-table is
# silently ignored (rejected as an unknown key with strict decoding).
# digest_type = 2               # Digest algorithm for DS: 2 (SHA-256, default) or 4 (SHA-384)

[registrar.dynadot]
enabled = true
api_key = ""                    # required; protect with config file mode 0640
api_secret = ""                 # required; HMAC-SHA256 key for X-Signature
sandbox = false                 # true → api-sandbox.dynadot.com (safe for testing)
timeout = "30s"
auto_publish = true             # Push DS automatically on add/rollover events

# Zone definitions — explicit paths, can be anywhere. Zone table headers MUST be
# quoted (`[zones."name"]`); the unquoted dotted form is parsed as nested tables
# and silently registers zero zones.
# Supports hierarchical organization: zones/net/ptudor/zone.db
[zones."ptudor.net"]
path = "/etc/dnssec-tudor/zones/net/ptudor/zone.db"
registrar = "dynadot"           # Opt-in: push DS via the registrar above

[zones."ptudor.com"]
path = "/etc/dnssec-tudor/zones/com/ptudor/zone.db"
ksk_lifetime = "5y"  # Override: I'm extra lazy about this one

[zones."example.org"]
path = "/srv/dns/org/example/zone.db"  # Can live anywhere
# (no registrar field — DS must be copy-pasted to the registrar manually)

# Hook to run after signing (e.g., reload NSD)
[hooks]
# post_sign     — string form, split on whitespace unless shell=true
# post_sign_cmd — exec-style array, preferred, no shell
# coalesce_post_sign — fire once per cycle with DNSSEC_DOMAINS env var
#                       instead of per-zone DNSSEC_DOMAIN. Recommended
#                       when managing 100+ zones so a signing pass
#                       produces one nsd-control reload, not N.
post_sign = "/usr/local/sbin/nsd-control reload"
coalesce_post_sign = true
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

## Registrar API Integration (Optional)

When a zone has `registrar = "dynadot"` and the registrar is configured with
`auto_publish = true`, the signer automatically manages DS records at the
registrar during key-state transitions.

### Adapter Contract

Every registrar adapter implements:

```go
type Registrar interface {
    Name() string
    GetDS(ctx context.Context, domain string) ([]*dns.DS, error)
    // ReplaceDS sets the registrar's DS record set for `domain` to exactly
    // the records provided. Implementations may clear-then-set if their
    // upstream API has no atomic "replace" operation; callers must be aware
    // that a brief (seconds) window with no DS can occur.
    ReplaceDS(ctx context.Context, domain string, ds []*dns.DS) error
    // AddDS additively publishes DS records alongside any existing ones.
    // Used at KSK rollover start so the old DS is never briefly absent.
    AddDS(ctx context.Context, domain string, ds []*dns.DS) error
}
```

### When DS records are touched

| Event                           | Operation at registrar          |
|---------------------------------|---------------------------------|
| `add` (new zone)                | `AddDS([new KSK])`              |
| `import` (existing keys)        | none (verify only, never push)  |
| `rollover start` (KSK/algo)     | `AddDS([new KSK])`              |
| `rollover complete` (KSK/algo)  | `ReplaceDS([new KSK])`          |
| ZSK rollover                    | nothing — ZSK doesn't touch DS  |

Auto-publish on `add` is deliberately additive, not destructive. If a publish
attempt fails (e.g., upstream API outage), an `AddDS` leaves whatever the
registrar previously held intact; a `ReplaceDS` would have already DELETE'd
before discovering the PUT failure, leaving a zone with zero DS at the
parent — a silent DNSSEC outage. Operators who need clean-state on add can
follow up with `dnssec-tudor registrar push` (which uses `ReplaceDS`
internally, but is now operator-explicit).

`import` is intentionally read-only because the registrar already has the
correct DS (that's how validation is working); pushing would risk wiping it
on a transient API error.

### Dynadot adapter specifics

- Endpoint: `https://api.dynadot.com/restful/v2` (or `api-sandbox.dynadot.com`).
- Paths:
  - `GET    /restful/v2/domains/{domain}/dnssec` → returns `data.dnssec_info_list[]`
  - `PUT    /restful/v2/domains/{domain}/dnssec` → accepts a **single** DS
    record per request (upsert by `key_tag`)
  - `DELETE /restful/v2/domains/{domain}/dnssec` → wipes the DS set
- Auth headers: `Authorization: Bearer <api_key>` plus a mandatory
  `X-Signature` computed as
  `base64(HMAC-SHA256(api_secret, api_key + "\n" + fullPathAndQuery + "\n" + xRequestId + "\n" + requestBody))`.
  Each request also carries a random `X-Request-ID` (UUIDv4) for operator
  trace correlation. Neither the key nor the secret is ever logged.
- `AddDS` issues one `PUT` per record (Dynadot's PUT accepts a single
  record body and upserts by key tag).
- `ReplaceDS` issues `PUT` per desired record first, then a single `DELETE`
  to wipe the set, then `PUT` per desired record again to restore. PUT-first
  is deliberate: if the publish format/auth is broken, the call aborts
  before any destructive DELETE, leaving the prior DS state intact. Used
  only at rollover *complete* (or via the explicit `registrar push` CLI),
  where the old DNSKEY is already retired in-zone. There is still a brief
  no-DS window between the DELETE and the second PUT.
- `GetDS` parses `data.dnssec_info_list` — note that Dynadot returns
  `algorithm` and `digest_type` as strings, so the adapter converts them
  back to numeric DNS field values.
- Rate limit: regular accounts are capped at 60 req/min. The adapter
  uses a sliding-scale limiter — 100ms gap for the first 20 requests
  in a burst, 500ms for the next 20, 2s thereafter; the counter resets
  after 60s of no calls. This stays burst-friendly for normal rollover
  work (≤3 calls) while self-throttling any bulk push that would
  otherwise hit Dynadot's 429 ceiling.

### Failure semantics

- Registrar failures are logged with `[REGISTRAR]` prefix and added to the
  zone's `warnings` array in the status output.
- A registrar failure **never prevents signing**. A zone that can't reach its
  registrar just keeps serving the same signed output, same as before.
- The CLI `registrar push` / `registrar verify` commands report errors
  directly and exit non-zero, so cron jobs can detect drift.

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
- TOML config with `pelletier/go-toml/v2` (uses strict decoding — `DisallowUnknownFields` — so misspelled keys error at load)
- No database — state is a single JSON file

### Code Organization

The domain logic lives in `internal/` packages; the root `package main` is the
application/wiring layer (CLI, daemon loop, HTTP servers, CLI glue). The
dependency graph is a strict DAG — `internal/` packages never import the root
package, and no import cycles exist between them.

```
main.go              # package main — cobra CLI entry point + all run* handlers
daemon.go            # signing/watch loop, orchestration (holds Signer/Rollover/…)
web.go, health.go    # HTTP servers (dashboard, /health, /metrics, /debug/vars)
hooks.go             # post-sign hook execution
heartbeat.go         # AnyStatus heartbeat client
status.go            # status/output DTOs (sit above state + validate)
zone_identity.go     # canonical-conflict check (bridges config + state)
registrar_cli.go     # `registrar` subcommands — CLI glue over the registrar pkg
filelock_*.go        # state-dir lock (build-tagged unix/windows)
syslog_*.go          # syslog handler (build-tagged unix/windows)

internal/
    config/          # Config + all sub-config types, LoadConfig, zone-file edits
    state/           # State/ZoneState/KeyState/RolloverState, JSON persistence
    fsutil/          # ownership-aware atomic writes, CopyFile (leaf, no deps)
    metrics/         # Prometheus + expvar collectors, Record*/UpdateZoneMetrics
    signer/          # Signer, KeyGenerator, RolloverManager — signing/keys/rollover
    registrar/       # Registrar interface, Dynadot adapter, rate limiter, DS diff
    validate/        # internet DNSSEC Validator + result types
    dnssectest/      # shared test fixtures (Config) — imported only by test files
```

Dependency direction (leaves first): `fsutil` → `config` → `state` →
`metrics`/`signer` → `registrar` → `validate` → root. The root package and
`internal/signer` white-box tests share fixtures via `internal/dnssectest` to
avoid a test import cycle. Test files live beside the code they exercise:
white-box tests in the owning package, black-box/integration tests at root.

**Naming note:** because the persistent-state package is named `state` and the
signing package `signer`, the root package imports them aliased (`statepkg`,
`signerpkg`) to avoid shadowing the pervasive local `state`/`signer` variables —
the same convention the sibling `dnssec-validator` uses for its `dns` package.

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
go build -o dnssec-tudor .   # main.go is at the repo root, not under cmd/

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
