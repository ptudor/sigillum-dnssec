# dnssec-tudor

A minimal, opinionated DNSSEC signing daemon for sysadmins who just want zones signed.

## Why This Exists

Every DNSSEC solution is either:
- **Overkill** (OpenDNSSEC, PowerDNS) — databases, complex configs, HSM support
- **Designed for DNS operators**, not sysadmins with a colo box

**dnssec-tudor** is for the sysadmin with 10-50 domains on a single server, using NSD or similar, who wants BIND-style zone files signed without DNSSEC becoming a part-time job.

## Features

- **Automatic signing** — watches zone files, re-signs on changes or before expiry
- **Automatic ZSK rollover** — pre-publish method, no human intervention
- **Semi-automatic KSK rollover** — generates keys, tells you what DS to publish
- **ED25519 by default** — smaller signatures, faster validation (ECDSA P-256/P-384 also supported)
- **NSEC or NSEC3** — configurable denial of existence
- **Web dashboard** — see status, copy DS records for registrars
- **JSON status output** — for scripting and monitoring
- **Post-sign hooks** — reload NSD/BIND after signing

## Quick Start

See [QUICKSTART.md](QUICKSTART.md) for a complete walkthrough.

```bash
# Build
make build

# Add a domain (generates keys, signs zone)
./dnssec-tudor add example.com /etc/nsd/zones/example.com.zone --config /etc/dnssec-tudor/config.toml

# Copy the DS record to your registrar, then run as daemon
./dnssec-tudor serve --config /etc/dnssec-tudor/config.toml
```

## Installation

### From Source

```bash
git clone https://github.com/ptudor/dnssec-tudor
cd dnssec-tudor
make build

# Or for a specific platform
make build-linux        # Linux x86_64
make build-linux-arm64  # Linux ARM64
make build-freebsd      # FreeBSD
make build-darwin-arm64 # macOS Apple Silicon
```

### Directory Setup

```bash
# Create directories
sudo mkdir -p /etc/dnssec-tudor
sudo mkdir -p /var/lib/dnssec-tudor/{keys,signed}

# Set permissions (run daemon as dedicated user)
sudo useradd -r -s /bin/false dnssec-tudor
sudo chown -R dnssec-tudor:dnssec-tudor /var/lib/dnssec-tudor
sudo chmod 700 /var/lib/dnssec-tudor/keys
```

## Configuration

Create `/etc/dnssec-tudor/config.toml`:

```toml
# Where to write signed zone files
output_dir = "/var/lib/dnssec-tudor/signed"

# Where to store keys and state
data_dir = "/var/lib/dnssec-tudor"

# How often to check for zone changes
poll_interval = "5m"

[dnssec]
algorithm = "ED25519"           # or ECDSAP256SHA256, ECDSAP384SHA384
ksk_lifetime = "3y"             # How long before KSK rollover reminder
zsk_lifetime = "90d"            # ZSK rolls automatically
signature_validity = "14d"      # How long signatures are valid
signature_refresh = "3d"        # Re-sign when this much validity remains
nsec_version = "nsec3"          # "nsec" or "nsec3"
nsec3_iterations = 0            # RFC 9276 recommends 0
nsec3_salt = ""                 # Empty salt recommended
dnskey_ttl = 0                  # 0 = use SOA TTL (recommended)
rollover_prepublish = "14d"     # Days before expiry to prepublish new key
rollover_switch = "7d"          # Days to wait before switching to new key

[web]
enabled = true
listen = "127.0.0.1:8053"

# Zone definitions
[zones]
[zones."example.com"]
path = "/etc/nsd/zones/example.com.zone"

[zones."example.org"]
path = "/etc/nsd/zones/example.org.zone"
ksk_lifetime = "5y"             # Per-zone override
algorithm = "ECDSAP256SHA256"   # Per-zone algorithm (for algorithm rollover)

[hooks]
post_sign = "systemctl reload nsd"
```

## Commands

### Daemon Mode

```bash
# Run in foreground
dnssec-tudor serve --config /etc/dnssec-tudor/config.toml

# With web UI on custom port
dnssec-tudor serve --config /etc/dnssec-tudor/config.toml --web :8080
```

### One-Shot Signing

```bash
# Sign all zones and exit
dnssec-tudor sign --config /etc/dnssec-tudor/config.toml
```

### Domain Management

```bash
# Add a new domain
dnssec-tudor add example.com /path/to/zone.db --config config.toml

# Remove a domain (keys are NOT deleted)
dnssec-tudor remove example.com --config config.toml
```

### Key Information

```bash
# Get DS record for registrar
dnssec-tudor ds example.com --config config.toml

# Get DNSKEY records
dnssec-tudor dnskey example.com --config config.toml

# Check status
dnssec-tudor status --config config.toml
dnssec-tudor status --domain example.com --config config.toml
```

### Key Rollover

ZSK rollover is fully automatic. KSK rollover requires DS updates at your registrar:

```bash
# Start KSK rollover (generates new key, shows new DS)
dnssec-tudor rollover start example.com --config config.toml

# After publishing new DS at registrar, complete rollover
dnssec-tudor rollover complete example.com --config config.toml

# Check rollover status
dnssec-tudor rollover status example.com --config config.toml
```

### Algorithm Rollover

To change algorithms (e.g., ECDSA to ED25519), use the algorithm rollover command:

```bash
# Start algorithm rollover (generates new keys with target algorithm)
dnssec-tudor rollover algorithm example.com ED25519 --config config.toml

# After publishing new DS at registrar, complete rollover
dnssec-tudor rollover complete example.com --config config.toml
```

During algorithm rollover, the zone is signed with both the old and new algorithm keys until you complete the rollover.

## NSD Integration

Configure NSD to use the signed zone files:

```
# /etc/nsd/nsd.conf
zone:
    name: "example.com"
    zonefile: "/var/lib/dnssec-tudor/signed/example.com.zone.signed"
```

The `post_sign` hook reloads NSD after signing:

```toml
[hooks]
post_sign = "nsd-control reload"
# or for systemd
post_sign = "systemctl reload nsd"
```

**Note:** Hooks have a 30-second timeout. If your hook needs longer (e.g., zone transfers to secondaries), consider having the hook trigger an async process instead.

## BIND Integration

```
// named.conf
zone "example.com" {
    type master;
    file "/var/lib/dnssec-tudor/signed/example.com.zone.signed";
};
```

```toml
[hooks]
post_sign = "rndc reload"
```

## Status Output

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
        "expires": "2026-01-15T00:00:00Z"
      },
      "zsk": {
        "id": 67890,
        "algorithm": "ED25519",
        "created": "2024-01-01T00:00:00Z",
        "expires": "2024-04-01T00:00:00Z"
      }
    }
  },
  "summary": {
    "total": 1,
    "healthy": 1,
    "action_required": 0,
    "errors": 0
  }
}
```

## Signals

- `SIGINT` / `SIGTERM` — Graceful shutdown
- `SIGHUP` — Reload configuration (add/remove zones without restart)

## Web Dashboard

When enabled, the web UI shows:
- All zones with status badges
- Key IDs and expiry dates
- DS records in registrar-friendly formats
- Rollover status and required actions

Access at `http://127.0.0.1:8053` (or your configured address). For public access, put it behind a reverse proxy with authentication.

## Algorithm Support

| Algorithm | Config Value | Notes |
|-----------|--------------|-------|
| ED25519 | `ED25519` | Recommended, smallest signatures |
| ECDSA P-256 | `ECDSAP256SHA256` | Wide registrar support |
| ECDSA P-384 | `ECDSAP384SHA384` | Higher security margin |

ED25519 (algorithm 15) has excellent resolver support but some registrars may not accept it. Check your registrar before choosing.

## File Locations

```
/etc/dnssec-tudor/
├── config.toml              # Configuration

/var/lib/dnssec-tudor/
├── state.json               # Daemon state
├── keys/
│   ├── example.com.ksk.key      # Public KSK
│   ├── example.com.ksk.private  # Private KSK (mode 0600)
│   ├── example.com.zsk.key      # Public ZSK
│   └── example.com.zsk.private  # Private ZSK (mode 0600)
└── signed/
    └── example.com.zone.signed  # Signed zone file
```

## Monitoring

Health and metrics endpoints (on internal health server, default `127.0.0.1:8054`):
- `GET /health` — JSON health status
- `GET /healthz` — Simple OK/UNHEALTHY for probes
- `GET /metrics` — Prometheus metrics

```bash
curl http://127.0.0.1:8054/healthz
curl http://127.0.0.1:8054/metrics
```

### Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `dnssec_tudor_zones_total` | Gauge | Total zones managed |
| `dnssec_tudor_zones_healthy` | Gauge | Zones in healthy state |
| `dnssec_tudor_zones_action_required` | Gauge | Zones needing action |
| `dnssec_tudor_zones_errors` | Gauge | Zones with errors |
| `dnssec_tudor_signing_operations_total` | Counter | Signing operations by domain/status |
| `dnssec_tudor_signing_duration_seconds` | Histogram | Signing duration by domain |
| `dnssec_tudor_last_signing_timestamp_seconds` | Gauge | Last successful sign time |
| `dnssec_tudor_signature_expiry_timestamp_seconds` | Gauge | When signatures expire |
| `dnssec_tudor_ksk_expiry_timestamp_seconds` | Gauge | KSK expiry time |
| `dnssec_tudor_zsk_expiry_timestamp_seconds` | Gauge | ZSK expiry time |
| `dnssec_tudor_rollover_in_progress` | Gauge | Rollover active (1/0) |
| `dnssec_tudor_rollover_operations_total` | Counter | Rollover operations |
| `dnssec_tudor_hook_executions_total` | Counter | Hook executions by status |
| `dnssec_tudor_hook_duration_seconds` | Histogram | Hook execution duration |

Configure the health server address in `config.toml`:

```toml
[health]
listen = "127.0.0.1:8054"
```

## Troubleshooting

### Verify Signed Zone

```bash
# Using ldns-utils
ldns-verify-zone /var/lib/dnssec-tudor/signed/example.com.zone.signed

# Using dig
dig +dnssec example.com @localhost
```

### Check DS Record Matches

```bash
# Get DS from signed zone
dnssec-tudor ds example.com --config config.toml

# Compare with published DS
dig DS example.com +short
```

### Debug Logging

```bash
dnssec-tudor serve --config config.toml --log-level debug
```

### Log Output Options

By default, logs go to stderr. For production on FreeBSD/Linux, use syslog:

```bash
# Log to syslog (daemon facility)
dnssec-tudor serve --config config.toml --log-output syslog

# Log to a file
dnssec-tudor serve --config config.toml --log-output /var/log/dnssec-tudor.log

# Combine with JSON format for log aggregation
dnssec-tudor serve --config config.toml --log-output syslog --log-format json
```

Environment variables are also supported: `LOG_OUTPUT`, `LOG_LEVEL`, `LOG_FORMAT`.

## Security Considerations

- Private keys are stored with mode 0600
- Run the daemon as a dedicated unprivileged user
- The web UI has no authentication — bind to localhost and proxy if needed
- Keys are never deleted automatically; manual cleanup required after rollover

## License

MIT

## See Also

- [QUICKSTART.md](QUICKSTART.md) — Step-by-step setup guide
- [RFC 4033-4035](https://datatracker.ietf.org/doc/html/rfc4033) — DNSSEC specifications
- [RFC 6781](https://datatracker.ietf.org/doc/html/rfc6781) — DNSSEC operational practices
- [RFC 7583](https://datatracker.ietf.org/doc/html/rfc7583) — DNSSEC key rollover timing
- [RFC 9276](https://datatracker.ietf.org/doc/html/rfc9276) — NSEC3 guidance
