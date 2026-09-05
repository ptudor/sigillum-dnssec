# Golang-dnssec-validator

A web-based DNSSEC troubleshooting and validation tool with a polished UI. Think "DNSViz" or "drill" but in your browser, with real-time streaming results and comprehensive diagnostics.

## Common Patterns (inherited from parent)

This project follows the TudorDNS-Golang common patterns:

| Pattern | Implementation |
|---------|----------------|
| **Transport** | Standalone HTTP (not FastCGI) — SSE requires long-lived connections |
| **Logging** | Structured logging via `log/slog` (JSON or text) |
| **Metrics** | Prometheus + expvar endpoints |
| **Rate Limiting** | Per-IP token bucket algorithm |
| **Graceful Shutdown** | SIGINT/SIGTERM with request draining |
| **Configuration** | TOML file (preferred), environment variables as fallback |
| **Health Checks** | `/health` and `/healthz` endpoints |
| **Database** | None — stateless validation service |

### Why Standalone HTTP (not FastCGI)

Unlike most TudorDNS services that use FastCGI behind Apache, this project runs as a standalone HTTP server because:

1. **SSE requirement**: Server-Sent Events need long-lived connections that don't work well with FastCGI's request/response model
2. **Simpler deployment**: Public diagnostic tools benefit from standalone operation
3. **Reverse proxy compatible**: Still runs behind Apache for HTTPS termination

Use FastCGI for: traditional request/response APIs, services that benefit from Apache's features (mTLS, mod_security, etc.)

Use standalone HTTP for: SSE/WebSocket services, simple diagnostic tools, services with streaming responses

**Note**: This project uses Apache as its reverse proxy. Do not reference nginx in code or documentation.

### Build Commands

```bash
make build              # Build for current platform
make build-linux        # Linux x86_64
make build-linux-arm64  # Linux ARM64
make build-darwin       # macOS x86_64
make build-darwin-arm64 # macOS Apple Silicon
make build-freebsd      # FreeBSD
make build-all          # All platforms
make test               # Run tests
make clean              # Remove build artifacts
```

### Dependencies

Minimal external dependencies following project conventions:

- `github.com/miekg/dns` - DNS library (same as dnssec-signer)
- `github.com/prometheus/client_golang` - Prometheus metrics
- Standard library for everything else

Go version: 1.21+ (required for `log/slog`)

---

## Project Purpose

This service performs iterative DNSSEC validation from the root zone down, querying authoritative nameservers at each level and streaming results back to the browser via Server-Sent Events (SSE). It validates the complete chain of trust using the IANA root trust anchors.

**Key differentiator**: Query *every* authoritative nameserver at each level (not just one), flagging inconsistencies between servers. If 4 of 5 nameservers return correct DNSSEC signatures but one returns garbage, we show that.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Browser (SPA)                                  │
│  ┌─────────────┐  ┌─────────────────────────────────────────────────────┐  │
│  │  Input Form │  │              Results Visualization                  │  │
│  │  ─────────  │  │  ┌─────┐   ┌─────┐   ┌─────────┐   ┌─────────────┐  │  │
│  │  Domain:    │  │  │  .  │ → │ net │ → │ ptudor  │ → │     www     │  │  │
│  │  [        ] │  │  │ ✓✓✓ │   │ ✓✓✓ │   │ ✓✓✓✓    │   │ ✓✓✓✓        │  │  │
│  │  [Validate] │  │  └─────┘   └─────┘   └─────────┘   └─────────────┘  │  │
│  └─────────────┘  │         (cards appear progressively via SSE)        │  │
│                   └─────────────────────────────────────────────────────┘  │
└───────────────────────────────────┬─────────────────────────────────────────┘
                                    │ EventSource (SSE)
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        dnssec-validator daemon                              │
│  ┌──────────────┐  ┌──────────────────────────────────────────────────┐    │
│  │ HTTP Server  │  │              Validation Engine                   │    │
│  │  /validate   │──│  1. Parse domain → zone hierarchy                │    │
│  │  /health     │  │  2. For each zone level (root → target):         │    │
│  │  /metrics    │  │     a. Resolve NS records                        │    │
│  │  /           │  │     b. Query ALL authoritative IPs               │    │
│  │  (static UI) │  │     c. Fetch DNSKEY, DS, RRSIG records           │    │
│  └──────────────┘  │     d. Validate signatures against parent DS     │    │
│                    │     e. Stream results back via SSE               │    │
│                    │  3. Final validation summary                     │    │
│                    └──────────────────────────────────────────────────┘    │
│                                       │                                     │
│  ┌────────────────────────────────────┴──────────────────────────────────┐ │
│  │                        Trust Anchor Store                             │ │
│  │  root-anchors.json (from internet-files-mirror)                       │ │
│  │  - KSK key tags, algorithms, digests                                  │ │
│  │  - Used to bootstrap root zone validation                             │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼ UDP/TCP :53
┌─────────────────────────────────────────────────────────────────────────────┐
│                    Authoritative DNS Servers Worldwide                      │
│    Root Servers    │    TLD Servers    │    Domain Authoritative NS        │
│    a.root → m.root │    *.gtld-servers │    ns1.example.com, etc.          │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Core Features

### 1. Progressive Streaming Results (SSE)

Results stream back as each zone level completes validation:

```
Client                                    Server
  │                                          │
  │  GET /validate?domain=www.ptudor.net     │
  │  Accept: text/event-stream               │
  │ ────────────────────────────────────────>│
  │                                          │
  │  event: zone                             │
  │  data: {"zone":".","status":"validating"}│
  │ <────────────────────────────────────────│
  │                                          │  (queries root servers)
  │  event: zone                             │
  │  data: {"zone":".","status":"secure"...} │
  │ <────────────────────────────────────────│
  │                                          │
  │  event: zone                             │
  │  data: {"zone":"net.","status":"secure"} │
  │ <────────────────────────────────────────│
  │                                          │
  │  event: zone                             │
  │  data: {"zone":"ptudor.net.",...}        │
  │ <────────────────────────────────────────│
  │                                          │
  │  event: zone                             │
  │  data: {"zone":"www.ptudor.net.",...}    │
  │ <────────────────────────────────────────│
  │                                          │
  │  event: complete                         │
  │  data: {"result":"secure","chain":[...]} │
  │ <────────────────────────────────────────│
```

### 2. Query All Authoritative Servers

For each zone level, query **every** authoritative nameserver IP (both IPv4 and IPv6):

```json
{
  "zone": "net.",
  "nameservers": [
    {
      "name": "a.gtld-servers.net.",
      "addresses": [
        {"ip": "192.5.6.30", "status": "secure", "rtt_ms": 12},
        {"ip": "2001:503:a83e::2:30", "status": "secure", "rtt_ms": 15}
      ]
    },
    {
      "name": "b.gtld-servers.net.",
      "addresses": [
        {"ip": "192.33.14.30", "status": "secure", "rtt_ms": 18},
        {"ip": "2001:503:231d::2:30", "status": "timeout", "error": "i/o timeout"}
      ]
    }
  ],
  "consensus": "secure",
  "disagreements": []
}
```

Flag any server returning different results:

```json
{
  "disagreements": [
    {
      "server": "ns3.example.com (192.0.2.3)",
      "issue": "RRSIG expired",
      "expected": "valid signature",
      "got": "signature expired 2024-01-15"
    }
  ]
}
```

#### How disagreement affects diagnostics (RA6X-018)

Per-address status is a verdict on **that server's own answer** against the
authenticated chain, not a transport result:

| Address status | Meaning |
|----------------|---------|
| `secure` | The server's DNSKEY RRset holds exactly the authenticated key material and its RRSIG verifies under the DS/anchor-authenticated keys. |
| `bogus` | The server answered, but its DNSKEY RRset differs from the authenticated one or its signature does not verify. Recorded in `disagreements` and as a zone warning. |
| `indeterminate` | The server did not answer (timeout, transport error, failure RCODE). |
| `insecure` | The zone is insecure (no DS / opt-out); the server's answer was not judged cryptographically. |

The zone's verdict is established from the **first server response that
authenticates** (DS/anchor digest match plus a verifying RRSIG over the wire
RRset); every other queried server is then judged against it. Disagreement is
diagnostic: one dissenting server never changes the zone's verdict, and not
every server has to agree for a valid path to be found. The same rule applies
to the leaf answer (`record_validation.server_disagreements`: differing content
or a failing signature on another server) and, in extended mode, to the parent
servers' DS answers (`disagreements` entries whose `server` is `parent <zone>`).
Quick mode queries at most two servers and judges those.

### 3. DNSSEC Validation Details

For each zone, capture and display:

| Data | Purpose |
|------|---------|
| **DNSKEY records** | Zone's public keys (KSK flag 257, ZSK flag 256) |
| **DS records** | Parent zone's hash of child's KSK |
| **RRSIG records** | Signatures over each RRset |
| **NSEC/NSEC3** | Authenticated denial of existence |
| **Key tags** | Numeric identifiers linking DS → DNSKEY |
| **Algorithms** | Cryptographic algorithm (8=RSA/SHA-256, 13=ECDSA P-256, 15=Ed25519) |
| **Signature validity** | inception/expiration timestamps |
| **Chain of trust** | Visual representation of DS → DNSKEY linkage |

### 4. Root Trust Anchor Integration

Bootstrap validation using `root-anchors.json`:

```go
type RootAnchors struct {
    Source      string   `json:"source"`
    Zone        string   `json:"zone"`
    GeneratedAt string   `json:"generatedAt"`
    Anchors     []Anchor `json:"anchors"`
}

type Anchor struct {
    ID             string  `json:"id"`
    KeyTag         int     `json:"keyTag"`
    Algorithm      int     `json:"algorithm"`
    AlgorithmName  string  `json:"algorithmName"`
    DigestType     int     `json:"digestType"`
    DigestTypeName string  `json:"digestTypeName"`
    Digest         string  `json:"digest"`
    ValidFrom      string  `json:"validFrom"`
    ValidUntil     *string `json:"validUntil"`
    PublicKey      string  `json:"publicKey,omitempty"`
    Flags          int     `json:"flags,omitempty"`
}
```

The browser can independently verify the root DNSKEY against these anchors.

## SSE Event Types

| Event | Payload | Description |
|-------|---------|-------------|
| `start` | `{domain, timestamp, mode}` | Validation begun |
| `zone` | `{zone, status, nameservers, dnskey, ds, rrsig, ...}` | Zone-level result |
| `progress` | `{zone, server, action}` | Per-server progress updates |
| `warning` | `{zone, message, severity}` | Non-fatal issues |
| `error` | `{zone, message, fatal}` | Errors during validation |
| `complete` | `{result, chain, duration_ms}` | Final summary |

## API Endpoints

### `GET /validate`

Stream DNSSEC validation results.

**Query Parameters:**

| Param | Required | Default | Description |
|-------|----------|---------|-------------|
| `domain` | Yes | - | Domain name to validate |
| `type` | No | `A` | Record type to validate (A, AAAA, MX, etc.) |
| `mode` | No | `extended` | `quick` (first responding NS) or `extended` (all NS) |

**Response:** `text/event-stream`

### `GET /api/validate`

JSON API (non-streaming) for programmatic access.

**Response:** `application/json`

```json
{
  "domain": "www.ptudor.net",
  "type": "A",
  "result": "secure",
  "chain": [
    {"zone": ".", "status": "secure", ...},
    {"zone": "net.", "status": "secure", ...},
    {"zone": "ptudor.net.", "status": "secure", ...},
    {"zone": "www.ptudor.net.", "status": "secure", ...}
  ],
  "duration_ms": 847
}
```

### `GET /api/anchors`

Return current root trust anchors.

### `GET /health`

Health check endpoint.

### `GET /metrics`

Prometheus metrics.

### `GET /`

Serve the static web UI.

## Validation States

| State | Meaning | UI Color |
|-------|---------|----------|
| `secure` | Full chain of trust verified | Green |
| `insecure` | Zone not signed (no DS in parent) | Gray |
| `bogus` | Validation failed (bad signature, missing key, etc.) | Red |
| `indeterminate` | Cannot determine (timeout, SERVFAIL) | Yellow |

## Web UI Design Goals

**Philosophy**: Polished, accessible, informative—not "developer made this in an afternoon."

### Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  🔐 DNSSEC Validator                              [About] [API] │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   ┌─────────────────────────────────────────────────────────┐   │
│   │  Enter domain:  [www.example.com          ] [Validate]  │   │
│   │                                                         │   │
│   │  ○ Quick (fastest responding server)                    │   │
│   │  ● Extended (query all authoritative servers)           │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│   ┌─ Chain of Trust ────────────────────────────────────────┐   │
│   │                                                         │   │
│   │  ┌───┐      ┌─────┐      ┌─────────┐      ┌─────────┐   │   │
│   │  │ . │ ───► │ net │ ───► │ example │ ───► │   www   │   │   │
│   │  │ ✓ │      │ ✓   │      │    ✓    │      │    ✓    │   │   │
│   │  └───┘      └─────┘      └─────────┘      └─────────┘   │   │
│   │   12ms       18ms          24ms             8ms         │   │
│   │                                                         │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                 │
│   ┌─ Details ───────────────────────────────────────────────┐   │
│   │  [.] [net] [example.com] [www.example.com]              │   │
│   │  ───────────────────────────────────────────            │   │
│   │  Zone: example.com.                                     │   │
│   │  Status: ✓ Secure                                       │   │
│   │                                                         │   │
│   │  Nameservers:                                           │   │
│   │   ├─ ns1.example.com (93.184.216.34)     ✓  12ms       │   │
│   │   ├─ ns1.example.com (2606:2800:220::)   ✓  15ms       │   │
│   │   ├─ ns2.example.com (93.184.216.35)     ✓  14ms       │   │
│   │   └─ ns2.example.com (2606:2800:221::)   ✓  18ms       │   │
│   │                                                         │   │
│   │  ▼ DNSKEY Records                                       │   │
│   │  ▼ DS Records (from parent)                             │   │
│   │  ▼ RRSIG Details                                        │   │
│   │  ▼ Raw DNS Response                                     │   │
│   └─────────────────────────────────────────────────────────┘   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### UI Requirements

1. **Progressive disclosure**: Show summary first, expand for nerd details
2. **Real-time updates**: Cards/nodes animate in as SSE events arrive
3. **Color-coded status**: Instant visual feedback (green/gray/red/yellow)
4. **Responsive**: Works on mobile (stacked cards)
5. **Dark mode**: Respect `prefers-color-scheme`
6. **Accessible**: Proper ARIA labels, keyboard navigation
7. **Shareable**: URL updates with query (`/validate?domain=example.com`)
8. **Copy-friendly**: Click to copy DNSKEY, DS records, dig commands

### Technology Choices

- **No framework required**: Vanilla JS + CSS is fine for this scope
- **CSS**: Custom properties for theming, CSS Grid for layout
- **Icons**: Inline SVG or minimal icon set
- **Fonts**: System font stack (no external fonts)

### CSS Standards (style.css)

Reference the established patterns from:
- `Golang-dns-query-server/Docs/Website/doh.css` — Dark theme, DNS-specific badges, DNSSEC indicators
- `Golang-internet-files-mirror/Docs/Website/style.css` — Light/dark auto-switching, accessibility patterns

**CSS Custom Properties (from doh.css — dark theme):**
```css
:root {
    --bg-primary: #0f0f1a;
    --bg-secondary: #1a1a2e;
    --bg-tertiary: #252540;
    --accent: #00d4ff;
    --accent-dim: #0099bb;
    --text-primary: #f0f0f0;
    --text-secondary: #9ca3af;
    --text-muted: #6b7280;
    --success: #10b981;
    --success-bg: #064e3b;
    --warning: #f59e0b;
    --warning-bg: #78350f;
    --error: #ef4444;
    --error-bg: #7f1d1d;
    --dnssec: #8b5cf6;
    --dnssec-bg: #4c1d95;
    --border: #374151;
    --radius: 8px;
    --radius-sm: 4px;
}
```

**Light/Dark Mode (from style.css):**
```css
@media (prefers-color-scheme: dark) {
    :root {
        --color-bg: #1a1a1a;
        --color-text: #e0e0e0;
        /* ... override light theme colors */
    }
}
```

**Required CSS Sections:**
1. **Reset** - `*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }`
2. **Layout** - `.container` with `max-width` and responsive padding
3. **Components** - `.badge`, `.status`, `.results`, answer cards
4. **Forms** - `.input-row`, focus states with `box-shadow: 0 0 0 2px var(--accent-dim)`
5. **Accessibility** - `.visually-hidden`, `.skip-link`, focus states
6. **Media Queries** - `@media (max-width: 480px)`, `@media (max-width: 768px)`
7. **Accessibility Queries** - `@media (prefers-reduced-motion: reduce)`, `@media (prefers-color-scheme: dark)`

**DNSSEC-specific patterns (from doh.css):**
```css
/* DNSSEC badge with gradient */
.badge.dnssec-valid {
    background: linear-gradient(135deg, #0d9488, #0891b2);
    color: #fff;
    text-shadow: 0 1px 1px rgba(0,0,0,0.2);
}
.badge.dnssec-valid::before { content: "\2713\0020"; }  /* ✓ */

.badge.dnssec-missing {
    background: var(--warning-bg);
    color: var(--warning);
}
.badge.dnssec-missing::before { content: "\26A0\0020"; }  /* ⚠ */

/* Status badges */
.badge.success { background: var(--success-bg); color: var(--success); }
.badge.warning { background: var(--warning-bg); color: var(--warning); }
.badge.error { background: var(--error-bg); color: var(--error); }
```

**Validation status colors for this project:**
```css
/* Map DNSSEC validation states to existing badge patterns */
.status-secure { /* use .badge.dnssec-valid pattern */ }
.status-insecure { /* use .badge with muted styling */ }
.status-bogus { /* use .badge.error pattern */ }
.status-indeterminate { /* use .badge.warning pattern */ }
```

**Typography:**
- System font stack: `-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif`
- Mono font: `"SF Mono", Monaco, "Cascadia Code", monospace`

**Accessibility (from style.css):**
```css
/* Skip link for keyboard users */
.skip-link {
    position: absolute;
    left: -9999px;
    /* ... becomes visible on :focus */
}

/* Focus states */
a:focus, button:focus {
    outline: 2px solid var(--color-accent);
    outline-offset: 2px;
}

/* Respect reduced motion */
@media (prefers-reduced-motion: reduce) {
    * { transition: none !important; }
}
```

## Data Structures

### Zone Result

```go
type ZoneResult struct {
    Zone         string              `json:"zone"`
    Status       ValidationStatus    `json:"status"`
    Nameservers  []NameserverResult  `json:"nameservers"`
    DNSKEY       []DNSKEYRecord      `json:"dnskey,omitempty"`
    DS           []DSRecord          `json:"ds,omitempty"`
    RRSIG        []RRSIGRecord       `json:"rrsig,omitempty"`
    NSEC         []NSECRecord        `json:"nsec,omitempty"`
    NSEC3        []NSEC3Record       `json:"nsec3,omitempty"`
    ChainLink    *ChainLink          `json:"chain_link,omitempty"`
    Warnings     []string            `json:"warnings,omitempty"`
    Errors       []string            `json:"errors,omitempty"`
    QueryTime    time.Duration       `json:"query_time_ns"`
    Timestamp    time.Time           `json:"timestamp"`
}

type NameserverResult struct {
    Name      string           `json:"name"`
    Addresses []AddressResult  `json:"addresses"`
}

type AddressResult struct {
    IP       string           `json:"ip"`
    Status   ValidationStatus `json:"status"`
    RTT      time.Duration    `json:"rtt_ns"`
    Error    string           `json:"error,omitempty"`
    Response *DNSResponse     `json:"response,omitempty"`
}

type ChainLink struct {
    ParentDS     *DSRecord     `json:"parent_ds"`
    ChildKSK     *DNSKEYRecord `json:"child_ksk"`
    DSMatchesKSK bool          `json:"ds_matches_ksk"`
    Algorithm    string        `json:"algorithm"`
}
```

### DNSSEC Records

```go
type DNSKEYRecord struct {
    Flags     uint16 `json:"flags"`      // 256=ZSK, 257=KSK
    Protocol  uint8  `json:"protocol"`   // Always 3
    Algorithm uint8  `json:"algorithm"`  // 8, 13, 15, etc.
    PublicKey string `json:"public_key"` // Base64
    KeyTag    uint16 `json:"key_tag"`    // Computed identifier
    IsKSK     bool   `json:"is_ksk"`
    IsZSK     bool   `json:"is_zsk"`
}

type DSRecord struct {
    KeyTag     uint16 `json:"key_tag"`
    Algorithm  uint8  `json:"algorithm"`
    DigestType uint8  `json:"digest_type"`  // 2=SHA-256, 4=SHA-384
    Digest     string `json:"digest"`        // Hex
}

type RRSIGRecord struct {
    TypeCovered uint16    `json:"type_covered"`
    Algorithm   uint8     `json:"algorithm"`
    Labels      uint8     `json:"labels"`
    OriginalTTL uint32    `json:"original_ttl"`
    Expiration  time.Time `json:"expiration"`
    Inception   time.Time `json:"inception"`
    KeyTag      uint16    `json:"key_tag"`
    SignerName  string    `json:"signer_name"`
    Signature   string    `json:"signature"`  // Base64
    IsValid     bool      `json:"is_valid"`
    IsExpired   bool      `json:"is_expired"`
}
```

## Configuration

Configuration is **TOML-first, with environment variables as a fallback** — this is exactly what `Load()` does: it reads a TOML file if one is found, and only falls back to environment variables when none is.

1. **TOML file (preferred).** Pass an explicit path with `-config /path/to/dnssec-validator.toml`, or drop the file at one of the default paths, checked in order:
   - `/usr/local/etc/tudordns/dnssec-validator.toml`
   - `/etc/tudordns/dnssec-validator.toml`
   - `./dnssec-validator.toml`

   Copy `dnssec-validator.toml.example` as your starting point. Unknown/misspelled keys are rejected at load time (strict decoding), so a typo is a startup error rather than a silently ignored setting.

2. **Environment variables (fallback).** When no TOML file is present — typical for a container or a minimal systemd unit — the same settings are read from the process environment (set them with systemd `Environment=`/`EnvironmentFile=` or exported shell variables). This project does **not** read a `.env` dotfile; TOML is the house configuration format.

### Environment variable fallback reference

| Variable | Default | Description |
|----------|---------|-------------|
| `LISTEN_ADDR` | `:8791` | HTTP listen address |
| `ROOT_ANCHORS_PATH` | `/etc/dnssec-validator/root-anchors.json` | Path to trust anchors |
| `ROOT_ANCHORS_URL` | `https://internet.any53.com/dns/anchors/root-anchors.json` | Fallback URL for anchors |
| `QUERY_TIMEOUT_SECONDS` | `5` | Per-server query timeout (seconds) |
| `TOTAL_TIMEOUT_SECONDS` | `30` | Total validation timeout (seconds) |
| `MAX_CONCURRENT` | `10` | Max concurrent DNS queries |
| `RATE_LIMIT_PER_SEC` | `10` | Requests per second per IP |
| `RATE_LIMIT_BURST` | `30` | Max burst size per IP |
| `RATE_LIMIT_CLEANUP_SECONDS` | `300` | Rate-limiter cleanup interval (seconds) |
| `LOG_FORMAT` | `json` | `json` or `text` |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `STATIC_DIR` | `./static` | Path to web UI files |
| `SHUTDOWN_TIMEOUT_SECONDS` | `30` | Graceful shutdown timeout (seconds) |
| `HEARTBEAT_INTERVAL_MINUTES` | `5` | Background heartbeat interval (minutes) |

**Note:** The DNS/rate-limit timeouts are read as **integers** with `_SECONDS`/`_MINUTES`
suffixes (parsed by `getEnvInt`), not Go duration strings. A value like `5s` is rejected
and logged as malformed, then the default is used — use plain integers.

### Configuration Pattern Reference

| Project Type | Config Method | Example |
|--------------|---------------|---------|
| FastCGI web services | Environment variables | rdap-proxy, dns-query |
| Standalone HTTP / local daemons | TOML file (env-var fallback) | this project, dnssec-signer |
| CLI tools | Command-line flags | All projects for one-shot commands |

## Deployment

### Standalone Mode (Recommended for this project)

Unlike other TudorDNS services, this runs as a standalone HTTP server (not FastCGI) because:
1. SSE requires long-lived connections
2. Simpler deployment for a public diagnostic tool
3. Can still run behind Apache/nginx as reverse proxy

```
┌──────────────┐     ┌─────────────────────┐     ┌───────────────────┐
│    Client    │────▶│  Apache (optional)  │────▶│ dnssec-validator  │
│   Browser    │     │  HTTPS termination  │     │    :8080          │
└──────────────┘     └─────────────────────┘     └───────────────────┘
```

### Apache Configuration (if used)

```apache
<VirtualHost *:443>
    ServerName dnssec.example.com

    SSLEngine on
    SSLCertificateFile /etc/letsencrypt/live/dnssec.example.com/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/dnssec.example.com/privkey.pem

    # Proxy to validator daemon
    ProxyPass /validate http://127.0.0.1:8080/validate
    ProxyPassReverse /validate http://127.0.0.1:8080/validate

    # SSE requires these settings
    ProxyTimeout 300
    SetEnv proxy-sendcl 1

    # Disable buffering for SSE
    SetEnv proxy-nokeepalive 1
    RequestHeader set X-Forwarded-Proto "https"
</VirtualHost>
```

### systemd Unit

```ini
[Unit]
Description=DNSSEC Validator Service
After=network.target

[Service]
Type=simple
User=dnssec-validator
Group=dnssec-validator
ExecStart=/opt/dnssec-validator/dnssec-validator
EnvironmentFile=/etc/dnssec-validator/env
Restart=always
RestartSec=5

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadOnlyPaths=/etc/dnssec-validator

[Install]
WantedBy=multi-user.target
```

## Dependencies

```go
require (
    github.com/miekg/dns v1.1.58              // DNS library (same as dnssec-signer)
    github.com/prometheus/client_golang v1.19.0  // Prometheus metrics
)
```

No database required—this is a stateless validation service. If future features require persistence (e.g., validation history, monitoring), use MariaDB following the `go-sql-driver/mysql` pattern from other TudorDNS projects.

## Validation Algorithm

```
ValidateDomain(domain, recordType):
    zones = SplitIntoZoneHierarchy(domain)  // [".", "net.", "ptudor.net.", "www.ptudor.net."]

    anchors = LoadRootAnchors()
    currentKeys = anchors  // Bootstrap with root trust anchors

    for each zone in zones:
        emit SSE event: {zone, status: "validating"}

        // Get nameservers for this zone
        nsRecords = ResolveNS(zone)
        nsAddresses = ResolveAllAddresses(nsRecords)  // Both A and AAAA

        // Query ALL authoritative servers
        results = []
        for each ns, addrs in nsAddresses:
            for each addr in addrs:
                result = QueryWithDNSSEC(addr, zone, DNSKEY)
                results.append(result)

        // Check for consensus
        if not AllAgree(results):
            emit warning with disagreements

        // Validate DNSKEY against parent DS (or root anchors)
        dnskeys = ExtractDNSKEY(results)
        valid = ValidateChain(currentKeys, dnskeys)

        if not valid:
            emit SSE event: {zone, status: "bogus", errors: [...]}
            return

        // This zone's DS records become trust for child zone
        currentKeys = ExtractDS(QueryDS(parentZone, zone))

        emit SSE event: {zone, status: "secure", dnskey: [...], ds: [...], ...}

    // Final record query
    emit SSE event: complete with full chain
```

## Error Handling

### RFC 7807 Error Responses

The `/api/*` JSON endpoints use **RFC 7807 (Problem Details for HTTP APIs)** for errors:

```
Content-Type: application/problem+json

{
  "type": "https://dnssec-validator.example.com/errors/invalid-domain",
  "title": "Invalid Domain",
  "status": 400,
  "detail": "The domain 'not..valid' contains invalid characters.",
  "instance": "/api/validate?domain=not..valid"
}
```

The SSE endpoint (`/validate`) uses SSE `error` events instead:
```
event: error
data: {"zone":"example.com.","message":"DNSKEY signature expired","fatal":true}
```

### Error Conditions

| Condition | HTTP Status | Behavior |
|-----------|-------------|----------|
| Domain invalid | 400 | RFC 7807 error with detail |
| Rate limited | 429 | RFC 7807 with Retry-After header |
| Root anchor file missing | 503 | Fall back to URL, then 503 if both fail |
| Nameserver timeout | N/A | Mark server as `indeterminate`, continue with others |
| All nameservers timeout | N/A | Mark zone as `indeterminate` in result |
| DNSSEC validation fails | N/A | Mark zone as `bogus` with specific reason |
| Zone not signed | N/A | Mark as `insecure` (valid state, not an error) |

### Security Headers

All responses include:
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Content-Security-Policy: default-src 'self'`
- `Referrer-Policy: strict-origin-when-cross-origin`

## Testing

```bash
# Unit tests
go test ./...

# Integration tests (requires network)
go test -tags=integration ./...

# Test specific domains
./dnssec-validator -test-domain=cloudflare.com
./dnssec-validator -test-domain=dnssec-failed.org  # Known bogus
./dnssec-validator -test-domain=unsigned.example   # Known insecure
```

### Test Domains

| Domain | Expected Result |
|--------|-----------------|
| `cloudflare.com` | Secure |
| `google.com` | Secure |
| `dnssec-failed.org` | Bogus (intentionally broken) |
| `unsigned-zone.example` | Insecure |
| `gov` | Secure (TLD) |

## Future Enhancements

1. **Batch validation**: Validate multiple domains in one request
2. **Historical comparison**: "Was this domain secure yesterday?"
3. **Webhook notifications**: Alert when a monitored domain goes bogus
4. **Algorithm timeline**: Show when keys were rotated
5. **Export formats**: PDF report, JSON download, dig commands

## Project Structure

Actual layout (see also the category-wide `GO-LAYOUT-STANDARD.md`). The domain
logic lives in `internal/` packages; the root `package main` is the HTTP
application/wiring layer. The `internal/` packages never import root and form a
strict DAG — the validation algorithm is fully self-contained (each package
carries its own config/params rather than importing a shared root Config).

```
Golang-dnssec-validator/
├── CLAUDE.md                 # This file — project spec and standards
├── dnssec-validator.toml.example
├── Makefile
├── go.mod / go.sum
│
│  # root package main — HTTP app / wiring layer:
├── main.go                   # entry point, flags, startup/shutdown, anchor refresh loop
├── server.go                 # HTTP server setup, routing, security headers
├── handlers.go               # /validate, /api/validate, /api/anchors, /health request handlers
├── sse.go                    # Server-Sent Events writer/formatting
├── health.go                 # /health + /healthz readiness (reflects anchor-store state)
├── problem.go                # RFC 7807 problem+json error responses
├── logging.go                # slog setup + Log* helpers (LogWarn/LogValidation/…)
├── ratelimit.go              # per-IP token-bucket limiter + HTTP middleware, trusted-proxy CIDRs
├── anchors_store.go          # cached trust-anchor store the app holds (built on internal/dns)
│
├── internal/
│   ├── config/   config.go                                   # Config + loaders (TOML, env fallback), Validate
│   ├── metrics/  metrics.go                                  # Prometheus/expvar collectors + Record*/Register*
│   ├── dns/      anchors.go query.go resolver.go types.go    # DNS queries, resolver, root-anchor auth (leaf)
│   ├── rdap/     client.go types.go                          # RDAP registrable-domain client (leaf)
│   ├── validator/ validator.go chain.go dnssec.go nsec.go result.go warnings.go  # validation engine (uses dns+rdap)
│   └── heartbeat/ heartbeat.go                               # AnyStatus heartbeat client (leaf, own local Config)
│
├── static/       index.html style.css app.js                 # embedded SPA (go:embed)
└── testdata/     root-anchors.json, mock DNS responses
```

`config` and `metrics` are library-shaped concerns extracted to `internal/`
(matching the signer). `anchors_store.go` (a stateful cache the server holds)
and `ratelimit.go` (HTTP middleware) stay at root as app/wiring, alongside the
HTTP handlers/server/SSE.

### File Embedding

Static files should be embedded in the binary using Go 1.16+ `embed` directive:

```go
//go:embed static/*
var staticFiles embed.FS
```

This enables single-binary deployment without external file dependencies.

## Related Projects

| Project | Relationship |
|---------|--------------|
| **internet-files-mirror** | Provides `root-anchors.json`; reference `Docs/Website/style.css` for light/dark mode and accessibility patterns |
| **dns-query-server** | DoH proxy; reference `Docs/Website/doh.css` for dark theme and DNSSEC badge patterns |
| **tudor-dnssec-signer** | Zone signing (uses same `miekg/dns` library, similar DNSSEC logic) |

### Integration with internet-files-mirror

The root trust anchors should be fetched from your internet-files-mirror instance:

```bash
# Configure validator to use mirrored trust anchors
ROOT_ANCHORS_PATH=/var/cache/dnssec-validator/root-anchors.json
ROOT_ANCHORS_URL=https://internet.any53.com/dns/anchors/root-anchors.json
```

The mirror daemon handles:
- Periodic refresh from IANA
- Safe file replacement (never overwrites valid with error)
- Version archiving for rollback

Actual current behavior (do not mistake the following for what the code does — see
R-025/R-058):
- On startup the validator loads the **local file first**; the configured URL is
  used only when the file is missing/empty/invalid (`LoadAnchorsWithFallback`).
- It does **not** compare the file's age or `GeneratedAt`, and a nonempty local
  file is **not** re-fetched or refreshed from the URL — the 24h background
  "refresh" re-reads the same file.
- Fetched anchors are **not** written back to a local cache.
- Every accepted anchor is authenticated against the pinned IANA root DS set
  (R-024); anchors that do not match a pinned record are rejected/ignored.

The freshness/rollover "prefer-fresh-then-fetch-and-cache" behavior described in
older revisions of this section is **not implemented** (tracked as R-025). Until it
is, keep the local anchor file current out of band (e.g. from the mirror).

Both the active KSK-2017 (tag 20326) and its pre-published successor KSK-2024
(tag 38696) are pinned, so the scheduled **2026-10-11 root KSK rollover** is a
non-event: either KSK alone satisfies the pinned-anchor gate, and the KSK-2017
entry can be dropped once it is revoked. A build pinning only KSK-2017 would have
rejected the post-rollover anchor file wholesale — note the failure mode is
*up-but-503*, not a crash (the process keeps serving the UI while `/health` reports
`degraded` and validation returns 503), so watch `/health` rather than liveness.
When pinning a future KSK, do not copy the digest out of the anchor file the pin
exists to authenticate; derive it by chaining from a digest already pinned, as
documented in `internal/dns/anchors.go`.
