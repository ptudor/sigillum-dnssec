# daemon/dnssec

DNSSEC tooling: a zone-signing daemon and a browser-based validation/troubleshooting tool.

Split out of TudorDNS-Golang on 2026-07-09 with filtered history. The full pre-split history remains frozen at `git@ptudor.net:/git/TudorDNS-Golang`.

**Package layout standard:** `GO-LAYOUT-STANDARD.md` (this dir) is the reusable recipe + prompt for decomposing a flat `package main` Go daemon into `internal/` packages. `Golang-tudor-dnssec-signer` is the worked exemplar; apply the same to other daemons (mail, dns, …).

## Projects

### Golang-tudor-dnssec-signer (dnssec-tudor)
Minimal, opinionated DNSSEC signing daemon for sysadmins managing zones on NSD or BIND.

**Architecture**: Zone Files → dnssec-tudor (watches/signs) → Signed Zone Files → NSD/BIND

- Automatic signing on zone file changes or before signature expiry
- Automatic ZSK rollover (pre-publish method); semi-automatic KSK rollover with DS record guidance
- ED25519 by default (ECDSA P-256/P-384 also supported); NSEC or NSEC3 denial of existence
- Web dashboard for status and DS record copying; post-sign hooks for DNS server reload

**Commands**: `serve`, `sign`, `add`, `remove`, `status`, `ds`, `dnskey`, `rollover`

Uses `github.com/miekg/dns` and `github.com/pelletier/go-toml/v2` (same TOML library as the other daemons; despite older notes, no project here is on BurntSushi).

### Golang-dnssec-validator
Web-based DNSSEC troubleshooting and validation tool with a polished UI — think DNSViz or `drill`, but in the browser, with real-time streaming results and comprehensive diagnostics.

## Common patterns

| Pattern | Implementation |
|---------|----------------|
| **Logging** | Structured logging via `log/slog` (JSON or text) |
| **Metrics** | Prometheus + expvar endpoints |
| **Graceful Shutdown** | SIGINT/SIGTERM with request draining |
| **Configuration** | TOML config file (preferred) or environment variables |
| **Health Checks** | `/health` and `/healthz` endpoints |

Default TOML paths are `/usr/local/etc/tudordns/{project}.toml` and `/etc/tudordns/{project}.toml`.

## Build commands

The root Makefile iterates every project; each project Makefile has the same targets individually.

```bash
make build              # Build all for current platform
make build-freebsd      # FreeBSD amd64
make build-linux        # Linux amd64
make build-darwin-arm64 # macOS Apple Silicon
make test               # Run tests in all projects
make clean              # Remove build artifacts
make deps               # go mod tidy in all projects
```

See each project's own `CLAUDE.md` and README for deployment details.
