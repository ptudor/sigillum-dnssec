# Sigillum DNSSEC validator

`sigillum-validator` walks DNS delegations, checks DNSSEC material against its chain
of trust, and streams progress to an embedded browser interface. It is a diagnostic
HTTP service, not a recursive resolver to put in `/etc/resolv.conf`.

Start with the [Sigillum README](../README.md) for release downloads and a local
walkthrough. See [Linux packages](../docs/linux-packages.md) for systemd or the
[FreeBSD walkthrough](QUICKSTART-FREEBSD.md) for rc.d deployment.

## Build and run

From this directory:

```sh
make build
./sigillum-validator -version
./sigillum-validator -check -config ../packaging/sigillum-validator.toml
./sigillum-validator -config ../packaging/sigillum-validator.toml
```

The packaged configuration binds to **127.0.0.1:8791**. Set `recursive_resolver`
to a reachable recursive DNS service before testing a domain. The default
`127.0.0.1` expects a local resolver. The service also needs outbound UDP/TCP DNS
to authoritative servers and HTTPS to any configured remote metadata services.

`-check` validates TOML and configuration without starting HTTP, fetching anchors,
or contacting DNS. A successful check does not prove that root anchors or upstream
services are available. `-version` works without a configuration file.

Without `-config`, the application searches `/usr/local/etc/sigillum-validator/config.toml`,
`/etc/sigillum-validator/config.toml`, and then `./config.toml`. If none exists, it
uses environment-based configuration. For a new deployment, pass an explicit TOML
path so the selected configuration is unambiguous. Unknown TOML
keys are errors. The web UI is embedded; `static_dir` is deprecated and ignored.

## HTTP interface

| Endpoint | Result |
| --- | --- |
| `/` | Embedded browser UI |
| `/validate?domain=example.com&type=A` | Server-Sent Events with validation progress |
| `/api/validate?domain=example.com&type=A` | Completed JSON validation result |
| `/api/anchors` | Loaded root-anchor information |
| `/healthz` | Liveness |
| `/health` | Detailed health, including root-anchor readiness |
| `/metrics` | Prometheus metrics, loopback-only by default |

API errors use `application/problem+json`; streaming errors are SSE events. Keep
proxy buffering disabled for `/validate`, and allow requests to remain open for
the configured validation deadline. `base_path` supports deployment below a URL
prefix. Trust forwarded client addresses only from your actual proxy CIDRs.

## Root trust and external services

The validator reads the JSON format represented by `internal/dns.RootAnchors`.
It first tries `root_anchors_path`, then the last-known-good cache at
`root_anchors_cache_path`, then the configured HTTPS `root_anchors_url`. Every
usable download is written to the cache atomically (private temporary file,
fsync, rename), so a restart while the mirror or the network is unavailable
still validates from the set that was last authenticated; a fetch, parse, pin
or write failure never replaces the previous cache. The packaged service keeps
the cache under `/var/lib/sigillum-validator`, its only writable path. The
default URL is the maintainer-operated Any53 mirror. IANA’s XML file is not a
drop-in replacement for this JSON format.

Loaded anchors are filtered for validity and checked against the root DS values
pinned in the executable. Downloaded metadata cannot introduce an arbitrary root
of trust. New root keys outside that pinned set require a reviewed software update;
the service does not implement a general RFC 5011 trust-anchor manager.

Failed initial loads retry with backoff; successful operation refreshes the store
periodically from the operator file or the URL (never from the cache, which
only serves starts), keeping the current set when a refresh fails. Check `/health` before treating the service as ready, and monitor
anchor availability. To use your own mirror or locally managed file, preserve the
JSON schema and validity metadata and verify health after changing it.

Optional registrar comparisons use `rdap_base_url`, which defaults to the
maintainer-operated Any53 RDAP proxy. Heartbeat reporting is optional and disabled
in shipped configurations. See [AnyStatus integration](ANYSTATUS.md) only if you
choose to enable it.

## Publishing a diagnostic endpoint

The package listens on loopback. Use a TLS reverse proxy and set request limits
appropriate to your audience. The validator bounds DNS work and blocks private,
loopback, link-local, and reserved authoritative destinations by default. Its
explicitly configured recursive resolver is allowed. A private diagnostic instance
can grant specific additional destination CIDRs; avoid widening this on a public
endpoint without considering what clients can cause the server to query.

`/metrics` has a separate allow list. Keep it restricted, including at the reverse
proxy: a loopback proxy can otherwise make an externally forwarded request appear
local. Review the [RFC notes](docs/RFC_COMPLIANCE.md) for implementation detail and
[security policy](../SECURITY.md) for private reporting.
