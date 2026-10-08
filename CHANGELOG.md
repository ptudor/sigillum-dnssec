# Changelog

## 1.2.0 — 2026-10-07

Fixes for the six High findings of the October 2026 review
(`review/2026/10/REVIEW_MYTHOS51_XHIGH.md`); see
`review/2026/10/HANDOVER_MYTHOS51_XHIGH.md` for the remaining work.

- Signer: a KSK or algorithm rollover changes the parent's DS set only after
  the DNSKEY RRset carrying the new key has propagated to every authoritative
  server and out of resolver caches (one DNSKEY TTL, plus the largest signed
  RRset TTL for an algorithm rollover). The old DS is removed, and the
  new-algorithm DS added, by the daemon at that point; a failed registrar
  update is retried every cycle and a KSK rollover does not end before it
  succeeded. `rollover algorithm` no longer publishes a DS at start.
  New persisted field `ds_add_pushed_at`; `phase_horizon` now also serves
  KSK and algorithm rollovers (RM51X-001, RM51X-016).
- Signer: parent-DS and publication probes cover every nameserver by
  identity. An address this host has no route to (the other address family
  on a single-stack host) is skipped when the same nameserver answers
  elsewhere and is reported; a timeout or refusal still fails. A probe that
  blocks an algorithm rollover phase is logged at Warn and shown in status
  (RM51X-002).
- Signer: owner names whose first label merely starts with `*` (`*foo`,
  `**`) are signed with their full label count; the post-sign check rejects
  a wildcard count on an ordinary owner. The canonical spelling escapes such
  asterisks, so the RRSIG and NSEC owners for those names are written as
  `\*foo` in the signed file (wire-identical) (RM51X-003).
- Packages: the state directory is created on first installation only;
  upgrades never apply ownership or modes to anything under it, closing a
  symlink redirection of root's chown/chmod and preserving a `signed/`
  directory re-grouped for the nameserver (RM51X-004, RM51X-020).
- Validator: a zone whose ancestor could not be authenticated is reported
  indeterminate with the ancestor named, instead of being verified under the
  grandparent's stale keys (bogus) or the parent's unauthenticated served
  keys (secure). An unsigned child of an indeterminate parent is not laundered
  into insecure (RM51X-005).
- Validator: an NXDOMAIN carrying a signed CNAME (or DNAME) at the queried
  name is validated as an alias answer whose target is proven absent on its
  own hop, so dangling aliases in correctly signed zones no longer read bogus
  (RM51X-006).

- Update `github.com/prometheus/common` to v0.72.0 and refresh compiled
  dependency notices.
- Update GoReleaser to v2.18.2, `govulncheck` to v1.8.0, and the pinned
  artifact-upload Action to v7.0.2. The release toolchain remains Go 1.27.1.
- Keep dependency alerts and scheduled security checks while disabling
  automatic dependency-update pull requests.
- Update the signer's `golang.org/x/net` to v0.59.0 and `golang.org/x/sys`
  to v0.48.0. Building either Sigillum module now requires Go 1.26 or later;
  release binaries continue to use Go 1.27.1.

## 1.1.1 — 2026-09-16

- Sign release RPMs, DEBs, and the `checksums.txt` manifest with the project's
  OpenPGP release key, `8C4F 58EF B945 4902 267D 9B3E 426C 4AA2 1A40 0728`,
  published in `packaging/release-signing-key.asc`. `rpm` and DNF verify the
  packages once the key is imported. APT does not check a local DEB's signature,
  so DEBs and archives are authenticated through the signed manifest.
- The release workflow refuses to build unless its signing secret matches the
  published key, and verifies every signature, including a DNF installation with
  signature checking enforced, before attestation and publication.
- CI and `make snapshot` sign with a throwaway key, so every build exercises the
  signing path. Both executables are unchanged from 1.1.0.

## 1.1.0 — 2026-09-15

- `sigillum-signer import --keys-dir` takes over a zone signed by another tool:
  every BIND-style key pair in the directory is listed, the parent's DS records
  and the zone's authoritative servers are consulted, and the parent-trusted
  KSK fixes the algorithm before a compatible ZSK is chosen (or checked, with
  `--ksk`/`--zsk` key tags). A conflicting served deployment is reported rather
  than preserved, even when a validating resolver returns SERVFAIL for it; an
  SOA-serial rollback is refused. `--dry-run` shows the inventory and plan
  without creating a state lock; `--offline` skips the network checks, and a
  KSK the parent does not name is
  refused without `--force`.
- Sign with RSASHA256 and RSASHA512 keys, including legacy 512-bit takeover
  keys, so a zone taken over with RSA keys keeps its algorithm through ordinary
  rollovers (RSA keys the signer mints are 2048-bit); RSA private keys use
  BIND's multi-field layout on disk. RSASHA1
  and RSASHA1-NSEC3-SHA1 keys are read and listed but never signed with.
- The parent DS probe reports the DS records the parent holds.
- Coordinate publication hooks with committed state and the exact signed output;
  bound hook dispatch, preserve concurrent CLI state updates, and require a
  restart when changing the signer's `data_dir`.
- Check every authoritative nameserver during publication and parent-DS probes;
  keep registrar DS updates aligned with the rollover phase and report failed
  CLI deployment hooks with a nonzero exit status.
- Detect source changes by content digest, bound zone input size and record
  count, refresh signatures by their actual expiry, and fix NSEC3 signing for
  mixed-case zone names.
- Select validator responses by authenticated DNSSEC evidence, bound
  authoritative query fanout, and release streaming resources on flush failure.
- Stop zone discovery at its context deadline even when a socket timeout arrives
  before the context's cancellation signal; never return a guessed chain for
  an expired discovery.
- Embed reviewed, pinned root anchors for offline validator startup and add an
  atomic last-known-good cache that remains separate from operator anchor files.
- Tighten integration URL, redirect, outbound-address, response-size, timing,
  and typed-environment validation. Invalid configurations now fail explicitly.
- Update the validator's `golang.org/x/net` dependency to v0.59.0 and refresh
  compiled dependency notices; add `make update-notices` to automate the refresh.
- Add BIND RSA import and rollover interoperability checks to CI alongside the
  native race tests, cross-builds, package lifecycle tests, and security scans.

## 1.0.0 — 2026-09-06

- First public release of Sigillum: automatic DNSSEC zone signing, key lifecycle
  management, and a streaming browser validator for the chain of trust.
- Publish static Linux, FreeBSD, and macOS binaries for amd64 and arm64, unsigned
  Linux RPMs and DEBs, SHA-256 manifests, and GitHub build attestations.
- Use canonical Go module paths beneath `github.com/ptudor/sigillum-dnssec`.
  Align executable, package, service, account, configuration, and state names as
  `sigillum-signer` and `sigillum-validator`; rename their metric namespaces too.
- Ship Linux service accounts, loopback configuration, systemd units, and package
  scripts that preserve configuration and require explicit service activation.
- Use `9.9.9.9` when no explicit or system DNS resolver is available.
- Provide validator `-version` and offline `-check` commands.
- Update DNS, TOML, Prometheus, Cobra, networking, and protobuf dependencies;
  resolve the reported dependency advisories, update pinned GitHub Actions, and
  build with Go 1.27.1.
- Preserve the out-of-zone denial-chain regression check with the DNS library’s
  earlier signature rejection.
- License the project under MIT and include dependency notices in archives and
  package copyright files, including on minimal Debian installations.
- Add native race tests, cross-builds, Debian/Fedora package lifecycle tests,
  scheduled vulnerability scans, and full-history secret scans in GitHub Actions.
