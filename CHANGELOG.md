# Changelog

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
