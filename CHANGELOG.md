# Changelog

## Unreleased

- Keep project and dependency license notices in the package copyright file so
  minimal Debian images preserve them.

- Adopt the MIT license and include dependency license/attribution notices in all
  release archives and Linux packages.

- Prepare Sigillum’s public README, component guides, and Linux operations guide.
- Move the Go modules to `signer/` and `validator/`, with canonical paths beneath
  `github.com/ptudor/sigillum-dnssec`. Existing executable names remain
  `dnssec-tudor` and `dnssec-validator`.
- Add GitHub CI, release archives for Linux/FreeBSD/macOS, unsigned Linux RPMs
  and DEBs, SHA-256 manifests, and build provenance attestations.
- Add dedicated Linux service accounts, loopback configuration, systemd units,
  configuration-preserving package scripts, and explicit operator activation.
- Add validator `-version` and `-check` commands. `-check` exits before network
  access; unexpected positional command arguments now fail with status 2.
- Bind the validator’s standalone example to loopback and remove its obsolete
  `static_dir` setting.
- Add scheduled vulnerability scans, history secret scans, and Dependabot updates.

The first published tag will establish the public release baseline. Review
[release setup](docs/releases.md) before publication.
