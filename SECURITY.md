# Security

Report a suspected vulnerability privately through this repository’s **Security →
Report a vulnerability** page when enabled. If that option is unavailable,
email **ptudor@ptudor.net** with the repository name and “security” in the subject.
Please avoid posting exploit details or production credentials in a public issue.

Include the affected version or commit, platform, a minimal reproduction, impact,
and any workaround you have verified. Redact private keys, API credentials,
authentication keys, and unrelated operator data.

Security fixes target the latest release and the default branch. Older releases
have no guaranteed backport schedule. This is an independently maintained project;
there is no guaranteed response time or commercial support agreement.

Release RPMs, DEBs, and the `checksums.txt` manifest are signed with the project's
OpenPGP release key, fingerprint `8C4F 58EF B945 4902 267D  9B3E 426C 4AA2 1A40 0728`,
published in [`packaging/release-signing-key.asc`](packaging/release-signing-key.asc).
Releases through 1.1.0 predate the key and are unsigned. Published release files
also have SHA-256 checksums and GitHub build provenance attestations. Verification
instructions are in [the release guide](docs/releases.md#verify-a-download).

Dependency update proposals and Linux/FreeBSD vulnerability scans run weekly.
Vulnerability scans also run on pull requests and gate tagged releases. Source review, automated tests,
and build provenance each answer different questions; none establishes an
independent security audit or certification of the protocol implementation.
