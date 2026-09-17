# Builds and releases

The repository uses GitHub Actions and GoReleaser OSS **v2.18.1**. The checked-in
`.goreleaser.yaml` builds the binaries, archives, RPMs, DEBs, and SHA-256 manifest.
It does not require GoReleaser Pro or a personal access token. GnuPG signs the
packages and the manifest: tagged releases use the
[release signing key](#release-signing-key), every other build a throwaway key.
The selected Go toolchain is recorded in `.go-version`.

## What runs automatically

| Trigger | Result |
| --- | --- |
| Push to `main` or a pull request | Vet and race tests on Linux amd64, Linux arm64, and macOS arm64; all release targets cross-built and signed with a throwaway key; signatures verified and package installation/reinstallation/removal exercised in Debian and Fedora containers |
| Manual **CI → Run workflow** | The same checks and downloadable snapshot artifacts |
| Push a `vMAJOR.MINOR.PATCH` tag, optionally with a prerelease suffix | Required CI, a draft GitHub Release with binaries, signed packages and signed checksums, verification against the published key, build provenance attestation, then automatic publication |
| Weekly Dependabot run | Pull requests for Go dependencies and SHA-pinned GitHub Actions |
| Push, pull request, weekly schedule, or release | Vulnerability scans for Linux/FreeBSD builds and a redacted secret scan of full Git history |

Release permissions are limited to the publishing job. Checkout does not retain
credentials, PR jobs cannot publish releases, and actions are pinned to commit
SHAs. GoReleaser uses the commit date for embedded build metadata and archive
binary timestamps, and builds use `-trimpath` with `CGO_ENABLED=0`. This improves
traceability; byte-for-byte reproducibility across arbitrary toolchains and
package tools is not claimed.

A release stays a draft if signature verification or attestation fails. Investigate the failed run before
publishing it manually. Never overwrite a public version tag to repair a release;
use a new version for corrected public artifacts.

## Public releases

[Sigillum v1.1.1](https://github.com/ptudor/sigillum-dnssec/releases/tag/v1.1.1)
is 1.1.0 with signed packages and a signed manifest; see its
[release notes](release-notes/v1.1.1.md). The [1.1.0 notes](release-notes/v1.1.0.md)
cover key-directory takeover, RSA signing, upgrade guidance, and platform
coverage, and the [1.0.0 notes](release-notes/v1.0.0.md)
describe the first public release. Development snapshots are also
available from successful [CI runs](https://github.com/ptudor/sigillum-dnssec/actions/workflows/ci.yml).

The project uses the [MIT license](../LICENSE). Archives and packages also carry
[third-party notices](../THIRD_PARTY_NOTICES.md) for their compiled dependencies.
CI checks those notices against every release binary.

## Local rehearsal

Install GoReleaser v2.18.1, GnuPG, and the Go version in `.go-version`, then run:

```sh
make release-check
make snapshot
ls dist/
```

`make snapshot` writes to the ignored `dist/` directory, replacing earlier
GoReleaser output there. It does not publish anything and does not require a tag
or GitHub credentials. Archives and packages have a development version.

A snapshot is signed the way a release is, with an RSA key generated for that
build and destroyed when it ends. `make snapshot` then checks the `checksums.txt`
signature, the manifest's hashes, and every DEB signature against the public half,
which it leaves in `dist/snapshot-signing-key.asc`. This proves the signing path
and nothing about the publisher: treat snapshot packages as unsigned.

On a Linux amd64 host with Docker:

```sh
sh scripts/test-packages.sh
```

This imports the snapshot key into disposable Debian 13 and Fedora 43 containers,
requires `rpm` to verify every RPM signature, installs the generated amd64
packages with DNF's local-package signature check enforced, checks accounts, file modes, executable entry points and systemd unit
syntax, confirms that services were not enabled or started, edits configuration,
reinstalls the packages, and verifies retained configuration/state after removal.
This exercises conffile retention on reinstall; native version-to-version upgrades
and runtime service behavior remain release acceptance tasks. The containers
receive no clock-control privileges or reference-clock devices. To check packages
signed by another key, pass its public key file as the first argument.

## Update dependencies

Apply dependency updates and run the module’s tests and `go mod tidy`. Rebuild
all release targets, refresh the compiled dependency notices, and rebuild the
packages so they carry the updated notices:

```sh
make update-notices
```

This target builds, regenerates the notices, rebuilds packages with the refreshed
file, and checks the result against every release binary.

Use the Go version in `.go-version` for both builds and notice generation. If your
Go distribution installs its `LICENSE` outside `GOROOT`, use
`make update-notices GO_LICENSE=/path/to/go/LICENSE`. Review upstream license
changes and commit the module files and refreshed notices together.

## Publish a version

Update `CHANGELOG.md` and add `docs/release-notes/vMAJOR.MINOR.PATCH.md` for the
version being released. After the intended commit has passed CI, create and push
an annotated version tag only when publication is authorized. For example:

```sh
# In this repository, with a github remote configured:
git tag -a v1.0.1 -m 'Release 1.0.1'
git push github v1.0.1
```

That tag is a publication action: the workflow will publish when its checks,
signature verification, and attestation succeed. Use `v1.1.0-rc.1` for a prerelease; GoReleaser marks it as such.
The workflow uses the version’s checked-in release notes for its GitHub Release.

Artifacts include one archive per OS/architecture, signed Linux packages,
`checksums.txt`, and its detached signature `checksums.txt.sig`. These are
downloadable package files. There is no APT/YUM repository, automatic repository
enrollment, or automatic host update mechanism in this setup; operators import
the release key themselves.

## Verify a download

Releases after 1.1.0 are signed with the [release signing key](#release-signing-key).
Take the key from this repository rather than from a release page, and compare
its fingerprint with `8C4F 58EF B945 4902 267D  9B3E 426C 4AA2 1A40 0728`:

```sh
curl -fsSLO https://raw.githubusercontent.com/ptudor/sigillum-dnssec/main/packaging/release-signing-key.asc
gpg --show-keys --with-fingerprint release-signing-key.asc
```

For any asset, download it with `checksums.txt` and `checksums.txt.sig` from the
same release. In the download directory:

```sh
gpg --import release-signing-key.asc
gpg --verify checksums.txt.sig checksums.txt
sha256sum --check --ignore-missing checksums.txt
```

`gpg` must report a good signature from that fingerprint. Its warning that the key
is not certified describes your own trust database, not the signature. On macOS,
check an individual asset with `shasum -a 256 FILE` and compare the result with
its entry in `checksums.txt`. A matching checksum alone detects corruption; the
signature is what authenticates the manifest.

RPMs also carry the signature inside the package, where `rpm` and DNF check it:

```sh
sudo rpm --import release-signing-key.asc
rpm -K sigillum-*.rpm
```

Every line must end in `digests signatures OK`. An unsigned package reports
`digests OK` alone, and one signed by a key you have not imported reports
`SIGNATURES NOT OK`.

DEBs carry an embedded origin signature too, but APT and dpkg do not check it
when installing a local file, so rely on the signed manifest above. To check the
embedded signature itself:

```sh
ar p FILE.deb debian-binary > signed-members
ar p FILE.deb control.tar.gz >> signed-members
ar p FILE.deb data.tar.gz >> signed-members
ar p FILE.deb _gpgorigin > origin.asc
gpg --verify origin.asc signed-members
```

For provenance, use a GitHub CLI version supporting artifact attestations:

```sh
gh attestation verify FILE --repo ptudor/sigillum-dnssec --signer-workflow ptudor/sigillum-dnssec/.github/workflows/release.yml
```

Replace `FILE` with the archive or package path, inspect the verified result, and
confirm the source repository and expected release tag/commit. Development CI
snapshots are not release-attested. Attestation establishes where and from which
commit a file was built; the signature establishes who published it.

## Release signing key

| | |
| --- | --- |
| Fingerprint | `8C4F 58EF B945 4902 267D  9B3E 426C 4AA2 1A40 0728` |
| User ID | Patrick Tudor (software release signing) |
| Algorithm | RSA 4096, signing only, no subkeys |
| Expires | 2029-09-16 |
| Public key | [`packaging/release-signing-key.asc`](../packaging/release-signing-key.asc) |

The same key signs [Carillon](https://github.com/ptudor/carillon-time) releases.
It is RSA because GoReleaser's RPM writer records signatures only under RPM's RSA
tags; `rpm` cannot verify a package signed that way with an Ed25519 key.

The secret key and its passphrase are the `RELEASE_GPG_KEY` and
`RELEASE_GPG_PASSPHRASE` Actions secrets, used only by the release job. That job
refuses to build unless the secret is the committed public key's other half and
the passphrase unlocks it. Before attestation and publication it verifies every
signature against the committed public key, including a DNF installation with
signature checking enforced.

To extend the expiry, run `gpg --quick-set-expire FINGERPRINT 3y`, export the
public key over `packaging/release-signing-key.asc` in both repositories, and
replace `RELEASE_GPG_KEY` in both, because the stored copy still carries the old
expiry and will refuse to sign once it passes:

```sh
gpg --armor --export-secret-keys FINGERPRINT | gh secret set RELEASE_GPG_KEY --repo ptudor/sigillum-dnssec
```

The fingerprint does not change, and signatures on published releases stay valid.
If the key is lost or exposed, publish its revocation certificate, generate a
new key, replace the committed public key and both secrets, and state the new
fingerprint in the next release notes.

The implementation follows [GoReleaser’s package configuration](https://goreleaser.com/customization/package/nfpm/)
and [GitHub’s artifact attestation guidance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).
