# Builds and releases

The repository uses GitHub Actions and GoReleaser OSS **v2.18.1**. The checked-in
`.goreleaser.yaml` builds the binaries, archives, RPMs, DEBs, and SHA-256 manifest.
It does not require GoReleaser Pro, a personal access token, or package-signing keys.
The selected Go toolchain is recorded in `.go-version`.

## What runs automatically

| Trigger | Result |
| --- | --- |
| Push to `main` or a pull request | Vet and race tests on Linux amd64, Linux arm64, and macOS arm64; all release targets cross-built; package installation/reinstallation/removal exercised in Debian and Fedora containers |
| Manual **CI → Run workflow** | The same checks and downloadable snapshot artifacts |
| Push a `vMAJOR.MINOR.PATCH` tag, optionally with a prerelease suffix | Required CI, a draft GitHub Release with binaries/packages/checksums, build provenance attestation, then automatic publication |
| Weekly Dependabot run | Pull requests for Go dependencies and SHA-pinned GitHub Actions |
| Push, pull request, weekly schedule, or release | Vulnerability scans for Linux/FreeBSD builds and a redacted secret scan of full Git history |

Release permissions are limited to the publishing job. Checkout does not retain
credentials, PR jobs cannot publish releases, and actions are pinned to commit
SHAs. GoReleaser uses the commit date for embedded build metadata and archive
binary timestamps, and builds use `-trimpath` with `CGO_ENABLED=0`. This improves
traceability; byte-for-byte reproducibility across arbitrary toolchains and
package tools is not claimed.

A release stays a draft if attestation fails. Investigate the failed run before
publishing it manually. Never overwrite a public version tag to repair a release;
use a new version for corrected public artifacts.

## First GitHub setup

The public repository is `https://github.com/ptudor/sigillum-dnssec`.
The maintainer uses a separate `github` remote for GitHub publication alongside
an existing private `origin`. Contributors can use an ordinary GitHub clone;
its `origin` remote points to GitHub.

For maintainers setting up or transferring this repository:

1. Review the [MIT license](../LICENSE) and [third-party notices](../THIRD_PARTY_NOTICES.md).
   Both snapshot and release archives/packages include these texts. The package
   metadata identifies the project as MIT. CI checks the notices against the
   actual built dependencies; refresh them when changing dependencies or Go.
2. Review the complete Git history for credentials, private keys, internal
   hostnames, deployment records, and material you do not intend to publish.
   This repository retains historical review and deployment notes. A clean
   working tree or a clean secret scan does not decide whether that history is
   suitable for public release. Decide whether to publish that history or an
   intentionally prepared public baseline. Do not copy a live `.env` or config.
3. Create the repository with `main` as the default branch, enable Actions and
   private vulnerability reporting, and enable Dependabot alerts. A useful About
   description is shown below. If the repository owner/name changes, update
   `.goreleaser.yaml`, README badges/links, and service documentation URLs.
4. Push `main` and verify the first CI run. Review the downloadable snapshot
   packages, including a native install on each deployment platform you intend
   to support. GitHub’s public-repository artifact attestations use the supplied
   `GITHUB_TOKEN` and OIDC permissions; no long-lived signing key is needed.
5. Protect the default branch and release tags with rules appropriate to your
   maintenance workflow. Require the CI test jobs and package job for changes.
   Keep write access to version tags limited to release maintainers.

Suggested About description:

> DNSSEC zone signing and streaming browser diagnostics for operators of their own nameservers.

Suggested topics: `dnssec`, `dns`, `golang`, `nsd`, `bind`, `freebsd`, `linux`, `systemd`.

## Local rehearsal

Install GoReleaser v2.18.1 and the Go version in `.go-version`, then run:

```sh
make release-check
make snapshot
ls dist/
```

`make snapshot` writes to the ignored `dist/` directory, replacing earlier
GoReleaser output there. It does not publish anything and does not require a tag
or GitHub credentials. Archives and packages have a development version.

On a Linux amd64 host with Docker:

```sh
sh scripts/test-packages.sh
```

This installs the generated amd64 packages into disposable Debian 13 and Fedora 43
containers, checks accounts, file modes, executable entry points and systemd unit
syntax, confirms that services were not enabled or started, edits configuration,
reinstalls the packages, and verifies retained configuration/state after removal.
This exercises conffile retention on reinstall; native version-to-version upgrades
and runtime service behavior remain release acceptance tasks. The containers
receive no clock-control privileges or reference-clock devices.

## Publish a version

After the intended commit has passed CI and the first-release setup is complete:

```sh
# In this repository, with a github remote configured:
git tag -a v0.1.0 -m 'First public release'
git push github v0.1.0
```

That tag is a publication action: the workflow will publish when its checks and
attestation succeed. Use `v0.1.0-rc.1` for a prerelease; GoReleaser marks it as such.
The name above is an example, not a tag created by this preparation work.

Artifacts include one archive per OS/architecture, unsigned Linux packages, and
`checksums.txt`. These are downloadable package files. There is no signed APT/YUM
repository, automatic repository enrollment, package-key distribution, or automatic
host update mechanism in this setup. An RPM signing or repository-hosting policy
can be added later with explicitly managed keys.

## Verify a download

Download an asset and `checksums.txt` from the same release. In the download
directory, Linux can check the files you obtained against the manifest:

```sh
sha256sum --check --ignore-missing checksums.txt
```

On macOS, check an individual asset with `shasum -a 256 FILE` and compare the result
with its entry in `checksums.txt`. A matching checksum detects corruption; it does
not authenticate a manifest downloaded with the same compromised asset.

For provenance, use a GitHub CLI version supporting artifact attestations:

```sh
gh attestation verify FILE --repo ptudor/sigillum-dnssec --signer-workflow ptudor/sigillum-dnssec/.github/workflows/release.yml
```

Replace `FILE` with the archive or package path, inspect the verified result, and
confirm the source repository and expected release tag/commit. Development CI
snapshots are not release-attested. Attestation establishes the build’s provenance;
it does not add an RPM GPG signature or sign an APT repository.

The implementation follows [GoReleaser’s package configuration](https://goreleaser.com/customization/package/nfpm/)
and [GitHub’s artifact attestation guidance](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations/use-artifact-attestations).
