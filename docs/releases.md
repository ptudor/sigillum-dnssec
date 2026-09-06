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

## Available builds

Development binaries and packages are available from successful
[CI runs](https://github.com/ptudor/sigillum-dnssec/actions/workflows/ci.yml).
The repository has no published version tag or GitHub Release. The
[1.0.0 notes](release-notes/v1.0.0.md) are an unpublished draft.

The project uses the [MIT license](../LICENSE). Archives and packages also carry
[third-party notices](../THIRD_PARTY_NOTICES.md) for their compiled dependencies.
CI checks those notices against every release binary.

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

## Update dependencies

Apply dependency updates and run the module’s tests and `go mod tidy`. Rebuild
all release targets, refresh the compiled dependency notices, and rebuild the
packages so they carry the updated notices:

```sh
make snapshot
python3 scripts/update-notices.py
make snapshot
python3 scripts/update-notices.py --check
```

Use the Go version in `.go-version` for both builds and notice generation. If your
Go distribution installs its `LICENSE` outside `GOROOT`, pass its location using
`--go-license /path/to/go/LICENSE`. Review upstream license changes and commit the
module files and refreshed notices together.

## Publish a version

Update `CHANGELOG.md` and add `docs/release-notes/vMAJOR.MINOR.PATCH.md` for the
version being released. After the intended commit has passed CI, create and push
an annotated version tag only when publication is authorized. For example:

```sh
# In this repository, with a github remote configured:
git tag -a v1.0.0 -m 'Release 1.0.0'
git push github v1.0.0
```

That tag is a publication action: the workflow will publish when its checks and
attestation succeed. Use `v1.1.0-rc.1` for a prerelease; GoReleaser marks it as such.
The workflow uses the version’s checked-in release notes for its GitHub Release.

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
