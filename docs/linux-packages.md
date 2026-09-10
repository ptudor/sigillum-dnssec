# Linux installation and operations

Packages target systemd-based Debian/Ubuntu and Fedora/RHEL-family Linux systems
on amd64 and arm64. CI exercises Debian 13 and Fedora 43 on amd64; other
distribution versions need their own acceptance run. Both executables are built
with `CGO_ENABLED=0`.

The project MIT license and dependency notices are combined in each package's
`/usr/share/doc/<package>/copyright`, which Debian slim retains when filtering
other documentation.

## What gets installed

| Component | Signer | Validator |
| --- | --- | --- |
| Package, account, service | `sigillum-signer` | `sigillum-validator` |
| Executable | `/usr/bin/sigillum-signer` | `/usr/bin/sigillum-validator` |
| Configuration | `/etc/sigillum-signer/config.toml` | `/etc/sigillum-validator/config.toml` |
| Persistent directory | `/var/lib/sigillum-signer` | `/var/lib/sigillum-validator` |
| HTTP default | `127.0.0.1:8053` | `127.0.0.1:8791` |

Configuration is root-owned, mode `0640`, and readable by the corresponding daemon
group. Account and state directories are created on installation. Signer keys
are in a `0700` directory. Units live in `/usr/lib/systemd/system`. The
validator's state directory holds its last-known-good root-anchor cache
(`root_anchors_cache_path`), written after every usable download and read
before the network on later starts; the unit declares it as
`StateDirectory=sigillum-validator`, the service's only writable path.

**Installation and upgrades do not enable, start, or restart either daemon.** RPM
configuration uses `%config(noreplace)`; DEBs register conffiles. Package removal
stops and disables the service when systemd is running, while preserving accounts
and generated state. Private keys are never removed by package scripts.

Download the matching packages and [verify them](releases.md#verify-a-download).
They are unsigned local packages, not packages from an APT/YUM repository:

```sh
# Choose the tool(s) you need; use arm64/aarch64 assets on ARM machines.
sudo apt install ./sigillum-signer_*_amd64.deb ./sigillum-validator_*_amd64.deb
# Or:
sudo dnf --setopt=localpkg_gpgcheck=0 install ./sigillum-signer-*.x86_64.rpm ./sigillum-validator-*.x86_64.rpm
```

## Signer: enroll a real zone

Read the [signer manual](../signer/README.md) first. Back up
existing keys and state before migration. The package starts with no enrolled zones.

1. Arrange read access for `sigillum-signer` to your unsigned, self-contained zone files.
   The producer must write a temporary file and atomically rename it into place.
2. As root, edit `/etc/sigillum-signer/config.toml` to add your zone definitions.
   Select a serial policy and publication confirmation mode for your topology.
3. Generate signed output as the daemon account so newly created keys have the
   right owner:

   ```sh
   sudo -u sigillum-signer /usr/bin/sigillum-signer sign --config /etc/sigillum-signer/config.toml
   ```

4. Configure NSD or BIND to load the signed files. The nameserver needs directory
   traversal and read permissions on the output. Grant access to the signed-output
   directory using an appropriate group or ACL; keep `keys/` private. Check SELinux
   or AppArmor policy as well as Unix permissions.
5. Configure and test a narrowly permitted reload hook or authoritative publication
   probe. A hook executes as `sigillum-signer`, not as root. The unit sets
   `NoNewPrivileges=yes`: a blanket `sudo systemctl reload …` hook will not work.
   Prefer the nameserver’s appropriately permissioned control socket/command, or
   a separately configured service integration with the exact access it needs.
6. Enable the service, check its dashboard and signed DNS answers, and then publish
   the real DS record at your registrar:

   ```sh
   sudo systemctl enable --now sigillum-signer
   sudo -u sigillum-signer sigillum-signer ds example.com --config /etc/sigillum-signer/config.toml
   sudo journalctl -u sigillum-signer -n 50 --no-pager
   ```

Replace `example.com` with an enrolled domain. Do not register DS values from a
demonstration or before the corresponding signed zone is served correctly.

Configuration is deliberately not writable by the running service. For routine
enrollment, edit it as root and use the daemon account for signing. CLI operations
that edit configuration (`add`, `remove`, some rollover operations) need an
explicit maintenance procedure with the service stopped and carefully managed
configuration/state ownership; do not run them indiscriminately as root. See the
manual’s command-specific behavior before using them on packaged installations.

After editing existing zone settings, use `sudo systemctl reload sigillum-signer`.
Some listener changes require a restart; inspect logs to confirm the new settings.

## Validator: configure and activate

Edit `/etc/sigillum-validator/config.toml`. Set a reachable
`recursive_resolver` and review the anchor and RDAP URLs. The installed defaults
expect a resolver on localhost and use maintainer-operated HTTPS metadata services.

```sh
sudo -u sigillum-validator sigillum-validator -check -config /etc/sigillum-validator/config.toml
sudo systemctl enable --now sigillum-validator
curl --fail http://127.0.0.1:8791/health
sudo journalctl -u sigillum-validator -n 50 --no-pager
```

`-check` verifies configuration only. `/health` additionally reflects root-anchor
readiness. A startup anchor failure is retried, so inspect the logs and network
configuration if health is not ready. The dashboard is at
`http://127.0.0.1:8791`. A remote browser can use an SSH port forward or a properly
configured reverse proxy.

Both web interfaces are unauthenticated. Keep the signer dashboard behind access
control. If publishing the validator, configure TLS and SSE proxy behavior and
restrict operational endpoints such as `/metrics` at the proxy too.

## Upgrade and removal

Earlier private deployments and development snapshots used different component
names. They are separate installations: the new packages do not move old keys,
state, accounts, or configuration automatically. Stop the old signer before
migrating, back up its complete state and key directory, and update explicit paths,
file ownership, service commands, monitoring identifiers, and hooks for the new
account. Keep the existing keys and published DS records. Verify configuration
and signed output before activating the renamed service; never run two signers
against the same state directory. Metric prefixes are now `sigillum_signer_` and
`sigillum_validator_`.

Read the new release notes, back up `/etc/sigillum-signer` and the signer’s entire
state directory, verify downloads, and install the new packages with APT or DNF.
Package scripts preserve configuration and do not restart a running daemon.
Review any `.rpmnew` file or Debian conffile prompt, validate settings, then
explicitly restart the service and check health/logs. A running process may still
be the old executable until you restart it.

Remove packages with `apt remove` or `dnf remove`. Debian `apt purge` additionally
removes package-managed configuration. Generated state and accounts remain by
design; deletion is a separate, deliberate operator action after backups and DNSSEC
decommissioning. Removing the signer does not remove a DS record from a registrar.

Manual `/usr/local` installations can shadow `/usr/bin` in your shell. Check
`command -v sigillum-signer` and `command -v sigillum-validator` during migration.
