#!/bin/sh
# Executed only inside the disposable containers in test-packages.sh.
set -eu
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y --no-install-recommends ca-certificates systemd passwd procps util-linux
    set -- /packages/*_amd64.deb
    test -f "$1"
    # apt ignores a DEB's embedded signature; verify-signatures.sh checks it on the host.
    apt-get install -y --no-install-recommends "$@"
    format=deb
else
    rpm --import /keys/signing-key.asc
    for package in /packages/*.rpm; do
        test -f "$package"
        # An unsigned package also exits 0, reporting only "digests OK".
        result=$(rpm -K "$package")
        printf '%s\n' "$result"
        case $result in
            *'signatures OK') ;;
            *) echo "No verified signature on $package" >&2; exit 1 ;;
        esac
    done
    set -- /packages/*.x86_64.rpm
    test -f "$1"
    dnf install -y --setopt=install_weak_deps=False --setopt=localpkg_gpgcheck=1 "$@" procps-ng util-linux
    format=rpm
fi

services='sigillum-signer sigillum-validator'
for service in $services; do
    getent passwd "$service"
    test -x "/usr/bin/$service"
    test -f "/usr/lib/systemd/system/$service.service"
    grep -qx 'MIT License' "/usr/share/doc/$service/copyright"
    # Debian slim deliberately excludes other /usr/share/doc files.
    grep -q '^## Go runtime and standard library' "/usr/share/doc/$service/copyright"
    grep -q '^## github.com/' "/usr/share/doc/$service/copyright"
    # The package must not create an enablement symlink or start a process.
    test ! -e "/etc/systemd/system/multi-user.target.wants/$service.service"
    # Linux comm names stop at 15 bytes (sigillum-validator is longer).
    if pgrep -x "$(printf '%.15s' "$service")"; then
        echo "Package unexpectedly started $service" >&2
        exit 1
    fi
    systemd-analyze verify "/usr/lib/systemd/system/$service.service"
    config="/etc/$service/config.toml"
    test "$(stat -c %a "$config")" = 640
    test "$(stat -c %U "$config")" = root
    test "$(stat -c %G "$config")" = "$service"
    runuser -u "$service" -- test -r "$config"
    printf '\n# package-upgrade-sentinel\n' >> "$config"
    printf 'preserve state\n' > "/var/lib/$service/package-test-sentinel"
done

for service in $services; do
    test "$(stat -c '%U %G %a' "/var/lib/$service")" = "$service $service 750"
done
test "$(stat -c '%U %G %a' /var/lib/sigillum-signer/keys)" = 'sigillum-signer sigillum-signer 700'
test "$(stat -c '%U %G %a' /var/lib/sigillum-signer/signed)" = 'sigillum-signer sigillum-signer 750'

sigillum-signer version | grep '^sigillum-signer '
sigillum-validator -version | grep '^sigillum-validator '
runuser -u sigillum-validator -- sigillum-validator -check -config /etc/sigillum-validator/config.toml
# Empty zone set: verify account permissions without modifying a live zone.
runuser -u sigillum-signer -- sigillum-signer sign --config /etc/sigillum-signer/config.toml

# Package scripts must never follow an entry the service account controls inside
# its own state directory (a planted symlink would redirect root's chown/chmod),
# and must keep operator changes such as a signed/ directory re-grouped for the
# nameserver. Both are exercised by the reinstall below.
runuser -u sigillum-signer -- sh -c \
    'mv /var/lib/sigillum-signer/keys /var/lib/sigillum-signer/keys.orig && ln -s /etc/systemd/system /var/lib/sigillum-signer/keys'
chgrp daemon /var/lib/sigillum-signer/signed
chmod 0755 /var/lib/sigillum-signer/signed
chgrp daemon /var/lib/sigillum-validator
systemd_dir_before=$(stat -c '%U %G %a' /etc/systemd/system)

# Reinstall through the package manager with a locally edited configuration.
# conffile retention uses the same package-manager mechanism on version upgrades.
if [ "$format" = deb ]; then
    apt-get install -y --reinstall -o Dpkg::Options::=--force-confold "$@"
else
    dnf reinstall -y --setopt=localpkg_gpgcheck=1 "$@"
fi
for service in $services; do
    config="/etc/$service/config.toml"
    grep -q '^# package-upgrade-sentinel$' "$config"
    test -f "/var/lib/$service/package-test-sentinel"
    test ! -e "/etc/systemd/system/multi-user.target.wants/$service.service"
    if pgrep -x "$(printf '%.15s' "$service")"; then
        echo "Package reinstall unexpectedly started $service" >&2
        exit 1
    fi
done
test "$(stat -c '%U %G %a' /etc/systemd/system)" = "$systemd_dir_before"
test -L /var/lib/sigillum-signer/keys
test "$(stat -c '%U %G %a' /var/lib/sigillum-signer/keys.orig)" = 'sigillum-signer sigillum-signer 700'
test "$(stat -c '%U %G %a' /var/lib/sigillum-signer/signed)" = 'sigillum-signer daemon 755'
test "$(stat -c '%U %G %a' /var/lib/sigillum-validator)" = 'sigillum-validator daemon 750'
rm /var/lib/sigillum-signer/keys
mv /var/lib/sigillum-signer/keys.orig /var/lib/sigillum-signer/keys
if [ "$format" = deb ]; then
    # Deliberate word splitting: this is a fixed list of package names.
    # shellcheck disable=SC2086
    apt-get remove -y $services
else
    # shellcheck disable=SC2086
    dnf remove -y $services
fi
for service in $services; do
    test ! -e "/usr/bin/$service"
    test -f "/var/lib/$service/package-test-sentinel"
    getent passwd "$service" >/dev/null
done
printf 'Package install, configuration retention, and removal passed (%s).\n' "$format"
