#!/bin/sh
# Executed only inside the disposable containers in test-packages.sh.
set -eu
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    apt-get install -y --no-install-recommends ca-certificates systemd passwd procps util-linux
    set -- /packages/*_amd64.deb
    test -f "$1"
    apt-get install -y --no-install-recommends "$@"
    format=deb
else
    set -- /packages/*.x86_64.rpm
    test -f "$1"
    dnf install -y --setopt=install_weak_deps=False --setopt=localpkg_gpgcheck=0 "$@" procps-ng util-linux
    format=rpm
fi

services='dnssec-tudor dnssec-validator'
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
    # Linux comm names stop at 15 bytes (dnssec-validator is longer).
    if pgrep -x "$(printf '%.15s' "$service")"; then
        echo "Package unexpectedly started $service" >&2
        exit 1
    fi
    systemd-analyze verify "/usr/lib/systemd/system/$service.service"
    if [ "$service" = dnssec-tudor ]; then
        config="/etc/$service/config.toml"
    else
        config="/etc/$service/$service.toml"
    fi
    test "$(stat -c %a "$config")" = 640
    test "$(stat -c %U "$config")" = root
    test "$(stat -c %G "$config")" = "$service"
    runuser -u "$service" -- test -r "$config"
    printf '\n# package-upgrade-sentinel\n' >> "$config"
    printf 'preserve state\n' > "/var/lib/$service/package-test-sentinel"
done

dnssec-tudor version
dnssec-validator -version
runuser -u dnssec-validator -- dnssec-validator -check -config /etc/dnssec-validator/dnssec-validator.toml
# Empty zone set: verify account permissions without modifying a live zone.
runuser -u dnssec-tudor -- dnssec-tudor sign --config /etc/dnssec-tudor/config.toml

# Reinstall through the package manager with a locally edited configuration.
# conffile retention uses the same package-manager mechanism on version upgrades.
if [ "$format" = deb ]; then
    apt-get install -y --reinstall -o Dpkg::Options::=--force-confold "$@"
else
    dnf reinstall -y --setopt=localpkg_gpgcheck=0 "$@"
fi
for service in $services; do
    if [ "$service" = dnssec-tudor ]; then
        config="/etc/$service/config.toml"
    else
        config="/etc/$service/$service.toml"
    fi
    grep -q '^# package-upgrade-sentinel$' "$config"
    test -f "/var/lib/$service/package-test-sentinel"
    test ! -e "/etc/systemd/system/multi-user.target.wants/$service.service"
    if pgrep -x "$(printf '%.15s' "$service")"; then
        echo "Package reinstall unexpectedly started $service" >&2
        exit 1
    fi
done
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
