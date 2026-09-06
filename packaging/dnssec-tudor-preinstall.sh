#!/bin/sh
set -eu
# Create identities before RPM resolves file ownership; never remove them on erase.
getent group dnssec-tudor >/dev/null || groupadd --system dnssec-tudor
if ! getent passwd dnssec-tudor >/dev/null; then
    useradd --system --gid dnssec-tudor --home-dir /var/lib/dnssec-tudor \
        --no-create-home --shell /sbin/nologin dnssec-tudor
fi
