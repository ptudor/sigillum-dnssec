#!/bin/sh
set -eu
# Create identities before RPM resolves file ownership; never remove them on erase.
getent group dnssec-validator >/dev/null || groupadd --system dnssec-validator
if ! getent passwd dnssec-validator >/dev/null; then
    useradd --system --gid dnssec-validator --home-dir /var/lib/dnssec-validator \
        --no-create-home --shell /sbin/nologin dnssec-validator
fi
