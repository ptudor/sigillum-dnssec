#!/bin/sh
set -eu
# Create identities before RPM resolves file ownership; never remove them on erase.
getent group sigillum-validator >/dev/null || groupadd --system sigillum-validator
if ! getent passwd sigillum-validator >/dev/null; then
    useradd --system --gid sigillum-validator --home-dir /var/lib/sigillum-validator \
        --no-create-home --shell /sbin/nologin sigillum-validator
fi
