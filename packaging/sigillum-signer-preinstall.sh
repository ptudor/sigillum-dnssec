#!/bin/sh
set -eu
# Create identities before RPM resolves file ownership; never remove them on erase.
getent group sigillum-signer >/dev/null || groupadd --system sigillum-signer
if ! getent passwd sigillum-signer >/dev/null; then
    useradd --system --gid sigillum-signer --home-dir /var/lib/sigillum-signer \
        --no-create-home --shell /sbin/nologin sigillum-signer
fi
