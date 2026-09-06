#!/bin/sh
set -eu
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
# Preserve service accounts and persistent state, including DNSSEC private keys.
