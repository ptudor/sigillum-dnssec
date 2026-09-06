#!/bin/sh
set -eu
# No recursive chown: existing private keys and operator-managed state keep their modes.
install -d -o dnssec-validator -g dnssec-validator -m 0750 /var/lib/dnssec-validator
install -d -o root -g dnssec-validator -m 0750 /etc/dnssec-validator
if [ -f /etc/dnssec-validator/dnssec-validator.toml ]; then
    chown root:dnssec-validator /etc/dnssec-validator/dnssec-validator.toml
    chmod 0640 /etc/dnssec-validator/dnssec-validator.toml
fi
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
# Activation and restart are operator decisions, including after an upgrade.
