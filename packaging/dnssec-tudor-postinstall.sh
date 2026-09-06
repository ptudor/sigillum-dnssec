#!/bin/sh
set -eu
# No recursive chown: existing private keys and operator-managed state keep their modes.
install -d -o dnssec-tudor -g dnssec-tudor -m 0750 /var/lib/dnssec-tudor
install -d -o root -g dnssec-tudor -m 0750 /etc/dnssec-tudor
if [ -f /etc/dnssec-tudor/config.toml ]; then
    chown root:dnssec-tudor /etc/dnssec-tudor/config.toml
    chmod 0640 /etc/dnssec-tudor/config.toml
fi
install -d -o dnssec-tudor -g dnssec-tudor -m 0700 /var/lib/dnssec-tudor/keys
install -d -o dnssec-tudor -g dnssec-tudor -m 0750 /var/lib/dnssec-tudor/signed
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
# Activation and restart are operator decisions, including after an upgrade.
