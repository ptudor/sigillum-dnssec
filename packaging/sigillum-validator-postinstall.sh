#!/bin/sh
set -eu
# No recursive chown: existing private keys and operator-managed state keep their modes.
install -d -o sigillum-validator -g sigillum-validator -m 0750 /var/lib/sigillum-validator
install -d -o root -g sigillum-validator -m 0750 /etc/sigillum-validator
if [ -f /etc/sigillum-validator/config.toml ]; then
    chown root:sigillum-validator /etc/sigillum-validator/config.toml
    chmod 0640 /etc/sigillum-validator/config.toml
fi
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
# Activation and restart are operator decisions, including after an upgrade.
