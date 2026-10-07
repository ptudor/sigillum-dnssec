#!/bin/sh
set -eu
# The state directory belongs to the service account, so it is created once,
# on first installation, and never modified afterwards (see the signer script
# for why re-applying ownership or modes on upgrade is unsafe). The unit also
# declares it as StateDirectory, which systemd maintains on every start.
if [ ! -e /var/lib/sigillum-validator ]; then
    install -d -o sigillum-validator -g sigillum-validator -m 0750 /var/lib/sigillum-validator
fi
# /etc is root-owned: nothing here can be redirected by the service account.
install -d -o root -g sigillum-validator -m 0750 /etc/sigillum-validator
if [ -f /etc/sigillum-validator/config.toml ]; then
    chown root:sigillum-validator /etc/sigillum-validator/config.toml
    chmod 0640 /etc/sigillum-validator/config.toml
fi
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
# Activation and restart are operator decisions, including after an upgrade.
