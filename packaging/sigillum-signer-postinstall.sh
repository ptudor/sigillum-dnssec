#!/bin/sh
set -eu
# No recursive chown: existing private keys and operator-managed state keep their modes.
install -d -o sigillum-signer -g sigillum-signer -m 0750 /var/lib/sigillum-signer
install -d -o root -g sigillum-signer -m 0750 /etc/sigillum-signer
if [ -f /etc/sigillum-signer/config.toml ]; then
    chown root:sigillum-signer /etc/sigillum-signer/config.toml
    chmod 0640 /etc/sigillum-signer/config.toml
fi
install -d -o sigillum-signer -g sigillum-signer -m 0700 /var/lib/sigillum-signer/keys
install -d -o sigillum-signer -g sigillum-signer -m 0750 /var/lib/sigillum-signer/signed
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
# Activation and restart are operator decisions, including after an upgrade.
