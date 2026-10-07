#!/bin/sh
set -eu
# The state directory belongs to the service account, so it is created once,
# on first installation, and never modified afterwards. Re-applying ownership
# or a mode to an entry inside it on upgrade would be unsafe: the account can
# replace that entry with a symlink, and install -d, chown and chmod follow an
# existing symlink, applying root's change to the target. Leaving the tree
# alone also keeps operator changes such as a signed/ directory re-grouped for
# the nameserver. Private keys and state are never touched by package scripts.
if [ ! -e /var/lib/sigillum-signer ]; then
    install -d -o sigillum-signer -g sigillum-signer -m 0750 /var/lib/sigillum-signer
    install -d -o sigillum-signer -g sigillum-signer -m 0700 /var/lib/sigillum-signer/keys
    install -d -o sigillum-signer -g sigillum-signer -m 0750 /var/lib/sigillum-signer/signed
fi
# /etc is root-owned: nothing here can be redirected by the service account.
install -d -o root -g sigillum-signer -m 0750 /etc/sigillum-signer
if [ -f /etc/sigillum-signer/config.toml ]; then
    chown root:sigillum-signer /etc/sigillum-signer/config.toml
    chmod 0640 /etc/sigillum-signer/config.toml
fi
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
fi
# Activation and restart are operator decisions, including after an upgrade.
