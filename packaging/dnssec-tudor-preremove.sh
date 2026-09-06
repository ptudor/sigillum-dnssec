#!/bin/sh
set -eu
# Debian supplies "remove"; RPM supplies 0 for final erase and 1 for upgrade.
case "${1:-}" in
    remove|0)
        if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
            systemctl stop dnssec-tudor.service
            systemctl disable dnssec-tudor.service
        fi
        ;;
esac
