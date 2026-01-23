#!/bin/sh
# Wrapper script for dnssec-validator daemon
# Sources environment file before exec'ing the binary
# Required because FreeBSD's daemon command strips environment variables

ENV_FILE="${DNSSEC_VALIDATOR_ENVFILE:-/usr/local/etc/tudordns/dnssec-validator.env}"

if [ -f "${ENV_FILE}" ]; then
    set -a
    . "${ENV_FILE}"
    set +a
fi

exec /usr/local/sbin/dnssec-validator "$@"
