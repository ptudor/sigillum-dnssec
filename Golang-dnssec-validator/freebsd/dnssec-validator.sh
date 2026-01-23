#!/bin/sh
# Wrapper script for dnssec-validator daemon
# Sources environment file before exec'ing the binary
# Required because FreeBSD's daemon command strips environment variables

# Default env file location - override via DNSSEC_VALIDATOR_ENVFILE if needed
ENV_FILE="/usr/local/etc/tudordns/dnssec-validator.env"
if [ -n "${DNSSEC_VALIDATOR_ENVFILE}" ]; then
    ENV_FILE="${DNSSEC_VALIDATOR_ENVFILE}"
fi

if [ -f "${ENV_FILE}" ]; then
    set -a
    . "${ENV_FILE}"
    set +a
else
    echo "Warning: env file not found: ${ENV_FILE}" >&2
fi

exec /usr/local/sbin/dnssec-validator "$@"
