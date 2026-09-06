#!/bin/sh
# Wrapper script for sigillum-validator daemon
# Sources environment file before exec'ing the binary
# Required because FreeBSD's daemon command strips environment variables

# Default env file location - override via SIGILLUM_VALIDATOR_ENVFILE if needed
ENV_FILE="/usr/local/etc/sigillum-validator/sigillum-validator.env"
if [ -n "${SIGILLUM_VALIDATOR_ENVFILE}" ]; then
    ENV_FILE="${SIGILLUM_VALIDATOR_ENVFILE}"
fi

if [ -f "${ENV_FILE}" ]; then
    set -a
    . "${ENV_FILE}"
    set +a
else
    echo "Warning: env file not found: ${ENV_FILE}" >&2
fi

exec /usr/local/sbin/sigillum-validator "$@"
