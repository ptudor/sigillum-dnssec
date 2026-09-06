#!/bin/sh
# Run on a Linux amd64 host with Docker. Containers receive no clock/device capabilities.
set -eu
project_dir=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
for distro in debian:13-slim fedora:43; do
    docker run --rm \
        -v "$project_dir/dist:/packages:ro" \
        -v "$project_dir/scripts:/checks:ro" \
        "$distro" sh /checks/package-container-test.sh
done
