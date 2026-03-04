#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# Build deterministic SGX Docker image (signing key required)
#
# Usage:
#   ./build.sh ubuntu20 /path/to/enclave-key.pem
#
# The signing key is passed via BuildKit --secret and is NEVER stored in the image.
# The resulting image has a deterministic MRENCLAVE that can be verified by anyone.

set -euo pipefail

usage() {
    echo "Usage: build.sh <ubuntu20> <signing-key-path>"
    echo ""
    echo "Arguments:"
    echo "  ubuntu20            Base image (currently only ubuntu20 supported)"
    echo "  signing-key-path    Path to enclave signing key PEM (required)"
    exit 1
}

if [ $# -ne 2 ]; then
    usage
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "${SCRIPT_DIR}")"

codename=""
case "$1" in
    ubuntu20) codename="focal" ;;
    *) usage ;;
esac

SIGNING_KEY="$2"
if [ ! -f "${SIGNING_KEY}" ]; then
    echo "ERROR: Signing key not found at ${SIGNING_KEY}" >&2
    exit 1
fi

echo "Building with signing key: ${SIGNING_KEY}"
echo "Image will have deterministic MRENCLAVE."

DOCKER_BUILDKIT=1 docker build \
    --platform linux/amd64 \
    --build-arg UBUNTU_CODENAME="${codename}" \
    --secret id=signing_key,src="${SIGNING_KEY}" \
    -t relationalnetwork/relational-sdk:"${codename}" \
    -f "${SCRIPT_DIR}/Dockerfile" \
    "${PROJECT_DIR}"
