#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# Start script for SGX container with DCAP RA-TLS attestation
#
# The enclave is pre-signed at Docker build time (gramine-sgx-sign runs in the
# Dockerfile via --mount=type=secret). No signing key is needed at runtime.

set -e

/restart_aesm.sh

echo "Enclave measurements:"
gramine-sgx-sigstruct-view /app/relational-sdk.sig \
    | grep -E "mr_enclave|mr_signer|isv_prod_id|isv_svn"

echo "Starting Relational SDK with DCAP RA-TLS attestation..."
echo "Server will be available at https://0.0.0.0:8080"

exec gramine-sgx relational-sdk
