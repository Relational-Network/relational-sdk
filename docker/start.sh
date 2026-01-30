#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# Start script for SGX container with DCAP RA-TLS attestation
# This script:
# 1. Restarts AESM service for SGX attestation
# 2. Signs the enclave if not already signed
# 3. Launches the server via gramine-sgx (which invokes gramine-ratls)

set -e

/restart_aesm.sh

KEY_PATH="${GRAMINE_SGX_SIGNING_KEY:-/keys/enclave-key.pem}"

if [ ! -f /app/relational-sdk.manifest.sgx ]; then
    if [ ! -f "${KEY_PATH}" ]; then
        echo "Missing SGX signing key at ${KEY_PATH}." >&2
        echo "Mount your host key and set GRAMINE_SGX_SIGNING_KEY if needed." >&2
        exit 1
    fi

    echo "Signing enclave with key: ${KEY_PATH}"
    gramine-sgx-sign \
        --manifest /app/relational-sdk.manifest \
        --output /app/relational-sdk.manifest.sgx \
        --key "${KEY_PATH}"
    
    echo "Enclave measurements:"
    gramine-sgx-sigstruct-view /app/relational-sdk.sig | grep -E "mr_enclave|mr_signer|isv_prod_id|isv_svn"
fi

echo "Starting Relational SDK with DCAP RA-TLS attestation..."
echo "Server will be available at https://0.0.0.0:8080"

# gramine-sgx will execute the manifest which uses gramine-ratls as entrypoint
# gramine-ratls generates TLS cert/key with DCAP attestation evidence,
# then executes the actual Rust server binary
exec gramine-sgx relational-sdk
