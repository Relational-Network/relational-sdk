# syntax=docker/dockerfile:1
# check=skip=FromPlatformFlagConstDisallowed

# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# SGX Enclave Docker image with DCAP RA-TLS attestation support
#
# DETERMINISTIC BUILDS: every version here is pinned so that the same commit
# produces an identical binary and identical MRENCLAVE on any machine.
#
# ── Pinned versions ────────────────────────────────────────────────────────────
# Ubuntu 20.04 amd64 digest (refresh with):
#   docker manifest inspect ubuntu:20.04 \
#     | python3 -c "import sys,json; m=json.load(sys.stdin); \
#         print(next(d['digest'] for d in m['manifests'] \
#               if d['platform']['architecture']=='amd64' and d['platform']['os']=='linux'))"
#
# Gramine / Intel SGX package versions (refresh with):
#   docker run --rm --platform linux/amd64 \
#     ubuntu:20.04@sha256:c664f8f86ed5a386b0a340d981b8f81714e21a8b9c73f658c4bea56aa179d54a \
#     bash -c "apt-get update -qq && \
#       curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg \
#         https://packages.gramineproject.io/gramine-keyring.gpg && \
#       echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] \
#         https://packages.gramineproject.io/ focal main' \
#         > /etc/apt/sources.list.d/gramine.list && \
#       curl -fsSLo /usr/share/keyrings/intel-sgx-deb.key \
#         https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key && \
#       echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.key] \
#         https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' \
#         > /etc/apt/sources.list.d/intel-sgx.list && \
#       curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor \
#         > /usr/share/keyrings/microsoft-prod.gpg && \
#       echo 'deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] \
#         https://packages.microsoft.com/ubuntu/20.04/prod focal main' \
#         > /etc/apt/sources.list.d/microsoft-prod.list && \
#       apt-get update -qq && \
#       apt-cache show gramine gramine-ratls-dcap sgx-aesm-service \
#         libsgx-aesm-launch-plugin libsgx-aesm-epid-plugin \
#         libsgx-aesm-quote-ex-plugin libsgx-aesm-ecdsa-plugin \
#         libsgx-dcap-quote-verify az-dcap-client \
#         | grep -E '^Package:|^Version:'"
# ───────────────────────────────────────────────────────────────────────────────

# Global ARGs — available in all stages (must be re-declared inside each stage).
# Rust version must match rust-toolchain.toml channel exactly.
ARG RUST_VERSION=1.92.0
ARG UBUNTU_CODENAME=focal

# ── Gramine / SGX package version pins ──────────────────────────────────────
# FILL IN these versions by running the discovery command above, then commit.
ARG GRAMINE_VERSION=1.8
ARG GRAMINE_RATLS_VERSION=1.8
ARG SGX_AESM_VERSION=2.25.100.3-focal1
ARG LIBSGX_AESM_LAUNCH_VERSION=2.25.100.3-focal1
ARG LIBSGX_AESM_EPID_VERSION=2.25.100.3-focal1
ARG LIBSGX_AESM_QUOTE_EX_VERSION=2.25.100.3-focal1
ARG LIBSGX_AESM_ECDSA_VERSION=2.25.100.3-focal1
ARG LIBSGX_DCAP_QUOTE_VERIFY_VERSION=1.22.100.3-focal1
ARG AZ_DCAP_VERSION=1.12.3

################################
# STAGE 1 - BUILDER
################################
# hadolint ignore=DL3006,DL3029
FROM --platform=linux/amd64 ubuntu:20.04@sha256:c664f8f86ed5a386b0a340d981b8f81714e21a8b9c73f658c4bea56aa179d54a AS builder
ARG UBUNTU_CODENAME
ARG RUST_VERSION
ARG GRAMINE_VERSION

ENV DEBIAN_FRONTEND=noninteractive
ENV CC=clang
ENV CXX=clang++

# Build-time tools (exact versions not critical for MRENCLAVE; these are not trusted files)
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gnupg2 \
    binutils \
    git \
    make \
    cmake \
    clang \
    llvm \
    pkg-config \
    ca-certificates \
    libffi-dev \
    libssl-dev \
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# Gramine repo
RUN curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg \
      https://packages.gramineproject.io/gramine-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] \
      https://packages.gramineproject.io/ ${UBUNTU_CODENAME} main" \
      > /etc/apt/sources.list.d/gramine.list

# Intel SGX repo
RUN curl -fsSLo /usr/share/keyrings/intel-sgx-deb.key \
      https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.key] \
      https://download.01.org/intel-sgx/sgx_repo/ubuntu ${UBUNTU_CODENAME} main" \
      > /etc/apt/sources.list.d/intel-sgx.list

# Microsoft repo (Azure DCAP)
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor \
      > /usr/share/keyrings/microsoft-prod.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] \
      https://packages.microsoft.com/ubuntu/20.04/prod focal main" \
      > /etc/apt/sources.list.d/microsoft-prod.list

# Gramine (build-time) — pinned version so gramine-manifest and gramine-sgx-sign
# produce manifests referencing the exact same runtime dir as the runtime stage.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    gramine=${GRAMINE_VERSION} \
    && rm -rf /var/lib/apt/lists/*

# Rust toolchain — pinned via rustup using rust-toolchain.toml
# Downloads rustup-init, installs it with no default toolchain, then lets
# rustup read rust-toolchain.toml to install the exact pinned version.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      -o /tmp/rustup-init && \
    chmod +x /tmp/rustup-init && \
    /tmp/rustup-init -y --profile minimal --default-toolchain none && \
    rm /tmp/rustup-init
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build

# Copy manifests and toolchain file first (separate layer — only invalidated by dep changes)
COPY rust-toolchain.toml Cargo.toml Cargo.lock ./

# Trigger rustup to download and install the exact toolchain pinned in rust-toolchain.toml.
# This prints the resolved version to build logs for auditing.
RUN rustup show active-toolchain

# Copy source and build
# Cache mounts persist across builds — deps only re-downloaded when Cargo.lock changes.
COPY src ./src
# hadolint ignore=DL3059
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,target=/build/target \
    SOURCE_DATE_EPOCH=0 \
    CARGO_INCREMENTAL=0 \
    cargo build --release --locked && \
    cp target/release/relational-sdk /build/relational-sdk-bin

################################
# STAGE 2 - RUNTIME
################################
# hadolint ignore=DL3006,DL3029
FROM --platform=linux/amd64 ubuntu:20.04@sha256:c664f8f86ed5a386b0a340d981b8f81714e21a8b9c73f658c4bea56aa179d54a AS runtime
ARG UBUNTU_CODENAME
ARG GRAMINE_VERSION
ARG GRAMINE_RATLS_VERSION
ARG SGX_AESM_VERSION
ARG LIBSGX_AESM_LAUNCH_VERSION
ARG LIBSGX_AESM_EPID_VERSION
ARG LIBSGX_AESM_QUOTE_EX_VERSION
ARG LIBSGX_AESM_ECDSA_VERSION
ARG LIBSGX_DCAP_QUOTE_VERIFY_VERSION
ARG AZ_DCAP_VERSION

ENV DEBIAN_FRONTEND=noninteractive

# Minimal bootstrap tools
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    gnupg2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Gramine repo
RUN curl -fsSLo /usr/share/keyrings/gramine-keyring.gpg \
      https://packages.gramineproject.io/gramine-keyring.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/gramine-keyring.gpg] \
      https://packages.gramineproject.io/ ${UBUNTU_CODENAME} main" \
      > /etc/apt/sources.list.d/gramine.list

# Intel SGX repo
RUN curl -fsSLo /usr/share/keyrings/intel-sgx-deb.key \
      https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/intel-sgx-deb.key] \
      https://download.01.org/intel-sgx/sgx_repo/ubuntu ${UBUNTU_CODENAME} main" \
      > /etc/apt/sources.list.d/intel-sgx.list

# Microsoft repo (Azure DCAP)
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor \
      > /usr/share/keyrings/microsoft-prod.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] \
      https://packages.microsoft.com/ubuntu/20.04/prod focal main" \
      > /etc/apt/sources.list.d/microsoft-prod.list

# Runtime dependencies — ALL PINNED to specific versions.
# These packages populate sgx.trusted_files and directly determine MRENCLAVE.
# Changing any version here changes MRENCLAVE.
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    gramine=${GRAMINE_VERSION} \
    gramine-ratls-dcap=${GRAMINE_RATLS_VERSION} \
    sgx-aesm-service=${SGX_AESM_VERSION} \
    libsgx-aesm-launch-plugin=${LIBSGX_AESM_LAUNCH_VERSION} \
    libsgx-aesm-epid-plugin=${LIBSGX_AESM_EPID_VERSION} \
    libsgx-aesm-quote-ex-plugin=${LIBSGX_AESM_QUOTE_EX_VERSION} \
    libsgx-aesm-ecdsa-plugin=${LIBSGX_AESM_ECDSA_VERSION} \
    libsgx-dcap-quote-verify=${LIBSGX_DCAP_QUOTE_VERIFY_VERSION} \
    az-dcap-client=${AZ_DCAP_VERSION} \
    psmisc \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Runtime directories
RUN mkdir -p /var/run/aesmd/ /data

WORKDIR /app

# Copy compiled binary (from builder's explicit copy, not from the cache mount)
COPY --from=builder /build/relational-sdk-bin /app/relational-sdk

# Copy manifest template
COPY relational-sdk.manifest.template /app/relational-sdk.manifest.template

# SGX_DEBUG: Set to 1 for debug enclaves (NEVER use in production!)
# Default is 0 (secure production mode). Override at build time:
#   docker build --build-arg SGX_DEBUG=1 ...
ARG SGX_DEBUG=0

# data_dir must be explicit path, not env reference
ARG DATA_DIR=/app/data

# Generate Gramine manifest
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
# hadolint ignore=SC2086,DL3059
RUN ENTRYPOINT=$(which gramine-ratls) && \
    SGX_DEBUG=${SGX_DEBUG} gramine-manifest \
    -Dentrypoint=${ENTRYPOINT} \
    -Dlog_level=error \
    -Darch_libdir=/lib/x86_64-linux-gnu \
    -Dapp_dir=/app \
    -Dself_exe=/app/relational-sdk \
    -Ddata_dir=${DATA_DIR} \
    -Dra_type=dcap \
    -Disvprodid=0 \
    -Disvsvn=0 \
    /app/relational-sdk.manifest.template /app/relational-sdk.manifest

# Sign at build time — key injected via BuildKit secret, never in any layer.
# gramine-sgx-sign is pure computation (no SGX hardware needed).
# --date 0000-00-00 makes the SIGSTRUCT date-independent.
RUN --mount=type=secret,id=signing_key,target=/keys/enclave-key.pem,required=true \
    gramine-sgx-sign \
        --manifest /app/relational-sdk.manifest \
        --output /app/relational-sdk.manifest.sgx \
        --key /keys/enclave-key.pem \
        --date 0000-00-00 && \
    echo "Build-time measurements:" && \
    gramine-sgx-sigstruct-view /app/relational-sdk.sig \
        | grep -E "mr_enclave|mr_signer|isv_prod_id|isv_svn"

# Copy startup scripts
COPY docker/restart_aesm.sh /restart_aesm.sh
COPY docker/start.sh /start.sh
RUN chmod +x /restart_aesm.sh /start.sh

ENV HOST=0.0.0.0
ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/start.sh"]
