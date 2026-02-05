# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Relational Network

# SGX Enclave Docker image with DCAP RA-TLS attestation support
# 
# Build: cd docker && ./build.sh ubuntu20
# Run:   See docker-run target in Makefile

ARG UBUNTU_IMAGE=ubuntu:20.04
ARG UBUNTU_CODENAME=focal

################################
# STAGE 1 - BUILDER
################################
# hadolint ignore=DL3006
FROM ${UBUNTU_IMAGE} AS builder
ARG UBUNTU_CODENAME

ENV DEBIAN_FRONTEND=noninteractive
ENV CC=clang
ENV CXX=clang++

# Build-time dependencies
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
# Set shell for pipefail support in pipes  
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor \
      > /usr/share/keyrings/microsoft-prod.gpg && \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] \
      https://packages.microsoft.com/ubuntu/20.04/prod focal main" \
      > /etc/apt/sources.list.d/microsoft-prod.list

# Gramine (build-time)
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    gramine \
    && rm -rf /var/lib/apt/lists/*

# Rust toolchain
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build

# Copy source and build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo fetch
# hadolint ignore=DL3059
RUN cargo build --release

################################
# STAGE 2 - RUNTIME
################################
# hadolint ignore=DL3006
FROM ${UBUNTU_IMAGE} AS runtime
ARG UBUNTU_CODENAME

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

# Runtime dependencies
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    gramine \
    gramine-ratls-dcap \
    sgx-aesm-service \
    libsgx-aesm-launch-plugin \
    libsgx-aesm-epid-plugin \
    libsgx-aesm-quote-ex-plugin \
    libsgx-aesm-ecdsa-plugin \
    libsgx-dcap-quote-verify \
    az-dcap-client \
    psmisc \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Runtime directories
RUN mkdir -p /var/run/aesmd/ /data

WORKDIR /app

# Copy built binary
COPY --from=builder /build/target/release/relational-sdk /app/relational-sdk

# Copy manifest template
COPY relational-sdk.manifest.template /app/relational-sdk.manifest.template

# SGX_DEBUG: Set to 1 for debug enclaves (NEVER use in production!)
# Default is 0 (secure production mode). Override at build time:
#   docker build --build-arg SGX_DEBUG=1 ...
ARG SGX_DEBUG=0

# data_dir must be explicit path, not env reference
ARG DATA_DIR=/app/data

# Generate Gramine manifest using same logic as Makefile (DOCKER=1 mode)
# This ensures consistency between Docker and native builds
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

# Copy startup scripts
COPY docker/restart_aesm.sh /restart_aesm.sh
COPY docker/start.sh /start.sh
RUN chmod +x /restart_aesm.sh /start.sh

ENV HOST=0.0.0.0
ENV PORT=8080
EXPOSE 8080

ENTRYPOINT ["/start.sh"]
