# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2023 Gramine contributors
# Copyright (C) 2026 Relational Network

# Use fixed x86_64-linux-gnu path (clang reports x86_64-pc-linux-gnu which doesn't exist)
ARCH_LIBDIR ?= /lib/x86_64-linux-gnu
ENTRYPOINT ?= $(firstword $(wildcard /usr/bin/gramine-ratls /usr/local/bin/gramine-ratls /bin/gramine-ratls))

# Docker mode: set DOCKER=1 to use /app paths instead of local paths
DOCKER ?= 0
ifeq ($(DOCKER),1)
    APP_DIR ?= /app
    SELF_EXE ?= /app/relational-sdk
    DATA_DIR ?= /app/data
else
    APP_DIR ?= $(shell pwd)
    SELF_EXE ?= target/release/relational-sdk
    DATA_DIR ?= $(shell pwd)/data
endif

RA_TYPE ?= dcap
ISVPRODID ?= 0
ISVSVN ?= 0

# Path to AVS secrets directory (for TLS cert used as CA in secret provisioning).
# Used by setup-dev-certs and docker-run targets.
SECRETS_DIR ?= ../attestation-verification-service/secrets

# SGX_DEBUG: Set to 1 for debug enclaves (NEVER use in production!)
# - 0 (default): Production mode - secure, no debugging
# - 1: Debug mode - allows debugging but exposes enclave memory
SGX_DEBUG ?= 0

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

.PHONY: all
all: relational-sdk.manifest.sgx relational-sdk.sig

# Note that we're compiling in release mode regardless of the DEBUG setting passed
# to Make, as compiling in debug mode results in an order of magnitude's difference in
# performance.
# The primary goal of the DEBUG setting is to control Gramine's loglevel.
-include $(SELF_EXE).d # See also: .cargo/config.toml
$(SELF_EXE): Cargo.toml
	cargo build --release

relational-sdk.manifest: relational-sdk.manifest.template $(SELF_EXE)
	@if [ -z "$(ENTRYPOINT)" ]; then \
		echo "error: gramine-ratls not found; set ENTRYPOINT=/path/to/gramine-ratls"; \
		exit 1; \
	fi
	@mkdir -p $(DATA_DIR)
	SGX_DEBUG=$(SGX_DEBUG) gramine-manifest \
		-Dentrypoint=$(ENTRYPOINT) \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dapp_dir=$(APP_DIR) \
		-Dself_exe=$(SELF_EXE) \
		-Ddata_dir=$(DATA_DIR) \
		-Dra_type=$(RA_TYPE) \
		-Disvprodid=$(ISVPRODID) \
		-Disvsvn=$(ISVSVN) \
		$< $@

relational-sdk.manifest.sgx relational-sdk.sig &: relational-sdk.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx \
		--date 0000-00-00

GRAMINE = gramine-sgx

.PHONY: start-relational-sdk
start-gramine-server: all
	$(GRAMINE) relational-sdk

.PHONY: clean
clean:
	$(RM) -rf *.sig *.manifest.sgx *.manifest
	$(MAKE) -C attestation-client clean

##################### DOCKER BUILD AND RUN ###################################

# Signing key path (required for Docker builds)
SIGNING_KEY ?= $(HOME)/.config/gramine/enclave-key.pem

# Build a signed Docker image with deterministic MRENCLAVE.
# Usage: make docker-build
# Usage: make docker-build SIGNING_KEY=/path/to/enclave-key.pem
.PHONY: docker-build
docker-build:
	cd docker && sudo ./build.sh ubuntu20 $(SIGNING_KEY)

.PHONY: docker-run
docker-run:
	@mkdir -p $(abspath data)
	sudo docker run --rm -it \
		--name relational-sdk-sgx \
		--network host \
		--device /dev/sgx/enclave \
		--device /dev/sgx/provision \
		-v "$(abspath data):/app/data" \
		-v "$(abspath $(SECRETS_DIR)/avs-tls.crt):/etc/ssl/certs/avs-ca.crt:ro" \
		-e SECRET_PROVISION_SERVERS=127.0.0.1:4433 \
		relationalnetwork/relational-sdk:focal

.PHONY: docker-stop
docker-stop:
	sudo docker stop relational-sdk-sgx

##################### REMOTE ATTESTATION CLIENT ##############################

# Build attestation client
.PHONY: attest
attest:
	$(MAKE) -C attestation-client

# Test attestation against running enclave
.PHONY: test-attest
test-attest:
	$(MAKE) -C attestation-client test

# Run all attestation tests (including negative tests)
.PHONY: test-attest-all
test-attest-all:
	$(MAKE) -C attestation-client test-all

# Show current enclave measurements
.PHONY: show-measurements
show-measurements: relational-sdk.sig
	@gramine-sgx-sigstruct-view relational-sdk.sig | grep -E "mr_enclave|mr_signer|isv_prod_id|isv_svn"

# Verify MRENCLAVE reproducibility
# Default: build locally (no cache) and compare mr_enclave against measurements.txt
# With DOCKER_IMAGE=...: also compare against a remote image's mr_enclave
#
# Usage: make verify-mrenclave
# Usage: make verify-mrenclave DOCKER_IMAGE=ghcr.io/relational-network/relational-sdk:sha-abc123
.PHONY: verify-mrenclave
verify-mrenclave:
	@if [ ! -f "$(SIGNING_KEY)" ]; then \
		echo "ERROR: Signing key not found at $(SIGNING_KEY)"; \
		echo "Set SIGNING_KEY=/path/to/enclave-key.pem"; \
		exit 1; \
	fi
	@echo "=== Building locally (no cache) ===" && \
	DOCKER_BUILDKIT=1 docker build \
		--platform linux/amd64 \
		--no-cache \
		-f docker/Dockerfile \
		--secret id=signing_key,src=$(SIGNING_KEY) \
		--build-arg SGX_DEBUG=0 \
		--progress=plain \
		-t relationalnetwork/relational-sdk:verify-local \
		. 2>&1 | grep -E "Build-time measurements|mr_enclave|mr_signer" || true
	@LOCAL_MR=$$(docker run --rm \
		--entrypoint gramine-sgx-sigstruct-view \
		relationalnetwork/relational-sdk:verify-local \
		/app/relational-sdk.sig 2>/dev/null | grep 'mr_enclave:' | awk '{print $$2}' | head -1); \
	EXPECTED_MR=$$(grep '^mr_enclave:' measurements.txt | awk '{print $$2}' | head -1); \
	echo ""; \
	echo "Built:    $$LOCAL_MR"; \
	echo "Expected: $$EXPECTED_MR  (measurements.txt)"; \
	echo ""; \
	if [ "$$LOCAL_MR" = "$$EXPECTED_MR" ]; then \
		echo "MATCH - MRENCLAVE matches measurements.txt"; \
	else \
		echo "MISMATCH - MRENCLAVE differs from measurements.txt!"; \
		echo "If intentional, update measurements.txt with the new hash."; \
		exit 1; \
	fi; \
	if [ -n "$(DOCKER_IMAGE)" ]; then \
		echo ""; \
		echo "=== Comparing against $(DOCKER_IMAGE) ==="; \
		REMOTE_MR=$$(docker run --rm --entrypoint gramine-sgx-sigstruct-view \
			$(DOCKER_IMAGE) /app/relational-sdk.sig 2>/dev/null \
			| grep 'mr_enclave:' | awk '{print $$2}' | head -1); \
		echo "Remote:   $$REMOTE_MR"; \
		if [ "$$LOCAL_MR" = "$$REMOTE_MR" ]; then \
			echo "MATCH - MRENCLAVE matches Docker image"; \
		else \
			echo "MISMATCH - MRENCLAVE differs from Docker image!"; \
			exit 1; \
		fi; \
	fi

.PHONY: distclean
distclean: clean
	$(RM) -rf target/ Cargo.lock

##################### SECRET PROVISIONING ####################################

# Copy the AVS TLS cert to the system CA store so the enclave can verify the
# secret provisioning TLS connection on port 4433. Run once after first-time
# setup or when avs-tls.crt is regenerated.
# Requires: ../attestation-verification-service/secrets/avs-tls.crt
.PHONY: setup-dev-certs
setup-dev-certs:
	@if [ ! -f "$(SECRETS_DIR)/avs-tls.crt" ]; then \
		echo "ERROR: $(SECRETS_DIR)/avs-tls.crt not found."; \
		echo "Run: cd ../attestation-verification-service && ./secrets/generate-keys.sh"; \
		exit 1; \
	fi
	sudo cp "$(SECRETS_DIR)/avs-tls.crt" /etc/ssl/certs/avs-ca.crt
	sudo update-ca-certificates --fresh
	@echo "Installed AVS CA cert at /etc/ssl/certs/avs-ca.crt"