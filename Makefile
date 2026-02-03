# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2023 Gramine contributors
# Copyright (C) 2026 Relational Network

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)
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
	gramine-manifest \
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
		--output $<.sgx

GRAMINE = gramine-sgx

.PHONY: start-relational-sdk
start-gramine-server: all
	$(GRAMINE) relational-sdk

.PHONY: clean
clean:
	$(RM) -rf *.sig *.manifest.sgx *.manifest
	$(MAKE) -C attestation-client clean

##################### DOCKER BUILD AND RUN ###################################

.PHONY: docker-build
docker-build:
	cd docker && sudo ./build.sh ubuntu20

.PHONY: docker-run
docker-run:
	sudo docker run --rm -it \
		--name relational-sdk-sgx \
		--device /dev/sgx/enclave \
		--device /dev/sgx/provision \
		-p 8080:8080 \
		-v "$$HOME/.config/gramine/enclave-key.pem:/keys/enclave-key.pem:ro" \
		-e GRAMINE_SGX_SIGNING_KEY=/keys/enclave-key.pem \
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

.PHONY: distclean
distclean: clean
	$(RM) -rf target/ Cargo.lock