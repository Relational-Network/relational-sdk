# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2023 Gramine contributors
# Copyright (C) 2026 Relational Network

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)
ENTRYPOINT ?= $(firstword $(wildcard /usr/bin/gramine-ratls /usr/local/bin/gramine-ratls /bin/gramine-ratls))

SELF_EXE = target/release/relational-sdk

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
	gramine-manifest \
		-Dentrypoint=$(ENTRYPOINT) \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dself_exe=$(SELF_EXE) \
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

.PHONY: distclean
distclean: clean
	$(RM) -rf target/ Cargo.lock