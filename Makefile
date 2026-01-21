# SPDX-License-Identifier: BSD-3-Clause
# Copyright (C) 2023 Gramine contributors
# Copyright (C) 2026 Relational Network

ARCH_LIBDIR ?= /lib/$(shell $(CC) -dumpmachine)

SELF_EXE = target/release/relational-sdk

.PHONY: all
all: $(SELF_EXE) relational-sdk.manifest
ifeq ($(SGX),1)
all: relational-sdk.manifest.sgx relational-sdk.sig
endif

ifeq ($(DEBUG),1)
GRAMINE_LOG_LEVEL = debug
else
GRAMINE_LOG_LEVEL = error
endif

# Note that we're compiling in release mode regardless of the DEBUG setting passed
# to Make, as compiling in debug mode results in an order of magnitude's difference in
# performance.
# The primary goal of the DEBUG setting is to control Gramine's loglevel.
-include $(SELF_EXE).d # See also: .cargo/config.toml
$(SELF_EXE): Cargo.toml
	cargo build --release

relational-sdk.manifest: relational-sdk.manifest.template $(SELF_EXE)
	gramine-manifest \
		-Dlog_level=$(GRAMINE_LOG_LEVEL) \
		-Darch_libdir=$(ARCH_LIBDIR) \
		-Dself_exe=$(SELF_EXE) \
		$< $@

relational-sdk.manifest.sgx relational-sdk.sig &: relational-sdk.manifest
	gramine-sgx-sign \
		--manifest $< \
		--output $<.sgx

ifeq ($(SGX),)
GRAMINE = gramine-direct
else
GRAMINE = gramine-sgx
endif

.PHONY: start-relational-sdk
start-gramine-server: all
	$(GRAMINE) relational-sdk

.PHONY: clean
clean:
	$(RM) -rf *.sig *.manifest.sgx *.manifest result-* OUTPUT

.PHONY: distclean
distclean: clean
	$(RM) -rf target/ Cargo.lock