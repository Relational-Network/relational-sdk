// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Configuration constants for the relational-sdk enclave service.

/// Environment variable for optional data directory readiness check.
pub const DATA_DIR_ENV: &str = "DATA_DIR";

/// AVS JWKS URL for token verification.
/// The enclave fetches signing keys from this endpoint to validate JWTs.
pub const AVS_JWKS_URL: &str = "http://127.0.0.1:9100/.well-known/jwks.json";

/// Expected audience claim in AVS-issued tokens.
/// Tokens must have this value in the `aud` claim to be accepted.
pub const AVS_AUDIENCE: &str = "relational-sdk";

/// Fixed RA-TLS certificate location written by gramine-ratls (tmpfs).
pub const DEFAULT_TLS_CERT_PATH: &str = "/tmp/ra-tls.crt.pem";

/// Fixed RA-TLS key location written by gramine-ratls (tmpfs).
pub const DEFAULT_TLS_KEY_PATH: &str = "/tmp/ra-tls.key.pem";

/// JWKS cache TTL in seconds (5 minutes).
pub const JWKS_CACHE_TTL_SECS: u64 = 300;
