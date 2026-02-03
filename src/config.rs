// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Configuration constants for the relational-sdk enclave service.

use std::env;

/// Environment variable for optional data directory readiness check.
pub const DATA_DIR_ENV: &str = "DATA_DIR";

/// Default AVS JWKS URL for token verification.
/// Override with AVS_JWKS_URL environment variable.
pub const DEFAULT_AVS_JWKS_URL: &str = "http://127.0.0.1:9100/.well-known/jwks.json";

/// Get AVS JWKS URL from environment or use default.
pub fn avs_jwks_url() -> String {
    env::var("AVS_JWKS_URL").unwrap_or_else(|_| DEFAULT_AVS_JWKS_URL.to_string())
}

/// Expected audience claim in AVS-issued tokens.
/// Tokens must have this value in the `aud` claim to be accepted.
pub const AVS_AUDIENCE: &str = "relational-sdk";

/// Expected issuer claim in AVS-issued tokens.
/// Tokens must have this value in the `iss` claim to be accepted.
pub const AVS_ISSUER: &str = "attestation-verification-service";

/// Fixed RA-TLS certificate location written by gramine-ratls (tmpfs).
pub const DEFAULT_TLS_CERT_PATH: &str = "/tmp/ra-tls.crt.pem";

/// Fixed RA-TLS key location written by gramine-ratls (tmpfs).
pub const DEFAULT_TLS_KEY_PATH: &str = "/tmp/ra-tls.key.pem";

/// JWKS cache TTL in seconds (5 minutes).
pub const JWKS_CACHE_TTL_SECS: u64 = 300;
