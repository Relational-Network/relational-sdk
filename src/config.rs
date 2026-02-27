// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Configuration constants for the relational-sdk enclave service.
//!
//! Non-sensitive values are hardcoded here. Only values that **must** differ
//! between environments use `env::var` with a default fallback.

use std::env;

// ============================================================================
// Auth (AVS JWT)
// ============================================================================

/// Default AVS JWKS URL for token verification.
/// Override with `AVS_JWKS_URL` environment variable.
pub const DEFAULT_AVS_JWKS_URL: &str = "http://127.0.0.1:9100/.well-known/jwks.json";

/// Get AVS JWKS URL from environment or use default.
pub fn avs_jwks_url() -> String {
    env::var("AVS_JWKS_URL").unwrap_or_else(|_| DEFAULT_AVS_JWKS_URL.to_string())
}

/// Expected audience claim in AVS-issued tokens.
pub const AVS_AUDIENCE: &str = "relational-sdk";

/// Expected issuer claim in AVS-issued tokens.
pub const AVS_ISSUER: &str = "attestation-verification-service";

/// JWKS cache TTL in seconds (5 minutes).
pub const JWKS_CACHE_TTL_SECS: u64 = 300;

// ============================================================================
// TLS (RA-TLS)
// ============================================================================

/// Fixed RA-TLS certificate location written by gramine-ratls (tmpfs).
pub const DEFAULT_TLS_CERT_PATH: &str = "/tmp/ra-tls.crt.pem";

/// Fixed RA-TLS key location written by gramine-ratls (tmpfs).
pub const DEFAULT_TLS_KEY_PATH: &str = "/tmp/ra-tls.key.pem";

// ============================================================================
// Server
// ============================================================================

/// Bind address for the HTTPS server.
pub const SERVER_HOST: [u8; 4] = [0, 0, 0, 0];

/// Port for the HTTPS server.
pub const SERVER_PORT: u16 = 8080;

/// Maximum request body size (20 MiB).
pub const MAX_BODY_SIZE: usize = 20 * 1024 * 1024;

// ============================================================================
// Storage
// ============================================================================

/// Default encrypted data directory (Gramine mounts /data as encrypted FS).
pub const DEFAULT_DATA_DIR: &str = "/data";

/// Environment variable for optional data directory override.
pub const DATA_DIR_ENV: &str = "DATA_DIR";

/// Get the data directory path from environment or use default.
pub fn data_dir() -> String {
    env::var(DATA_DIR_ENV).unwrap_or_else(|_| DEFAULT_DATA_DIR.to_string())
}

// ============================================================================
// Solana
// ============================================================================

/// Default Solana RPC URL — devnet for development, override for mainnet.
pub const DEFAULT_SOLANA_RPC_URL: &str = "https://api.devnet.solana.com";

/// Default Solana network name.
pub const DEFAULT_SOLANA_NETWORK: &str = "devnet";

/// Get Solana RPC URL from environment or use default.
pub fn solana_rpc_url() -> String {
    env::var("SOLANA_RPC_URL").unwrap_or_else(|_| DEFAULT_SOLANA_RPC_URL.to_string())
}

/// Get Solana network name from environment or use default.
pub fn solana_network() -> String {
    env::var("SOLANA_NETWORK").unwrap_or_else(|_| DEFAULT_SOLANA_NETWORK.to_string())
}

// ============================================================================
// CORS
// ============================================================================

/// Default CORS allowed origins (local dev).
#[allow(dead_code)]
pub const DEFAULT_CORS_ORIGINS: &str = "http://localhost:3000";

/// Get CORS allowed origins as a `Vec<String>`.
/// Set `CORS_ALLOWED_ORIGINS` env var to a comma-separated list for staging/prod.
#[allow(dead_code)]
pub fn cors_allowed_origins() -> Vec<String> {
    env::var("CORS_ALLOWED_ORIGINS")
        .unwrap_or_else(|_| DEFAULT_CORS_ORIGINS.to_string())
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

// ============================================================================
// Background Indexer
// ============================================================================

/// Whether the background tx indexer runs continuously.
///
/// Hardcoded to `false` — transaction updates are pulled on-demand by API
/// handlers.  Flip to `true` and rebuild to enable continuous polling.
pub const INDEXER_ENABLED: bool = false;

/// Tx indexer poll interval in seconds (when enabled).
pub const INDEXER_POLL_INTERVAL_SECS: u64 = 60;

/// LRU cache capacity (number of wallet first-pages cached).
pub const TX_CACHE_CAPACITY: usize = 128;

/// LRU cache entry TTL (seconds).
pub const TX_CACHE_TTL_SECS: u64 = 30;

// ============================================================================
// DRT Smart Contract
// ============================================================================

/// DRT program ID on Solana (devnet).
/// Hardcoded — this program is immutable and deployed at the same address
/// on all networks.
pub const DRT_PROGRAM_ID_STR: &str = "kG7AyfxRoNKcYWGH8aDR6tCFpLVcETt2kBVaPnQCrnp";

/// Get the DRT program `Pubkey`.
pub fn drt_program_id() -> solana_sdk::pubkey::Pubkey {
    use std::str::FromStr;
    solana_sdk::pubkey::Pubkey::from_str(DRT_PROGRAM_ID_STR)
        .expect("invalid DRT_PROGRAM_ID_STR — this is a compile-time bug")
}
