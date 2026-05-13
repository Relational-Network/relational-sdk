// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Pool metadata persisted in the enclave's encrypted filesystem.
//!
//! Each DRT pool has a corresponding directory under `/data/pools/{pool_pda}/`
//! containing a `pool.meta.json` file that tracks the pool's lifecycle state,
//! credential counts, and ownership.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::data_validation::ValidationMode;

/// Pool lifecycle state.
///
/// Pools transition through these states:
/// - `NeedsInit` — Pool created on-chain, awaiting initial dataset seeding.
/// - `Ready` — Initial dataset seeded; pool accepts credential issuance via append DRTs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolState {
    /// On-chain pool created, dataset not yet seeded.
    NeedsInit,
    /// Initial dataset seeded, pool accepts issuance.
    Ready,
}

/// Enclave-side metadata for a DRT pool.
///
/// Stored at `/data/pools/{pool_pda}/pool.meta.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolMetadata {
    /// Pool PDA (base58-encoded Solana address).
    pub pool_pda: String,
    /// Human-readable pool name.
    pub pool_name: String,
    /// Wallet ID of the pool owner (enclave-side wallet, not Solana pubkey).
    pub owner_wallet_id: String,
    /// Solana public key of the pool owner (base58). Used for marketplace display.
    #[serde(default)]
    pub owner_pubkey: Option<String>,
    /// Schema used for CSV validation (e.g., `"pilot_v1"`).
    pub schema_id: String,
    /// How strictly CSV uploads are validated against the pool's schema.
    /// Defaults to `HeadersOnly` for forward-compat with pools written before
    /// this field existed.
    #[serde(default)]
    pub validation_mode: ValidationMode,
    /// Current lifecycle state.
    pub state: PoolState,
    /// When the pool was created on-chain.
    pub created_onchain_at: DateTime<Utc>,
    /// When the initial dataset was seeded (None if still `needs_init`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initialized_at: Option<DateTime<Utc>>,
    /// When the last credential issuance occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_issue_at: Option<DateTime<Utc>>,
    /// Total credential rows stored across all uploads.
    pub total_credentials: u64,
    /// Number of revoked credentials.
    pub revoked_count: u64,
}
