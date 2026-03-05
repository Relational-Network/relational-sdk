// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! DRT types matching the on-chain IDL (`drt_contract.json`).
//!
//! Borsh serialization layout follows Anchor conventions: strings are
//! `len:u32 + utf8_bytes`, vecs are `len:u32 + items`, pubkeys are 32
//! raw bytes, bools are single bytes.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use solana_sdk::pubkey::Pubkey;
use std::collections::HashMap;
use utoipa::ToSchema;

// ============================================================================
// Constants
// ============================================================================

/// Deployed program ID on Solana (devnet and mainnet).
/// Canonical source: [`crate::config::DRT_PROGRAM_ID_STR`] / [`crate::config::drt_program_id()`].
#[allow(unused_imports)]
pub use crate::config::DRT_PROGRAM_ID_STR;

/// Token-2022 program.
pub const TOKEN_2022_PROGRAM_ID_STR: &str = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

/// Associated Token Program.
pub const ASSOCIATED_TOKEN_PROGRAM_ID_STR: &str = "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL";

/// System program.
pub const SYSTEM_PROGRAM_ID_STR: &str = "11111111111111111111111111111111";

/// The DRT type string for append-type DRTs.
pub const APPEND_DRT_TYPE: &str = "append";

// ── Instruction discriminators (auto-generated from IDL) ────────

pub use super::idl_generated::DISC_BUY_DRT;
pub use super::idl_generated::DISC_CLOSE_POOL;
pub use super::idl_generated::DISC_CREATE_POOL_ATOMIC;
pub use super::idl_generated::DISC_REDEEM_DRT;

// ── Account discriminators (auto-generated from IDL) ────────────

pub use super::idl_generated::DISC_POOL_ACCOUNT;

// ── Event discriminators (auto-generated from IDL) ──────────────

pub use super::idl_generated::DISC_APPEND_REDEEMED;
pub use super::idl_generated::DISC_DRT_INITIALIZED;
pub use super::idl_generated::DISC_DRT_PURCHASED;
pub use super::idl_generated::DISC_DRT_REDEEMED;
pub use super::idl_generated::DISC_POOL_CLOSED;
pub use super::idl_generated::DISC_POOL_CREATED;

// ── Validation limits ───────────────────────────────────────────────

pub const MAX_POOL_NAME_LEN: usize = 32;
pub const MAX_DRT_TYPE_LEN: usize = 32;
pub const MAX_GITHUB_URL_LEN: usize = 256;
pub const MAX_TOKEN_NAME_LEN: usize = 32;
pub const MAX_TOKEN_SYMBOL_LEN: usize = 10;
pub const MAX_TOKEN_URI_LEN: usize = 200;
pub const MAX_DRTS_PER_POOL: usize = 20;
pub const MAX_SUPPLY: u64 = 1_000_000_000;
pub const MAX_COST_LAMPORTS: u64 = 100_000_000_000; // 100 SOL
pub const MAX_TRANSFER_FEE_BPS: u16 = 10_000;

// ============================================================================
// On-chain Borsh types
// ============================================================================

/// DRT configuration as stored on-chain (Pool.drts[]).
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct DrtConfig {
    pub drt_type: String,
    pub mint: Pubkey,
    pub supply: u64,
    pub cost: u64,
    pub github_url: String,
    pub expected_hash: [u8; 32],
    pub fixed_supply: bool,
    pub token_name: String,
    pub token_symbol: String,
    pub token_uri: String,
    pub enable_transfer_hook: bool,
    pub transfer_fee_basis_points: u16,
    pub max_transfer_fee: u64,
    pub is_minted: bool,
}

/// DRT configuration for instruction input (create_pool_atomic / initialize_and_mint_drt).
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct DrtInitConfig {
    pub drt_type: String,
    pub supply: u64,
    pub cost: u64,
    pub github_url: String,
    pub expected_hash: [u8; 32],
    pub fixed_supply: bool,
    pub token_name: String,
    pub token_symbol: String,
    pub token_uri: String,
    pub enable_transfer_hook: bool,
    pub transfer_fee_basis_points: u16,
    pub max_transfer_fee: u64,
}

/// On-chain Pool account (8-byte discriminator prefix handled externally).
#[derive(Debug, Clone, BorshDeserialize)]
// All fields required for correct Borsh deserialization layout
pub struct Pool {
    #[allow(dead_code)]
    pub bump: u8,
    pub name: String,
    pub owner: Pubkey,
    pub drts: Vec<DrtConfig>,
}

// ============================================================================
// API request / response types
// ============================================================================

/// Single DRT config in a create-pool API request.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct DrtInitConfigRequest {
    pub drt_type: String,
    pub supply: u64,
    pub cost: u64,
    /// Script URL (empty for append-type DRTs).
    #[serde(default)]
    pub github_url: String,
    /// SHA-256 hex string (64 chars) of the script, or all-zero for append.
    #[serde(default)]
    pub expected_hash: String,
    #[serde(default)]
    pub fixed_supply: bool,
    pub token_name: String,
    pub token_symbol: String,
    pub token_uri: String,
    #[serde(default)]
    pub enable_transfer_hook: bool,
    #[serde(default)]
    pub transfer_fee_basis_points: u16,
    #[serde(default)]
    pub max_transfer_fee: u64,
}

/// Create-pool request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreatePoolRequest {
    /// Wallet UUID that owns the pool (must belong to caller).
    pub wallet_id: String,
    /// Pool name (≤32 bytes, trimmed, non-empty).
    pub pool_name: String,
    /// One or more DRT configurations (max 20).
    pub drt_configs: Vec<DrtInitConfigRequest>,
}

/// Create-pool response.
#[derive(Debug, Serialize, ToSchema)]
pub struct CreatePoolResponse {
    /// Transaction signature.
    pub signature: String,
    /// Pool PDA address (base58).
    pub pool_pda: String,
    /// Map of drt_type → mint PDA address (base58).
    pub mints: HashMap<String, String>,
    /// Solana Explorer URL.
    pub explorer_url: String,
}

/// Buy-DRT request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct BuyDrtRequest {
    /// Wallet UUID of the buyer (must belong to caller).
    pub wallet_id: String,
    /// DRT type to purchase.
    pub drt_type: String,
    /// Number of tokens to buy.
    pub amount: u64,
}

/// Buy-DRT response.
#[derive(Debug, Serialize, ToSchema)]
pub struct BuyDrtResponse {
    pub signature: String,
    pub explorer_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<DrtPurchasedEventResponse>,
}

/// Redeem-DRT request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RedeemDrtRequest {
    /// Wallet UUID of the redeemer (must belong to caller).
    pub wallet_id: String,
    /// DRT type to redeem.
    pub drt_type: String,
}

/// Redeem-DRT response.
#[derive(Debug, Serialize, ToSchema)]
pub struct RedeemDrtResponse {
    pub signature: String,
    pub explorer_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub event: Option<RedeemEventResponse>,
}

/// Close-pool request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct ClosePoolRequest {
    /// Wallet UUID of the pool owner (must belong to caller).
    pub wallet_id: String,
}

/// Close-pool response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ClosePoolResponse {
    pub signature: String,
    pub explorer_url: String,
}

/// DRT config in API responses (human-readable).
#[derive(Debug, Serialize, ToSchema)]
pub struct DrtConfigResponse {
    pub drt_type: String,
    pub mint: String,
    pub supply: u64,
    pub cost: u64,
    pub github_url: String,
    /// Hex-encoded expected hash.
    pub expected_hash: String,
    pub fixed_supply: bool,
    pub token_name: String,
    pub token_symbol: String,
    pub token_uri: String,
    pub enable_transfer_hook: bool,
    pub transfer_fee_basis_points: u16,
    pub max_transfer_fee: u64,
    pub is_minted: bool,
}

impl From<&DrtConfig> for DrtConfigResponse {
    fn from(c: &DrtConfig) -> Self {
        Self {
            drt_type: c.drt_type.clone(),
            mint: c.mint.to_string(),
            supply: c.supply,
            cost: c.cost,
            github_url: c.github_url.clone(),
            expected_hash: hex::encode(c.expected_hash),
            fixed_supply: c.fixed_supply,
            token_name: c.token_name.clone(),
            token_symbol: c.token_symbol.clone(),
            token_uri: c.token_uri.clone(),
            enable_transfer_hook: c.enable_transfer_hook,
            transfer_fee_basis_points: c.transfer_fee_basis_points,
            max_transfer_fee: c.max_transfer_fee,
            is_minted: c.is_minted,
        }
    }
}

/// Pool info response.
#[derive(Debug, Serialize, ToSchema)]
pub struct PoolInfoResponse {
    pub pool_pda: String,
    pub name: String,
    pub owner: String,
    pub drts: Vec<DrtConfigResponse>,
}

/// DRT balance response.
#[derive(Debug, Serialize, ToSchema)]
pub struct DrtBalanceResponse {
    pub drt_type: String,
    pub mint: String,
    pub user_balance: u64,
    pub vault_balance: u64,
}

/// Purchased event data in API response.
#[derive(Debug, Serialize, ToSchema)]
pub struct DrtPurchasedEventResponse {
    pub pool: String,
    pub drt_type: String,
    pub buyer: String,
    pub cost: u64,
    pub amount: u64,
    pub total_cost: u64,
    pub timestamp: i64,
}

/// Redeem event (union type for append vs non-append).
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "type")]
pub enum RedeemEventResponse {
    #[serde(rename = "drt_redeemed")]
    DrtRedeemed {
        pool: String,
        drt_type: String,
        redeemer: String,
        github_url: String,
        expected_hash: String,
        timestamp: i64,
    },
    #[serde(rename = "append_redeemed")]
    AppendRedeemed {
        pool: String,
        drt_type: String,
        redeemer: String,
        timestamp: i64,
    },
}

/// Wrapper for event list from a transaction.
#[derive(Debug, Serialize, ToSchema)]
pub struct TxEventsResponse {
    pub signature: String,
    pub events: Vec<DrtEventResponse>,
}

/// Single event in API format.
#[derive(Debug, Serialize, ToSchema)]
#[serde(tag = "type")]
pub enum DrtEventResponse {
    #[serde(rename = "pool_created")]
    PoolCreated {
        pool: String,
        owner: String,
        name: String,
        drt_types: Vec<String>,
    },
    #[serde(rename = "drt_initialized")]
    DrtInitialized {
        pool: String,
        owner: String,
        drt_type: String,
        mint: String,
        supply: u64,
        cost: u64,
        timestamp: i64,
    },
    #[serde(rename = "drt_purchased")]
    DrtPurchased {
        pool: String,
        drt_type: String,
        buyer: String,
        cost: u64,
        amount: u64,
        total_cost: u64,
        timestamp: i64,
    },
    #[serde(rename = "drt_redeemed")]
    DrtRedeemed {
        pool: String,
        drt_type: String,
        redeemer: String,
        github_url: String,
        expected_hash: String,
        timestamp: i64,
    },
    #[serde(rename = "append_redeemed")]
    AppendRedeemed {
        pool: String,
        drt_type: String,
        redeemer: String,
        timestamp: i64,
    },
    #[serde(rename = "pool_closed")]
    PoolClosed {
        pool: String,
        owner: String,
        timestamp: i64,
    },
}
