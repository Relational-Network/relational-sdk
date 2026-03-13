// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! On-chain account deserialization for DRT program accounts.

use borsh::BorshDeserialize;
use solana_pubkey::Pubkey;

use crate::blockchain::rpc::JsonRpcClient;
use super::types::{DrtConfig, Pool, DISC_POOL_ACCOUNT};
use crate::error::ApiError;

/// Maximum expected size of a Pool account (after discriminator).
///
/// Solana accounts can be up to 10 MiB, but a realistic Pool with several DRT
/// configs is far smaller. We cap deserialization to 10 KiB to prevent
/// Borsh from allocating unbounded memory when given untrusted RPC data.
const MAX_POOL_DATA_SIZE: usize = 10 * 1024;

/// Fetch and deserialize a Pool account from chain.
///
/// Verifies the 8-byte Anchor discriminator before Borsh deserialization.
pub async fn fetch_pool(rpc: &JsonRpcClient, pool_pda: &Pubkey) -> Result<Pool, ApiError> {
    let data = rpc
        .get_account_data(pool_pda)
        .await
        .map_err(|e| ApiError::not_found(format!("pool account {pool_pda} not found: {e}")))?
        .ok_or_else(|| ApiError::not_found(format!("pool account {pool_pda} not found")))?;

    if data.len() < 8 {
        return Err(ApiError::internal("pool account data too short"));
    }

    let disc: [u8; 8] = data[..8].try_into().unwrap();
    if disc != DISC_POOL_ACCOUNT {
        return Err(ApiError::internal(
            "invalid pool account discriminator — not a DRT Pool",
        ));
    }

    let payload = &data[8..];
    if payload.len() > MAX_POOL_DATA_SIZE {
        return Err(ApiError::internal(format!(
            "pool account data too large ({} bytes, max {MAX_POOL_DATA_SIZE})",
            payload.len()
        )));
    }

    Pool::try_from_slice(payload)
        .map_err(|e| ApiError::internal(format!("failed to deserialize pool account: {e}")))
}

/// Find a DRT config by type within a deserialized pool.
pub fn find_drt_in_pool<'a>(pool: &'a Pool, drt_type: &str) -> Result<&'a DrtConfig, ApiError> {
    pool.drts
        .iter()
        .find(|d| d.drt_type == drt_type)
        .ok_or_else(|| ApiError::not_found(format!("DRT type '{drt_type}' not found in pool")))
}
