// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! On-chain account deserialization for DRT program accounts.

use borsh::BorshDeserialize;
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;

use super::types::{DrtConfig, Pool, DISC_POOL_ACCOUNT};
use crate::error::ApiError;

/// Fetch and deserialize a Pool account from chain.
///
/// Verifies the 8-byte Anchor discriminator before Borsh deserialization.
pub async fn fetch_pool(rpc: &RpcClient, pool_pda: &Pubkey) -> Result<Pool, ApiError> {
    let account = rpc
        .get_account(pool_pda)
        .await
        .map_err(|e| ApiError::not_found(format!("pool account {pool_pda} not found: {e}")))?;

    let data = &account.data;
    if data.len() < 8 {
        return Err(ApiError::internal("pool account data too short"));
    }

    let disc: [u8; 8] = data[..8].try_into().unwrap();
    if disc != DISC_POOL_ACCOUNT {
        return Err(ApiError::internal(
            "invalid pool account discriminator — not a DRT Pool",
        ));
    }

    Pool::try_from_slice(&data[8..])
        .map_err(|e| ApiError::internal(format!("failed to deserialize pool account: {e}")))
}

/// Find a DRT config by type within a deserialized pool.
pub fn find_drt_in_pool<'a>(pool: &'a Pool, drt_type: &str) -> Result<&'a DrtConfig, ApiError> {
    pool.drts
        .iter()
        .find(|d| d.drt_type == drt_type)
        .ok_or_else(|| ApiError::not_found(format!("DRT type '{drt_type}' not found in pool")))
}
