// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Thin wrapper around [`RpcClient`] for common Solana queries.

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use tracing::debug;

use super::types::{NetworkConfig, TokenBalance};
use crate::error::ApiError;

/// Async Solana RPC client wrapper.
pub struct SolanaClient {
    pub(crate) rpc: RpcClient,
    pub(crate) network: NetworkConfig,
}

impl SolanaClient {
    /// Create a new client for the given RPC URL and network.
    pub fn new(rpc_url: &str, network: NetworkConfig) -> Self {
        Self {
            rpc: RpcClient::new(rpc_url.to_string()),
            network,
        }
    }

    /// Get the network configuration.
    pub fn network(&self) -> &NetworkConfig {
        &self.network
    }

    /// Reference to the inner RPC client.
    pub fn rpc(&self) -> &RpcClient {
        &self.rpc
    }

    /// Get native SOL balance for an address.
    pub async fn get_native_balance(&self, address: &str) -> Result<TokenBalance, ApiError> {
        let pubkey = Pubkey::from_str(address)
            .map_err(|_| ApiError::bad_request(format!("invalid Solana address: {address}")))?;
        let lamports = self
            .rpc
            .get_balance(&pubkey)
            .await
            .map_err(|e| ApiError::service_unavailable(format!("Solana RPC error: {e}")))?;
        debug!(address, lamports, "Fetched SOL balance");

        let sol = lamports as f64 / 1_000_000_000.0;
        Ok(TokenBalance {
            token: "SOL".to_string(),
            mint: String::new(),
            raw_amount: lamports.to_string(),
            ui_amount: format!("{sol:.9}"),
            decimals: 9,
        })
    }
}
