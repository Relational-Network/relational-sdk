// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Anchor event parsing from Solana transaction logs.
//!
//! Anchor emits events as base64-encoded Borsh data prefixed with an 8-byte
//! discriminator. Events appear in transaction logs as:
//!
//! ```text
//! Program data: <base64-encoded-data>
//! ```
//!
//! We scan log lines for this prefix, decode, match discriminators, and
//! deserialize.

use base64::Engine;
use borsh::BorshDeserialize;
use solana_sdk::pubkey::Pubkey;

use super::types::*;

// ============================================================================
// Raw event structs (Borsh-deserializable from on-chain log data)
// ============================================================================

#[derive(Debug, Clone, BorshDeserialize)]
pub struct PoolCreatedEvent {
    pub pool: Pubkey,
    pub owner: Pubkey,
    pub name: String,
    pub drt_types: Vec<String>,
}

#[derive(Debug, Clone, BorshDeserialize)]
#[allow(dead_code)] // All fields required for correct Borsh deserialization layout
pub struct DrtInitializedEvent {
    pub pool: Pubkey,
    pub owner: Pubkey,
    pub drt_type: String,
    pub mint: Pubkey,
    pub supply: u64,
    pub cost: u64,
    pub fixed_supply: bool,
    pub enable_transfer_hook: bool,
    pub transfer_fee_basis_points: u16,
    pub max_transfer_fee: u64,
    pub timestamp: i64,
}

#[derive(Debug, Clone, BorshDeserialize)]
pub struct DrtPurchasedEvent {
    pub pool: Pubkey,
    pub drt_type: String,
    pub buyer: Pubkey,
    pub cost: u64,
    pub amount: u64,
    pub total_cost: u64,
    pub timestamp: i64,
}

#[derive(Debug, Clone, BorshDeserialize)]
pub struct DrtRedeemedEvent {
    pub pool: Pubkey,
    pub drt_type: String,
    pub redeemer: Pubkey,
    pub github_url: String,
    pub expected_hash: [u8; 32],
    pub timestamp: i64,
}

#[derive(Debug, Clone, BorshDeserialize)]
pub struct AppendRedeemedEvent {
    pub pool: Pubkey,
    pub drt_type: String,
    pub redeemer: Pubkey,
    pub timestamp: i64,
}

#[derive(Debug, Clone, BorshDeserialize)]
pub struct PoolClosedEvent {
    pub pool: Pubkey,
    pub owner: Pubkey,
    pub timestamp: i64,
}

// ============================================================================
// Unified event enum
// ============================================================================

#[derive(Debug, Clone)]
pub enum DrtEvent {
    PoolCreated(PoolCreatedEvent),
    DrtInitialized(DrtInitializedEvent),
    DrtPurchased(DrtPurchasedEvent),
    DrtRedeemed(DrtRedeemedEvent),
    AppendRedeemed(AppendRedeemedEvent),
    PoolClosed(PoolClosedEvent),
}

impl DrtEvent {
    /// Convert to API-friendly response type.
    pub fn to_response(&self) -> DrtEventResponse {
        match self {
            DrtEvent::PoolCreated(e) => DrtEventResponse::PoolCreated {
                pool: e.pool.to_string(),
                owner: e.owner.to_string(),
                name: e.name.clone(),
                drt_types: e.drt_types.clone(),
            },
            DrtEvent::DrtInitialized(e) => DrtEventResponse::DrtInitialized {
                pool: e.pool.to_string(),
                owner: e.owner.to_string(),
                drt_type: e.drt_type.clone(),
                mint: e.mint.to_string(),
                supply: e.supply,
                cost: e.cost,
                timestamp: e.timestamp,
            },
            DrtEvent::DrtPurchased(e) => DrtEventResponse::DrtPurchased {
                pool: e.pool.to_string(),
                drt_type: e.drt_type.clone(),
                buyer: e.buyer.to_string(),
                cost: e.cost,
                amount: e.amount,
                total_cost: e.total_cost,
                timestamp: e.timestamp,
            },
            DrtEvent::DrtRedeemed(e) => DrtEventResponse::DrtRedeemed {
                pool: e.pool.to_string(),
                drt_type: e.drt_type.clone(),
                redeemer: e.redeemer.to_string(),
                github_url: e.github_url.clone(),
                expected_hash: hex::encode(e.expected_hash),
                timestamp: e.timestamp,
            },
            DrtEvent::AppendRedeemed(e) => DrtEventResponse::AppendRedeemed {
                pool: e.pool.to_string(),
                drt_type: e.drt_type.clone(),
                redeemer: e.redeemer.to_string(),
                timestamp: e.timestamp,
            },
            DrtEvent::PoolClosed(e) => DrtEventResponse::PoolClosed {
                pool: e.pool.to_string(),
                owner: e.owner.to_string(),
                timestamp: e.timestamp,
            },
        }
    }
}

// ============================================================================
// Parsing
// ============================================================================

const PROGRAM_DATA_PREFIX: &str = "Program data: ";

/// Parse DRT events from transaction log lines.
///
/// Scans for `"Program data: "` lines, base64-decodes the payload, matches
/// the 8-byte Anchor discriminator, and Borsh-deserializes the rest.
pub fn parse_drt_events(logs: &[String]) -> Vec<DrtEvent> {
    let mut events = Vec::new();

    for line in logs {
        let data_b64 = match line.strip_prefix(PROGRAM_DATA_PREFIX) {
            Some(s) => s.trim(),
            None => continue,
        };

        let bytes = match base64::engine::general_purpose::STANDARD.decode(data_b64) {
            Ok(b) => b,
            Err(_) => continue,
        };

        if bytes.len() < 8 {
            continue;
        }

        let disc: [u8; 8] = bytes[..8].try_into().unwrap();
        let payload = &bytes[8..];

        let event = match disc {
            DISC_POOL_CREATED => {
                PoolCreatedEvent::try_from_slice(payload).ok().map(DrtEvent::PoolCreated)
            }
            DISC_DRT_INITIALIZED => {
                DrtInitializedEvent::try_from_slice(payload).ok().map(DrtEvent::DrtInitialized)
            }
            DISC_DRT_PURCHASED => {
                DrtPurchasedEvent::try_from_slice(payload).ok().map(DrtEvent::DrtPurchased)
            }
            DISC_DRT_REDEEMED => {
                DrtRedeemedEvent::try_from_slice(payload).ok().map(DrtEvent::DrtRedeemed)
            }
            DISC_APPEND_REDEEMED => {
                AppendRedeemedEvent::try_from_slice(payload).ok().map(DrtEvent::AppendRedeemed)
            }
            DISC_POOL_CLOSED => {
                PoolClosedEvent::try_from_slice(payload).ok().map(DrtEvent::PoolClosed)
            }
            _ => None,
        };

        if let Some(e) = event {
            events.push(e);
        }
    }

    events
}

/// Fetch and parse DRT events from a confirmed transaction signature.
pub async fn parse_events_from_signature(
    rpc: &solana_client::nonblocking::rpc_client::RpcClient,
    signature_str: &str,
) -> Result<Vec<DrtEvent>, crate::error::ApiError> {
    use solana_sdk::signature::Signature;
    use solana_transaction_status::UiTransactionEncoding;
    use std::str::FromStr;

    let signature = Signature::from_str(signature_str)
        .map_err(|_| crate::error::ApiError::bad_request("invalid transaction signature"))?;

    let config = solana_client::rpc_config::RpcTransactionConfig {
        encoding: Some(UiTransactionEncoding::Json),
        commitment: Some(solana_commitment_config::CommitmentConfig::confirmed()),
        max_supported_transaction_version: Some(0),
    };

    let tx = rpc
        .get_transaction_with_config(&signature, config)
        .await
        .map_err(|e| {
            crate::error::ApiError::service_unavailable(format!(
                "failed to fetch transaction: {e}"
            ))
        })?;

    let logs: Vec<String> = tx
        .transaction
        .meta
        .and_then(|m| {
            use solana_transaction_status::option_serializer::OptionSerializer;
            match m.log_messages {
                OptionSerializer::Some(v) => Some(v),
                _ => None,
            }
        })
        .unwrap_or_default();

    Ok(parse_drt_events(&logs))
}
