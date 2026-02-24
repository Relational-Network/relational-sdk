// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Transaction data types for the wallet service.
//!
//! Persistence is handled by the redb-backed [`TxDatabase`](super::tx_database::TxDatabase).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Whether a transfer was native SOL or an SPL token.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenType {
    /// Native SOL transfer.
    Native,
    /// SPL token transfer, identified by mint address.
    SplToken(String),
}

/// On-chain confirmation status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TxStatus {
    Pending,
    Confirmed,
    Failed,
}

/// Stored transaction record (written to redb).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct StoredTransaction {
    pub signature: String,
    pub wallet_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counterparty_wallet_id: Option<String>,
    pub from: String,
    pub to: String,
    pub amount: String,
    pub token: TokenType,
    pub network: String,
    pub status: TxStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_lamports: Option<u64>,
    pub explorer_url: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Direction hint stored in the wallet→tx index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxDirection {
    Sent,
    Received,
}

impl TxDirection {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Sent => "sent",
            Self::Received => "received",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "sent" => Some(Self::Sent),
            "received" => Some(Self::Received),
            _ => None,
        }
    }
}
