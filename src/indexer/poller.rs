// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Polling loop that fetches new Solana transaction signatures for watched
//! addresses and upserts them into the [`TxDatabase`].

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use solana_client::rpc_config::RpcTransactionConfig;
use solana_commitment_config::CommitmentConfig;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signature;
use solana_transaction_status::UiTransactionEncoding;
use std::str::FromStr;
use tokio::time::interval;
use tracing::{debug, info, warn};

use crate::blockchain::SolanaClient;
use crate::storage::repository::transactions::{StoredTransaction, TokenType, TxStatus};
use crate::storage::tx_cache::TxCache;
use crate::storage::tx_database::TxDatabase;

/// Start the background indexer.
///
/// This spawns a Tokio task that runs forever (until the runtime shuts down).
/// Call from `main` after building `AppState`.
pub fn spawn_indexer(
    solana: Arc<SolanaClient>,
    tx_db: Arc<TxDatabase>,
    tx_cache: Arc<TxCache>,
    poll_interval: Duration,
) {
    tokio::spawn(async move {
        info!(
            interval_secs = poll_interval.as_secs(),
            "Transaction indexer started"
        );
        let mut ticker = interval(poll_interval);

        loop {
            ticker.tick().await;
            if let Err(e) = poll_once(&solana, &tx_db, &tx_cache).await {
                warn!(error = %e, "Indexer poll cycle failed");
            }
        }
    });
}

/// Trigger a one-shot sync for a single address.
pub async fn sync_address_once(
    solana: &SolanaClient,
    tx_db: &TxDatabase,
    tx_cache: &Arc<TxCache>,
    address: &str,
    wallet_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    poll_address(solana, tx_db, tx_cache, address, wallet_id).await
}

/// Single poll cycle: iterate all registered addresses and fetch new sigs.
async fn poll_once(
    solana: &SolanaClient,
    tx_db: &TxDatabase,
    tx_cache: &Arc<TxCache>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let addresses = tx_db.get_all_addresses()?;
    debug!(address_count = addresses.len(), "Indexer polling addresses");

    for (address, wallet_id) in &addresses {
        if let Err(e) = poll_address(solana, tx_db, tx_cache, address, wallet_id).await {
            warn!(address = %address, error = %e, "Failed to poll address");
        }
    }

    Ok(())
}

/// Poll a single address for new transaction signatures.
async fn poll_address(
    solana: &SolanaClient,
    tx_db: &TxDatabase,
    tx_cache: &Arc<TxCache>,
    address: &str,
    wallet_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let pubkey = Pubkey::from_str(address)?;

    // Get last-seen signature for this address (to avoid re-fetching).
    let state_key = format!("last_sig:{address}");
    let last_sig = tx_db.get_indexer_state(&state_key)?;
    let until_sig = last_sig
        .as_deref()
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .and_then(|s| Signature::from_str(s).ok());

    // Fetch recent signatures.
    let config = solana_client::rpc_client::GetConfirmedSignaturesForAddress2Config {
        before: None,
        until: until_sig,
        limit: Some(50),
        commitment: Some(CommitmentConfig::confirmed()),
    };

    let sigs = solana
        .rpc()
        .get_signatures_for_address_with_config(&pubkey, config)
        .await?;

    if sigs.is_empty() {
        return Ok(());
    }

    debug!(
        address = %address,
        new_sigs = sigs.len(),
        "Indexer found new signatures"
    );

    let mut newest_sig: Option<String> = None;

    for sig_info in &sigs {
        let sig_str = &sig_info.signature;

        // Track the newest signature (first in the list = most recent).
        if newest_sig.is_none() {
            newest_sig = Some(sig_str.clone());
        }

        // Skip if we already have this tx.
        if tx_db.get_transaction(sig_str)?.is_some() {
            continue;
        }

        // Fetch full transaction details.
        let signature = Signature::from_str(sig_str)?;
        let tx_config = RpcTransactionConfig {
            encoding: Some(UiTransactionEncoding::JsonParsed),
            commitment: Some(CommitmentConfig::confirmed()),
            max_supported_transaction_version: Some(0),
        };

        match solana.rpc().get_transaction_with_config(&signature, tx_config).await {
            Ok(tx_detail) => {
                let status = if sig_info.err.is_some() {
                    TxStatus::Failed
                } else {
                    TxStatus::Confirmed
                };

                let now = Utc::now();
                let stored = StoredTransaction {
                    signature: sig_str.clone(),
                    wallet_id: wallet_id.to_string(),
                    counterparty_wallet_id: None,
                    from: address.to_string(),     // simplification — sender
                    to: String::new(),              // parsed below if available
                    amount: "0".to_string(),        // parsed below if available
                    token: TokenType::Native,
                    network: solana.network().name.to_string(),
                    status,
                    slot: Some(tx_detail.slot),
                    fee_lamports: tx_detail.transaction.meta.as_ref().map(|m| m.fee),
                    explorer_url: solana.network().explorer_tx_url(sig_str),
                    created_at: sig_info
                        .block_time
                        .and_then(|t| chrono::DateTime::from_timestamp(t, 0))
                        .unwrap_or(now),
                    updated_at: now,
                };

                // Determine direction: if this address is the signer, it's "sent".
                let direction = if stored.from == address { "sent" } else { "received" };
                let directions = vec![(address.to_string(), direction)];

                if let Err(e) = tx_db.upsert_transaction(&stored, &directions) {
                    warn!(sig = %sig_str, error = %e, "Failed to store indexed tx");
                }
            }
            Err(e) => {
                debug!(sig = %sig_str, error = %e, "Failed to fetch tx detail (skipping)");
            }
        }
    }

    // Update the last-seen signature.
    if let Some(newest) = newest_sig {
        tx_db.set_indexer_state(&state_key, newest.as_bytes())?;
    }

    // Invalidate tx cache for this address so queries see fresh data.
    tx_cache.invalidate(address);

    Ok(())
}
