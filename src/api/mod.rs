// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Wallet API endpoint handlers.
//!
//! Each sub-module groups related endpoints. The [`wallet_router`] function
//! assembles all routes into a single Axum sub-router that is merged into
//! the application root.

pub mod admin;
pub mod balance;
pub mod credentials;
pub mod pools;
pub mod transactions;
pub mod users;
pub mod wallets;

use axum::{
    routing::{get, post},
    Router,
};

use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::ownership::OwnershipEnforcer;
use crate::storage::repository::wallets::{WalletMetadata, WalletStatus};

/// Check that the caller owns the wallet and the wallet is not deleted/suspended.
///
/// Shared helper used by balance, transaction, and other wallet-scoped endpoints.
pub(crate) fn enforce_owner_active(
    wallet: &WalletMetadata,
    caller_sub: &str,
) -> Result<(), ApiError> {
    wallet.verify_ownership(caller_sub)?;
    if wallet.status == WalletStatus::Deleted {
        return Err(ApiError::not_found(format!(
            "wallet {} not found",
            wallet.wallet_id
        )));
    }
    if wallet.status == WalletStatus::Suspended {
        return Err(ApiError::forbidden(format!(
            "wallet {} is suspended",
            wallet.wallet_id
        )));
    }
    Ok(())
}

/// Build the wallet-service routes (nested under `/v1`).
pub fn wallet_router() -> Router<AppState> {
    Router::new()
        // ── User identity ───────────────────────────────────────
        .route("/v1/users/me", get(users::get_me))
        // ── Wallet CRUD ─────────────────────────────────────────
        .route("/v1/wallets", get(wallets::list_wallets))
        .route("/v1/wallets", post(wallets::create_wallet))
        .route("/v1/wallets/{wallet_id}", get(wallets::get_wallet))
        .route(
            "/v1/wallets/{wallet_id}",
            axum::routing::delete(wallets::delete_wallet),
        )
        // ── Balance ─────────────────────────────────────────────
        .route("/v1/wallets/{wallet_id}/balance", get(balance::get_balance))
        .route(
            "/v1/wallets/{wallet_id}/balance/native",
            get(balance::get_native_balance),
        )
        // ── Transactions ────────────────────────────────────────
        .route(
            "/v1/wallets/{wallet_id}/estimate",
            post(transactions::estimate_fee),
        )
        .route(
            "/v1/wallets/{wallet_id}/send",
            post(transactions::send_transaction),
        )
        .route(
            "/v1/wallets/{wallet_id}/transactions",
            get(transactions::list_transactions),
        )
        .route(
            "/v1/wallets/{wallet_id}/transactions/{signature}",
            get(transactions::get_transaction_status),
        )
        // ── Admin ───────────────────────────────────────────────
        .route("/v1/admin/wallet-stats", get(admin::get_wallet_stats))
        .route("/v1/admin/wallets", get(admin::list_all_wallets))
        .route("/v1/admin/audit/events", get(admin::query_audit_logs))
        .route(
            "/v1/admin/wallets/{wallet_id}/suspend",
            post(admin::suspend_wallet),
        )
        .route(
            "/v1/admin/wallets/{wallet_id}/activate",
            post(admin::activate_wallet),
        )
        .route(
            "/v1/admin/log-role-change",
            post(admin::log_role_change),
        )
}

/// Build the DRT pool routes (nested under `/v1/drt`).
pub fn drt_router() -> Router<AppState> {
    Router::new()
        // ── Pool CRUD ───────────────────────────────────────────
        .route("/v1/drt/pools", post(pools::create_pool))
        .route("/v1/drt/pools/{pool_pda}", get(pools::get_pool))
        .route(
            "/v1/drt/pools/by-owner/{owner_pubkey}/{pool_name}",
            get(pools::get_pool_by_owner),
        )
        // ── Pool operations ─────────────────────────────────────
        .route("/v1/drt/pools/{pool_pda}/buy", post(pools::buy_drt))
        .route("/v1/drt/pools/{pool_pda}/redeem", post(pools::redeem_drt))
        .route("/v1/drt/pools/{pool_pda}/close", post(pools::close_pool))
        // ── Balance + events ────────────────────────────────────
        .route(
            "/v1/drt/pools/{pool_pda}/balance/{drt_type}",
            get(pools::get_drt_balance),
        )
        .route("/v1/drt/events/{signature}", get(pools::get_tx_events))        // ── Credential issuance ─────────────────────────────────
        .route("/v1/drt/pools/{pool_pda}/initialize", post(credentials::initialize_pool))
        .route("/v1/drt/pools/{pool_pda}/issue", post(credentials::issue_credentials))
        .route("/v1/drt/pools/{pool_pda}/revoke", post(credentials::revoke_credentials))
        .route("/v1/drt/pools/{pool_pda}/revocations", get(credentials::list_revocations))
        .route("/v1/drt/pools/{pool_pda}/audit", get(credentials::pool_audit))
        .route("/v1/drt/pools/{pool_pda}/summary", get(credentials::pool_summary))
        .route("/v1/drt/pools/by-wallet/{wallet_id}", get(credentials::list_pools_by_wallet))}
