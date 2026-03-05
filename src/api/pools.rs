// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! DRT pool API handlers.
//!
//! - `POST /v1/drt/pools`                          — create pool
//! - `GET  /v1/drt/pools/{pool_pda}`               — get pool info
//! - `GET  /v1/drt/pools/by-owner/{owner}/{name}`  — get pool by owner+name
//! - `POST /v1/drt/pools/{pool_pda}/buy`           — buy DRT tokens
//! - `POST /v1/drt/pools/{pool_pda}/redeem`        — redeem (burn) 1 DRT
//! - `POST /v1/drt/pools/{pool_pda}/close`         — close pool
//! - `GET  /v1/drt/pools/{pool_pda}/balance/{drt_type}` — check balances
//! - `GET  /v1/drt/events/{signature}`             — parse tx events

use axum::{
    extract::{Path, State},
    Json,
};
use solana_sdk::{
    pubkey::Pubkey,
    signer::{keypair::Keypair, Signer},
};
use std::collections::HashMap;
use std::str::FromStr;
use tracing::info;

use crate::audit_log;
use crate::auth::UserToken;
use crate::blockchain::drt::{
    accounts::{fetch_pool, find_drt_in_pool},
    events::{parse_events_from_signature, DrtEvent},
    instructions::{build_buy_drt, build_close_pool, build_create_pool_atomic, build_redeem_drt},
    pda::{derive_mint_pda, derive_pool_pda, derive_user_ata, derive_vault_ata},
    types::*,
    validation::validate_create_pool_request,
};
use crate::blockchain::signing::keypair_from_bytes_verified;
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::audit::AuditEventType;
use crate::storage::ownership::OwnershipEnforcer;
use crate::storage::repository::wallets::{WalletMetadata, WalletRepository, WalletStatus};

// ============================================================================
// Helpers
// ============================================================================

/// Load a wallet keypair, verifying ownership and active status.
fn load_wallet_keypair(
    repo: &WalletRepository<'_>,
    wallet_id: &str,
    caller_sub: &str,
) -> Result<(WalletMetadata, Keypair), ApiError> {
    let wallet = repo.get(wallet_id)?;
    wallet.verify_ownership(caller_sub)?;
    if wallet.status == WalletStatus::Deleted {
        return Err(ApiError::not_found(format!("wallet {wallet_id} not found")));
    }
    if wallet.status == WalletStatus::Suspended {
        return Err(ApiError::forbidden(format!(
            "wallet {wallet_id} is suspended"
        )));
    }

    let keypair_bytes = repo.read_keypair(wallet_id)?;
    let keypair = keypair_from_bytes_verified(&keypair_bytes, &wallet.public_address)?;
    Ok((wallet, keypair))
}

/// Sign and send a transaction, returning the signature string + events.
async fn sign_send_and_parse(
    state: &AppState,
    keypair: &Keypair,
    instructions: Vec<solana_sdk::instruction::Instruction>,
) -> Result<(String, Vec<DrtEvent>), ApiError> {
    let rpc = state.solana_client.rpc();
    let recent_blockhash = rpc
        .get_latest_blockhash()
        .await
        .map_err(|e| ApiError::service_unavailable(format!("blockhash fetch failed: {e}")))?;

    let message = solana_message::Message::new(&instructions, Some(&keypair.pubkey()));
    let tx = solana_transaction::Transaction::new(&[keypair], message, recent_blockhash);

    let signature = rpc
        .send_and_confirm_transaction(&tx)
        .await
        .map_err(|e| ApiError::service_unavailable(format!("transaction failed: {e}")))?;

    let sig_str = signature.to_string();

    // Fetch tx to parse events.
    let events = parse_events_from_signature(rpc, &sig_str)
        .await
        .unwrap_or_default();

    Ok((sig_str, events))
}

fn explorer_url(state: &AppState, sig: &str) -> String {
    state.solana_client.network().explorer_tx_url(sig)
}

// ============================================================================
// Handlers
// ============================================================================

/// Create a DRT pool with one or more DRT configurations.
#[utoipa::path(
    post,
    path = "/v1/drt/pools",
    tag = "DRT Pools",
    summary = "Create DRT pool",
    description = "Create a new Data Rights Token pool with the specified DRT configurations. Signs and broadcasts an atomic create_pool transaction.",
    security(("bearer_auth" = [])),
    request_body = CreatePoolRequest,
    responses(
        (status = 201, description = "Pool created", body = CreatePoolResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 503, description = "Solana RPC unavailable"),
    )
)]
pub async fn create_pool(
    UserToken(token): UserToken,
    State(state): State<AppState>,
    Json(payload): Json<CreatePoolRequest>,
) -> Result<(axum::http::StatusCode, Json<CreatePoolResponse>), ApiError> {
    // Validate all inputs.
    let drt_configs = validate_create_pool_request(&payload.pool_name, &payload.drt_configs)?;

    // Load wallet.
    let repo = WalletRepository::new(&state.storage);
    let (wallet, keypair) = load_wallet_keypair(&repo, &payload.wallet_id, &token.sub)?;

    let owner = Pubkey::from_str(&wallet.public_address)
        .map_err(|_| ApiError::internal("invalid stored wallet address"))?;
    let (pool_pda, _) = derive_pool_pda(&owner, &payload.pool_name);

    // Build mints map for response.
    let mut mints = HashMap::new();
    for cfg in &drt_configs {
        let (mint_pda, _) = derive_mint_pda(&pool_pda, &cfg.drt_type);
        mints.insert(cfg.drt_type.clone(), mint_pda.to_string());
    }

    // Build and send transaction.
    let instructions =
        build_create_pool_atomic(&owner, &pool_pda, &payload.pool_name, &drt_configs)
            .map_err(ApiError::internal)?;
    let (sig_str, _events) = sign_send_and_parse(&state, &keypair, instructions).await?;

    info!(
        signature = %sig_str,
        pool = %pool_pda,
        owner = %owner,
        drts = drt_configs.len(),
        "DRT pool created"
    );

    audit_log!(
        &state.storage,
        AuditEventType::TransactionBroadcast,
        &token.sub,
        "drt_pool",
        &pool_pda.to_string()
    );

    Ok((
        axum::http::StatusCode::CREATED,
        Json(CreatePoolResponse {
            signature: sig_str.clone(),
            pool_pda: pool_pda.to_string(),
            mints,
            explorer_url: explorer_url(&state, &sig_str),
        }),
    ))
}

/// Get pool info by PDA address.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}",
    tag = "DRT Pools",
    summary = "Get DRT pool",
    description = "Fetch pool state from the Solana blockchain by its PDA address.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
    ),
    responses(
        (status = 200, description = "Pool info", body = PoolInfoResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool not found"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn get_pool(
    UserToken(_token): UserToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
) -> Result<Json<PoolInfoResponse>, ApiError> {
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;

    Ok(Json(PoolInfoResponse {
        pool_pda: pool_pda_str,
        name: pool.name,
        owner: pool.owner.to_string(),
        drts: pool.drts.iter().map(DrtConfigResponse::from).collect(),
    }))
}

/// Get pool info by owner pubkey and pool name.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/by-owner/{owner_pubkey}/{pool_name}",
    tag = "DRT Pools",
    summary = "Get DRT pool by owner",
    description = "Derive the pool PDA from owner + name and fetch its state.",
    security(("bearer_auth" = [])),
    params(
        ("owner_pubkey" = String, Path, description = "Pool owner Solana address (base58)"),
        ("pool_name" = String, Path, description = "Pool name"),
    ),
    responses(
        (status = 200, description = "Pool info", body = PoolInfoResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool not found"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn get_pool_by_owner(
    UserToken(_token): UserToken,
    State(state): State<AppState>,
    Path((owner_str, pool_name)): Path<(String, String)>,
) -> Result<Json<PoolInfoResponse>, ApiError> {
    let owner =
        Pubkey::from_str(&owner_str).map_err(|_| ApiError::bad_request("invalid owner address"))?;
    let (pool_pda, _) = derive_pool_pda(&owner, &pool_name);

    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;

    Ok(Json(PoolInfoResponse {
        pool_pda: pool_pda.to_string(),
        name: pool.name,
        owner: pool.owner.to_string(),
        drts: pool.drts.iter().map(DrtConfigResponse::from).collect(),
    }))
}

/// Buy DRT tokens from a pool.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/buy",
    tag = "DRT Pools",
    summary = "Buy DRT tokens",
    description = "Purchase DRT tokens by paying SOL to the pool owner. The buyer's wallet signs the transaction.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
    ),
    request_body = BuyDrtRequest,
    responses(
        (status = 200, description = "Purchase complete", body = BuyDrtResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Pool or DRT not found"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn buy_drt(
    UserToken(token): UserToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    Json(payload): Json<BuyDrtRequest>,
) -> Result<Json<BuyDrtResponse>, ApiError> {
    if payload.amount == 0 {
        return Err(ApiError::bad_request("amount must be greater than zero"));
    }

    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    // Load buyer wallet.
    let repo = WalletRepository::new(&state.storage);
    let (_wallet, keypair) = load_wallet_keypair(&repo, &payload.wallet_id, &token.sub)?;

    // Fetch pool to find DRT config and owner.
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    let drt = find_drt_in_pool(&pool, &payload.drt_type)?;

    let ix = build_buy_drt(
        &pool_pda,
        &pool.owner,
        &keypair.pubkey(),
        &payload.drt_type,
        payload.amount,
        &drt.mint,
        drt.enable_transfer_hook,
    )
    .map_err(ApiError::internal)?;

    let (sig_str, events) = sign_send_and_parse(&state, &keypair, vec![ix]).await?;

    // Find purchased event.
    let purchased_event = events.iter().find_map(|e| {
        if let DrtEvent::DrtPurchased(p) = e {
            Some(DrtPurchasedEventResponse {
                pool: p.pool.to_string(),
                drt_type: p.drt_type.clone(),
                buyer: p.buyer.to_string(),
                cost: p.cost,
                amount: p.amount,
                total_cost: p.total_cost,
                timestamp: p.timestamp,
            })
        } else {
            None
        }
    });

    info!(
        signature = %sig_str,
        pool = %pool_pda,
        drt_type = %payload.drt_type,
        amount = payload.amount,
        "DRT purchased"
    );

    audit_log!(
        &state.storage,
        AuditEventType::TransactionBroadcast,
        &token.sub,
        "drt_buy",
        &sig_str
    );

    Ok(Json(BuyDrtResponse {
        signature: sig_str.clone(),
        explorer_url: explorer_url(&state, &sig_str),
        event: purchased_event,
    }))
}

/// Redeem (burn) 1 DRT token and receive the event with script details.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/redeem",
    tag = "DRT Pools",
    summary = "Redeem DRT",
    description = "Burn 1 DRT token. The program emits a DrtRedeemed or AppendRedeemed event containing the script URL and hash for off-chain execution.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
    ),
    request_body = RedeemDrtRequest,
    responses(
        (status = 200, description = "DRT redeemed", body = RedeemDrtResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Pool or DRT not found"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn redeem_drt(
    UserToken(token): UserToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    Json(payload): Json<RedeemDrtRequest>,
) -> Result<Json<RedeemDrtResponse>, ApiError> {
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    // Load user wallet.
    let repo = WalletRepository::new(&state.storage);
    let (_wallet, keypair) = load_wallet_keypair(&repo, &payload.wallet_id, &token.sub)?;

    // Fetch pool to find DRT config.
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    let drt = find_drt_in_pool(&pool, &payload.drt_type)?;

    let ix = build_redeem_drt(&pool_pda, &keypair.pubkey(), &payload.drt_type, &drt.mint)
        .map_err(ApiError::internal)?;

    let (sig_str, events) = sign_send_and_parse(&state, &keypair, vec![ix]).await?;

    // Find redeem event (DrtRedeemed or AppendRedeemed).
    let redeem_event = events.iter().find_map(|e| match e {
        DrtEvent::DrtRedeemed(r) => Some(RedeemEventResponse::DrtRedeemed {
            pool: r.pool.to_string(),
            drt_type: r.drt_type.clone(),
            redeemer: r.redeemer.to_string(),
            github_url: r.github_url.clone(),
            expected_hash: hex::encode(r.expected_hash),
            timestamp: r.timestamp,
        }),
        DrtEvent::AppendRedeemed(a) => Some(RedeemEventResponse::AppendRedeemed {
            pool: a.pool.to_string(),
            drt_type: a.drt_type.clone(),
            redeemer: a.redeemer.to_string(),
            timestamp: a.timestamp,
        }),
        _ => None,
    });

    info!(
        signature = %sig_str,
        pool = %pool_pda,
        drt_type = %payload.drt_type,
        "DRT redeemed"
    );

    audit_log!(
        &state.storage,
        AuditEventType::TransactionBroadcast,
        &token.sub,
        "drt_redeem",
        &sig_str
    );

    Ok(Json(RedeemDrtResponse {
        signature: sig_str.clone(),
        explorer_url: explorer_url(&state, &sig_str),
        event: redeem_event,
    }))
}

/// Close a DRT pool and reclaim rent.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/close",
    tag = "DRT Pools",
    summary = "Close DRT pool",
    description = "Close a pool and reclaim rent. All DRT supplies must be burned (zero remaining).",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
    ),
    request_body = ClosePoolRequest,
    responses(
        (status = 200, description = "Pool closed", body = ClosePoolResponse),
        (status = 400, description = "Pool still has active supply"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not the pool owner"),
        (status = 404, description = "Pool not found"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn close_pool(
    UserToken(token): UserToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    Json(payload): Json<ClosePoolRequest>,
) -> Result<Json<ClosePoolResponse>, ApiError> {
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    // Load owner wallet.
    let repo = WalletRepository::new(&state.storage);
    let (wallet, keypair) = load_wallet_keypair(&repo, &payload.wallet_id, &token.sub)?;

    // Fetch pool and verify ownership.
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    let owner = Pubkey::from_str(&wallet.public_address)
        .map_err(|_| ApiError::internal("invalid stored wallet address"))?;
    if pool.owner != owner {
        return Err(ApiError::forbidden("you are not the pool owner"));
    }

    let ix = build_close_pool(&pool_pda, &owner, &pool.drts);
    let (sig_str, _events) = sign_send_and_parse(&state, &keypair, vec![ix]).await?;

    info!(
        signature = %sig_str,
        pool = %pool_pda,
        "DRT pool closed"
    );

    audit_log!(
        &state.storage,
        AuditEventType::TransactionBroadcast,
        &token.sub,
        "drt_close",
        &pool_pda.to_string()
    );

    Ok(Json(ClosePoolResponse {
        signature: sig_str.clone(),
        explorer_url: explorer_url(&state, &sig_str),
    }))
}

/// Get DRT token balance for a user and vault.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/balance/{drt_type}",
    tag = "DRT Pools",
    summary = "Get DRT balance",
    description = "Check the user's token balance and the vault supply for a specific DRT type.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("drt_type" = String, Path, description = "DRT type name"),
    ),
    responses(
        (status = 200, description = "Balance info", body = DrtBalanceResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool or DRT not found"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn get_drt_balance(
    UserToken(token): UserToken,
    State(state): State<AppState>,
    Path((pool_pda_str, drt_type)): Path<(String, String)>,
) -> Result<Json<DrtBalanceResponse>, ApiError> {
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    // We need the user's wallet to derive their ATA. Use first active wallet.
    let repo = WalletRepository::new(&state.storage);
    let wallets = repo.list_by_owner(&token.sub)?;
    let wallet = wallets
        .first()
        .ok_or_else(|| ApiError::bad_request("no active wallet found for user"))?;
    let user_pubkey = Pubkey::from_str(&wallet.public_address)
        .map_err(|_| ApiError::internal("invalid stored wallet address"))?;

    // Fetch pool to get mint.
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    let drt = find_drt_in_pool(&pool, &drt_type)?;

    let user_ata = derive_user_ata(&user_pubkey, &drt.mint);
    let vault_ata = derive_vault_ata(&pool_pda, &drt.mint);

    let rpc = state.solana_client.rpc();

    // Fetch user balance (may not exist yet → 0).
    let user_balance = match rpc.get_token_account_balance(&user_ata).await {
        Ok(b) => b.amount.parse::<u64>().unwrap_or(0),
        Err(_) => 0,
    };

    // Fetch vault balance.
    let vault_balance = match rpc.get_token_account_balance(&vault_ata).await {
        Ok(b) => b.amount.parse::<u64>().unwrap_or(0),
        Err(_) => 0,
    };

    Ok(Json(DrtBalanceResponse {
        drt_type,
        mint: drt.mint.to_string(),
        user_balance,
        vault_balance,
    }))
}

/// Parse DRT events from a transaction signature.
#[utoipa::path(
    get,
    path = "/v1/drt/events/{signature}",
    tag = "DRT Pools",
    summary = "Get DRT events from transaction",
    description = "Fetch a confirmed transaction and parse any DRT contract events from its logs.",
    security(("bearer_auth" = [])),
    params(
        ("signature" = String, Path, description = "Transaction signature (base58)"),
    ),
    responses(
        (status = 200, description = "Parsed events", body = TxEventsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Transaction not found"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn get_tx_events(
    UserToken(_token): UserToken,
    State(state): State<AppState>,
    Path(signature): Path<String>,
) -> Result<Json<TxEventsResponse>, ApiError> {
    let events = parse_events_from_signature(state.solana_client.rpc(), &signature).await?;

    Ok(Json(TxEventsResponse {
        signature,
        events: events.iter().map(|e| e.to_response()).collect(),
    }))
}
