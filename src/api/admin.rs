// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Admin endpoints for the wallet service.
//!
//! All endpoints require `AdminToken` (admin role).
//!
//! - `GET  /v1/admin/wallet-stats`              — aggregate stats
//! - `GET  /v1/admin/wallets`                   — list all wallets (any owner)
//! - `GET  /v1/admin/audit/events`              — query audit log
//! - `POST /v1/admin/wallets/{id}/suspend`      — suspend a wallet
//! - `POST /v1/admin/wallets/{id}/activate`     — reactivate a wallet

use axum::{
    extract::{Path, Query, State},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::info;
use utoipa::{IntoParams, ToSchema};

use crate::audit_log;
use crate::auth::AdminToken;
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::audit::{AuditEvent, AuditEventType, AuditRepository};
use crate::storage::repository::wallets::{WalletRepository, WalletResponse, WalletStatus};

// ============================================================================
// Response types
// ============================================================================

/// Aggregate wallet statistics.
#[derive(Debug, Serialize, ToSchema)]
pub struct WalletStatsResponse {
    pub total_wallets: usize,
    pub active_wallets: usize,
    pub suspended_wallets: usize,
    pub deleted_wallets: usize,
}

/// All wallets (admin view).
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminListWalletsResponse {
    pub wallets: Vec<AdminWalletEntry>,
    pub total: usize,
}

/// Extended wallet info visible to admins.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminWalletEntry {
    #[serde(flatten)]
    pub wallet: WalletResponse,
    /// Owner user ID (visible to admins).
    pub owner_user_id: String,
}

/// Audit event query params.
#[derive(Debug, Deserialize, IntoParams)]
pub struct AuditQuery {
    /// Date in `YYYY-MM-DD` format.
    pub date: Option<String>,
    /// Maximum number of events to return (default 50, max 200).
    #[serde(default = "super::default_page_limit")]
    pub limit: usize,
    /// Offset for pagination (default 0).
    #[serde(default)]
    pub offset: usize,
}

/// Audit log response.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuditEventsResponse {
    pub events: Vec<AuditEvent>,
    pub count: usize,
}

/// Generic status response for suspend/activate.
#[derive(Debug, Serialize, ToSchema)]
pub struct WalletStatusChangeResponse {
    pub wallet_id: String,
    pub new_status: String,
}

// ============================================================================
// Handlers
// ============================================================================

/// Get aggregate wallet statistics.
#[utoipa::path(
    get,
    path = "/v1/admin/wallet-stats",
    tag = "Admin",
    summary = "Wallet statistics",
    description = "Returns aggregate counts of wallets by status. Admin only.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Stats", body = WalletStatsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
    )
)]
pub async fn get_wallet_stats(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
) -> Result<Json<WalletStatsResponse>, ApiError> {
    let repo = WalletRepository::new(&state.storage);
    let all = repo.list_all_wallets()?;

    let active = all
        .iter()
        .filter(|w| w.status == WalletStatus::Active)
        .count();
    let suspended = all
        .iter()
        .filter(|w| w.status == WalletStatus::Suspended)
        .count();
    let deleted = all
        .iter()
        .filter(|w| w.status == WalletStatus::Deleted)
        .count();

    audit_log!(
        &state.storage,
        &state.tx_db,
        AuditEventType::AdminAccess,
        &token.sub,
        "system",
        "wallet-stats"
    );

    Ok(Json(WalletStatsResponse {
        total_wallets: all.len(),
        active_wallets: active,
        suspended_wallets: suspended,
        deleted_wallets: deleted,
    }))
}

/// List all wallets (all users, all statuses).
#[utoipa::path(
    get,
    path = "/v1/admin/wallets",
    tag = "Admin",
    summary = "List all wallets (admin)",
    description = "Returns all wallets across all users with pagination. Admin only.",
    security(("bearer_auth" = [])),
    params(super::PaginationQuery),
    responses(
        (status = 200, description = "All wallets", body = AdminListWalletsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
    )
)]
pub async fn list_all_wallets(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Query(pagination): Query<super::PaginationQuery>,
) -> Result<Json<AdminListWalletsResponse>, ApiError> {
    let repo = WalletRepository::new(&state.storage);
    let all = repo.list_all_wallets()?;
    let total = all.len();

    let limit = pagination.clamped_limit();
    let entries: Vec<AdminWalletEntry> = all
        .into_iter()
        .skip(pagination.offset)
        .take(limit)
        .map(|w| AdminWalletEntry {
            owner_user_id: w.owner_user_id.clone(),
            wallet: WalletResponse::from(w),
        })
        .collect();

    audit_log!(
        &state.storage,
        &state.tx_db,
        AuditEventType::AdminAccess,
        &token.sub,
        "system",
        "list-all-wallets"
    );

    Ok(Json(AdminListWalletsResponse {
        wallets: entries,
        total,
    }))
}

/// Query audit log for a specific date.
#[utoipa::path(
    get,
    path = "/v1/admin/audit/events",
    tag = "Admin",
    summary = "Query audit log",
    description = "Returns audit events for a given date (default: today). Admin only.",
    security(("bearer_auth" = [])),
    params(AuditQuery),
    responses(
        (status = 200, description = "Audit events", body = AuditEventsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
    )
)]
pub async fn query_audit_logs(
    AdminToken(_token): AdminToken,
    State(state): State<AppState>,
    Query(query): Query<AuditQuery>,
) -> Result<Json<AuditEventsResponse>, ApiError> {
    let date = query
        .date
        .unwrap_or_else(|| chrono::Utc::now().format("%Y-%m-%d").to_string());

    // Validate date format (YYYY-MM-DD) to prevent filesystem scanning with invalid paths.
    chrono::NaiveDate::parse_from_str(&date, "%Y-%m-%d")
        .map_err(|_| ApiError::bad_request("date must be in YYYY-MM-DD format"))?;

    // Query from redb audit index (O(k) prefix scan by date).
    let limit = query.limit.clamp(1, 200);
    let events = state
        .tx_db
        .list_audit_by_date(&date, limit, query.offset)
        .map_err(|e| ApiError::internal(format!("failed to query audit events: {e}")))?;
    let count = events.len();

    Ok(Json(AuditEventsResponse { events, count }))
}

/// Suspend a wallet (admin action).
#[utoipa::path(
    post,
    path = "/v1/admin/wallets/{wallet_id}/suspend",
    tag = "Admin",
    summary = "Suspend wallet",
    description = "Suspend a wallet, preventing the owner from transacting. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, description = "Wallet UUID"),
    ),
    responses(
        (status = 200, description = "Wallet suspended", body = WalletStatusChangeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "Wallet not found"),
    )
)]
pub async fn suspend_wallet(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Json<WalletStatusChangeResponse>, ApiError> {
    let repo = WalletRepository::new(&state.storage);
    let mut wallet = repo.get(&wallet_id)?;

    if wallet.status == WalletStatus::Deleted {
        return Err(ApiError::bad_request("cannot suspend a deleted wallet"));
    }

    wallet.status = WalletStatus::Suspended;
    repo.update(&wallet)?;

    info!(
        wallet_id = %wallet_id,
        admin = %token.sub,
        "Wallet suspended by admin"
    );

    audit_log!(
        &state.storage,
        &state.tx_db,
        AuditEventType::AdminAccess,
        &token.sub,
        "wallet",
        &wallet_id
    );

    Ok(Json(WalletStatusChangeResponse {
        wallet_id,
        new_status: "suspended".to_string(),
    }))
}

/// Reactivate a suspended wallet (admin action).
#[utoipa::path(
    post,
    path = "/v1/admin/wallets/{wallet_id}/activate",
    tag = "Admin",
    summary = "Activate wallet",
    description = "Reactivate a suspended wallet. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, description = "Wallet UUID"),
    ),
    responses(
        (status = 200, description = "Wallet activated", body = WalletStatusChangeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
        (status = 404, description = "Wallet not found"),
    )
)]
pub async fn activate_wallet(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Json<WalletStatusChangeResponse>, ApiError> {
    let repo = WalletRepository::new(&state.storage);
    let mut wallet = repo.get(&wallet_id)?;

    if wallet.status == WalletStatus::Deleted {
        return Err(ApiError::bad_request("cannot activate a deleted wallet"));
    }

    wallet.status = WalletStatus::Active;
    repo.update(&wallet)?;

    info!(
        wallet_id = %wallet_id,
        admin = %token.sub,
        "Wallet activated by admin"
    );

    audit_log!(
        &state.storage,
        &state.tx_db,
        AuditEventType::AdminAccess,
        &token.sub,
        "wallet",
        &wallet_id
    );

    Ok(Json(WalletStatusChangeResponse {
        wallet_id,
        new_status: "active".to_string(),
    }))
}

// ============================================================================
// Role change audit logging
// ============================================================================

/// Request body for logging a role change.
#[derive(Debug, Deserialize, ToSchema)]
pub struct LogRoleChangeRequest {
    /// Clerk user ID of the target user.
    pub target_user_id: String,
    /// Previous role (before the change).
    pub old_role: String,
    /// New role (after the change).
    pub new_role: String,
}

/// Response for role change audit logging.
#[derive(Debug, Serialize, ToSchema)]
pub struct LogRoleChangeResponse {
    pub logged: bool,
}

/// Log a role assignment change to the enclave audit trail.
///
/// Called by the dashboard after updating a user's role via Clerk API.
/// Emits a `RoleAssigned` audit event with structured details.
#[utoipa::path(
    post,
    path = "/v1/admin/log-role-change",
    tag = "Admin",
    summary = "Log role change",
    description = "Record a role assignment change in the enclave audit trail. Called after updating Clerk publicMetadata.",
    security(("bearer_auth" = [])),
    request_body = LogRoleChangeRequest,
    responses(
        (status = 200, description = "Event logged", body = LogRoleChangeResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Admin role required"),
    )
)]
pub async fn log_role_change(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Json(payload): Json<LogRoleChangeRequest>,
) -> Json<LogRoleChangeResponse> {
    let audit_event = AuditEvent::new(AuditEventType::RoleAssigned)
        .with_user(&token.sub)
        .with_resource("user", &payload.target_user_id)
        .with_details(serde_json::json!({
            "target_user": payload.target_user_id,
            "old_role": payload.old_role,
            "new_role": payload.new_role,
            "assigned_by": token.sub
        }));
    AuditRepository::new(&state.storage).log(&audit_event).await;

    info!(
        admin = %token.sub,
        target = %payload.target_user_id,
        old_role = %payload.old_role,
        new_role = %payload.new_role,
        "Role assignment logged"
    );

    Json(LogRoleChangeResponse { logged: true })
}

// ============================================================================
// Grant / revoke a DRT to an analyst (admin-only)
// ============================================================================

use solana_pubkey::Pubkey;
use solana_signer::Signer;
use std::str::FromStr;

use crate::blockchain::drt::{
    accounts::{fetch_grant, fetch_pool},
    instructions::{build_grant_right, build_revoke_grant},
    pda::{compute_commitment, derive_drt_config_pda, derive_grant_pda},
    types::{GrantResponse, GrantRightRequest, RevokeGrantRequest},
};
use crate::storage::pool_metadata::PoolKind;

/// Grant a DRT to an analyst.
///
/// Computes `commitment = sha256(analyst_id ‖ pool_uuid ‖ right_id)`, burns 1
/// admin-held DRT, and writes a `Grant` PDA on-chain. The analyst identity
/// is never persisted on-chain — only the commitment hash.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/grant",
    tag = "Admin",
    summary = "Grant DRT to analyst",
    description = "Admin-only. Burns 1 admin-held DRT and writes a Grant PDA keyed by sha256(analyst_id || pool_uuid || right_id).",
    security(("bearer_auth" = [])),
    params(("pool_pda" = String, Path, description = "Pool PDA address (base58)")),
    request_body = GrantRightRequest,
    responses(
        (status = 200, description = "Right granted", body = GrantResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not pool owner"),
        (status = 404, description = "Pool or DRT not found"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn grant_right(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    axum::extract::Path(pool_pda_str): axum::extract::Path<String>,
    Json(payload): Json<GrantRightRequest>,
) -> Result<Json<GrantResponse>, ApiError> {
    if payload.drt_name.is_empty() {
        return Err(ApiError::bad_request("drt_name cannot be empty"));
    }
    if payload.analyst_id.is_empty() {
        return Err(ApiError::bad_request("analyst_id cannot be empty"));
    }
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    // Load pool meta and locate the requested DRT.
    let meta = crate::api::pools::load_pool_meta(&state, &pool_pda_str)?;
    if meta.kind == PoolKind::IobErp && payload.drt_name == "append" {
        return Err(ApiError::bad_request("IOB ERP pools have no 'append' DRT"));
    }
    let drt = meta.drts.get(&payload.drt_name).ok_or_else(|| {
        ApiError::not_found(format!("DRT '{}' not found in pool", payload.drt_name))
    })?;

    // Verify the DRT script before any on-chain side effects.
    // The `append` DRT has no executable code (empty URL, zero hash) — skip it.
    if !drt.code_repo_url.is_empty() {
        crate::drt::verified_fetch::fetch_and_verify(
            &drt.code_repo_url,
            &drt.code_hash_hex,
            &state.storage,
        )
        .await?;
    }

    let right_id = crate::api::credentials::decode_right_id(&drt.right_id_hex)?;
    let pool_uuid = crate::api::credentials::decode_right_id(&meta.pool_uuid_hex)?;
    let mint = Pubkey::from_str(&drt.mint)
        .map_err(|_| ApiError::internal("invalid mint pubkey in pool metadata"))?;
    let (drt_config_pda, _) = derive_drt_config_pda(&pool_pda, &right_id);

    // Load caller's wallet — must be the pool owner.
    let repo = crate::storage::repository::wallets::WalletRepository::new(&state.storage);
    let (wallet, keypair) =
        crate::api::pools::load_wallet_keypair(&repo, &payload.wallet_id, &token.sub)?;
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    crate::api::pools::verify_pool_ownership(&pool, &wallet)?;

    // Build + send.
    let commitment = compute_commitment(&payload.analyst_id, &pool_uuid, &right_id);
    let (grant_pda, _) = derive_grant_pda(&commitment);
    let ix = build_grant_right(
        &pool_pda,
        &drt_config_pda,
        &mint,
        &keypair.pubkey(),
        &commitment,
    );
    let (sig, events) =
        crate::api::pools::sign_send_and_parse(&state, &keypair, vec![ix], "finalized").await?;

    let evt = AuditEvent::new(AuditEventType::RightGranted)
        .with_user(&token.sub)
        .with_resource("drt_grant", grant_pda.to_string())
        .with_pool_pda(&pool_pda_str)
        .with_details(serde_json::json!({
            "pool_pda": pool_pda_str,
            "drt_name": payload.drt_name,
            "analyst_id_hash": hex::encode(commitment),
            "grant_pda": grant_pda.to_string(),
            "tx_signature": sig,
            "chain": crate::api::pools::chain_section(
                std::slice::from_ref(&sig),
                &events,
                {
                    let mut extra = serde_json::Map::new();
                    extra.insert(
                        hex::encode(commitment),
                        serde_json::Value::String(format!("grant of '{}' to analyst", payload.drt_name)),
                    );
                    extra.insert(
                        grant_pda.to_string(),
                        serde_json::Value::String(format!("grant of '{}'", payload.drt_name)),
                    );
                    crate::api::pools::pool_labels(&meta, Some(extra))
                },
            ),
        }));
    AuditRepository::new(&state.storage)
        .with_tx_db(&state.tx_db)
        .log(&evt)
        .await;

    info!(
        signature = %sig,
        pool = %pool_pda_str,
        drt = %payload.drt_name,
        grant = %grant_pda,
        "Right granted"
    );

    Ok(Json(GrantResponse {
        signature: sig.clone(),
        explorer_url: crate::api::pools::explorer_url(&state, &sig),
        commitment_hex: hex::encode(commitment),
        grant_pda: grant_pda.to_string(),
    }))
}

/// Live grant-status diagnostic.
#[derive(Debug, Serialize, ToSchema)]
pub struct GrantStatusResponse {
    pub pool_pda: String,
    pub drt_name: String,
    pub commitment_hex: String,
    pub grant_pda: String,
    pub granted: bool,
    /// Unix timestamp (seconds) the grant was minted, when `granted=true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub granted_at: Option<i64>,
}

/// Check whether an analyst currently holds a grant for a given DRT.
///
/// Computes the same commitment used at grant time and reads the Grant PDA
/// from chain. Returns `granted: false` if the account does not exist.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/grant/{analyst_id}/{drt_name}",
    tag = "Admin",
    summary = "Check DRT grant status",
    description = "Looks up Grant PDA at sha256(analyst_id || pool_uuid || right_id). Returns whether it exists and when it was minted.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        ("analyst_id" = String, Path, description = "Analyst identifier (Clerk sub or similar)"),
        ("drt_name" = String, Path, description = "DRT name"),
    ),
    responses(
        (status = 200, description = "Grant status", body = GrantStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool or DRT not found"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn get_grant_status(
    AdminToken(_token): AdminToken,
    State(state): State<AppState>,
    axum::extract::Path((pool_pda_str, analyst_id, drt_name)): axum::extract::Path<(
        String,
        String,
        String,
    )>,
) -> Result<Json<GrantStatusResponse>, ApiError> {
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;
    let meta = crate::api::pools::load_pool_meta(&state, &pool_pda_str)?;
    let drt = meta
        .drts
        .get(&drt_name)
        .ok_or_else(|| ApiError::not_found(format!("DRT '{drt_name}' not found in pool")))?;
    let right_id = crate::api::credentials::decode_right_id(&drt.right_id_hex)?;
    let pool_uuid = crate::api::credentials::decode_right_id(&meta.pool_uuid_hex)?;
    let commitment = compute_commitment(&analyst_id, &pool_uuid, &right_id);
    let (grant_pda, _) = derive_grant_pda(&commitment);

    let (granted, granted_at) = match fetch_grant(state.solana_client.rpc(), &grant_pda).await {
        Ok(g) => (true, Some(g.granted_at)),
        Err(_) => (false, None),
    };

    // Suppress unused-import: `pool_pda` is computed for validation/symmetry.
    let _ = pool_pda;

    Ok(Json(GrantStatusResponse {
        pool_pda: pool_pda_str,
        drt_name,
        commitment_hex: hex::encode(commitment),
        grant_pda: grant_pda.to_string(),
        granted,
        granted_at,
    }))
}

/// Revoke a previously granted DRT.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/revoke-grant",
    tag = "Admin",
    summary = "Revoke DRT grant",
    description = "Admin-only. Closes the Grant PDA matching sha256(analyst_id || pool_uuid || right_id).",
    security(("bearer_auth" = [])),
    params(("pool_pda" = String, Path, description = "Pool PDA address (base58)")),
    request_body = RevokeGrantRequest,
    responses(
        (status = 200, description = "Grant revoked", body = GrantResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not pool owner"),
        (status = 404, description = "Pool, DRT, or grant not found"),
        (status = 503, description = "RPC unavailable"),
    )
)]
pub async fn revoke_grant(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    axum::extract::Path(pool_pda_str): axum::extract::Path<String>,
    Json(payload): Json<RevokeGrantRequest>,
) -> Result<Json<GrantResponse>, ApiError> {
    if payload.drt_name.is_empty() {
        return Err(ApiError::bad_request("drt_name cannot be empty"));
    }
    if payload.analyst_id.is_empty() {
        return Err(ApiError::bad_request("analyst_id cannot be empty"));
    }
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    let meta = crate::api::pools::load_pool_meta(&state, &pool_pda_str)?;
    let drt = meta.drts.get(&payload.drt_name).ok_or_else(|| {
        ApiError::not_found(format!("DRT '{}' not found in pool", payload.drt_name))
    })?;
    let right_id = crate::api::credentials::decode_right_id(&drt.right_id_hex)?;
    let pool_uuid = crate::api::credentials::decode_right_id(&meta.pool_uuid_hex)?;
    let (drt_config_pda, _) = derive_drt_config_pda(&pool_pda, &right_id);

    let repo = crate::storage::repository::wallets::WalletRepository::new(&state.storage);
    let (wallet, keypair) =
        crate::api::pools::load_wallet_keypair(&repo, &payload.wallet_id, &token.sub)?;
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    crate::api::pools::verify_pool_ownership(&pool, &wallet)?;

    let commitment = compute_commitment(&payload.analyst_id, &pool_uuid, &right_id);
    let (grant_pda, _) = derive_grant_pda(&commitment);
    let ix = build_revoke_grant(&keypair.pubkey(), &pool_pda, &drt_config_pda, &commitment);
    let (sig, events) =
        crate::api::pools::sign_send_and_parse(&state, &keypair, vec![ix], "finalized").await?;

    let evt = AuditEvent::new(AuditEventType::RightRevoked)
        .with_user(&token.sub)
        .with_resource("drt_grant", grant_pda.to_string())
        .with_pool_pda(&pool_pda_str)
        .with_details(serde_json::json!({
            "pool_pda": pool_pda_str,
            "drt_name": payload.drt_name,
            "analyst_id_hash": hex::encode(commitment),
            "grant_pda": grant_pda.to_string(),
            "tx_signature": sig,
            "chain": crate::api::pools::chain_section(
                std::slice::from_ref(&sig),
                &events,
                {
                    let mut extra = serde_json::Map::new();
                    extra.insert(
                        hex::encode(commitment),
                        serde_json::Value::String(format!("revoked '{}' grant", payload.drt_name)),
                    );
                    extra.insert(
                        grant_pda.to_string(),
                        serde_json::Value::String(format!("revoked grant of '{}'", payload.drt_name)),
                    );
                    crate::api::pools::pool_labels(&meta, Some(extra))
                },
            ),
        }));
    AuditRepository::new(&state.storage)
        .with_tx_db(&state.tx_db)
        .log(&evt)
        .await;

    info!(
        signature = %sig,
        pool = %pool_pda_str,
        drt = %payload.drt_name,
        grant = %grant_pda,
        "Right revoked"
    );

    Ok(Json(GrantResponse {
        signature: sig.clone(),
        explorer_url: crate::api::pools::explorer_url(&state, &sig),
        commitment_hex: hex::encode(commitment),
        grant_pda: grant_pda.to_string(),
    }))
}
