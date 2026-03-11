// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Credential issuance, revocation, and pool discovery endpoints.
//!
//! - `POST /v1/drt/pools/{pool_pda}/initialize` — seed initial dataset
//! - `POST /v1/drt/pools/{pool_pda}/issue`      — issue credentials (append-DRT gated)
//! - `POST /v1/drt/pools/{pool_pda}/revoke`     — revoke credential(s)
//! - `GET  /v1/drt/pools/{pool_pda}/revocations` — list revocations
//! - `GET  /v1/drt/pools/{pool_pda}/audit`      — pool-scoped audit log
//! - `GET  /v1/drt/pools/{pool_pda}/summary`    — pool metadata + on-chain state
//! - `GET  /v1/drt/pools/by-wallet/{wallet_id}` — list pools owned by wallet

use axum::{
    extract::{Multipart, Path, Query, State},
    Json,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use solana_sdk::{pubkey::Pubkey, signer::Signer};
use std::str::FromStr;
use std::sync::Arc;
use tracing::{info, warn};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use crate::auth::AdminToken;
use crate::blockchain::drt::{
    accounts::{fetch_pool, find_drt_in_pool},
    instructions::build_redeem_drt,
    pda::derive_user_ata,
};
use crate::error::ApiError;
use crate::handlers::{parse_csv_payload, validate_payload};
use crate::state::AppState;
use crate::storage::audit::{AuditEvent, AuditEventType, AuditRepository};
use crate::storage::pool_metadata::{PoolMetadata, PoolState};
use crate::storage::repository::wallets::{WalletRepository, WalletStatus};

use super::pools::{load_wallet_keypair, sign_send_and_parse, verify_pool_ownership};

// ============================================================================
// Request / Response types
// ============================================================================

/// Response for pool initialization.
#[derive(Debug, Serialize, ToSchema)]
pub struct InitializePoolResponse {
    /// Number of credential rows stored.
    pub rows: u64,
    /// Record ID of the stored dataset.
    pub record_id: String,
    /// Pool lifecycle state after initialization.
    pub state: String,
}

/// Response for credential issuance.
#[derive(Debug, Serialize, ToSchema)]
pub struct IssueCredentialsResponse {
    /// UUID of the stored credential record.
    pub record_id: String,
    /// Number of credential rows issued.
    pub rows_issued: u64,
    /// Transaction signature of the append DRT redemption.
    pub redeem_signature: String,
    /// Updated total credential count for the pool.
    pub total_credentials: u64,
    /// Solana Explorer URL for the redeem transaction.
    pub explorer_url: String,
}

/// Revocation request body.
#[derive(Debug, Deserialize, ToSchema)]
pub struct RevokeCredentialsRequest {
    /// Wallet ID of the pool owner.
    pub wallet_id: String,
    /// Credential record IDs to revoke (UUIDs from `/issue` responses).
    pub credential_ids: Vec<String>,
    /// Optional reason for revocation.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Revocation response.
#[derive(Debug, Serialize, ToSchema)]
pub struct RevokeCredentialsResponse {
    /// Number of credentials revoked.
    pub revoked: usize,
}

/// Single revocation entry.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RevocationEntry {
    pub credential_id: String,
    pub revoked_by: String,
    pub revoked_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Revocation list response.
#[derive(Debug, Serialize, ToSchema)]
pub struct RevocationsResponse {
    pub pool_pda: String,
    pub revocations: Vec<RevocationEntry>,
    pub total: usize,
}

/// Pool-scoped audit query parameters.
#[derive(Debug, Deserialize, IntoParams)]
pub struct PoolAuditQuery {
    /// Maximum number of events to return (default: 50).
    #[serde(default = "default_limit")]
    pub limit: usize,
    /// Offset for pagination (default: 0).
    #[serde(default)]
    pub offset: usize,
}

fn default_limit() -> usize {
    50
}

/// Pool-scoped audit response.
#[derive(Debug, Serialize, ToSchema)]
pub struct PoolAuditResponse {
    pub pool_pda: String,
    pub events: Vec<AuditEvent>,
    pub total: usize,
}

/// Pool summary response (enclave metadata + on-chain state).
#[derive(Debug, Serialize, ToSchema)]
pub struct PoolSummaryResponse {
    pub pool_pda: String,
    pub pool_name: String,
    pub owner: String,
    pub schema_id: String,
    pub state: String,
    pub total_credentials: u64,
    pub revoked_count: u64,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initialized_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_issue_at: Option<String>,
    /// On-chain DRT configuration.
    pub drts: Vec<DrtConfigResponseCompact>,
    /// Recent audit events (last 10).
    pub recent_events: Vec<AuditEvent>,
}

/// Compact DRT config for the summary endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct DrtConfigResponseCompact {
    pub drt_type: String,
    pub supply: u64,
    pub cost: u64,
    pub is_minted: bool,
}

/// Single pool entry in the list response.
#[derive(Debug, Serialize, ToSchema)]
pub struct PoolListEntry {
    pub pool_pda: String,
    pub pool_name: String,
    pub total_credentials: u64,
    pub revoked_count: u64,
    pub schema_id: String,
    pub state: String,
    pub created_at: String,
}

/// List pools by wallet response.
#[derive(Debug, Serialize, ToSchema)]
pub struct PoolsByWalletResponse {
    pub wallet_id: String,
    pub pools: Vec<PoolListEntry>,
}

/// Metadata for a stored credential dataset file.
#[derive(Debug, Serialize, Deserialize)]
struct DatasetFileMeta {
    record_id: String,
    uploaded_by: String,
    rows: u64,
    uploaded_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    redeem_tx_signature: Option<String>,
}

// ============================================================================
// Helpers
// ============================================================================

/// Acquire the per-pool mutex from the DashMap. Creates a new entry if absent.
fn acquire_pool_lock(
    state: &AppState,
    pool_pda: &str,
) -> Arc<tokio::sync::Mutex<()>> {
    state
        .pool_locks
        .entry(pool_pda.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
}

/// Load pool metadata from enclave storage, returning a helpful error if missing.
fn load_pool_meta(state: &AppState, pool_pda: &str) -> Result<PoolMetadata, ApiError> {
    let meta_path = state.storage.paths().pool_meta(pool_pda);
    state.storage.read_json::<PoolMetadata>(&meta_path).map_err(|_| {
        ApiError::not_found(format!(
            "pool metadata not found for {pool_pda} — pool may need initialization"
        ))
    })
}

/// Save pool metadata back to storage.
fn save_pool_meta(state: &AppState, pool_pda: &str, meta: &PoolMetadata) -> Result<(), ApiError> {
    let meta_path = state.storage.paths().pool_meta(pool_pda);
    state.storage.write_json(&meta_path, meta).map_err(|e| {
        ApiError::internal(format!("failed to write pool metadata: {e}"))
    })
}

/// Recover pool directory structure if it was lost after on-chain creation.
/// Returns true if recovery was needed.
fn ensure_pool_dirs(state: &AppState, pool_pda: &str) -> Result<bool, ApiError> {
    let dataset_dir = state.storage.paths().pool_dataset_dir(pool_pda);
    if state.storage.exists(&dataset_dir) {
        return Ok(false);
    }
    state.storage.create_dir(&dataset_dir).map_err(|e| {
        ApiError::internal(format!("failed to create pool directory: {e}"))
    })?;
    Ok(true)
}

/// Count CSV rows (excluding header).
fn count_csv_rows(csv_bytes: &[u8]) -> u64 {
    let text = String::from_utf8_lossy(csv_bytes);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    if lines.len() > 1 {
        (lines.len() - 1) as u64 // subtract header
    } else {
        0
    }
}

// ============================================================================
// Handlers
// ============================================================================

/// Seed the initial dataset for a pool.
///
/// The pool must be in `needs_init` state. No append DRT is required —
/// this is the initial seeding by the pool creator.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/initialize",
    tag = "Credentials",
    summary = "Initialize pool dataset",
    description = "Seed the initial credential dataset for a pool. Requires the pool to be in `needs_init` state. No DRT required — only the pool creator can call this.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
    ),
    responses(
        (status = 200, description = "Dataset initialized", body = InitializePoolResponse),
        (status = 400, description = "Validation error or pool already initialized"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not pool owner"),
        (status = 404, description = "Pool not found"),
    )
)]
pub async fn initialize_pool(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    multipart: Multipart,
) -> Result<Json<InitializePoolResponse>, ApiError> {
    // Parse and decrypt the CSV payload.
    let parsed = parse_csv_payload(multipart).await?;

    // Validate the pool PDA format.
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    // Fetch on-chain pool to verify it exists and get ownership.
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;

    // Load wallet for ownership verification.
    // We need `wallet_id` — extract from multipart or fall back to first wallet.
    let repo = WalletRepository::new(&state.storage);
    let wallets = repo.list_by_owner(&token.sub)?;
    let wallet = wallets
        .iter()
        .find(|w| w.status == WalletStatus::Active)
        .ok_or_else(|| ApiError::bad_request("no active wallet found"))?;

    // Verify caller owns the on-chain pool.
    verify_pool_ownership(&pool, wallet)?;

    // Ensure pool dirs exist (idempotent recovery).
    let recovered = ensure_pool_dirs(&state, &pool_pda_str)?;
    if recovered {
        warn!(pool = %pool_pda_str, "Recovered pool directory structure");
    }

    // Load or create pool metadata.
    let mut meta = match load_pool_meta(&state, &pool_pda_str) {
        Ok(m) => m,
        Err(_) if recovered => {
            // Bootstrap recovery — create metadata from chain state.
            PoolMetadata {
                pool_pda: pool_pda_str.clone(),
                pool_name: pool.name.clone(),
                owner_wallet_id: wallet.wallet_id.clone(),
                schema_id: parsed.schema_id.clone(),
                state: PoolState::NeedsInit,
                created_onchain_at: Utc::now(),
                initialized_at: None,
                last_issue_at: None,
                total_credentials: 0,
                revoked_count: 0,
            }
        }
        Err(e) => return Err(e),
    };

    // Verify pool is in `needs_init` state.
    if meta.state != PoolState::NeedsInit {
        return Err(ApiError::bad_request(
            "pool is already initialized — use /issue to add credentials",
        ));
    }

    // Validate CSV against the pool's schema.
    let summary = validate_payload(&meta.schema_id, &parsed.csv_bytes)?;
    if !summary.valid {
        return Err(ApiError::bad_request(format!(
            "CSV validation failed: {} error(s)",
            summary.errors.len()
        )));
    }

    let row_count = count_csv_rows(&parsed.csv_bytes);
    let record_id = "initial".to_string();

    // Store the CSV dataset.
    let dataset_dir = state.storage.paths().pool_dataset_dir(&pool_pda_str);
    let csv_path = dataset_dir.join("initial.csv");
    let meta_file_path = dataset_dir.join("initial.meta.json");

    state.storage.write_raw(&csv_path, &parsed.csv_bytes).map_err(|e| {
        ApiError::internal(format!("failed to write initial dataset: {e}"))
    })?;

    let file_meta = DatasetFileMeta {
        record_id: record_id.clone(),
        uploaded_by: token.sub.clone(),
        rows: row_count,
        uploaded_at: Utc::now().to_rfc3339(),
        redeem_tx_signature: None,
    };
    state.storage.write_json(&meta_file_path, &file_meta).map_err(|e| {
        ApiError::internal(format!("failed to write dataset metadata: {e}"))
    })?;

    // Update pool metadata.
    meta.state = PoolState::Ready;
    meta.initialized_at = Some(Utc::now());
    meta.total_credentials = row_count;
    save_pool_meta(&state, &pool_pda_str, &meta)?;

    // Log audit event.
    let audit_event = AuditEvent::new(AuditEventType::DatasetInitialized)
        .with_user(&token.sub)
        .with_resource("drt_pool", &pool_pda_str)
        .with_details(serde_json::json!({
            "pool_pda": pool_pda_str,
            "record_id": record_id,
            "row_count": row_count,
            "schema_id": meta.schema_id,
            "state_transition": "needs_init -> ready"
        }));
    AuditRepository::new(&state.storage).log(&audit_event).await;

    info!(
        pool = %pool_pda_str,
        rows = row_count,
        schema = %meta.schema_id,
        "Pool dataset initialized"
    );

    Ok(Json(InitializePoolResponse {
        rows: row_count,
        record_id,
        state: "ready".to_string(),
    }))
}

/// Issue credentials to a pool (append-DRT gated).
///
/// Burns 1 append DRT on-chain, then stores the encrypted CSV dataset
/// in the pool's directory.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/issue",
    tag = "Credentials",
    summary = "Issue credentials",
    description = "Issue credentials by redeeming an append DRT and storing encrypted CSV data. Validates ownership, DRT balance, CSV schema, then burns 1 append DRT and stores the dataset.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
    ),
    responses(
        (status = 200, description = "Credentials issued", body = IssueCredentialsResponse),
        (status = 400, description = "Validation error or insufficient DRTs"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not pool owner"),
        (status = 404, description = "Pool not found"),
        (status = 503, description = "Solana RPC unavailable"),
    )
)]
pub async fn issue_credentials(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    multipart: Multipart,
) -> Result<Json<IssueCredentialsResponse>, ApiError> {
    // ── VALIDATION (reversible, cheap) ────────────────────────────

    // Parse and decrypt the CSV payload.
    let parsed = parse_csv_payload(multipart).await?;

    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    // Load pool metadata — must be in Ready state.
    let meta = load_pool_meta(&state, &pool_pda_str)?;
    if meta.state != PoolState::Ready {
        return Err(ApiError::bad_request(
            "pool not initialized — call /initialize first",
        ));
    }

    // Load caller's wallet and verify pool ownership.
    let repo = WalletRepository::new(&state.storage);
    let (wallet, keypair) = load_wallet_keypair(
        &repo,
        &meta.owner_wallet_id,
        &token.sub,
    )?;

    // Fetch on-chain pool and verify ownership.
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    verify_pool_ownership(&pool, &wallet)?;

    // Find the "append" DRT config in the pool.
    let append_drt = find_drt_in_pool(&pool, "append")?;

    // Check wallet has ≥1 append DRT.
    let user_pubkey = Pubkey::from_str(&wallet.public_address)
        .map_err(|_| ApiError::internal("invalid stored wallet address"))?;
    let user_ata = derive_user_ata(&user_pubkey, &append_drt.mint);
    let user_balance = match state.solana_client.rpc().get_token_account_balance(&user_ata).await {
        Ok(b) => b.amount.parse::<u64>().unwrap_or(0),
        Err(_) => 0,
    };
    if user_balance < 1 {
        return Err(ApiError::bad_request(
            "insufficient append DRTs — buy more before issuing",
        ));
    }

    // Validate CSV against pool's schema.
    let summary = validate_payload(&meta.schema_id, &parsed.csv_bytes)?;
    if !summary.valid {
        return Err(ApiError::bad_request(format!(
            "CSV validation failed: {} error(s)",
            summary.errors.len()
        )));
    }

    let row_count = count_csv_rows(&parsed.csv_bytes);

    // ── ACQUIRE POOL LOCK ─────────────────────────────────────────
    let lock = acquire_pool_lock(&state, &pool_pda_str);
    let _guard = lock.lock().await;

    // ── IRREVERSIBLE OPERATIONS ───────────────────────────────────

    // 1. Redeem (burn) 1 append DRT on-chain.
    let ix = build_redeem_drt(&pool_pda, &keypair.pubkey(), "append", &append_drt.mint)
        .map_err(ApiError::internal)?;

    let (sig_str, _events) = match sign_send_and_parse(
        &state,
        &keypair,
        vec![ix],
        solana_commitment_config::CommitmentConfig::finalized(),
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            // DRT not burned — clean failure.
            return Err(e);
        }
    };

    // 2. Store CSV dataset.
    let record_id = Uuid::new_v4().to_string();
    let dataset_dir = state.storage.paths().pool_dataset_dir(&pool_pda_str);
    let csv_path = dataset_dir.join(format!("{record_id}.csv"));
    let meta_file_path = dataset_dir.join(format!("{record_id}.meta.json"));

    if let Err(e) = state.storage.write_raw(&csv_path, &parsed.csv_bytes) {
        // DRT was burned but file write failed — audit log this edge case.
        warn!(
            pool = %pool_pda_str,
            record_id = %record_id,
            redeem_sig = %sig_str,
            error = %e,
            "DRT burned but file write failed"
        );
        let fail_event = AuditEvent::new(AuditEventType::CredentialIssuanceFailed)
            .with_user(&token.sub)
            .with_resource("drt_pool", &pool_pda_str)
            .with_details(serde_json::json!({
                "pool_pda": pool_pda_str,
                "record_id": record_id,
                "redeem_tx_sig": sig_str,
                "error": e.to_string()
            }));
        AuditRepository::new(&state.storage).log(&fail_event).await;

        return Err(ApiError::internal(format!(
            "DRT burned (sig: {sig_str}) but file write failed — contact admin for recovery"
        )));
    }

    let file_meta = DatasetFileMeta {
        record_id: record_id.clone(),
        uploaded_by: token.sub.clone(),
        rows: row_count,
        uploaded_at: Utc::now().to_rfc3339(),
        redeem_tx_signature: Some(sig_str.clone()),
    };
    // Best-effort metadata write.
    if let Err(e) = state.storage.write_json(&meta_file_path, &file_meta) {
        warn!(
            pool = %pool_pda_str,
            record_id = %record_id,
            error = %e,
            "Failed to write dataset file metadata"
        );
    }

    // 3. Update pool.meta.json.
    let mut updated_meta = load_pool_meta(&state, &pool_pda_str)?;
    updated_meta.total_credentials += row_count;
    updated_meta.last_issue_at = Some(Utc::now());
    save_pool_meta(&state, &pool_pda_str, &updated_meta)?;

    // 4. Audit log.
    let audit_event = AuditEvent::new(AuditEventType::CredentialIssued)
        .with_user(&token.sub)
        .with_resource("drt_pool", &pool_pda_str)
        .with_details(serde_json::json!({
            "pool_pda": pool_pda_str,
            "record_id": record_id,
            "row_count": row_count,
            "redeem_tx_sig": sig_str,
            "total_credentials": updated_meta.total_credentials
        }));
    AuditRepository::new(&state.storage).log(&audit_event).await;

    let explorer_url = state.solana_client.network().explorer_tx_url(&sig_str);

    info!(
        pool = %pool_pda_str,
        record_id = %record_id,
        rows = row_count,
        redeem_sig = %sig_str,
        total = updated_meta.total_credentials,
        "Credentials issued"
    );

    Ok(Json(IssueCredentialsResponse {
        record_id,
        rows_issued: row_count,
        redeem_signature: sig_str,
        total_credentials: updated_meta.total_credentials,
        explorer_url,
    }))
}

/// Revoke credential(s) from a pool.
///
/// Appends revocation entries to the pool's `revocations.jsonl` sidecar file.
/// This is an enclave-side soft revocation — on-chain revocation may be added later.
#[utoipa::path(
    post,
    path = "/v1/drt/pools/{pool_pda}/revoke",
    tag = "Credentials",
    summary = "Revoke credentials",
    description = "Revoke one or more credentials by record ID. Writes revocation entries to the pool's sidecar file. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
    ),
    request_body = RevokeCredentialsRequest,
    responses(
        (status = 200, description = "Credentials revoked", body = RevokeCredentialsResponse),
        (status = 400, description = "Validation error"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not pool owner"),
        (status = 404, description = "Pool or credential not found"),
    )
)]
pub async fn revoke_credentials(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    Json(payload): Json<RevokeCredentialsRequest>,
) -> Result<Json<RevokeCredentialsResponse>, ApiError> {
    if payload.credential_ids.is_empty() {
        return Err(ApiError::bad_request("credential_ids must not be empty"));
    }

    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    // Verify ownership.
    let repo = WalletRepository::new(&state.storage);
    let (wallet, _) = load_wallet_keypair(&repo, &payload.wallet_id, &token.sub)?;

    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    verify_pool_ownership(&pool, &wallet)?;

    // Verify pool metadata exists.
    let _meta = load_pool_meta(&state, &pool_pda_str)?;

    // Verify each credential_id references an existing dataset file.
    let dataset_dir = state.storage.paths().pool_dataset_dir(&pool_pda_str);
    for cid in &payload.credential_ids {
        let csv_path = if cid == "initial" {
            dataset_dir.join("initial.csv")
        } else {
            dataset_dir.join(format!("{cid}.csv"))
        };
        if !state.storage.exists(&csv_path) {
            return Err(ApiError::not_found(format!(
                "credential record '{cid}' not found in pool"
            )));
        }
    }

    // Append revocation entries to JSONL file.
    let revocations_path = state.storage.paths().pool_revocations(&pool_pda_str);
    let now = Utc::now().to_rfc3339();
    let mut lines = String::new();
    for cid in &payload.credential_ids {
        let entry = RevocationEntry {
            credential_id: cid.clone(),
            revoked_by: token.sub.clone(),
            revoked_at: now.clone(),
            reason: payload.reason.clone(),
        };
        let json = serde_json::to_string(&entry)
            .map_err(|e| ApiError::internal(format!("failed to serialize revocation: {e}")))?;
        lines.push_str(&json);
        lines.push('\n');
    }

    // Append to file (create if missing).
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&revocations_path)
        .map_err(|e| ApiError::internal(format!("failed to open revocations file: {e}")))?;
    file.write_all(lines.as_bytes())
        .map_err(|e| ApiError::internal(format!("failed to write revocations: {e}")))?;

    // Update pool metadata.
    let revoked_count = payload.credential_ids.len();
    let mut updated_meta = load_pool_meta(&state, &pool_pda_str)?;
    updated_meta.revoked_count += revoked_count as u64;
    save_pool_meta(&state, &pool_pda_str, &updated_meta)?;

    // Audit log.
    let audit_event = AuditEvent::new(AuditEventType::CredentialRevoked)
        .with_user(&token.sub)
        .with_resource("drt_pool", &pool_pda_str)
        .with_details(serde_json::json!({
            "pool_pda": pool_pda_str,
            "credential_ids": payload.credential_ids,
            "revoked_count": revoked_count,
            "reason": payload.reason
        }));
    AuditRepository::new(&state.storage).log(&audit_event).await;

    info!(
        pool = %pool_pda_str,
        count = revoked_count,
        "Credentials revoked"
    );

    Ok(Json(RevokeCredentialsResponse {
        revoked: revoked_count,
    }))
}

/// List revocation entries for a pool.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/revocations",
    tag = "Credentials",
    summary = "List revocations",
    description = "List all revocation entries for a pool. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
    ),
    responses(
        (status = 200, description = "Revocation list", body = RevocationsResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not pool owner"),
        (status = 404, description = "Pool not found"),
    )
)]
pub async fn list_revocations(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
) -> Result<Json<RevocationsResponse>, ApiError> {
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    // Verify ownership.
    let repo = WalletRepository::new(&state.storage);
    let wallets = repo.list_by_owner(&token.sub)?;
    let wallet = wallets
        .iter()
        .find(|w| w.status == WalletStatus::Active)
        .ok_or_else(|| ApiError::bad_request("no active wallet found"))?;

    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    verify_pool_ownership(&pool, wallet)?;

    // Read revocations file.
    let revocations_path = state.storage.paths().pool_revocations(&pool_pda_str);
    let entries: Vec<RevocationEntry> = match std::fs::read_to_string(&revocations_path) {
        Ok(data) => data
            .lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect(),
        Err(_) => Vec::new(),
    };

    let total = entries.len();

    Ok(Json(RevocationsResponse {
        pool_pda: pool_pda_str,
        revocations: entries,
        total,
    }))
}

/// Query pool-scoped audit events.
///
/// Scans daily JSONL files from pool creation to now, filtering by pool PDA.
/// Supports pagination via `limit` and `offset` query parameters.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/audit",
    tag = "Credentials",
    summary = "Pool audit log",
    description = "Query audit events scoped to a specific pool. Iterates daily JSONL files and filters by pool PDA. Admin only.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
        PoolAuditQuery,
    ),
    responses(
        (status = 200, description = "Audit events", body = PoolAuditResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not pool owner"),
        (status = 404, description = "Pool not found"),
    )
)]
pub async fn pool_audit(
    AdminToken(token): AdminToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
    Query(query): Query<PoolAuditQuery>,
) -> Result<Json<PoolAuditResponse>, ApiError> {
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    // Verify ownership.
    let repo = WalletRepository::new(&state.storage);
    let wallets = repo.list_by_owner(&token.sub)?;
    let wallet = wallets
        .iter()
        .find(|w| w.status == WalletStatus::Active)
        .ok_or_else(|| ApiError::bad_request("no active wallet found"))?;

    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;
    verify_pool_ownership(&pool, wallet)?;

    // Load pool metadata for creation date.
    let meta = load_pool_meta(&state, &pool_pda_str)?;
    let start_date = meta.created_onchain_at.date_naive();
    let end_date = Utc::now().date_naive();

    // Iterate over date range and collect matching events.
    let audit = AuditRepository::new(&state.storage);
    let mut all_events: Vec<AuditEvent> = Vec::new();

    let mut current = start_date;
    while current <= end_date {
        let date_str = current.format("%Y-%m-%d").to_string();
        let events = audit.read_verified_events(&date_str);
        // Filter events that reference this pool.
        for event in events {
            if event.resource_id.as_deref() == Some(&pool_pda_str) {
                all_events.push(event);
            }
        }
        current = current.succ_opt().unwrap_or(end_date);
        if current == end_date && start_date != end_date {
            // Include end date.
            let date_str = current.format("%Y-%m-%d").to_string();
            let events = audit.read_verified_events(&date_str);
            for event in events {
                if event.resource_id.as_deref() == Some(&pool_pda_str) {
                    all_events.push(event);
                }
            }
            break;
        }
    }

    // Deduplicate (the loop above might scan end_date twice).
    all_events.dedup_by(|a, b| a.event_id == b.event_id);

    let total = all_events.len();

    // Apply pagination.
    let offset = query.offset.min(total);
    let limit = query.limit.min(200); // cap at 200
    let page: Vec<AuditEvent> = all_events.into_iter().skip(offset).take(limit).collect();

    Ok(Json(PoolAuditResponse {
        pool_pda: pool_pda_str,
        events: page,
        total,
    }))
}

/// Get pool summary (enclave metadata + on-chain state + recent events).
#[utoipa::path(
    get,
    path = "/v1/drt/pools/{pool_pda}/summary",
    tag = "Credentials",
    summary = "Pool summary",
    description = "Combined view of pool enclave metadata, on-chain DRT state, and recent audit events.",
    security(("bearer_auth" = [])),
    params(
        ("pool_pda" = String, Path, description = "Pool PDA address (base58)"),
    ),
    responses(
        (status = 200, description = "Pool summary", body = PoolSummaryResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Pool not found"),
    )
)]
pub async fn pool_summary(
    AdminToken(_token): AdminToken,
    State(state): State<AppState>,
    Path(pool_pda_str): Path<String>,
) -> Result<Json<PoolSummaryResponse>, ApiError> {
    let pool_pda = Pubkey::from_str(&pool_pda_str)
        .map_err(|_| ApiError::bad_request("invalid pool PDA address"))?;

    // Load enclave metadata.
    let meta = load_pool_meta(&state, &pool_pda_str)?;

    // Fetch on-chain pool.
    let pool = fetch_pool(state.solana_client.rpc(), &pool_pda).await?;

    let drts: Vec<DrtConfigResponseCompact> = pool
        .drts
        .iter()
        .map(|d| DrtConfigResponseCompact {
            drt_type: d.drt_type.clone(),
            supply: d.supply,
            cost: d.cost,
            is_minted: d.is_minted,
        })
        .collect();

    // Recent audit events (last 10 from today, best-effort).
    let today = Utc::now().format("%Y-%m-%d").to_string();
    let audit = AuditRepository::new(&state.storage);
    let today_events = audit.read_verified_events(&today);
    let recent_events: Vec<AuditEvent> = today_events
        .into_iter()
        .filter(|e| e.resource_id.as_deref() == Some(&pool_pda_str))
        .rev()
        .take(10)
        .collect();

    let state_str = match meta.state {
        PoolState::NeedsInit => "needs_init",
        PoolState::Ready => "ready",
    };

    Ok(Json(PoolSummaryResponse {
        pool_pda: pool_pda_str,
        pool_name: meta.pool_name,
        owner: pool.owner.to_string(),
        schema_id: meta.schema_id,
        state: state_str.to_string(),
        total_credentials: meta.total_credentials,
        revoked_count: meta.revoked_count,
        created_at: meta.created_onchain_at.to_rfc3339(),
        initialized_at: meta.initialized_at.map(|d| d.to_rfc3339()),
        last_issue_at: meta.last_issue_at.map(|d| d.to_rfc3339()),
        drts,
        recent_events,
    }))
}

/// List pools owned by a specific wallet.
///
/// Scans the enclave's `/data/pools/` directory for pools where the
/// `owner_wallet_id` matches. Enclave-side discovery only — no on-chain indexing.
#[utoipa::path(
    get,
    path = "/v1/drt/pools/by-wallet/{wallet_id}",
    tag = "Credentials",
    summary = "List pools by wallet",
    description = "List all pools owned by a specific wallet. Reads from enclave storage.",
    security(("bearer_auth" = [])),
    params(
        ("wallet_id" = String, Path, description = "Wallet UUID"),
    ),
    responses(
        (status = 200, description = "Pool list", body = PoolsByWalletResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Not wallet owner"),
    )
)]
pub async fn list_pools_by_wallet(
    crate::auth::UserToken(token): crate::auth::UserToken,
    State(state): State<AppState>,
    Path(wallet_id): Path<String>,
) -> Result<Json<PoolsByWalletResponse>, ApiError> {
    // Verify wallet ownership.
    let repo = WalletRepository::new(&state.storage);
    let wallet = repo.get(&wallet_id)?;
    crate::storage::ownership::OwnershipEnforcer::verify_ownership(&wallet, &token.sub)?;

    // Scan pools directory.
    let pools_dir = state.storage.paths().pools_dir();
    let pool_dirs = match state.storage.list_dirs(&pools_dir) {
        Ok(dirs) => dirs,
        Err(_) => Vec::new(),
    };

    let mut pools: Vec<PoolListEntry> = Vec::new();
    for pda in pool_dirs {
        let meta_path = state.storage.paths().pool_meta(&pda);
        if let Ok(meta) = state.storage.read_json::<PoolMetadata>(&meta_path) {
            if meta.owner_wallet_id == wallet_id {
                let state_str = match meta.state {
                    PoolState::NeedsInit => "needs_init",
                    PoolState::Ready => "ready",
                };
                pools.push(PoolListEntry {
                    pool_pda: meta.pool_pda,
                    pool_name: meta.pool_name,
                    total_credentials: meta.total_credentials,
                    revoked_count: meta.revoked_count,
                    schema_id: meta.schema_id,
                    state: state_str.to_string(),
                    created_at: meta.created_onchain_at.to_rfc3339(),
                });
            }
        }
    }

    Ok(Json(PoolsByWalletResponse {
        wallet_id,
        pools,
    }))
}
