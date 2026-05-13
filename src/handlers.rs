// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! HTTP request handlers for the enclave API.
//!
//! This module contains handlers for:
//! - Public key endpoint (for browser encryption)
//! - Protected endpoints (require authentication)
//! - Admin endpoints (require admin role)
//! - Data endpoints (require appropriate roles)

use axum::{
    extract::{Multipart, State},
    Json,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::{AdminToken, ReadOnlyToken, UserToken};
use crate::config::MAX_BODY_SIZE;
use crate::crypto::{enclave_key, Jwk};
use crate::data_validation::{
    load_pool_schema, validate_csv_bytes, ValidationMode, ValidationSummary,
};
use crate::error::ApiError;
use crate::state::AppState;
use crate::storage::paths::StoragePaths;

// ============================================================================
// Public Key Endpoint
// ============================================================================

/// Get the enclave's public key for encrypting data.
///
/// Browsers use this key to encrypt payloads that only the enclave can decrypt.
/// The key is ephemeral and generated at enclave startup.
///
/// **Note:** In production, verify this key via AVS attestation tokens instead
/// of fetching directly.
#[utoipa::path(
    get,
    path = "/v1/attestation/public-key",
    tag = "Attestation",
    summary = "Get enclave public key",
    description = "Returns the enclave's P-256 public key in JWK format for browser encryption.",
    responses(
        (status = 200, description = "Public key returned", body = Jwk)
    )
)]
pub async fn get_public_key() -> Json<Jwk> {
    debug!("Serving enclave public key");
    let key = enclave_key();
    Json(key.public_jwk().clone())
}

// ============================================================================
// Admin Endpoints
// ============================================================================

/// Response for admin status endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdminStatusResponse {
    pub status: String,
    pub admin_user: String,
    pub uptime_seconds: u64,
}

/// Admin-only status endpoint.
///
/// Returns enclave operational status. Requires admin role.
#[utoipa::path(
    get,
    path = "/v1/admin/status",
    tag = "Admin",
    summary = "Admin status",
    description = "Returns enclave status. Requires admin role.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Status returned", body = AdminStatusResponse),
        (status = 401, description = "Unauthorized - missing or invalid token"),
        (status = 403, description = "Forbidden - admin role required")
    )
)]
pub async fn admin_status(AdminToken(token): AdminToken) -> Json<AdminStatusResponse> {
    info!(admin_user = %token.sub, "Admin status requested");
    let uptime_seconds = crate::STARTED_AT
        .get()
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);
    Json(AdminStatusResponse {
        status: "operational".to_string(),
        admin_user: token.sub,
        uptime_seconds,
    })
}

// ============================================================================
// Data Endpoints
// ============================================================================

#[derive(Debug, Default)]
pub(crate) struct MultipartCsvInput {
    pub schema_id: Option<String>,
    pub file: Option<Vec<u8>>,
    pub encrypted_data: Option<String>,
    pub ephemeral_public_key: Option<String>,
    pub nonce: Option<String>,
    /// Optional wallet_id field (used by pool-scoped endpoints like `/initialize`, `/issue`).
    pub wallet_id: Option<String>,
}

pub(crate) struct ParsedCsvPayload {
    pub schema_id: String,
    pub csv_bytes: Vec<u8>,
}

/// Request body for data upload.
///
/// 1. Decode `encrypted_data`, `ephemeral_public_key`, and `iv` from base64
/// 2. Perform ECDH key agreement using the ephemeral public key + enclave private key
/// 3. Derive AES-256-GCM key via HKDF, decrypt ciphertext
/// 4. Validate `nonce` for replay protection (reject reused nonces)
/// 5. Store decrypted payload to Gramine encrypted FS
#[derive(Debug, Deserialize, ToSchema)]
pub struct DataUploadRequest {
    /// Base64-encoded AES-GCM ciphertext (encrypted with derived ECDH shared secret).
    pub encrypted_data: String,
    /// Base64-encoded ephemeral P-256 public key (SEC1 uncompressed bytes).
    /// The client generates this per-upload for forward secrecy.
    pub ephemeral_public_key: String,
    /// Base64-encoded 12-byte AES-GCM nonce/IV used for encryption.
    pub iv: String,
    /// Unique nonce for replay protection (required). Reject duplicate nonces.
    pub nonce: String,
}

/// Response for data upload.
#[derive(Debug, Serialize, ToSchema)]
pub struct DataUploadResponse {
    pub status: String,
    pub record_id: String,
}

/// Upload encrypted data to the enclave.
///
/// Requires user or admin role. The data should be encrypted with
/// the enclave's public key obtained via AVS attestation.
#[utoipa::path(
    post,
    path = "/v1/data/upload",
    tag = "Data",
    summary = "Upload encrypted data",
    description = "Upload encrypted data to the enclave. Requires user or admin role.",
    security(("bearer_auth" = [])),
    request_body = DataUploadRequest,
    responses(
        (status = 200, description = "Data uploaded", body = DataUploadResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - user role required")
    )
)]
pub async fn data_upload(
    UserToken(token): UserToken,
    State(state): State<AppState>,
    Json(payload): Json<DataUploadRequest>,
) -> Result<Json<DataUploadResponse>, ApiError> {
    let record_id = Uuid::new_v4().to_string();
    info!(
        sub = %token.sub,
        role = %token.role,
        record_id = %record_id,
        data_size = payload.encrypted_data.len(),
        "Data upload received"
    );

    // ── 1. Nonce replay protection (mandatory) ──────────────────────
    {
        let is_new = state
            .tx_db
            .record_nonce(&payload.nonce)
            .map_err(|e| ApiError::internal(format!("nonce check failed: {e}")))?;
        if !is_new {
            return Err(ApiError::conflict("nonce already used — replay rejected"));
        }
        debug!(nonce = %payload.nonce, "Nonce accepted (first use)");
    }

    // ── 2. ECDH-ES + AES-256-GCM decryption ─────────────────────────
    let plaintext = crate::crypto::decrypt_ecdh_payload(
        &payload.encrypted_data,
        &payload.ephemeral_public_key,
        &payload.iv,
    )
    .map_err(ApiError::bad_request)?;

    // ── 3. Store decrypted data to encrypted FS (Gramine auto-encrypts at rest)
    let upload_dir = state
        .storage
        .paths()
        .root()
        .join("uploads")
        .join("decrypted");
    state.storage.create_dir(&upload_dir)?;

    let data_path = upload_dir.join(format!("{record_id}.bin"));
    state.storage.write_raw(&data_path, &plaintext)?;

    // Persist metadata for audit/query.
    let meta = serde_json::json!({
        "record_id": record_id,
        "uploaded_by": token.sub,
        "plaintext_size_bytes": plaintext.len(),
        "uploaded_at": chrono::Utc::now().to_rfc3339(),
    });
    let meta_path = upload_dir.join(format!("{record_id}.meta.json"));
    state.storage.write_json(&meta_path, &meta)?;

    info!(
        sub = %token.sub,
        record_id = %record_id,
        plaintext_size = plaintext.len(),
        "Decrypted data stored to encrypted FS"
    );

    Ok(Json(DataUploadResponse {
        status: "stored".to_string(),
        record_id,
    }))
}

/// Response for data query.
#[derive(Debug, Serialize, ToSchema)]
pub struct DataQueryResponse {
    pub results: Vec<String>,
    pub user: String,
}

/// Query data from the enclave.
///
/// Requires at least read_only role.
#[utoipa::path(
    get,
    path = "/v1/data/query",
    tag = "Data",
    summary = "Query data",
    description = "Query data from the enclave. Requires read_only, user, or admin role.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Query results", body = DataQueryResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - read_only role required")
    )
)]
pub async fn data_query(ReadOnlyToken(token): ReadOnlyToken) -> Json<DataQueryResponse> {
    info!(sub = %token.sub, role = %token.role, "Data query requested");
    // TODO: Implement secure query execution:
    // 1. Parse query parameters (add query params to endpoint if needed)
    // 2. Execute query against enclave-protected data store
    // 3. Optionally encrypt results for the requesting user
    // 4. Return results with pagination if needed
    Json(DataQueryResponse {
        results: vec!["sample_result".to_string()],
        user: token.sub,
    })
}

/// Validate a CSV payload against the pool's stored schema.
///
/// `mode == None` skips the schema lookup entirely. Other modes require the
/// schema to have been uploaded via `POST /v1/drt/pools/{pda}/schema`.
pub(crate) fn validate_payload(
    paths: &StoragePaths,
    pool_pda: &str,
    csv_bytes: &[u8],
    mode: ValidationMode,
) -> Result<ValidationSummary, ApiError> {
    if matches!(mode, ValidationMode::None) {
        return Ok(validate_csv_bytes(csv_bytes, &[], mode));
    }

    let schema = load_pool_schema(paths, pool_pda).ok_or_else(|| {
        ApiError::bad_request(format!(
            "schema for pool {pool_pda} not found — upload one to the enclave first",
        ))
    })?;

    Ok(validate_csv_bytes(csv_bytes, &schema, mode))
}

pub(crate) async fn parse_csv_payload(multipart: Multipart) -> Result<ParsedCsvPayload, ApiError> {
    let input = parse_multipart_fields(multipart).await?;
    let schema_id = input
        .schema_id
        .ok_or_else(|| ApiError::bad_request("schema_id is required"))?;

    // Only encrypted uploads are accepted — plaintext file uploads are rejected.
    if input.file.is_some() {
        return Err(ApiError::bad_request(
            "plaintext file uploads are not accepted — use encrypted_data with ephemeral_public_key and nonce",
        ));
    }

    let encrypted_data = input
        .encrypted_data
        .ok_or_else(|| ApiError::bad_request("missing encrypted_data field"))?;

    let ephemeral_key = input.ephemeral_public_key.ok_or_else(|| {
        ApiError::bad_request("ephemeral_public_key is required for encrypted uploads")
    })?;
    let nonce = input
        .nonce
        .ok_or_else(|| ApiError::bad_request("nonce is required for encrypted uploads"))?;

    let csv_bytes = crate::crypto::decrypt_ecdh_payload(&encrypted_data, &ephemeral_key, &nonce)
        .map_err(ApiError::bad_request)?;

    ensure_size_limit(&csv_bytes)?;

    Ok(ParsedCsvPayload {
        schema_id,
        csv_bytes,
    })
}

pub(crate) async fn parse_multipart_fields(
    mut multipart: Multipart,
) -> Result<MultipartCsvInput, ApiError> {
    let mut input = MultipartCsvInput::default();
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| ApiError::bad_request("invalid multipart payload"))?
    {
        let Some(name) = field.name().map(str::to_owned) else {
            continue;
        };

        match name.as_str() {
            "file" => {
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|_| ApiError::bad_request("failed to read file part"))?;
                input.file = Some(bytes.to_vec());
            }
            "schema_id" => {
                let value = field
                    .text()
                    .await
                    .map_err(|_| ApiError::bad_request("invalid schema_id field"))?;
                if !value.trim().is_empty() {
                    input.schema_id = Some(value.trim().to_string());
                }
            }
            "encrypted_data" => {
                let value = field
                    .text()
                    .await
                    .map_err(|_| ApiError::bad_request("invalid encrypted_data field"))?;
                if !value.trim().is_empty() {
                    input.encrypted_data = Some(value.trim().to_string());
                }
            }
            "ephemeral_public_key" => {
                let value = field
                    .text()
                    .await
                    .map_err(|_| ApiError::bad_request("invalid ephemeral_public_key field"))?;
                if !value.trim().is_empty() {
                    input.ephemeral_public_key = Some(value.trim().to_string());
                }
            }
            "nonce" => {
                let value = field
                    .text()
                    .await
                    .map_err(|_| ApiError::bad_request("invalid nonce field"))?;
                if !value.trim().is_empty() {
                    input.nonce = Some(value.trim().to_string());
                }
            }
            "wallet_id" => {
                let value = field
                    .text()
                    .await
                    .map_err(|_| ApiError::bad_request("invalid wallet_id field"))?;
                if !value.trim().is_empty() {
                    input.wallet_id = Some(value.trim().to_string());
                }
            }
            _ => {}
        }
    }
    Ok(input)
}

pub(crate) fn ensure_size_limit(bytes: &[u8]) -> Result<(), ApiError> {
    if bytes.len() > MAX_BODY_SIZE {
        return Err(ApiError::bad_request(format!(
            "payload exceeds maximum size of {} bytes",
            MAX_BODY_SIZE
        )));
    }
    Ok(())
}
