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

use crate::auth::{AdminToken, AnalystToken, UserToken};
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
    pub encrypted_data: Option<String>,
    pub ephemeral_public_key: Option<String>,
    pub nonce: Option<String>,
}

pub(crate) struct ParsedCsvPayload {
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

/// Request body for `/v1/data/query`.
#[derive(Debug, Deserialize, ToSchema)]
pub struct DataQueryRequest {
    /// Pool PDA (base58) the DRT script reads from.
    pub pool_pda: String,
    /// Name of the DRT to invoke — must be present in the pool's `drts` map.
    pub drt_name: String,
    /// Free-form arguments forwarded to the DRT as the `args` JSON field.
    #[serde(default)]
    pub args: serde_json::Value,
}

/// Response for `/v1/data/query`.
#[derive(Debug, Serialize, ToSchema)]
pub struct DataQueryResponse {
    /// Pool PDA the script ran against.
    pub pool_pda: String,
    /// DRT name that was invoked.
    pub drt_name: String,
    /// SHA-256 of the script that ran (matches on-chain `code_hash`).
    pub code_hash_hex: String,
    /// `run()` exit code from the WASM module. 0 = success.
    pub exit_code: i32,
    /// Script-emitted result as JSON.
    pub result: serde_json::Value,
}

/// Execute a DRT script against a pool inside the enclave.
///
/// Pipeline:
///
/// 1. Look up the pool and DRT metadata.
/// 2. Re-verify the script against the on-chain (mirrored) `code_hash`,
///    fetching from GitHub if not cached. Any mismatch fails the call.
/// 3. Read the pool's CSV datasets and concatenate them.
/// 4. Apply the row-level employer-group filter derived from the caller's
///    Entra claim. (Placeholder today — Entra plumb-through is Phase 2.5
///    backlog; for now the filter is a no-op and a TODO is emitted in logs.)
/// 5. Hand `{ csv, args }` to the wasmi sandbox; cap fuel + wall-clock + memory.
/// 6. Return whatever the script wrote — typically a small JSON blob.
///
/// Authorization: requires the analyst role. The `analyst_id` recorded in
/// the on-chain grant must match `token.sub` (verified by `commitment_hex`)
/// — TODO once the grant scan helper is wired (D3 backend).
#[utoipa::path(
    post,
    path = "/v1/data/query",
    tag = "Data",
    summary = "Run a DRT script against a pool",
    description = "Analyst-only. Fetches and verifies the DRT script, loads pool data, executes \
                   the script inside the WASM sandbox, and returns the result.",
    security(("bearer_auth" = [])),
    request_body = DataQueryRequest,
    responses(
        (status = 200, description = "Query result", body = DataQueryResponse),
        (status = 400, description = "Bad request / hash mismatch / script trap"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - analyst role required"),
        (status = 404, description = "Pool or DRT not found"),
    )
)]
pub async fn data_query(
    AnalystToken(token): AnalystToken,
    State(state): State<AppState>,
    Json(payload): Json<DataQueryRequest>,
) -> Result<Json<DataQueryResponse>, ApiError> {
    info!(
        sub = %token.sub,
        role = %token.role,
        pool = %payload.pool_pda,
        drt = %payload.drt_name,
        "Data query requested"
    );

    if payload.drt_name.is_empty() {
        return Err(ApiError::bad_request("drt_name cannot be empty"));
    }

    // 1. Pool + DRT lookup.
    let meta_path = state.storage.paths().pool_meta(&payload.pool_pda);
    let meta = state
        .storage
        .read_json::<crate::storage::pool_metadata::PoolMetadata>(&meta_path)
        .map_err(|_| ApiError::not_found(format!("pool {} not found", payload.pool_pda)))?;

    let drt = meta
        .drts
        .get(&payload.drt_name)
        .ok_or_else(|| ApiError::not_found(format!("DRT '{}' not in pool", payload.drt_name)))?;

    if drt.code_repo_url.is_empty() {
        return Err(ApiError::bad_request(format!(
            "DRT '{}' has no executable script (append-only)",
            payload.drt_name
        )));
    }

    // 2. Fetch + SHA-256 verify against on-chain hash (cached + re-checked).
    let wasm_bytes = crate::drt::verified_fetch::fetch_and_verify(
        &drt.code_repo_url,
        &drt.code_hash_hex,
        &state.storage,
    )
    .await?;

    // 3. Load pool CSVs. For the pilot we concatenate every `*.csv` in the
    // pool's dataset dir; the schema is identical across files (initial.csv +
    // append snapshots), so a single CSV header followed by all body rows is
    // safe.
    let dataset_dir = state.storage.paths().pool_dataset_dir(&payload.pool_pda);
    let csv = load_and_concat_pool_csvs(&dataset_dir)?;

    // 4. TODO(phase-2.5): apply row-level employer_group filter from
    // `token.employer_group` once the AVS embeds the Entra group claim.
    if csv.is_empty() {
        return Err(ApiError::bad_request("pool has no data uploaded yet"));
    }

    // 5. Sandboxed execution.
    let runtime_input = crate::drt::runtime::RuntimeInput {
        csv: &csv,
        args: &payload.args,
    };
    let output = crate::drt::runtime::execute(wasm_bytes, runtime_input).await?;

    // 6. Try to parse the body as JSON; fall back to a string blob otherwise.
    let result_json: serde_json::Value = serde_json::from_slice(&output.body)
        .unwrap_or_else(|_| serde_json::Value::String(String::from_utf8_lossy(&output.body).into()));

    Ok(Json(DataQueryResponse {
        pool_pda: payload.pool_pda,
        drt_name: payload.drt_name,
        code_hash_hex: drt.code_hash_hex.clone(),
        exit_code: output.exit_code,
        result: result_json,
    }))
}

fn load_and_concat_pool_csvs(dataset_dir: &std::path::Path) -> Result<String, ApiError> {
    use std::io::Read;
    let mut entries: Vec<std::path::PathBuf> = match std::fs::read_dir(dataset_dir) {
        Ok(rd) => rd
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("csv"))
            .collect(),
        Err(_) => return Ok(String::new()),
    };
    entries.sort();

    let mut out = String::new();
    let mut header_emitted = false;
    for path in entries {
        let mut file = match std::fs::File::open(&path) {
            Ok(f) => f,
            Err(_) => continue,
        };
        let mut buf = String::new();
        if file.read_to_string(&mut buf).is_err() {
            continue;
        }
        let mut lines = buf.lines();
        let Some(header) = lines.next() else { continue };
        if !header_emitted {
            out.push_str(header);
            out.push('\n');
            header_emitted = true;
        }
        for line in lines {
            if line.is_empty() {
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
    }
    Ok(out)
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
    let (encrypted_data, ephemeral_key, nonce) = input.encrypted_parts()?;

    let csv_bytes = crate::crypto::decrypt_ecdh_payload(&encrypted_data, &ephemeral_key, &nonce)
        .map_err(ApiError::bad_request)?;

    ensure_size_limit(&csv_bytes)?;

    Ok(ParsedCsvPayload { csv_bytes })
}

impl MultipartCsvInput {
    fn encrypted_parts(self) -> Result<(String, String, String), ApiError> {
        let encrypted_data = self
            .encrypted_data
            .ok_or_else(|| ApiError::bad_request("missing encrypted_data field"))?;

        let ephemeral_key = self.ephemeral_public_key.ok_or_else(|| {
            ApiError::bad_request("ephemeral_public_key is required for encrypted uploads")
        })?;
        let nonce = self
            .nonce
            .ok_or_else(|| ApiError::bad_request("nonce is required for encrypted uploads"))?;

        Ok((encrypted_data, ephemeral_key, nonce))
    }
}

fn validate_csv_multipart_field_name(name: &str) -> Result<(), ApiError> {
    match name {
        "encrypted_data" | "ephemeral_public_key" | "nonce" => Ok(()),
        "file" => Err(ApiError::bad_request(
            "plaintext file uploads are not accepted — use encrypted_data with ephemeral_public_key and nonce",
        )),
        other => Err(ApiError::bad_request(format!(
            "unsupported multipart field: {other}"
        ))),
    }
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
        validate_csv_multipart_field_name(&name)?;

        match name.as_str() {
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
            _ => unreachable!("validated unsupported multipart field"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_upload_parts_do_not_require_schema_id() {
        let input = MultipartCsvInput {
            encrypted_data: Some("ciphertext".to_string()),
            ephemeral_public_key: Some("ephemeral-key".to_string()),
            nonce: Some("nonce".to_string()),
        };

        let parts = input.encrypted_parts();
        assert!(parts.is_ok());
    }

    #[test]
    fn encrypted_upload_parts_require_encrypted_fields() {
        let input = MultipartCsvInput {
            encrypted_data: Some("ciphertext".to_string()),
            ephemeral_public_key: None,
            nonce: Some("nonce".to_string()),
        };

        assert!(input.encrypted_parts().is_err());
    }

    #[test]
    fn credential_upload_rejects_schema_id_field() {
        assert!(validate_csv_multipart_field_name("schema_id").is_err());
    }

    #[test]
    fn credential_upload_rejects_plaintext_file_field() {
        assert!(validate_csv_multipart_field_name("file").is_err());
    }

    #[test]
    fn credential_upload_accepts_encrypted_fields() {
        assert!(validate_csv_multipart_field_name("encrypted_data").is_ok());
        assert!(validate_csv_multipart_field_name("ephemeral_public_key").is_ok());
        assert!(validate_csv_multipart_field_name("nonce").is_ok());
    }
}
