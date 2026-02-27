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
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use base64::Engine;
use serde::{Deserialize, Serialize};
use tracing::{debug, info};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::auth::{AdminToken, ReadOnlyToken, TokenData, UserToken};
use crate::config::MAX_BODY_SIZE;
use crate::crypto::{enclave_key, Jwk};
use crate::data_validation::{
    schema_for_id, supported_schema_ids, validate_csv_bytes, ValidationError, ValidationSummary,
    DEFAULT_SCHEMA_ID,
};
use crate::error::ApiError;
use crate::state::AppState;

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
// Protected Endpoints
// ============================================================================

/// Response for the /protected endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct ProtectedResponse {
    pub message: String,
    pub user: String,
    pub role: String,
}

/// Protected endpoint that requires any valid token.
///
/// Returns information about the authenticated user.
#[utoipa::path(
    get,
    path = "/v1/protected",
    tag = "Protected",
    summary = "Protected endpoint",
    description = "Requires valid JWT token. Returns user information.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Authenticated successfully", body = ProtectedResponse),
        (status = 401, description = "Unauthorized - missing or invalid token")
    )
)]
pub async fn protected(token: TokenData) -> Json<ProtectedResponse> {
    debug!(sub = %token.sub, role = %token.role, "Protected endpoint accessed");
    Json(ProtectedResponse {
        message: "authenticated inside enclave".to_string(),
        user: token.sub,
        role: token.role,
    })
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
    Json(AdminStatusResponse {
        status: "operational".to_string(),
        admin_user: token.sub,
        uptime_seconds: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs(),
    })
}

// ============================================================================
// Data Endpoints
// ============================================================================

/// Response for CSV validation endpoint.
#[derive(Debug, Serialize, ToSchema)]
pub struct DataValidateResponse {
    pub valid: bool,
    pub schema_id: String,
    pub rows_validated: usize,
    pub errors: Vec<ValidationError>,
}

/// Response for validated CSV uploads.
#[derive(Debug, Serialize, ToSchema)]
pub struct DataFileUploadResponse {
    pub status: String,
    pub record_id: String,
    pub schema_id: String,
    pub rows_validated: usize,
}

#[derive(Debug, Serialize)]
struct StoredUploadMetadata {
    schema_id: String,
    uploaded_by: String,
    rows_validated: usize,
    uploaded_at: chrono::DateTime<chrono::Utc>,
    source: String,
}

#[derive(Debug, Default)]
struct MultipartCsvInput {
    schema_id: Option<String>,
    file: Option<Vec<u8>>,
    encrypted_data: Option<String>,
    ephemeral_public_key: Option<String>,
    nonce: Option<String>,
}

struct ParsedCsvPayload {
    schema_id: String,
    csv_bytes: Vec<u8>,
    source: String,
}

/// Validate CSV without persisting it.
#[utoipa::path(
    post,
    path = "/v1/data/validate",
    tag = "Data",
    summary = "Validate CSV upload",
    description = "Validates a CSV file against a schema_id. Accepts multipart file upload and optional encrypted multipart fields.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "Validation result", body = DataValidateResponse),
        (status = 400, description = "Invalid request"),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - user role required")
    )
)]
pub async fn data_validate(
    UserToken(_token): UserToken,
    multipart: Multipart,
) -> Result<Json<DataValidateResponse>, ApiError> {
    let payload = parse_csv_payload(multipart).await?;
    let validation = validate_payload(&payload.schema_id, &payload.csv_bytes)?;

    Ok(Json(DataValidateResponse {
        valid: validation.valid,
        schema_id: payload.schema_id,
        rows_validated: validation.rows_validated,
        errors: validation.errors,
    }))
}

/// Validate and persist CSV data.
#[utoipa::path(
    post,
    path = "/v1/data/upload-file",
    tag = "Data",
    summary = "Upload CSV data",
    description = "Validates and persists CSV data. Returns 422 with validation errors when payload is invalid.",
    security(("bearer_auth" = [])),
    responses(
        (status = 200, description = "CSV stored", body = DataFileUploadResponse),
        (status = 401, description = "Unauthorized"),
        (status = 403, description = "Forbidden - user role required"),
        (status = 422, description = "Validation failed", body = DataValidateResponse)
    )
)]
pub async fn data_upload_file(
    UserToken(token): UserToken,
    State(state): State<AppState>,
    multipart: Multipart,
) -> Result<Response, ApiError> {
    let payload = parse_csv_payload(multipart).await?;
    let validation = validate_payload(&payload.schema_id, &payload.csv_bytes)?;

    if !validation.valid {
        let response = DataValidateResponse {
            valid: false,
            schema_id: payload.schema_id,
            rows_validated: validation.rows_validated,
            errors: validation.errors,
        };
        return Ok((StatusCode::UNPROCESSABLE_ENTITY, Json(response)).into_response());
    }

    let record_id = Uuid::new_v4().to_string();
    let upload_dir = state
        .storage
        .paths()
        .root()
        .join("uploads")
        .join(&payload.schema_id);
    state.storage.create_dir(&upload_dir)?;

    let csv_path = upload_dir.join(format!("{record_id}.csv"));
    state.storage.write_raw(&csv_path, &payload.csv_bytes)?;

    let metadata = StoredUploadMetadata {
        schema_id: payload.schema_id.clone(),
        uploaded_by: token.sub.clone(),
        rows_validated: validation.rows_validated,
        uploaded_at: chrono::Utc::now(),
        source: payload.source.clone(),
    };
    let meta_path = upload_dir.join(format!("{record_id}.meta.json"));
    state.storage.write_json(&meta_path, &metadata)?;

    info!(
        sub = %token.sub,
        role = %token.role,
        record_id = %record_id,
        schema_id = %payload.schema_id,
        rows_validated = validation.rows_validated,
        source = %payload.source,
        csv_size = payload.csv_bytes.len(),
        "Validated CSV upload stored"
    );

    Ok(Json(DataFileUploadResponse {
        status: "stored".to_string(),
        record_id,
        schema_id: payload.schema_id,
        rows_validated: validation.rows_validated,
    })
    .into_response())
}

/// Request body for data upload.
///
/// **TODO:** Implement decryption using enclave's private key:
/// 1. Decode `encrypted_data` from base64
/// 2. Decrypt using ECIES with enclave's P-256 private key
/// 3. Validate `nonce` for replay protection (store in memory/DB)
/// 4. Process decrypted payload and store results
#[derive(Debug, Deserialize, ToSchema)]
#[allow(dead_code)] // Fields used after decryption is implemented
pub struct DataUploadRequest {
    /// Base64-encoded encrypted data.
    pub encrypted_data: String,
    /// Optional nonce for replay protection.
    #[serde(default)]
    pub nonce: Option<String>,
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
    Json(payload): Json<DataUploadRequest>,
) -> Json<DataUploadResponse> {
    let record_id = Uuid::new_v4().to_string();
    info!(
        sub = %token.sub,
        role = %token.role,
        record_id = %record_id,
        data_size = payload.encrypted_data.len(),
        has_nonce = payload.nonce.is_some(),
        "Data upload received"
    );
    // TODO: Implement encrypted data processing:
    // 1. Base64-decode payload.encrypted_data
    // 2. Decrypt using enclave's P-256 private key (ECIES or ECDH-ES+A256GCM)
    // 3. Validate payload.nonce for replay protection
    // 4. Parse and process the decrypted data
    // 5. Store results securely within enclave
    Json(DataUploadResponse {
        status: "received".to_string(),
        record_id,
    })
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

fn validate_payload(schema_id: &str, csv_bytes: &[u8]) -> Result<ValidationSummary, ApiError> {
    let schema = schema_for_id(schema_id).ok_or_else(|| {
        let supported = supported_schema_ids().join(", ");
        ApiError::bad_request(format!(
            "unsupported schema_id '{schema_id}'. Supported schema IDs: {supported}"
        ))
    })?;

    Ok(validate_csv_bytes(csv_bytes, &schema))
}

async fn parse_csv_payload(multipart: Multipart) -> Result<ParsedCsvPayload, ApiError> {
    let input = parse_multipart_fields(multipart).await?;
    let schema_id = input
        .schema_id
        .unwrap_or_else(|| DEFAULT_SCHEMA_ID.to_string());

    if input.file.is_some() && input.encrypted_data.is_some() {
        return Err(ApiError::bad_request(
            "provide either 'file' or 'encrypted_data', not both",
        ));
    }

    if let Some(file_bytes) = input.file {
        ensure_size_limit(&file_bytes)?;
        return Ok(ParsedCsvPayload {
            schema_id,
            csv_bytes: file_bytes,
            source: "multipart_file".to_string(),
        });
    }

    let encrypted_data = input
        .encrypted_data
        .ok_or_else(|| ApiError::bad_request("missing file field or encrypted_data field"))?;

    let csv_bytes = match (input.ephemeral_public_key, input.nonce) {
        (Some(ephemeral_public_key), Some(nonce)) => {
            crate::crypto::decrypt_ecdh_payload(&encrypted_data, &ephemeral_public_key, &nonce)
                .map_err(ApiError::bad_request)?
        }
        (None, None) => decode_base64_any(&encrypted_data)
            .ok_or_else(|| ApiError::bad_request("encrypted_data is not valid base64/base64url"))?,
        _ => {
            return Err(ApiError::bad_request(
                "ephemeral_public_key and nonce must be provided together",
            ));
        }
    };

    ensure_size_limit(&csv_bytes)?;

    Ok(ParsedCsvPayload {
        schema_id,
        csv_bytes,
        source: "multipart_encrypted_or_base64".to_string(),
    })
}

async fn parse_multipart_fields(mut multipart: Multipart) -> Result<MultipartCsvInput, ApiError> {
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
            _ => {}
        }
    }
    Ok(input)
}

fn ensure_size_limit(bytes: &[u8]) -> Result<(), ApiError> {
    if bytes.len() > MAX_BODY_SIZE {
        return Err(ApiError::bad_request(format!(
            "payload exceeds maximum size of {} bytes",
            MAX_BODY_SIZE
        )));
    }
    Ok(())
}

fn decode_base64_any(input: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .ok()
        .or_else(|| {
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(input)
                .ok()
        })
        .or_else(|| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(input)
                .ok()
        })
        .or_else(|| base64::engine::general_purpose::URL_SAFE.decode(input).ok())
}
