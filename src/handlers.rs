// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! HTTP request handlers for the enclave API.
//!
//! This module contains handlers for:
//! - Public key endpoint (for browser encryption)
//! - Protected endpoints (require authentication)
//! - Admin endpoints (require admin role)
//! - Data endpoints (require appropriate roles)

use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use crate::auth::{AdminToken, ReadOnlyToken, TokenData, UserToken};
use crate::crypto::{enclave_key, Jwk};

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
    // TODO: Implement encrypted data processing:
    // 1. Base64-decode payload.encrypted_data
    // 2. Decrypt using enclave's P-256 private key (ECIES or ECDH-ES+A256GCM)
    // 3. Validate payload.nonce for replay protection
    // 4. Parse and process the decrypted data
    // 5. Store results securely within enclave
    let _ = payload; // Mark as used until decryption is implemented
    Json(DataUploadResponse {
        status: "received".to_string(),
        record_id: format!("rec_{}", token.sub.chars().take(8).collect::<String>()),
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
pub async fn data_query(
    ReadOnlyToken(token): ReadOnlyToken,
) -> Json<DataQueryResponse> {
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
