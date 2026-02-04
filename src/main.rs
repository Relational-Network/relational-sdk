// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Relational SDK - SGX Enclave Server with RA-TLS
//!
//! This server runs inside an Intel SGX enclave and provides:
//! - RA-TLS attestation binding enclave identity to public keys
//! - JWT validation using AVS-issued tokens
//! - Role-based access control (admin, user, read_only)
//! - Encrypted data upload and query endpoints
//!
//! # Architecture
//!
//! ```text
//! Browser → AVS → JWT + enclave public key
//!                     ↓
//! Browser encrypts data → Enclave (this server) decrypts inside SGX
//! ```
//!
//! # Building & Running
//!
//! ```bash
//! make SGX=1 RA_TYPE=dcap
//! gramine-sgx relational-sdk
//! ```

mod auth;
mod config;
mod crypto;
mod handlers;
mod health;
mod tls;

use axum::{
    extract::DefaultBodyLimit,
    routing::{get, post},
    Router,
};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use tracing::info;
use tracing_subscriber::EnvFilter;
use utoipa::{openapi::security::SecurityScheme, Modify, OpenApi};
use utoipa_swagger_ui::SwaggerUi;

use auth::AppState;
use config::{avs_jwks_url, AVS_AUDIENCE, DEFAULT_TLS_CERT_PATH, DEFAULT_TLS_KEY_PATH};
use crypto::enclave_key;
use handlers::{
    admin_status, data_query, data_upload, get_public_key, protected, AdminStatusResponse,
    DataQueryResponse, DataUploadRequest, DataUploadResponse, ProtectedResponse,
};
use health::{health, liveness, readiness, HealthChecks, HealthResponse, ReadyResponse};
use tls::load_tls_config;

/// Start time captured once for uptime reporting.
static STARTED_AT: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

// ============================================================================
// OpenAPI Documentation
// ============================================================================

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Relational SDK API",
        version = "0.1.0",
        description = r#"SGX Enclave server with RA-TLS, JWT validation, and RBAC.

## Authentication

Protected endpoints require a JWT token from the Attestation Verification Service (AVS).

### How to get a token:

```bash
curl -s -X POST http://127.0.0.1:9100/v1/attest \
  -H 'Content-Type: application/json' \
  -d '{"enclave_url":"https://127.0.0.1:8080"}' | jq -r '.token'
```

### How to use in Swagger UI:

1. Click the **Authorize** button at the top right
2. Paste your JWT token (without "Bearer " prefix)
3. Click **Authorize**, then **Close**
4. Now you can test protected endpoints

### Roles:

- **admin**: Full access to all endpoints
- **user**: Can upload and query data
- **read_only**: Can only query data

To get a token with a specific role:

```bash
curl -s -X POST http://127.0.0.1:9100/v1/attest \
  -H 'Content-Type: application/json' \
  -d '{"enclave_url":"https://127.0.0.1:8080","role":"admin"}' | jq -r '.token'
```
"#
    ),
    paths(
        health::health,
        health::liveness,
        health::readiness,
        handlers::get_public_key,
        handlers::protected,
        handlers::admin_status,
        handlers::data_upload,
        handlers::data_query,
    ),
    components(schemas(
        HealthResponse,
        ReadyResponse,
        HealthChecks,
        ProtectedResponse,
        AdminStatusResponse,
        DataUploadRequest,
        DataUploadResponse,
        DataQueryResponse,
        crypto::Jwk,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "Health", description = "Health check endpoints"),
        (name = "Attestation", description = "Enclave attestation and public key"),
        (name = "Protected", description = "JWT-protected endpoints"),
        (name = "Admin", description = "Admin-only endpoints"),
        (name = "Data", description = "Data upload and query endpoints"),
    )
)]
struct ApiDoc;

/// Add bearer auth security scheme to OpenAPI.
struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(utoipa::openapi::security::Http::new(
                    utoipa::openapi::security::HttpAuthScheme::Bearer,
                )),
            );
        }
    }
}

// ============================================================================
// Application Entry Point
// ============================================================================

/// Service entrypoint: build router, set up TLS, and serve.
///
/// # Threading
///
/// Uses 2 worker threads to keep SGX thread budget predictable.
/// Account for: 4 Gramine helper threads + 2 Tokio workers when setting `sgx.max_threads`.
#[tokio::main(worker_threads = 2)]
async fn main() {
    // Initialize tracing with environment filter (RUST_LOG).
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(true)
        .init();

    // Capture process start for uptime reporting.
    let _ = STARTED_AT.set(Instant::now());

    // Initialize enclave keypair.
    let _ = enclave_key();

    info!(jwks_url = %avs_jwks_url(), "JWT validation enabled");

    // Create shared application state.
    let state = AppState {
        audience: AVS_AUDIENCE.to_string(),
        jwks_cache: Arc::new(RwLock::new(None)),
    };

    // Build the router with all endpoints.
    // Body limit: 10MB max for file uploads, prevents DoS
    let app = Router::new()
        // Health endpoints (unversioned for k8s probes).
        .route("/health", get(health))
        .route("/health/live", get(liveness))
        .route("/health/ready", get(readiness))
        // v1 API endpoints.
        .route("/v1/attestation/public-key", get(get_public_key))
        .route("/v1/protected", get(protected))
        .route("/v1/admin/status", get(admin_status))
        .route("/v1/data/upload", post(data_upload))
        .route("/v1/data/query", get(data_query))
        // OpenAPI documentation.
        .merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", ApiDoc::openapi()))
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024)) // 10MB max request body
        .with_state(state);

    // Bind on all interfaces for VM access.
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8080));
    info!(%addr, "Starting HTTPS server");

    // TLS is required for RA-TLS deployments.
    let tls_paths_exist = std::path::Path::new(DEFAULT_TLS_CERT_PATH).exists()
        && std::path::Path::new(DEFAULT_TLS_KEY_PATH).exists();

    if tls_paths_exist {
        // Install rustls crypto provider.
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Load TLS configuration.
        let tls_config = load_tls_config(DEFAULT_TLS_CERT_PATH, DEFAULT_TLS_KEY_PATH)
            .await
            .expect("failed to load TLS cert/key");

        // Start HTTPS server.
        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await
            .expect("server error");
    } else {
        panic!("TLS cert/key not available; RA-TLS requires TLS");
    }
}
