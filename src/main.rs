// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

use axum::{
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use base64::Engine;
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io;
use std::sync::OnceLock;
use std::time::Instant;
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

// Start time captured once so uptime can be reported without mutable globals.
static STARTED_AT: OnceLock<Instant> = OnceLock::new();
// Enclave keypair is created once per process and used to build the public JWK.
// TODO: Update key generation for rotation or persistence as needed.
static ENCLAVE_KEY: OnceLock<EnclaveKey> = OnceLock::new();
// TODO: Decide if/when to use a configured data directory for readiness checks.
const DATA_DIR_ENV: &str = "DATA_DIR";

// Fixed RA-TLS certificate location written by gramine-ratls (tmpfs).
const DEFAULT_TLS_CERT_PATH: &str = "/tmp/ra-tls.crt.pem";
// Fixed RA-TLS key location written by gramine-ratls (tmpfs).
const DEFAULT_TLS_KEY_PATH: &str = "/tmp/ra-tls.key.pem";

// Lightweight liveness payload (always 200).
#[derive(Serialize, ToSchema)]
struct LiveResponse {
    // Overall status for the liveness probe.
    status: &'static str,
    // Build metadata for ops visibility.
    service: &'static str,
    version: &'static str,
    // Seconds since process start.
    uptime_seconds: u64,
}

// Individual readiness check result.
#[derive(Serialize, ToSchema)]
struct CheckStatus {
    // Check identifier (e.g., "data_dir").
    name: String,
    // "ok" or "fail".
    status: &'static str,
    // Optional failure message when status == "fail".
    message: Option<String>,
}

// Readiness payload, used by /health and /health/ready.
#[derive(Serialize, ToSchema)]
struct ReadyResponse {
    // Overall readiness status ("ok" or "not_ready").
    status: &'static str,
    // Build metadata for ops visibility.
    service: &'static str,
    version: &'static str,
    // Seconds since process start.
    uptime_seconds: u64,
    // Per-check results to aid debugging.
    checks: Vec<CheckStatus>,
}

// JWK describing the enclave's public key for client-side encryption.
#[derive(Serialize, ToSchema)]
struct Jwk {
    kty: &'static str,
    crv: &'static str,
    x: String,
    y: String,
    #[serde(rename = "use")]
    use_: &'static str,
    alg: &'static str,
    kid: String,
}

// In-memory keypair bound to the enclave instance lifetime.
struct EnclaveKey {
    _private_key: SecretKey,
    public_jwk: Jwk,
}

// Compute uptime in seconds from the captured start instant.
fn uptime_seconds() -> u64 {
    STARTED_AT
        .get()
        .map(|started_at| started_at.elapsed().as_secs())
        .unwrap_or(0)
}

// Health endpoints should not be cached by proxies.
fn health_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers
}

// Shared liveness response builder.
fn live_response() -> LiveResponse {
    LiveResponse {
        status: "ok",
        service: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: uptime_seconds(),
    }
}

// Aggregate readiness checks (extend as dependencies are added).
fn readiness_checks() -> Vec<CheckStatus> {
    let mut checks = Vec::new();

    // Optional data directory check for when a storage path is configured.
    if let Ok(path) = std::env::var(DATA_DIR_ENV) {
        let result = check_data_dir(&path);
        checks.push(CheckStatus {
            name: "data_dir".to_string(),
            status: if result.is_ok() { "ok" } else { "fail" },
            message: result.err(),
        });
    }

    checks
}

// Generate or return the enclave keypair for encrypting uploads.
// TODO: Seal or persist the private key across restarts (optional).
// TODO: Derive keys using mr_enclave to bind to the enclave identity.
// TODO: Rotate keys on a schedule and bind them to an attestation token.
fn enclave_key() -> &'static EnclaveKey {
    ENCLAVE_KEY.get_or_init(|| {
        let secret_key = SecretKey::random(&mut OsRng);
        let public_jwk = jwk_for_public_key(&secret_key.public_key());
        EnclaveKey {
            _private_key: secret_key,
            public_jwk,
        }
    })
}

// Convert the enclave public key into a JWK for browser-side encryption.
fn jwk_for_public_key(public_key: &p256::PublicKey) -> Jwk {
    let encoded = public_key.to_encoded_point(false);
    let bytes = encoded.as_bytes();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[1..33]);
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes[33..65]);
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let kid = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize());

    Jwk {
        kty: "EC",
        crv: "P-256",
        x,
        y,
        use_: "enc",
        alg: "ECDH-ES",
        kid,
    }
}

// Verify the configured data directory exists and is a directory.
fn check_data_dir(path: &str) -> Result<(), String> {
    let metadata = std::fs::metadata(path)
        .map_err(|err| format!("{}: {}", path, err))?;
    if !metadata.is_dir() {
        return Err("path is not a directory".to_string());
    }
    Ok(())
}

// /health behaves like readiness for common load-balancer expectations.
#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Service is ready", body = ReadyResponse),
        (status = 503, description = "Service is not ready", body = ReadyResponse)
    )
)]
async fn health() -> impl IntoResponse {
    health_ready().await
}

// Liveness endpoint: process is up and serving.
#[utoipa::path(
    get,
    path = "/health/live",
    responses(
        (status = 200, description = "Service is live", body = LiveResponse)
    )
)]
async fn health_live() -> impl IntoResponse {
    let headers = health_headers();
    let body = live_response();

    (StatusCode::OK, headers, Json(body))
}

// Readiness endpoint: checks dependencies and returns 200 or 503.
#[utoipa::path(
    get,
    path = "/health/ready",
    responses(
        (status = 200, description = "Service is ready", body = ReadyResponse),
        (status = 503, description = "Service is not ready", body = ReadyResponse)
    )
)]
async fn health_ready() -> impl IntoResponse {
    let headers = health_headers();
    let checks = readiness_checks();
    // Any failing check marks the service as not ready.
    let ready = checks.iter().all(|check| check.status == "ok");
    let body = ReadyResponse {
        status: if ready { "ok" } else { "not_ready" },
        service: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: uptime_seconds(),
        checks,
    };

    if ready {
        (StatusCode::OK, headers, Json(body))
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, headers, Json(body))
    }
}

// Public key for browser-side encryption, bound to the enclave instance.
// TODO: Consider rate limits and access control; this exposes the enclave's public key.
#[utoipa::path(
    get,
    path = "/attestation/public-key",
    responses(
        (status = 200, description = "Enclave public key (JWK)", body = Jwk)
    )
)]
async fn attestation_public_key() -> impl IntoResponse {
    let headers = health_headers();
    // TODO: Consider rate limits and access control; this exposes the enclave's public key.
    let jwk = &enclave_key().public_jwk;
    (StatusCode::OK, headers, Json(jwk))
}

// OpenAPI spec for /docs.
#[derive(OpenApi)]
#[openapi(
    paths(health, health_live, health_ready, attestation_public_key),
    components(schemas(LiveResponse, ReadyResponse, CheckStatus, Jwk))
)]
// OpenAPI registry for Swagger UI.
struct ApiDoc;

// TODO: Revisit worker_threads and sgx.max_threads when adding blocking work or queues.
// Service entrypoint: build router, set up TLS, and serve.
#[tokio::main(worker_threads = 2)]
async fn main() {
    // Capture process start for uptime.
    let _ = STARTED_AT.set(Instant::now());
    let _ = enclave_key();

    // Minimal router with health endpoints and docs.
    let app = Router::new()
        .route("/health", get(health))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/attestation/public-key", get(attestation_public_key))
        .merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", ApiDoc::openapi()));

    // Bind on all interfaces for VM access.
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("listening on {}", addr);

    // Start serving requests over TLS if cert/key are available.
    // TLS is required for RA-TLS deployments.
    let tls_cert = DEFAULT_TLS_CERT_PATH.to_string();
    let tls_key = DEFAULT_TLS_KEY_PATH.to_string();
    let tls_paths_exist = std::path::Path::new(DEFAULT_TLS_CERT_PATH).exists()
        && std::path::Path::new(DEFAULT_TLS_KEY_PATH).exists();

    if tls_paths_exist {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls_config = load_tls_config(&tls_cert, &tls_key)
            .await
            .expect("failed to load TLS cert/key");
        axum_server::bind_rustls(addr, tls_config)
            .serve(app.into_make_service())
            .await
            .expect("server error");
    } else {
        panic!("TLS cert/key not available; RA-TLS requires TLS");
    }
}

// Load TLS configuration from PEM or DER, falling back between formats.
// This handles both gramine-ratls PEM output and DER-only scenarios.
async fn load_tls_config(
    cert_path: &str,
    key_path: &str,
) -> io::Result<axum_server::tls_rustls::RustlsConfig> {
    let cert = tokio::fs::read(cert_path).await?;
    let key = tokio::fs::read(key_path).await?;
    let cert = normalize_ratls_pem_cert(cert);

    match axum_server::tls_rustls::RustlsConfig::from_pem(cert.clone(), key.clone()).await {
        Ok(config) => Ok(config),
        Err(pem_err) => {
            let der_err = axum_server::tls_rustls::RustlsConfig::from_der(vec![cert], key).await;
            match der_err {
                Ok(config) => Ok(config),
                Err(der_err) => Err(io::Error::new(
                    io::ErrorKind::Other,
                    format!(
                        "failed to parse TLS cert/key as PEM ({pem_err}) or DER ({der_err})"
                    ),
                )),
            }
        }
    }
}

// gramine-ratls emits \"TRUSTED CERTIFICATE\" PEM labels; rustls expects \"CERTIFICATE\".
// Rewrite the PEM headers so rustls can parse the self-signed RA-TLS cert.
fn normalize_ratls_pem_cert(cert: Vec<u8>) -> Vec<u8> {
    const TRUSTED_BEGIN: &str = "-----BEGIN TRUSTED CERTIFICATE-----";
    const TRUSTED_END: &str = "-----END TRUSTED CERTIFICATE-----";
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";

    let Ok(text) = std::str::from_utf8(&cert) else {
        return cert;
    };
    if !text.contains(TRUSTED_BEGIN) {
        return cert;
    }
    text.replace(TRUSTED_BEGIN, BEGIN)
        .replace(TRUSTED_END, END)
        .into_bytes()
}
