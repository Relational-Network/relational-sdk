// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

use axum::{
    extract::{FromRequestParts, State},
    http::{header, request::Parts, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use base64::Engine;
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use p256::elliptic_curve::rand_core::OsRng;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::SecretKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io;
use std::sync::{Arc, OnceLock, RwLock};
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
// AVS JWKS URL for token verification.
const AVS_JWKS_URL: &str = "http://127.0.0.1:9100/.well-known/jwks.json";
// Expected audience claim in AVS tokens.
const AVS_AUDIENCE: &str = "relational-sdk";

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
#[derive(Clone, Serialize, Deserialize, ToSchema)]
struct Jwk {
    kty: String,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
    n: Option<String>,
    e: Option<String>,
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    use_: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
}

// JWKS response from AVS.
#[derive(Clone, Deserialize)]
struct JwksResponse {
    keys: Vec<Jwk>,
}

// Claims from AVS-issued attestation tokens.
#[derive(Debug, Deserialize)]
struct AttestationClaims {
    iss: String,
    sub: String,
    aud: Option<String>,
    exp: u64,
    iat: u64,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    nonce: Option<String>,
}

// Validated token data extracted for request handlers.
#[derive(Debug, Clone)]
pub struct TokenData {
    pub sub: String,
    pub role: String,
    pub iss: String,
}

// Cached JWKS for token verification.
struct JwksCache {
    keys: Vec<(String, DecodingKey)>,
    fetched_at: Instant,
}

// Shared application state.
#[derive(Clone)]
struct AppState {
    audience: String,
    jwks_cache: Arc<RwLock<Option<JwksCache>>>,
}

// In-memory keypair bound to the enclave instance lifetime.
struct EnclaveKey {
    _private_key: SecretKey,
    public_jwk: Jwk,
}

// JWKS cache TTL in seconds.
const JWKS_CACHE_TTL_SECS: u64 = 300;

// Fetch JWKS from AVS and cache the decoding keys.
async fn fetch_jwks(url: &str) -> Result<Vec<(String, DecodingKey)>, String> {
    let response = reqwest::get(url)
        .await
        .map_err(|e| format!("failed to fetch JWKS: {e}"))?;
    let jwks: JwksResponse = response
        .json()
        .await
        .map_err(|e| format!("failed to parse JWKS: {e}"))?;

    let mut keys = Vec::new();
    for jwk in jwks.keys {
        let kid = jwk.kid.clone().unwrap_or_default();
        // Support EC P-256 keys (used by AVS).
        if jwk.kty == "EC" {
            if let (Some(x), Some(y)) = (&jwk.x, &jwk.y) {
                if let Ok(key) = DecodingKey::from_ec_components(x, y) {
                    keys.push((kid.clone(), key));
                }
            }
        }
        // Support RSA keys if needed in future.
        if jwk.kty == "RSA" {
            if let (Some(n), Some(e)) = (&jwk.n, &jwk.e) {
                if let Ok(key) = DecodingKey::from_rsa_components(n, e) {
                    keys.push((kid.clone(), key));
                }
            }
        }
    }
    Ok(keys)
}

// Get or refresh JWKS cache.
async fn get_decoding_keys(state: &AppState) -> Result<Vec<(String, DecodingKey)>, String> {
    // Check cache validity.
    {
        let cache = state.jwks_cache.read().unwrap();
        if let Some(ref c) = *cache {
            if c.fetched_at.elapsed().as_secs() < JWKS_CACHE_TTL_SECS {
                return Ok(c.keys.clone());
            }
        }
    }

    // Fetch and update cache.
    let keys = fetch_jwks(AVS_JWKS_URL).await?;
    {
        let mut cache = state.jwks_cache.write().unwrap();
        *cache = Some(JwksCache {
            keys: keys.clone(),
            fetched_at: Instant::now(),
        });
    }
    Ok(keys)
}

// Validate an AVS-issued JWT and extract claims.
async fn validate_token(state: &AppState, token: &str) -> Result<TokenData, String> {
    let keys = get_decoding_keys(state).await?;
    if keys.is_empty() {
        return Err("no valid keys in JWKS".to_string());
    }

    // Decode header to find kid.
    let header = decode_header(token).map_err(|e| format!("invalid token header: {e}"))?;
    let kid = header.kid.as_deref();

    // Find matching key or try all keys.
    let decoding_key = if let Some(kid) = kid {
        keys.iter()
            .find(|(k, _)| k == kid)
            .map(|(_, key)| key)
            .ok_or_else(|| format!("no key found for kid: {kid}"))?
    } else {
        &keys[0].1
    };

    // Configure validation.
    let mut validation = Validation::new(Algorithm::ES256);
    validation.set_audience(&[&state.audience]);
    validation.validate_exp = true;

    let token_data = decode::<AttestationClaims>(token, decoding_key, &validation)
        .map_err(|e| format!("token validation failed: {e}"))?;

    Ok(TokenData {
        sub: token_data.claims.sub,
        role: token_data.claims.role.unwrap_or_else(|| "user".to_string()),
        iss: token_data.claims.iss,
    })
}

// Axum extractor for validated tokens from Authorization header.
impl FromRequestParts<AppState> for TokenData {
    type Rejection = (StatusCode, Json<serde_json::Value>);

    async fn from_request_parts(
        parts: &mut Parts,
        state: &AppState,
    ) -> Result<Self, Self::Rejection> {
        let auth_header = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "missing authorization header"})),
                )
            })?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({"error": "invalid authorization header format"})),
                )
            })?;

        validate_token(state, token).await.map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error": e})),
            )
        })
    }
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
        kty: "EC".to_string(),
        crv: Some("P-256".to_string()),
        x: Some(x),
        y: Some(y),
        n: None,
        e: None,
        use_: Some("enc".to_string()),
        alg: Some("ECDH-ES".to_string()),
        kid: Some(kid),
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

// Protected endpoint response.
#[derive(Serialize, ToSchema)]
struct ProtectedResponse {
    message: String,
    sub: String,
    role: String,
}

// Protected test endpoint requiring valid AVS token.
#[utoipa::path(
    get,
    path = "/protected",
    responses(
        (status = 200, description = "Access granted", body = ProtectedResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(("bearer_auth" = []))
)]
async fn protected(
    State(_state): State<AppState>,
    token: TokenData,
) -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(ProtectedResponse {
            message: "access granted".to_string(),
            sub: token.sub,
            role: token.role,
        }),
    )
}

// OpenAPI spec for /docs.
#[derive(OpenApi)]
#[openapi(
    paths(health, health_live, health_ready, attestation_public_key, protected),
    components(schemas(LiveResponse, ReadyResponse, CheckStatus, Jwk, ProtectedResponse)),
    modifiers(&SecurityAddon)
)]
// OpenAPI registry for Swagger UI.
struct ApiDoc;

// Add bearer auth to OpenAPI.
struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "bearer_auth",
                utoipa::openapi::security::SecurityScheme::Http(
                    utoipa::openapi::security::Http::new(
                        utoipa::openapi::security::HttpAuthScheme::Bearer,
                    ),
                ),
            );
        }
    }
}

// TODO: Revisit worker_threads and sgx.max_threads when adding blocking work or queues.
// Service entrypoint: build router, set up TLS, and serve.
#[tokio::main(worker_threads = 2)]
async fn main() {
    // Capture process start for uptime.
    let _ = STARTED_AT.set(Instant::now());
    let _ = enclave_key();

    println!("JWT validation enabled with JWKS from: {}", AVS_JWKS_URL);

    let state = AppState {
        audience: AVS_AUDIENCE.to_string(),
        jwks_cache: Arc::new(RwLock::new(None)),
    };

    // Minimal router with health endpoints and docs.
    let app = Router::new()
        .route("/health", get(health))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/attestation/public-key", get(attestation_public_key))
        .route("/protected", get(protected))
        .merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", ApiDoc::openapi()))
        .with_state(state);

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
