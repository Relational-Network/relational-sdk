// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

use axum::{
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use serde::Serialize;
use std::sync::OnceLock;
use std::time::Instant;
use utoipa::{OpenApi, ToSchema};
use utoipa_swagger_ui::SwaggerUi;

// Start time captured once so uptime can be reported without mutable globals.
static STARTED_AT: OnceLock<Instant> = OnceLock::new();
// TODO: Decide if/when to use a configured data directory for readiness checks.
const DATA_DIR_ENV: &str = "DATA_DIR";

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

// OpenAPI spec for /docs.
#[derive(OpenApi)]
#[openapi(
    paths(health, health_live, health_ready),
    components(schemas(LiveResponse, ReadyResponse, CheckStatus))
)]
struct ApiDoc;

// TODO: Revisit worker_threads and sgx.max_threads when adding blocking work or queues.
#[tokio::main(worker_threads = 2)]
async fn main() {
    // Capture process start for uptime.
    let _ = STARTED_AT.set(Instant::now());

    // Minimal router with health endpoints and docs.
    let app = Router::new()
        .route("/health", get(health))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .merge(SwaggerUi::new("/docs").url("/api-doc/openapi.json", ApiDoc::openapi()));

    // Bind on all interfaces for VM access.
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8080));
    println!("listening on {}", addr);

    // Start serving requests.
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind address");
    axum::serve(listener, app)
        .await
        .expect("server error");
}
