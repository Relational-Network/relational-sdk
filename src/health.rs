// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Health check endpoints for Kubernetes probes and load balancers.
//!
//! This module provides three health endpoints:
//!
//! - `/health` - Combined liveness and readiness check
//! - `/health/live` - Liveness probe (always 200 if running)
//! - `/health/ready` - Readiness probe (checks dependencies)
//!
//! # Kubernetes Integration
//!
//! Configure your pod with:
//!
//! ```yaml
//! livenessProbe:
//!   httpGet:
//!     path: /health/live
//!     port: 8080
//! readinessProbe:
//!   httpGet:
//!     path: /health/ready
//!     port: 8080
//! ```

use axum::{http::StatusCode, Json};
use serde::Serialize;
use std::path::Path;
use utoipa::ToSchema;

use crate::config::DATA_DIR_ENV;

/// Health check response with individual component status.
#[derive(Debug, Serialize, ToSchema)]
pub struct ReadyResponse {
    /// Overall health status ("ok" or "degraded").
    pub status: String,
    /// Individual health checks and their results.
    pub checks: HealthChecks,
}

/// Individual health check results.
#[derive(Debug, Serialize, ToSchema)]
pub struct HealthChecks {
    /// Whether the service process is running.
    pub service: String,
    /// Data directory availability (if configured).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<String>,
}

/// Simple health check response for liveness probes.
#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
}

/// Check if the data directory exists and is accessible.
fn check_data_dir() -> Option<String> {
    if let Ok(dir) = std::env::var(DATA_DIR_ENV) {
        if Path::new(&dir).exists() {
            Some("ok".to_string())
        } else {
            Some("missing".to_string())
        }
    } else {
        None // Not configured, don't report.
    }
}

/// Health check endpoint handler.
///
/// Returns 200 if all checks pass, 503 if any check fails.
#[utoipa::path(
    get,
    path = "/health",
    tag = "Health",
    summary = "Combined health check",
    description = "Returns health status with individual check results. Returns 503 if any check fails.",
    responses(
        (status = 200, description = "Service is healthy", body = ReadyResponse),
        (status = 503, description = "Service is unhealthy", body = ReadyResponse)
    )
)]
pub async fn health() -> (StatusCode, Json<ReadyResponse>) {
    let data_dir = check_data_dir();
    let all_ok = data_dir.as_ref().map(|s| s == "ok").unwrap_or(true);

    let response = ReadyResponse {
        status: if all_ok { "ok" } else { "degraded" }.to_string(),
        checks: HealthChecks {
            service: "ok".to_string(),
            data_dir,
        },
    };

    let status = if all_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(response))
}

/// Liveness probe handler.
///
/// Always returns 200 if the process is running.
/// Does not check dependencies - use readiness for that.
#[utoipa::path(
    get,
    path = "/health/live",
    tag = "Health",
    summary = "Liveness probe",
    description = "Always returns 200 if the service is running. Use for Kubernetes liveness probes.",
    responses(
        (status = 200, description = "Service is alive", body = HealthResponse)
    )
)]
pub async fn liveness() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

/// Readiness probe handler.
///
/// Returns 200 only if all dependencies are available.
/// Use for Kubernetes readiness probes.
#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "Health",
    summary = "Readiness probe",
    description = "Checks all dependencies and returns 200 only if ready to serve traffic.",
    responses(
        (status = 200, description = "Service is ready", body = ReadyResponse),
        (status = 503, description = "Service is not ready", body = ReadyResponse)
    )
)]
pub async fn readiness() -> (StatusCode, Json<ReadyResponse>) {
    health().await
}
