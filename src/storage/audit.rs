// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Audit event logging (daily JSONL append).
//!
//! Each day's events are written to `/data/audit/{YYYY-MM-DD}.jsonl`.
//! Events are **appended** (never overwritten) for tamper-evident logging.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::Write;
use tracing::warn;

use super::encrypted_fs::EncryptedStorage;

/// Categories of auditable events.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    WalletCreated,
    WalletDeleted,
    WalletAccessed,
    TransactionSigned,
    TransactionBroadcast,
    PermissionDenied,
    AdminAccess,
}

/// A single audit event.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AuditEvent {
    pub event_id: String,
    pub timestamp: DateTime<Utc>,
    pub event_type: AuditEventType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
    pub success: bool,
}

impl AuditEvent {
    /// Start building an event with the given type (defaults to `success: true`).
    pub fn new(event_type: AuditEventType) -> Self {
        Self {
            event_id: uuid::Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            event_type,
            user_id: None,
            resource_type: None,
            resource_id: None,
            details: None,
            success: true,
        }
    }

    /// Attach user identity.
    pub fn with_user(mut self, user_id: impl Into<String>) -> Self {
        self.user_id = Some(user_id.into());
        self
    }

    /// Attach resource type and id.
    pub fn with_resource(
        mut self,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        self.resource_type = Some(resource_type.into());
        self.resource_id = Some(resource_id.into());
        self
    }

    /// Mark as a failed action (e.g., permission denied).
    #[allow(dead_code)]
    pub fn failed(mut self) -> Self {
        self.success = false;
        self
    }

    /// Attach arbitrary detail JSON.
    #[allow(dead_code)]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }
}

/// Writes [`AuditEvent`]s to daily JSONL files.
pub struct AuditRepository<'a> {
    storage: &'a EncryptedStorage,
}

impl<'a> AuditRepository<'a> {
    pub fn new(storage: &'a EncryptedStorage) -> Self {
        Self { storage }
    }

    /// Append an event to today's audit log.
    ///
    /// Errors are logged but **not** propagated — audit logging must never
    /// block business logic.
    pub fn log(&self, event: &AuditEvent) {
        let date = event.timestamp.format("%Y-%m-%d").to_string();
        let path = self.storage.paths().audit_events_file(&date);

        // Ensure audit directory exists.
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        match serde_json::to_string(event) {
            Ok(mut line) => {
                line.push('\n');
                if let Err(e) = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                    .and_then(|mut f| f.write_all(line.as_bytes()))
                {
                    warn!(error = %e, path = %path.display(), "Failed to write audit event");
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to serialize audit event");
            }
        }
    }

    /// Read all events for a given date (for admin querying).
    pub fn read_events(&self, date: &str) -> Vec<AuditEvent> {
        let path = self.storage.paths().audit_events_file(date);
        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };
        data.lines()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }
}

/// Convenience macro for fire-and-forget audit logging.
///
/// ```rust,ignore
/// audit_log!(storage, AuditEventType::WalletCreated, "user_123", "wallet", "wallet_456");
/// ```
#[macro_export]
macro_rules! audit_log {
    ($storage:expr, $event_type:expr, $user_id:expr, $resource_type:expr, $resource_id:expr) => {{
        let repo = $crate::storage::audit::AuditRepository::new($storage);
        repo.log(
            &$crate::storage::audit::AuditEvent::new($event_type)
                .with_user($user_id)
                .with_resource($resource_type, $resource_id),
        );
    }};
}
