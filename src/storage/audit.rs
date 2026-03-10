// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Audit event logging (daily JSONL append) with HMAC integrity.
//!
//! Each day's events are written to `/data/audit/{YYYY-MM-DD}.jsonl`.
//! Events are **appended** (never overwritten) for tamper-evident logging.
//! An HMAC-SHA256 tag is computed over each event's canonical JSON so that
//! any post-hoc modification of the log file is detectable.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::io::AsyncWriteExt;
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
    /// HMAC-SHA256 integrity tag over the canonical JSON of this event
    /// (computed with `hmac` field absent). `None` for legacy events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
}

type HmacSha256 = Hmac<Sha256>;

/// Derive a 32-byte HMAC key from the enclave's P-256 **private** scalar via HKDF.
///
/// The private key material never leaves the process — `EnclaveKey::hmac_key()`
/// performs the HKDF derivation internally and returns only the purpose-bound
/// output key.
fn audit_hmac_key() -> [u8; 32] {
    crate::crypto::enclave_key().hmac_key(b"audit-hmac-v1")
}

/// Compute HMAC-SHA256 of a canonical JSON blob.
fn compute_hmac(json_bytes: &[u8]) -> String {
    let key = audit_hmac_key();
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take key of any size");
    mac.update(json_bytes);
    hex::encode(mac.finalize().into_bytes())
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
            hmac: None,
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
    /// The HMAC tag is computed over the canonical JSON (with the `hmac` field
    /// absent), then the full event including `hmac` is serialised and appended.
    ///
    /// Errors are logged but **not** propagated — audit logging must never
    /// block business logic.
    pub async fn log(&self, event: &AuditEvent) {
        let date = event.timestamp.format("%Y-%m-%d").to_string();
        let path = self.storage.paths().audit_events_file(&date);

        // Ensure audit directory exists.
        if let Some(parent) = path.parent() {
            let _ = tokio::fs::create_dir_all(parent).await;
        }

        // Compute HMAC over the canonical JSON (without hmac field).
        let mut canonical = event.clone();
        canonical.hmac = None;
        match serde_json::to_string(&canonical) {
            Ok(canonical_json) => {
                let tag = compute_hmac(canonical_json.as_bytes());
                let mut signed = event.clone();
                signed.hmac = Some(tag);
                match serde_json::to_string(&signed) {
                    Ok(mut line) => {
                        line.push('\n');
                        match tokio::fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&path)
                            .await
                        {
                            Ok(mut f) => {
                                if let Err(e) = f.write_all(line.as_bytes()).await {
                                    warn!(error = %e, path = %path.display(), "Failed to write audit event");
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, path = %path.display(), "Failed to open audit log file");
                            }
                        }
                    }
                    Err(e) => warn!(error = %e, "Failed to serialize signed audit event"),
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to serialize audit event for HMAC");
            }
        }
    }

    /// Read only events with a valid HMAC for the given date.
    ///
    /// Legacy events without an HMAC field are excluded.
    pub fn read_verified_events(&self, date: &str) -> Vec<AuditEvent> {
        let path = self.storage.paths().audit_events_file(date);
        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(_) => return Vec::new(),
        };
        data.lines()
            .filter_map(|line| {
                let event: AuditEvent = serde_json::from_str(line).ok()?;
                let tag = event.hmac.as_ref()?;
                let mut canonical = event.clone();
                canonical.hmac = None;
                let canonical_json = serde_json::to_string(&canonical).ok()?;
                let expected = compute_hmac(canonical_json.as_bytes());
                if tag == &expected {
                    Some(event)
                } else {
                    warn!(
                        event_id = %event.event_id,
                        "Audit event HMAC mismatch — excluding"
                    );
                    None
                }
            })
            .collect()
    }
}

/// Convenience macro for fire-and-forget audit logging.
///
/// Must be called from inside an async context (handler). The `.await` is
/// non-blocking because it uses `tokio::fs` internally.
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
        )
        .await;
    }};
}
