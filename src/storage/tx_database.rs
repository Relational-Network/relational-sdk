// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Embedded ACID transaction database backed by [`redb`].
//!
//! Tables:
//! - `transactions`      — signature (str) → StoredTransaction JSON bytes
//! - `wallet_tx_index`   — composite key → direction ("sent" / "received")
//! - `address_wallet_map` — base58 address → wallet_id (UUID)
//! - `indexer_state`     — key → checkpoint bytes

use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::path::Path;

use super::repository::transactions::{StoredTransaction, TxStatus};

// ── Table definitions ──────────────────────────────────────────────

const TRANSACTIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("transactions");
const WALLET_TX_INDEX: TableDefinition<&[u8], &str> = TableDefinition::new("wallet_tx_index");
const ADDRESS_WALLET_MAP: TableDefinition<&str, &str> = TableDefinition::new("address_wallet_map");
const INDEXER_STATE: TableDefinition<&str, &[u8]> = TableDefinition::new("indexer_state");
/// Nonce replay protection: nonce_string → unix_timestamp (i64 LE bytes).
const NONCES: TableDefinition<&str, &[u8]> = TableDefinition::new("nonces");

/// Result alias for tx database operations.
pub type TxDbResult<T> = Result<T, TxDbError>;

/// Transaction database error.
#[derive(Debug)]
pub enum TxDbError {
    Redb(redb::Error),
    Database(redb::DatabaseError),
    TableError(redb::TableError),
    StorageError(redb::StorageError),
    TransactionError(redb::TransactionError),
    CommitError(redb::CommitError),
    Json(serde_json::Error),
    /// Client provided a tampered or invalid pagination cursor.
    InvalidCursor,
}

impl std::fmt::Display for TxDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Redb(e) => write!(f, "redb: {e}"),
            Self::Database(e) => write!(f, "database: {e}"),
            Self::TableError(e) => write!(f, "table: {e}"),
            Self::StorageError(e) => write!(f, "storage: {e}"),
            Self::TransactionError(e) => write!(f, "transaction: {e}"),
            Self::CommitError(e) => write!(f, "commit: {e}"),
            Self::Json(e) => write!(f, "json: {e}"),
            Self::InvalidCursor => write!(f, "invalid pagination cursor"),
        }
    }
}

impl std::error::Error for TxDbError {}

impl From<redb::Error> for TxDbError {
    fn from(e: redb::Error) -> Self {
        Self::Redb(e)
    }
}
impl From<redb::DatabaseError> for TxDbError {
    fn from(e: redb::DatabaseError) -> Self {
        Self::Database(e)
    }
}
impl From<redb::TableError> for TxDbError {
    fn from(e: redb::TableError) -> Self {
        Self::TableError(e)
    }
}
impl From<redb::StorageError> for TxDbError {
    fn from(e: redb::StorageError) -> Self {
        Self::StorageError(e)
    }
}
impl From<redb::TransactionError> for TxDbError {
    fn from(e: redb::TransactionError) -> Self {
        Self::TransactionError(e)
    }
}
impl From<redb::CommitError> for TxDbError {
    fn from(e: redb::CommitError) -> Self {
        Self::CommitError(e)
    }
}
impl From<serde_json::Error> for TxDbError {
    fn from(e: serde_json::Error) -> Self {
        Self::Json(e)
    }
}

impl From<TxDbError> for crate::error::ApiError {
    fn from(e: TxDbError) -> Self {
        match &e {
            TxDbError::InvalidCursor => Self::bad_request("invalid pagination cursor"),
            _ => {
                tracing::error!(error = %e, "Transaction database error");
                Self::internal("internal database error")
            }
        }
    }
}

/// Embedded ACID transaction store.
pub struct TxDatabase {
    db: Database,
}

impl TxDatabase {
    /// Open (or create) the redb database at the given path.
    pub fn open(path: &Path) -> TxDbResult<Self> {
        let db = Database::create(path)?;

        // Ensure tables exist.
        let write_txn = db.begin_write()?;
        {
            let _ = write_txn.open_table(TRANSACTIONS)?;
            let _ = write_txn.open_table(WALLET_TX_INDEX)?;
            let _ = write_txn.open_table(ADDRESS_WALLET_MAP)?;
            let _ = write_txn.open_table(INDEXER_STATE)?;
            let _ = write_txn.open_table(NONCES)?;
        }
        write_txn.commit()?;

        Ok(Self { db })
    }

    /// Start a read transaction.  Used by the readiness probe to verify
    /// the database file is intact and readable.
    pub fn begin_read_txn(&self) -> TxDbResult<()> {
        let _txn = self.db.begin_read()?;
        Ok(())
    }

    /// Insert or update a transaction, with direction entries for each involved address.
    ///
    /// `directions` is a list of `(address, direction)` pairs — e.g.,
    /// `[("SenderAddr", "sent"), ("ReceiverAddr", "received")]`.
    pub fn upsert_transaction(
        &self,
        tx: &StoredTransaction,
        directions: &[(String, &str)],
    ) -> TxDbResult<()> {
        let json_bytes = serde_json::to_vec(tx)?;
        let write_txn = self.db.begin_write()?;
        {
            // Main transaction record.
            let mut table = write_txn.open_table(TRANSACTIONS)?;
            table.insert(tx.signature.as_str(), json_bytes.as_slice())?;

            // Wallet→tx index entries.
            let mut idx = write_txn.open_table(WALLET_TX_INDEX)?;
            for (address, direction) in directions {
                let key = make_index_key(address, tx.created_at.timestamp(), &tx.signature);
                idx.insert(key.as_slice(), *direction)?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Get a single transaction by signature.
    pub fn get_transaction(&self, signature: &str) -> TxDbResult<Option<StoredTransaction>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(TRANSACTIONS)?;
        match table.get(signature)? {
            Some(bytes) => {
                let tx: StoredTransaction = serde_json::from_slice(bytes.value())?;
                Ok(Some(tx))
            }
            None => Ok(None),
        }
    }

    /// List transactions for a wallet address with cursor-based pagination.
    ///
    /// Returns `(entries, next_cursor)` where each entry is `(StoredTransaction, direction)`.
    #[allow(clippy::type_complexity)]
    pub fn list_by_wallet(
        &self,
        address: &str,
        cursor: Option<&str>,
        limit: usize,
    ) -> TxDbResult<(Vec<(StoredTransaction, String)>, Option<String>)> {
        let read_txn = self.db.begin_read()?;
        let idx = read_txn.open_table(WALLET_TX_INDEX)?;
        let tx_table = read_txn.open_table(TRANSACTIONS)?;

        // Build start key from cursor or scan from the beginning of the address prefix.
        let prefix = format!("{address}|");
        let start = match cursor {
            Some(c) => verify_cursor(c)
                .ok_or(TxDbError::InvalidCursor)?
                .into_bytes(),
            None => prefix.as_bytes().to_vec(),
        };

        let mut results = Vec::new();
        let mut next_cursor = None;

        let range = idx.range(start.as_slice()..)?;
        for entry in range {
            let (key_guard, val_guard) = entry?;
            let key_bytes = key_guard.value();
            let key_str = std::str::from_utf8(key_bytes).unwrap_or("");

            // Stop once we leave this address's prefix.
            if !key_str.starts_with(&prefix) {
                break;
            }

            if results.len() >= limit {
                next_cursor = Some(sign_cursor(key_str));
                break;
            }

            let direction = val_guard.value().to_string();
            // Extract signature from key: "address|!timestamp|signature"
            if let Some(sig) = key_str.rsplit('|').next() {
                if let Some(bytes) = tx_table.get(sig)? {
                    if let Ok(tx) = serde_json::from_slice::<StoredTransaction>(bytes.value()) {
                        results.push((tx, direction));
                    }
                }
            }
        }

        Ok((results, next_cursor))
    }

    /// Update status, slot, and fee of an existing transaction.
    #[allow(dead_code)]
    pub fn update_status(
        &self,
        signature: &str,
        status: TxStatus,
        slot: Option<u64>,
        fee: Option<u64>,
    ) -> TxDbResult<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(TRANSACTIONS)?;

            // Read the existing record into owned bytes first to release borrow.
            let existing_bytes = { table.get(signature)?.map(|guard| guard.value().to_vec()) };

            if let Some(bytes) = existing_bytes {
                let mut tx: StoredTransaction = serde_json::from_slice(&bytes)?;
                tx.status = status;
                if let Some(s) = slot {
                    tx.slot = Some(s);
                }
                if let Some(f) = fee {
                    tx.fee_lamports = Some(f);
                }
                tx.updated_at = chrono::Utc::now();
                let json_bytes = serde_json::to_vec(&tx)?;
                table.insert(signature, json_bytes.as_slice())?;
            }
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Register a Solana address → wallet_id mapping (for the indexer).
    pub fn register_address(&self, address: &str, wallet_id: &str) -> TxDbResult<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(ADDRESS_WALLET_MAP)?;
            table.insert(address, wallet_id)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    /// Look up which wallet owns an address.
    #[allow(dead_code)]
    pub fn get_wallet_id_for_address(&self, address: &str) -> TxDbResult<Option<String>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(ADDRESS_WALLET_MAP)?;
        Ok(table.get(address)?.map(|v| v.value().to_string()))
    }

    /// Get all registered addresses (for the indexer to poll).
    pub fn get_all_addresses(&self) -> TxDbResult<Vec<(String, String)>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(ADDRESS_WALLET_MAP)?;
        let mut result = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            result.push((k.value().to_string(), v.value().to_string()));
        }
        Ok(result)
    }

    /// Read indexer checkpoint (e.g., last processed signature).
    pub fn get_indexer_state(&self, key: &str) -> TxDbResult<Option<Vec<u8>>> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(INDEXER_STATE)?;
        Ok(table.get(key)?.map(|v| v.value().to_vec()))
    }

    /// Write indexer checkpoint.
    pub fn set_indexer_state(&self, key: &str, value: &[u8]) -> TxDbResult<()> {
        let write_txn = self.db.begin_write()?;
        {
            let mut table = write_txn.open_table(INDEXER_STATE)?;
            table.insert(key, value)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    // ── Nonce replay protection ────────────────────────────────────

    /// Record a nonce. Returns `true` if the nonce was **new** (inserted),
    /// `false` if it was already present (replay detected).
    pub fn record_nonce(&self, nonce: &str) -> TxDbResult<bool> {
        let write_txn = self.db.begin_write()?;
        let is_new = {
            let mut table = write_txn.open_table(NONCES)?;
            if table.get(nonce)?.is_some() {
                false
            } else {
                let now = chrono::Utc::now().timestamp().to_le_bytes();
                table.insert(nonce, now.as_slice())?;
                true
            }
        };
        write_txn.commit()?;
        Ok(is_new)
    }

    /// Purge nonces older than `max_age_secs` to prevent unbounded growth.
    pub fn purge_expired_nonces(&self, max_age_secs: i64) -> TxDbResult<usize> {
        let cutoff = chrono::Utc::now().timestamp() - max_age_secs;
        let write_txn = self.db.begin_write()?;
        let mut removed = 0usize;
        {
            let mut table = write_txn.open_table(NONCES)?;
            let mut to_remove = Vec::new();
            {
                let iter = table.iter()?;
                for entry in iter {
                    let entry = entry?;
                    let nonce_key = entry.0.value().to_string();
                    let ts_bytes: [u8; 8] = entry.1.value().try_into().unwrap_or([0u8; 8]);
                    let ts = i64::from_le_bytes(ts_bytes);
                    if ts < cutoff {
                        to_remove.push(nonce_key);
                    }
                }
            }
            for key in &to_remove {
                table.remove(key.as_str())?;
                removed += 1;
            }
        }
        write_txn.commit()?;
        Ok(removed)
    }
}

// ── Index key helpers ──────────────────────────────────────────────

/// Build a composite index key: `{address}|{!timestamp_be}|{signature}`.
///
/// Timestamp is bitwise-inverted so that lexicographic ordering gives
/// reverse chronological order (newest first).
fn make_index_key(address: &str, timestamp: i64, signature: &str) -> Vec<u8> {
    let mut key = Vec::with_capacity(address.len() + 1 + 8 + 1 + signature.len());
    key.extend_from_slice(address.as_bytes());
    key.push(b'|');
    key.extend_from_slice(&(!timestamp as u64).to_be_bytes());
    key.push(b'|');
    key.extend_from_slice(signature.as_bytes());
    key
}

// ── Signed pagination cursor helpers ───────────────────────────────

use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Derive an HMAC key specifically for cursor signing from the enclave's
/// **private** scalar (not the public `kid`).
fn cursor_hmac_key() -> [u8; 32] {
    crate::crypto::enclave_key().hmac_key(b"cursor-hmac-v1")
}

/// Sign a raw cursor value, returning an opaque token: `base64url(raw).hmac_hex`.
pub fn sign_cursor(raw: &str) -> String {
    let key = cursor_hmac_key();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw.as_bytes());
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take any key size");
    mac.update(raw.as_bytes());
    let tag = hex::encode(mac.finalize().into_bytes());
    format!("{encoded}.{tag}")
}

/// Verify a signed cursor and return the raw cursor value, or `None` if forged.
pub fn verify_cursor(token: &str) -> Option<String> {
    let (encoded, tag) = token.rsplit_once('.')?;
    let raw_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()?;
    let raw = String::from_utf8(raw_bytes).ok()?;
    let key = cursor_hmac_key();
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC can take any key size");
    mac.update(raw.as_bytes());
    let expected = hex::encode(mac.finalize().into_bytes());
    if expected == tag { Some(raw) } else { None }
}
