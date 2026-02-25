// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Encrypted storage layer backed by Gramine's sealed filesystem.
//!
//! Gramine mounts `/data` as `type = "encrypted"` using AES-GCM with a key
//! derived from the enclave signer identity (`_sgx_mrsigner`).  The Rust code
//! uses **normal `std::fs`** — Gramine handles encryption transparently.
//!
//! # Layout
//!
//! ```text
//! /data/
//! ├── wallets/{wallet_id}/
//! │   ├── meta.json
//! │   └── keypair.json
//! ├── audit/
//! │   └── 2026-02-24.jsonl
//! └── tx.redb
//! ```

pub mod audit;
pub mod encrypted_fs;
pub mod ownership;
pub mod paths;
pub mod repository;
pub mod tx_cache;
pub mod tx_database;

// Re-exports for convenience.
pub use encrypted_fs::EncryptedStorage;
pub use paths::StoragePaths;
