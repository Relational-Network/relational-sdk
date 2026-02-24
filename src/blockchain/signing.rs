// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Load Ed25519 keypairs from stored byte arrays.

use crate::error::ApiError;
use solana_sdk::signer::keypair::Keypair;
use solana_sdk::signer::Signer;

/// Reconstruct a Solana [`Keypair`] from the 64-byte array stored on disk.
pub fn keypair_from_bytes(bytes: &[u8]) -> Result<Keypair, ApiError> {
    Keypair::try_from(bytes).map_err(|e| ApiError::internal(format!("invalid keypair data: {e}")))
}

/// Generate a new random Ed25519 keypair for Solana.
///
/// Returns `(keypair_bytes, base58_public_address)`.
pub fn generate_solana_keypair() -> Result<(Vec<u8>, String), ApiError> {
    let keypair = Keypair::new();
    let public_address = keypair.pubkey().to_string();
    let keypair_bytes = keypair.to_bytes().to_vec();
    Ok((keypair_bytes, public_address))
}
