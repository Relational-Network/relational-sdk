// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Client-side validation for DRT instruction inputs.
//!
//! All rules match Section 15 of the sprint contract doc so requests can be
//! rejected early before hitting the chain.

use super::types::*;
use crate::error::ApiError;

/// Validate a pool name.
pub fn validate_pool_name(name: &str) -> Result<(), ApiError> {
    if name.is_empty() {
        return Err(ApiError::bad_request("pool name cannot be empty"));
    }
    if name != name.trim() {
        return Err(ApiError::bad_request(
            "pool name cannot have leading/trailing whitespace",
        ));
    }
    if name.len() > MAX_POOL_NAME_LEN {
        return Err(ApiError::bad_request(format!(
            "pool name exceeds maximum {MAX_POOL_NAME_LEN} bytes"
        )));
    }
    Ok(())
}

/// Validate a DRT type string.
fn validate_drt_type(drt_type: &str) -> Result<(), ApiError> {
    if drt_type.is_empty() {
        return Err(ApiError::bad_request("DRT type cannot be empty"));
    }
    if drt_type != drt_type.trim() {
        return Err(ApiError::bad_request(
            "DRT type cannot have leading/trailing whitespace",
        ));
    }
    if drt_type.len() > MAX_DRT_TYPE_LEN {
        return Err(ApiError::bad_request(format!(
            "DRT type exceeds maximum {MAX_DRT_TYPE_LEN} bytes"
        )));
    }
    Ok(())
}

/// Parse a 64-char hex string into `[u8; 32]`.
///
/// Returns all-zero for an empty or all-zero hex string.
pub fn validate_expected_hash(hash_hex: &str) -> Result<[u8; 32], ApiError> {
    if hash_hex.is_empty() {
        return Ok([0u8; 32]);
    }

    let clean = hash_hex.strip_prefix("0x").unwrap_or(hash_hex);
    if clean.len() != 64 {
        return Err(ApiError::bad_request(
            "expected_hash must be a 64-character hex string",
        ));
    }

    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&clean[i * 2..i * 2 + 2], 16)
            .map_err(|_| ApiError::bad_request("expected_hash contains invalid hex characters"))?;
    }
    Ok(bytes)
}

/// Validate a single `DrtInitConfigRequest` and convert to on-chain `DrtInitConfig`.
pub fn validate_drt_init_config(cfg: &DrtInitConfigRequest) -> Result<DrtInitConfig, ApiError> {
    validate_drt_type(&cfg.drt_type)?;

    // Supply bounds.
    if cfg.supply == 0 {
        return Err(ApiError::bad_request(
            "DRT supply must be greater than zero",
        ));
    }
    if cfg.supply > MAX_SUPPLY {
        return Err(ApiError::bad_request(format!(
            "DRT supply exceeds maximum ({MAX_SUPPLY})"
        )));
    }

    // Cost bounds.
    if cfg.cost == 0 {
        return Err(ApiError::bad_request("DRT cost must be greater than zero"));
    }
    if cfg.cost > MAX_COST_LAMPORTS {
        return Err(ApiError::bad_request(format!(
            "DRT cost exceeds maximum ({MAX_COST_LAMPORTS} lamports = 100 SOL)"
        )));
    }

    // Append vs non-append validation.
    let is_append = cfg.drt_type == APPEND_DRT_TYPE;
    let expected_hash = validate_expected_hash(&cfg.expected_hash)?;

    if is_append {
        if !cfg.github_url.is_empty() {
            return Err(ApiError::bad_request(
                "append DRT must not include github_url",
            ));
        }
        if expected_hash != [0u8; 32] {
            return Err(ApiError::bad_request(
                "append DRT must use a zeroed expected_hash",
            ));
        }
    } else {
        if cfg.github_url.is_empty() {
            return Err(ApiError::bad_request(
                "non-append DRT requires a github_url",
            ));
        }
        if cfg.github_url != cfg.github_url.trim() {
            return Err(ApiError::bad_request(
                "github_url cannot have leading/trailing whitespace",
            ));
        }
        if cfg.github_url.len() > MAX_GITHUB_URL_LEN {
            return Err(ApiError::bad_request(format!(
                "github_url exceeds maximum {MAX_GITHUB_URL_LEN} bytes"
            )));
        }
        if expected_hash == [0u8; 32] {
            return Err(ApiError::bad_request(
                "non-append DRT requires a non-zero expected_hash",
            ));
        }
    }

    // Token metadata.
    validate_token_string("token_name", &cfg.token_name, MAX_TOKEN_NAME_LEN)?;
    validate_token_string("token_symbol", &cfg.token_symbol, MAX_TOKEN_SYMBOL_LEN)?;
    validate_token_string("token_uri", &cfg.token_uri, MAX_TOKEN_URI_LEN)?;

    // Transfer fee.
    if cfg.transfer_fee_basis_points > MAX_TRANSFER_FEE_BPS {
        return Err(ApiError::bad_request(format!(
            "transfer_fee_basis_points exceeds maximum ({MAX_TRANSFER_FEE_BPS})"
        )));
    }
    if cfg.transfer_fee_basis_points > 0 && cfg.max_transfer_fee == 0 {
        return Err(ApiError::bad_request(
            "max_transfer_fee must be > 0 when transfer_fee_basis_points > 0",
        ));
    }

    Ok(DrtInitConfig {
        drt_type: cfg.drt_type.clone(),
        supply: cfg.supply,
        cost: cfg.cost,
        github_url: cfg.github_url.clone(),
        expected_hash,
        fixed_supply: cfg.fixed_supply,
        token_name: cfg.token_name.clone(),
        token_symbol: cfg.token_symbol.clone(),
        token_uri: cfg.token_uri.clone(),
        enable_transfer_hook: cfg.enable_transfer_hook,
        transfer_fee_basis_points: cfg.transfer_fee_basis_points,
        max_transfer_fee: cfg.max_transfer_fee,
    })
}

/// Validate a complete pool creation request (all configs).
pub fn validate_create_pool_request(
    pool_name: &str,
    configs: &[DrtInitConfigRequest],
) -> Result<Vec<DrtInitConfig>, ApiError> {
    validate_pool_name(pool_name)?;

    if configs.is_empty() {
        return Err(ApiError::bad_request("at least one DRT config is required"));
    }
    if configs.len() > MAX_DRTS_PER_POOL {
        return Err(ApiError::bad_request(format!(
            "too many DRT configs (max {MAX_DRTS_PER_POOL})"
        )));
    }

    // Check for duplicate drt_type.
    let mut seen = std::collections::HashSet::new();
    for cfg in configs {
        if !seen.insert(&cfg.drt_type) {
            return Err(ApiError::bad_request(format!(
                "duplicate DRT type '{}'",
                cfg.drt_type
            )));
        }
    }

    // Validate each config.
    configs.iter().map(validate_drt_init_config).collect()
}

/// Validate a non-empty, trimmed string field with a max byte length.
fn validate_token_string(field: &str, value: &str, max_len: usize) -> Result<(), ApiError> {
    if value.is_empty() {
        return Err(ApiError::bad_request(format!("{field} cannot be empty")));
    }
    if value != value.trim() {
        return Err(ApiError::bad_request(format!(
            "{field} cannot have leading/trailing whitespace"
        )));
    }
    if value.len() > max_len {
        return Err(ApiError::bad_request(format!(
            "{field} exceeds maximum {max_len} bytes"
        )));
    }
    Ok(())
}
