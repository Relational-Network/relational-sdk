// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! PDA (Program Derived Address) derivation for the DRT program.
//!
//! All addresses are deterministic and must match the on-chain program's
//! seed conventions exactly.

use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;
use std::sync::OnceLock;

use super::types::{ASSOCIATED_TOKEN_PROGRAM_ID_STR, TOKEN_2022_PROGRAM_ID_STR};
use crate::config::drt_program_id;

/// Derive the Pool PDA.
///
/// Seeds: `["pool", owner_bytes, pool_name_utf8]`
pub fn derive_pool_pda(owner: &Pubkey, pool_name: &str) -> (Pubkey, u8) {
    let program_id = drt_program_id();
    Pubkey::find_program_address(
        &[b"pool", owner.as_ref(), pool_name.as_bytes()],
        &program_id,
    )
}

/// Derive the DRT Mint PDA.
///
/// Seeds: `["drt_mint", pool_pda_bytes, drt_type_utf8]`
pub fn derive_mint_pda(pool: &Pubkey, drt_type: &str) -> (Pubkey, u8) {
    let program_id = drt_program_id();
    Pubkey::find_program_address(
        &[b"drt_mint", pool.as_ref(), drt_type.as_bytes()],
        &program_id,
    )
}

/// Derive the ExtraAccountMetaList PDA (for transfer hook).
///
/// Seeds: `["extra-account-metas", mint_bytes]`
pub fn derive_extra_metas_pda(mint: &Pubkey) -> (Pubkey, u8) {
    let program_id = drt_program_id();
    Pubkey::find_program_address(&[b"extra-account-metas", mint.as_ref()], &program_id)
}

/// Derive the vault ATA (Associated Token Account) for a pool holding DRT tokens.
///
/// This is a Token-2022 ATA: `seeds = [pool, TOKEN_2022_PROGRAM, mint]` under ATA program.
pub fn derive_vault_ata(pool: &Pubkey, mint: &Pubkey) -> Pubkey {
    static TOKEN_PROGRAM: OnceLock<Pubkey> = OnceLock::new();
    static ATA_PROGRAM: OnceLock<Pubkey> = OnceLock::new();
    let token_program = TOKEN_PROGRAM.get_or_init(|| {
        Pubkey::from_str(TOKEN_2022_PROGRAM_ID_STR).expect("valid Token-2022 program ID")
    });
    let ata_program = ATA_PROGRAM.get_or_init(|| {
        Pubkey::from_str(ASSOCIATED_TOKEN_PROGRAM_ID_STR).expect("valid ATA program ID")
    });
    Pubkey::find_program_address(
        &[pool.as_ref(), token_program.as_ref(), mint.as_ref()],
        ata_program,
    )
    .0
}

/// Derive a user's ATA for a Token-2022 mint.
pub fn derive_user_ata(user: &Pubkey, mint: &Pubkey) -> Pubkey {
    static TOKEN_PROGRAM: OnceLock<Pubkey> = OnceLock::new();
    static ATA_PROGRAM: OnceLock<Pubkey> = OnceLock::new();
    let token_program = TOKEN_PROGRAM.get_or_init(|| {
        Pubkey::from_str(TOKEN_2022_PROGRAM_ID_STR).expect("valid Token-2022 program ID")
    });
    let ata_program = ATA_PROGRAM.get_or_init(|| {
        Pubkey::from_str(ASSOCIATED_TOKEN_PROGRAM_ID_STR).expect("valid ATA program ID")
    });
    Pubkey::find_program_address(
        &[user.as_ref(), token_program.as_ref(), mint.as_ref()],
        ata_program,
    )
    .0
}
