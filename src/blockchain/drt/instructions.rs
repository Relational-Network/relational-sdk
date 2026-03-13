// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Raw Solana instruction builders for the DRT program.
//!
//! Each function returns a `solana_instruction::Instruction` ready to
//! be included in a transaction. No `anchor-client` dependency — we build
//! the instruction data directly with the 8-byte Anchor discriminator
//! followed by Borsh-serialized arguments.

use borsh::BorshSerialize;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;
use std::str::FromStr;
use std::sync::OnceLock;

use super::pda::{derive_extra_metas_pda, derive_mint_pda, derive_vault_ata};
use super::types::*;
use crate::config::drt_program_id;

fn system_program_id() -> Pubkey {
    static ID: OnceLock<Pubkey> = OnceLock::new();
    *ID.get_or_init(|| Pubkey::from_str(SYSTEM_PROGRAM_ID_STR).expect("valid system program ID"))
}

// ============================================================================
// Helpers
// ============================================================================

fn token_2022_program_id() -> Pubkey {
    static ID: OnceLock<Pubkey> = OnceLock::new();
    *ID.get_or_init(|| {
        Pubkey::from_str(TOKEN_2022_PROGRAM_ID_STR).expect("valid Token-2022 program ID")
    })
}

fn associated_token_program_id() -> Pubkey {
    static ID: OnceLock<Pubkey> = OnceLock::new();
    *ID.get_or_init(|| {
        Pubkey::from_str(ASSOCIATED_TOKEN_PROGRAM_ID_STR).expect("valid ATA program ID")
    })
}

/// Build a `ComputeBudgetProgram::SetComputeUnitLimit` instruction.
pub fn build_compute_budget_ix(units: u32) -> Instruction {
    static COMPUTE_BUDGET_ID: OnceLock<Pubkey> = OnceLock::new();
    let program_id = *COMPUTE_BUDGET_ID.get_or_init(|| {
        Pubkey::from_str("ComputeBudget111111111111111111111111111111")
            .expect("valid ComputeBudget program ID")
    });
    // ComputeBudget instruction index 2 = SetComputeUnitLimit, followed by u32 LE.
    let data = {
        let mut buf = vec![2u8]; // instruction type
        buf.extend_from_slice(&units.to_le_bytes());
        buf
    };
    Instruction {
        program_id,
        accounts: vec![],
        data,
    }
}

// ============================================================================
// create_pool_atomic
// ============================================================================

/// Build the `create_pool_atomic` instruction.
///
/// Named accounts: pool (PDA, writable), owner (signer, writable),
/// token_program, associated_token_program, system_program.
///
/// Remaining accounts per DRT: [mint (writable), vault (writable), extra_metas (writable)].
pub fn build_create_pool_atomic(
    owner: &Pubkey,
    pool_pda: &Pubkey,
    pool_name: &str,
    drt_configs: &[DrtInitConfig],
) -> Result<Vec<Instruction>, String> {
    let program_id = drt_program_id();

    // Serialize instruction data: discriminator + args (name: String, drt_configs: Vec<DrtInitConfig>).
    let mut data = Vec::new();
    data.extend_from_slice(&DISC_CREATE_POOL_ATOMIC);
    pool_name
        .to_string()
        .serialize(&mut data)
        .map_err(|e| format!("Borsh serialize pool_name: {e}"))?;
    drt_configs
        .to_vec()
        .serialize(&mut data)
        .map_err(|e| format!("Borsh serialize drt_configs: {e}"))?;

    // Named accounts.
    let mut accounts = vec![
        AccountMeta::new(*pool_pda, false), // pool (writable, not signer)
        AccountMeta::new(*owner, true),     // owner (writable, signer)
        AccountMeta::new_readonly(token_2022_program_id(), false), // token_program
        AccountMeta::new_readonly(associated_token_program_id(), false), // associated_token_program
        AccountMeta::new_readonly(system_program_id(), false), // system_program
    ];

    // Remaining accounts: 3 per DRT (mint, vault, extra_metas).
    for cfg in drt_configs {
        let (mint_pda, _) = derive_mint_pda(pool_pda, &cfg.drt_type);
        let vault_ata = derive_vault_ata(pool_pda, &mint_pda);
        let (extra_metas_pda, _) = derive_extra_metas_pda(&mint_pda);

        accounts.push(AccountMeta::new(mint_pda, false)); // writable
        accounts.push(AccountMeta::new(vault_ata, false)); // writable
        accounts.push(AccountMeta::new(extra_metas_pda, false)); // writable
    }

    let main_ix = Instruction {
        program_id,
        accounts,
        data,
    };

    // Include compute budget instruction for multi-DRT transactions.
    Ok(vec![build_compute_budget_ix(800_000), main_ix])
}

// ============================================================================
// buy_drt
// ============================================================================

/// Build the `buy_drt` instruction.
///
/// Pass `hook_enabled = true` to add the 2 extra remaining accounts required
/// for DRTs with transfer hooks.
pub fn build_buy_drt(
    pool_pda: &Pubkey,
    pool_owner: &Pubkey,
    buyer: &Pubkey,
    drt_type: &str,
    amount: u64,
    mint: &Pubkey,
    hook_enabled: bool,
) -> Result<Instruction, String> {
    let program_id = drt_program_id();

    // Serialize instruction data: discriminator + drt_type + amount.
    let mut data = Vec::new();
    data.extend_from_slice(&DISC_BUY_DRT);
    drt_type
        .to_string()
        .serialize(&mut data)
        .map_err(|e| format!("Borsh serialize drt_type: {e}"))?;
    amount
        .serialize(&mut data)
        .map_err(|e| format!("Borsh serialize amount: {e}"))?;

    let vault_ata = derive_vault_ata(pool_pda, mint);
    let buyer_ata = super::pda::derive_user_ata(buyer, mint);

    let mut accounts = vec![
        AccountMeta::new_readonly(*pool_pda, false), // pool
        AccountMeta::new(*mint, false),              // drt_mint (writable)
        AccountMeta::new(vault_ata, false),          // vault_token_account (writable)
        AccountMeta::new(*buyer, true),              // buyer (signer, writable)
        AccountMeta::new(buyer_ata, false),          // buyer_token_account (writable)
        AccountMeta::new(*pool_owner, false),        // pool_owner (writable)
        AccountMeta::new_readonly(token_2022_program_id(), false), // token_program
        AccountMeta::new_readonly(associated_token_program_id(), false), // associated_token_program
        AccountMeta::new_readonly(system_program_id(), false), // system_program
    ];

    // Hook remaining accounts.
    if hook_enabled {
        let (extra_metas_pda, _) = derive_extra_metas_pda(mint);
        accounts.push(AccountMeta::new_readonly(extra_metas_pda, false));
        accounts.push(AccountMeta::new_readonly(program_id, false));
    }

    Ok(Instruction {
        program_id,
        accounts,
        data,
    })
}

// ============================================================================
// redeem_drt
// ============================================================================

/// Build the `redeem_drt` instruction (burns 1 token).
pub fn build_redeem_drt(
    pool_pda: &Pubkey,
    user: &Pubkey,
    drt_type: &str,
    mint: &Pubkey,
) -> Result<Instruction, String> {
    let program_id = drt_program_id();

    let mut data = Vec::new();
    data.extend_from_slice(&DISC_REDEEM_DRT);
    drt_type
        .to_string()
        .serialize(&mut data)
        .map_err(|e| format!("Borsh serialize drt_type: {e}"))?;

    let user_ata = super::pda::derive_user_ata(user, mint);

    let accounts = vec![
        AccountMeta::new_readonly(*pool_pda, false), // pool
        AccountMeta::new(*mint, false),              // drt_mint (writable)
        AccountMeta::new(*user, true),               // user (signer, writable)
        AccountMeta::new(user_ata, false),           // user_token_account (writable)
        AccountMeta::new_readonly(token_2022_program_id(), false), // token_program
    ];

    Ok(Instruction {
        program_id,
        accounts,
        data,
    })
}

// ============================================================================
// close_pool
// ============================================================================

/// Build the `close_pool` instruction.
///
/// Remaining accounts: per DRT in the pool, 3 accounts
/// `[mint (writable), vault (writable), extra_metas_or_placeholder]`.
/// For non-hook mints, use `SystemProgram` as placeholder.
pub fn build_close_pool(pool_pda: &Pubkey, owner: &Pubkey, drts: &[DrtConfig]) -> Instruction {
    let program_id = drt_program_id();

    let data = DISC_CLOSE_POOL.to_vec();

    let mut accounts = vec![
        AccountMeta::new(*pool_pda, false), // pool (writable)
        AccountMeta::new(*owner, true),     // owner (signer, writable)
        AccountMeta::new_readonly(token_2022_program_id(), false), // token_program
        AccountMeta::new_readonly(system_program_id(), false), // system_program
    ];

    for drt in drts {
        let mint = drt.mint;
        let vault = derive_vault_ata(pool_pda, &mint);

        accounts.push(AccountMeta::new(mint, false)); // writable
        accounts.push(AccountMeta::new(vault, false)); // writable

        if drt.enable_transfer_hook {
            let (extra_metas, _) = derive_extra_metas_pda(&mint);
            accounts.push(AccountMeta::new(extra_metas, false)); // writable
        } else {
            // Placeholder — system program as non-writable.
            accounts.push(AccountMeta::new_readonly(system_program_id(), false));
        }
    }

    Instruction {
        program_id,
        accounts,
        data,
    }
}
