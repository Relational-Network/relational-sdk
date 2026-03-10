// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Constants derived from the Anchor IDL (`idl/drt_contract.json`).
//!
//! When the smart contract changes, update the IDL JSON and copy the new
//! discriminators / error codes here.  Discriminators are the first 8 bytes
//! of `sha256("global:<instruction_name>")` (Anchor convention).
//!
//! Not all constants are used by the client — that's expected and intentional.
#![allow(dead_code)]

/// Deployed program address (from IDL).
pub const IDL_PROGRAM_ADDRESS: &str = "kG7AyfxRoNKcYWGH8aDR6tCFpLVcETt2kBVaPnQCrnp";

// ── Instruction discriminators ──────────────────────────────────

pub const DISC_BUY_DRT: [u8; 8] = [218, 223, 158, 106, 131, 8, 185, 169];
pub const DISC_CLOSE_POOL: [u8; 8] = [140, 189, 209, 23, 239, 62, 239, 11];
pub const DISC_CREATE_POOL: [u8; 8] = [233, 146, 209, 142, 207, 104, 64, 188];
pub const DISC_CREATE_POOL_ATOMIC: [u8; 8] = [111, 115, 11, 248, 238, 190, 197, 135];
pub const DISC_EXECUTE_TRANSFER_HOOK: [u8; 8] = [105, 37, 101, 197, 75, 251, 102, 26];
pub const DISC_INITIALIZE_AND_MINT_DRT: [u8; 8] = [99, 243, 187, 87, 69, 42, 72, 26];
pub const DISC_REDEEM_DRT: [u8; 8] = [79, 17, 209, 207, 80, 225, 246, 145];

// ── Account discriminators ──────────────────────────────────────

pub const DISC_POOL_ACCOUNT: [u8; 8] = [241, 154, 109, 4, 17, 177, 109, 188];

// ── Event discriminators ────────────────────────────────────────

pub const DISC_APPEND_REDEEMED: [u8; 8] = [23, 103, 73, 233, 18, 83, 30, 232];
pub const DISC_DRT_INITIALIZED: [u8; 8] = [151, 135, 79, 83, 56, 230, 190, 206];
pub const DISC_DRT_PURCHASED: [u8; 8] = [116, 59, 17, 172, 205, 194, 249, 108];
pub const DISC_DRT_REDEEMED: [u8; 8] = [91, 80, 227, 141, 229, 217, 44, 23];
pub const DISC_POOL_CLOSED: [u8; 8] = [106, 46, 29, 231, 42, 44, 73, 119];
pub const DISC_POOL_CREATED: [u8; 8] = [202, 44, 41, 88, 104, 220, 157, 82];

// ── Program error codes ─────────────────────────────────────────

/// Pool name cannot be empty or have leading/trailing whitespace
pub const ERR_INVALID_POOL_NAME: u32 = 6000;
/// At least one DRT config is required
pub const ERR_EMPTY_DRT_CONFIGS: u32 = 6001;
/// DRT type cannot be empty or have leading/trailing whitespace
pub const ERR_INVALID_DRT_TYPE: u32 = 6002;
/// DRT supply must be greater than zero
pub const ERR_INVALID_SUPPLY: u32 = 6003;
/// DRT cost must be greater than zero
pub const ERR_INVALID_COST: u32 = 6004;
/// github_url cannot be empty or have whitespace padding for non-append DRTs
pub const ERR_INVALID_GITHUB_URL: u32 = 6005;
/// expected_hash must be a non-zero 32-byte value for non-append DRTs
pub const ERR_INVALID_EXPECTED_HASH: u32 = 6006;
/// append DRT must not include github_url and must use a zeroed expected_hash
pub const ERR_INVALID_APPEND_METADATA: u32 = 6007;
/// Duplicate DRT type in pool config
pub const ERR_DUPLICATE_DRT_TYPE: u32 = 6008;
/// DRT not found in pool
pub const ERR_DRT_NOT_FOUND: u32 = 6009;
/// Caller is not the pool owner
pub const ERR_UNAUTHORIZED: u32 = 6010;
/// DRT supply has not been minted yet
pub const ERR_NOT_MINTED: u32 = 6011;
/// Vault has insufficient tokens
pub const ERR_INSUFFICIENT_VAULT_TOKENS: u32 = 6012;
/// User does not hold this DRT token
pub const ERR_INSUFFICIENT_TOKENS: u32 = 6013;
/// Pool name exceeds maximum PDA seed length (32 bytes)
pub const ERR_NAME_TOO_LONG: u32 = 6014;
/// DRT type exceeds maximum PDA seed length (32 bytes)
pub const ERR_DRT_TYPE_TOO_LONG: u32 = 6015;
/// Too many DRT configs (max 20)
pub const ERR_TOO_MANY_DRT_CONFIGS: u32 = 6016;
/// github_url exceeds maximum length (256 bytes)
pub const ERR_GITHUB_URL_TOO_LONG: u32 = 6017;
/// Pool still has unminted or active DRT supply
pub const ERR_POOL_NOT_EMPTY: u32 = 6018;
/// DRT supply exceeds maximum (1 billion)
pub const ERR_SUPPLY_TOO_HIGH: u32 = 6019;
/// DRT cost exceeds maximum (100 SOL)
pub const ERR_COST_TOO_HIGH: u32 = 6020;
/// Token name is invalid
pub const ERR_INVALID_TOKEN_NAME: u32 = 6021;
/// Token symbol is invalid
pub const ERR_INVALID_TOKEN_SYMBOL: u32 = 6022;
/// Token URI is invalid
pub const ERR_INVALID_TOKEN_URI: u32 = 6023;
/// Transfer fee config is invalid
pub const ERR_INVALID_TRANSFER_FEE: u32 = 6024;
/// Token metadata serialization/size calculation failed
pub const ERR_METADATA_SERIALIZATION_FAILED: u32 = 6025;
/// Invalid amount
pub const ERR_INVALID_AMOUNT: u32 = 6026;
/// Arithmetic overflow
pub const ERR_ARITHMETIC_OVERFLOW: u32 = 6027;
/// Invalid remaining account layout
pub const ERR_INVALID_REMAINING_ACCOUNTS: u32 = 6028;
/// DRT mint account mismatch
pub const ERR_DRT_MINT_MISMATCH: u32 = 6029;
/// Vault account mismatch
pub const ERR_VAULT_MISMATCH: u32 = 6030;
/// Mint account already initialized
pub const ERR_MINT_ALREADY_INITIALIZED: u32 = 6031;
/// Invalid token program for provided account
pub const ERR_INVALID_TOKEN_PROGRAM: u32 = 6032;
/// ExtraAccountMetaList PDA mismatch
pub const ERR_EXTRA_METAS_MISMATCH: u32 = 6033;
/// ExtraAccountMetaList account is not owned by this program
pub const ERR_INVALID_EXTRA_METAS_OWNER: u32 = 6034;
/// Invalid transfer-hook program account
pub const ERR_INVALID_HOOK_PROGRAM: u32 = 6035;
/// Pool account is full; create a new pool with shorter metadata
pub const ERR_POOL_ACCOUNT_FULL: u32 = 6036;

// ── Instruction account lists (name, writable, signer) ──────────

pub const BUY_DRT_ACCOUNTS: &[(&str, bool, bool)] = &[
    ("pool", false, false),
    ("drt_mint", true, false),
    ("vault_token_account", true, false),
    ("buyer", true, true),
    ("buyer_token_account", true, false),
    ("pool_owner", true, false),
    ("token_program", false, false),
    ("associated_token_program", false, false),
    ("system_program", false, false),
];

pub const CLOSE_POOL_ACCOUNTS: &[(&str, bool, bool)] = &[
    ("pool", true, false),
    ("owner", true, true),
    ("token_program", false, false),
    ("system_program", false, false),
];

pub const CREATE_POOL_ACCOUNTS: &[(&str, bool, bool)] = &[
    ("pool", true, false),
    ("owner", true, true),
    ("system_program", false, false),
];

pub const CREATE_POOL_ATOMIC_ACCOUNTS: &[(&str, bool, bool)] = &[
    ("pool", true, false),
    ("owner", true, true),
    ("token_program", false, false),
    ("associated_token_program", false, false),
    ("system_program", false, false),
];

pub const EXECUTE_TRANSFER_HOOK_ACCOUNTS: &[(&str, bool, bool)] = &[
    ("source", false, false),
    ("mint", false, false),
    ("destination", false, false),
    ("authority", false, false),
    ("extra_account_metas", false, false),
];

pub const INITIALIZE_AND_MINT_DRT_ACCOUNTS: &[(&str, bool, bool)] = &[
    ("pool", true, false),
    ("owner", true, true),
    ("drt_mint", true, false),
    ("vault_token_account", true, false),
    ("extra_metas_account", true, false),
    ("token_program", false, false),
    ("associated_token_program", false, false),
    ("system_program", false, false),
];

pub const REDEEM_DRT_ACCOUNTS: &[(&str, bool, bool)] = &[
    ("pool", false, false),
    ("drt_mint", true, false),
    ("user", true, true),
    ("user_token_account", true, false),
    ("token_program", false, false),
];
