// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! DRT (Data Rights Token) smart contract integration.
//!
//! Provides Borsh-based instruction building, PDA derivation, on-chain account
//! deserialization, and Anchor event parsing for the deployed DRT program
//! (`kG7AyfxRoNKcYWGH8aDR6tCFpLVcETt2kBVaPnQCrnp`).

pub mod accounts;
pub mod events;
pub mod instructions;
pub mod pda;
pub mod types;
pub mod validation;
