// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! Build, sign, and send Solana transactions (native SOL + SPL tokens).

use solana_message::Message;
use solana_sdk::{
    pubkey::Pubkey,
    signature::Signature,
    signer::{keypair::Keypair, Signer},
};
use solana_system_interface::instruction as system_instruction;
use solana_transaction::Transaction;
use std::str::FromStr;
use tracing::info;

use super::client::SolanaClient;
use super::types::SendResult;
use crate::error::ApiError;

impl SolanaClient {
    /// Send native SOL from `keypair` to `recipient`.
    pub async fn send_native(
        &self,
        keypair: &Keypair,
        recipient: &str,
        lamports: u64,
    ) -> Result<SendResult, ApiError> {
        let to = Pubkey::from_str(recipient)
            .map_err(|_| ApiError::unprocessable(format!("invalid recipient: {recipient}")))?;

        let instruction = system_instruction::transfer(&keypair.pubkey(), &to, lamports).into();
        let recent_blockhash = self
            .rpc
            .get_latest_blockhash()
            .await
            .map_err(|e| ApiError::service_unavailable(format!("blockhash fetch failed: {e}")))?;

        let message = Message::new(&[instruction], Some(&keypair.pubkey()));
        let tx = Transaction::new(&[keypair], message, recent_blockhash);

        let signature: Signature = self
            .rpc
            .send_and_confirm_transaction(&tx)
            .await
            .map_err(|e| ApiError::service_unavailable(format!("transaction failed: {e}")))?;

        let sig_str = signature.to_string();
        info!(signature = %sig_str, to = %recipient, lamports, "SOL transfer sent");

        Ok(SendResult {
            explorer_url: self.network.explorer_tx_url(&sig_str),
            signature: sig_str,
        })
    }

    /// Estimate the fee for a transfer message.
    pub async fn estimate_fee(
        &self,
        from: &Pubkey,
        to: &Pubkey,
        lamports: u64,
    ) -> Result<u64, ApiError> {
        let instruction = system_instruction::transfer(from, to, lamports).into();
        let recent_blockhash = self
            .rpc
            .get_latest_blockhash()
            .await
            .map_err(|e| ApiError::service_unavailable(format!("blockhash fetch failed: {e}")))?;

        let message = Message::new_with_blockhash(&[instruction], Some(from), &recent_blockhash);
        self.rpc
            .get_fee_for_message(&message)
            .await
            .map_err(|e| ApiError::service_unavailable(format!("fee estimation failed: {e}")))
    }
}
