// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Relational Network

//! SPL token balance queries and transfers.

use solana_sdk::{
    pubkey::Pubkey,
    signer::{keypair::Keypair, Signer},
};
use std::str::FromStr;
use tracing::info;

use super::client::SolanaClient;
use super::types::SendResult;
use crate::error::ApiError;

impl SolanaClient {
    /// Send SPL tokens from `keypair` to `recipient`.
    pub async fn send_spl_token(
        &self,
        keypair: &Keypair,
        recipient: &str,
        mint_address: &str,
        amount: u64,
        decimals: u8,
    ) -> Result<SendResult, ApiError> {
        let to_pubkey = Pubkey::from_str(recipient)
            .map_err(|_| ApiError::unprocessable(format!("invalid recipient: {recipient}")))?;
        let mint = Pubkey::from_str(mint_address)
            .map_err(|_| ApiError::unprocessable("invalid mint address"))?;

        let from_ata =
            spl_associated_token_account::get_associated_token_address(&keypair.pubkey(), &mint);
        let to_ata = spl_associated_token_account::get_associated_token_address(&to_pubkey, &mint);

        let mut instructions = Vec::new();

        // Create ATA for recipient if it doesn't exist.
        // Check if the account exists first.
        let to_ata_exists = self.rpc.get_account(&to_ata).await.is_ok();
        if !to_ata_exists {
            instructions.push(
                spl_associated_token_account::instruction::create_associated_token_account(
                    &keypair.pubkey(),
                    &to_pubkey,
                    &mint,
                    &spl_token::id(),
                ),
            );
        }

        // SPL transfer instruction.
        instructions.push(
            spl_token::instruction::transfer_checked(
                &spl_token::id(),
                &from_ata,
                &mint,
                &to_ata,
                &keypair.pubkey(),
                &[],
                amount,
                decimals,
            )
            .map_err(|e| ApiError::internal(format!("SPL instruction error: {e}")))?,
        );

        let recent_blockhash =
            self.rpc.get_latest_blockhash().await.map_err(|e| {
                ApiError::service_unavailable(format!("blockhash fetch failed: {e}"))
            })?;

        let message = solana_message::Message::new(&instructions, Some(&keypair.pubkey()));
        let tx = solana_transaction::Transaction::new(&[keypair], message, recent_blockhash);

        // Send without waiting for finalization.
        let signature =
            self.rpc.send_transaction(&tx).await.map_err(|e| {
                ApiError::service_unavailable(format!("SPL transfer send failed: {e}"))
            })?;

        // Wait for `confirmed` commitment (~400ms).
        use solana_commitment_config::CommitmentConfig;
        let commitment = CommitmentConfig::confirmed();
        let start = std::time::Instant::now();
        let timeout = std::time::Duration::from_secs(30);
        loop {
            if start.elapsed() > timeout {
                return Err(ApiError::service_unavailable(
                    "SPL transfer confirmation timed out (30s)".to_string(),
                ));
            }
            match self
                .rpc
                .confirm_transaction_with_commitment(&signature, commitment)
                .await
            {
                Ok(resp) if resp.value => break,
                _ => tokio::time::sleep(std::time::Duration::from_millis(400)).await,
            }
        }

        let sig_str = signature.to_string();
        info!(signature = %sig_str, to = %recipient, mint = %mint_address, amount, "SPL transfer sent");

        Ok(SendResult {
            explorer_url: self.network.explorer_tx_url(&sig_str),
            signature: sig_str,
        })
    }
}
