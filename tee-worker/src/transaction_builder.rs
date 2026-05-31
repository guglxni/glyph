use anyhow::{Context, Result};
use base64::Engine;
use borsh::BorshSerialize;
use sha2::{Digest, Sha256};

use glyph_common::{
    canonical_target_instruction_bytes as canonical_target_instruction_bytes_common,
    CanonicalAccountMeta,
};

use crate::types::{GlyphProofBundle, TransactionIntent};

/// Minimal Solana types to avoid solana-sdk dependency conflicts
pub mod solana_types {
    use borsh::{BorshDeserialize, BorshSerialize};
    use serde::{Deserialize, Serialize};

    #[derive(
        Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
    )]
    pub struct Pubkey([u8; 32]);

    impl std::str::FromStr for Pubkey {
        type Err = anyhow::Error;
        fn from_str(s: &str) -> Result<Self, Self::Err> {
            let bytes = bs58::decode(s).into_vec()?;
            if bytes.len() != 32 {
                anyhow::bail!("invalid pubkey length");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Ok(Pubkey(arr))
        }
    }

    impl AsRef<[u8]> for Pubkey {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    pub struct Instruction {
        pub program_id: Pubkey,
        pub accounts: Vec<AccountMeta>,
        pub data: Vec<u8>,
    }

    pub struct AccountMeta {
        pub pubkey: Pubkey,
        pub is_signer: bool,
        pub is_writable: bool,
    }
}

use solana_types::*;
use std::str::FromStr;

/// Matches the on-chain VerifyAndExecuteArgs exactly (Borsh-serialized).
///
/// IMPORTANT: This struct must stay byte-for-byte compatible with the Anchor
/// `VerifyAndExecuteArgs` in `programs/glyph-verifier/src/instructions/verify_and_execute.rs`.
/// Any field addition or reordering must be mirrored in both places.
///
/// Key change from placeholder → real ZK:
/// - Removed `public_inputs` (5 × 32 bytes) — now derived on-chain from journal
/// - Added `journal_bytes: Vec<u8>` — raw borsh PublicOutputs from the circuit
#[derive(BorshSerialize)]
struct VerifyAndExecuteArgs {
    proof: ProofData,
    /// Raw borsh-encoded PublicOutputs from the RISC Zero circuit journal.
    /// The on-chain verifier: (1) decodes this to extract policy_commitment/agent_pubkey/nonce,
    /// (2) computes SHA-256(journal_bytes) as the Groth16 public input.
    journal_bytes: Vec<u8>,
}

#[derive(BorshSerialize)]
struct ProofData {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
}

pub struct TransactionBuilder {
    pub program_id: Pubkey,
}

impl TransactionBuilder {
    pub fn new(program_id: Pubkey, _rpc_url: &str) -> Self {
        Self { program_id }
    }

    /// Build the `verify_and_execute` instruction data for the GLYPH verifier program.
    ///
    /// The output is passed as the first instruction in the atomic transaction:
    ///   Instruction 0: verify_and_execute (GLYPH verifier)
    ///   Instruction 1: target instruction (the actual DeFi action)
    ///
    /// The `tx_hash` committed in the ZK proof equals SHA-256(instruction_1.data),
    /// enforcing instruction binding on-chain.
    pub fn build_verify_tx(
        &self,
        intent: &TransactionIntent,
        bundle: &GlyphProofBundle,
        _payer_keypair: &ed25519_dalek::SigningKey,
    ) -> Result<Vec<u8>> {
        // 1. Canonicalize target instruction bytes (program_id || metas || data)
        let full_ix_bytes = canonical_target_instruction_bytes(intent)?;

        // 2. Verify the instruction binding locally before submitting:
        //    The tx_hash in the bundle must be SHA-256(full_ix_bytes).
        //    This is a local sanity check; the on-chain program enforces it cryptographically.
        let expected_tx_hash = sha256(&full_ix_bytes);
        if expected_tx_hash != bundle.public_inputs.tx_hash {
            anyhow::bail!(
                "tx_hash mismatch: bundle has {}, target_data hashes to {}",
                hex::encode(bundle.public_inputs.tx_hash),
                hex::encode(expected_tx_hash),
            );
        }

        // 3. Build the VerifyAndExecuteArgs with the real journal bytes
        let discriminator = anchor_discriminator("global:verify_and_execute");

        let args = VerifyAndExecuteArgs {
            proof: ProofData {
                a: bundle.proof.a,
                b: bundle.proof.b,
                c: bundle.proof.c,
            },
            journal_bytes: bundle.journal_bytes.clone(),
        };

        let mut data = Vec::with_capacity(8 + 256 + 4 + bundle.journal_bytes.len());
        data.extend_from_slice(&discriminator);
        args.serialize(&mut data)
            .context("failed to borsh-serialize VerifyAndExecuteArgs")?;

        Ok(data)
    }
}

/// Canonical byte serialization of the target instruction used for tx_hash binding.
///
/// Adapter over [`glyph_common::canonical_target_instruction_bytes`] that decodes
/// the wire-format intent (base58 pubkeys, base64 data) into the typed canonical
/// representation and delegates to the shared encoder. The shared encoder is now
/// length-prefixed (`num_accounts: u32`, `data_len: u32`) — see
/// `common/src/lib.rs` for the byte layout.
pub fn canonical_target_instruction_bytes(intent: &TransactionIntent) -> Result<Vec<u8>> {
    let target_data = base64::engine::general_purpose::STANDARD
        .decode(&intent.action.data)
        .context("failed to decode target instruction data")?;

    let target_program = Pubkey::from_str(&intent.action.target_program)
        .map_err(|_| anyhow::anyhow!("invalid target program id"))?;
    let mut target_program_bytes = [0u8; 32];
    target_program_bytes.copy_from_slice(target_program.as_ref());

    let mut accounts: Vec<CanonicalAccountMeta> = Vec::with_capacity(intent.action.accounts.len());
    for meta in &intent.action.accounts {
        let pk = Pubkey::from_str(&meta.pubkey)
            .map_err(|_| anyhow::anyhow!("invalid account pubkey"))?;
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(pk.as_ref());
        accounts.push(CanonicalAccountMeta {
            pubkey: pk_bytes,
            is_signer: meta.is_signer,
            is_writable: meta.is_writable,
        });
    }

    Ok(canonical_target_instruction_bytes_common(
        &target_program_bytes,
        &accounts,
        &target_data,
    ))
}

/// Compute Anchor 8-byte instruction discriminator: SHA-256(namespace:name)[..8]
fn anchor_discriminator(namespace_and_name: &str) -> [u8; 8] {
    let hash = Sha256::digest(namespace_and_name.as_bytes());
    let mut disc = [0u8; 8];
    disc.copy_from_slice(&hash[..8]);
    disc
}

fn sha256(data: &[u8]) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

#[cfg(test)]
mod tests {
    use super::canonical_target_instruction_bytes;
    use crate::types::{
        AccountMeta, ActionType, IntentAction, IntentConstraints, TransactionIntent,
    };
    use base64::Engine;

    fn b58_pk(byte: u8) -> String {
        bs58::encode([byte; 32]).into_string()
    }

    fn sample_intent() -> TransactionIntent {
        TransactionIntent {
            version: 1,
            agent_pubkey: b58_pk(9),
            nonce: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
            timestamp: 1_700_000_000,
            expiry: 1_700_000_600,
            action: IntentAction {
                action_type: ActionType::CpiCall,
                target_program: b58_pk(1),
                accounts: vec![
                    AccountMeta {
                        pubkey: b58_pk(2),
                        is_signer: true,
                        is_writable: false,
                    },
                    AccountMeta {
                        pubkey: b58_pk(3),
                        is_signer: false,
                        is_writable: true,
                    },
                ],
                data: base64::engine::general_purpose::STANDARD.encode([1u8, 2, 3, 4]),
            },
            constraints: IntentConstraints {
                max_lamports: 1,
                max_slippage_bps: None,
                allowed_tokens: None,
            },
            signature: String::new(),
        }
    }

    #[test]
    fn canonical_bytes_change_when_program_changes() {
        let intent = sample_intent();
        let mut changed = intent.clone();
        changed.action.target_program = b58_pk(7);

        let original = canonical_target_instruction_bytes(&intent).unwrap();
        let modified = canonical_target_instruction_bytes(&changed).unwrap();

        assert_ne!(original, modified);
    }

    #[test]
    fn canonical_bytes_change_when_account_flags_change() {
        let intent = sample_intent();
        let mut changed = intent.clone();
        changed.action.accounts[0].is_signer = false;

        let original = canonical_target_instruction_bytes(&intent).unwrap();
        let modified = canonical_target_instruction_bytes(&changed).unwrap();

        assert_ne!(original, modified);
    }

    #[test]
    fn canonical_bytes_change_when_data_changes() {
        let intent = sample_intent();
        let mut changed = intent.clone();
        changed.action.data = base64::engine::general_purpose::STANDARD.encode([9u8, 9, 9, 9]);

        let original = canonical_target_instruction_bytes(&intent).unwrap();
        let modified = canonical_target_instruction_bytes(&changed).unwrap();

        assert_ne!(original, modified);
    }
}
