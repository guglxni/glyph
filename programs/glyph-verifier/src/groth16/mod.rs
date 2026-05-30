//! BN254 Groth16 verifier for GLYPH.
//!
//! This module verifies RISC Zero Groth16 proofs on-chain.
//! RISC Zero uses BN254 (aka alt_bn128) for its Groth16 proving system.
//!
//! ## Verification Key
//! The VK is derived from the RISC Zero trusted setup and specific to the
//! GLYPH circuit image ID. It must be updated every time the guest ELF changes.
//!
//! ## Public Input
//! RISC Zero Groth16's single public input is: SHA-256(journal_bytes)
//! where journal_bytes is the borsh-serialized PublicOutputs committed via env::commit().
//!
//! ## Compute Budget
//! BN254 pairing on Solana via alt_bn128 syscalls costs ~1.3M CU.
//! Set compute budget to 1.4M CU in the transaction.

pub mod vk;
pub mod verifier;

#[cfg(test)]
mod tests;

pub use verifier::verify_groth16;

/// Pinned RISC Zero prover version. The on-chain claim-digest derivation in
/// `verify_and_execute` (sha256(image_id_be || sha256(journal))) matches this
/// version's wire format. Bumping the prover requires re-validating the
/// digest layout — see `docs/zk-references.md`.
pub const RISC0_PROVER_VERSION: &str = "1.2.6";

use anchor_lang::prelude::*;

/// Groth16 proof structure for BN254 proofs.
/// 
/// A Groth16 proof consists of three elliptic curve points:
/// - A: G1 point (64 bytes: 32 bytes x || 32 bytes y)
/// - B: G2 point (128 bytes: two G1 coordinates)
/// - C: G1 point (64 bytes: 32 bytes x || 32 bytes y)
#[derive(Clone, Debug, AnchorSerialize, AnchorDeserialize)]
pub struct Groth16Proof {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
}
