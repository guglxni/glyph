//! GLYPH Circuit Host — generates Groth16 ZK proofs for GLYPH policy compliance.
//!
//! ## Architecture
//! The RISC Zero zkVM runs the guest circuit in a sandboxed RISC-V environment.
//! The prover generates a STARK proof, then wraps it in a Groth16 proof over BN254
//! (via the `ProverOpts::groth16()` option).
//!
//! ## ELF Embedding
//! When built with the `risc0` feature, `GLYPH_CIRCUIT_ELF` is populated by
//! risc0-build from the compiled guest binary. Without the feature, `generate_proof()`
//! returns an error immediately with a helpful message.
//!
//! ## Usage
//! ```ignore
//! // Set RISC0_PROVER=bonsai + BONSAI_API_KEY for remote proving
//! // Leave unset for local CPU proving (slow)
//! let (proof, public_inputs) = glyph_circuit_host::generate_proof(
//!     intent_payload, policy, target_data
//! )?;
//! ```

#[cfg(feature = "risc0")]
use anyhow::Context;
use anyhow::{anyhow, Result};
#[cfg(feature = "risc0")]
use borsh::BorshDeserialize;
#[cfg(feature = "risc0")]
use glyph_common::{build_mint_merkle_root, canonical_serialize_policy, sha256};
use glyph_common::{IntentPayload, MerklePath, Policy, PublicOutputs};
use serde::{Deserialize, Serialize};

pub mod types;

// ─── Guest ELF ───────────────────────────────────────────────────────────────

// risc0-build emits a `methods.rs` into OUT_DIR with these constants:
//   pub const GLYPH_CIRCUIT_GUEST_ELF: &[u8] = include_bytes!("...");
//   pub const GLYPH_CIRCUIT_GUEST_ID:  [u32; 8] = [...];
//   pub const GLYPH_CIRCUIT_GUEST_PATH: &str = "...";
//
// We include that file then publicly re-export with shorter aliases so the
// rest of the host crate (and the VK extractor) can refer to one canonical
// pair of names regardless of build mode.
#[cfg(feature = "risc0")]
mod methods {
    include!(concat!(env!("OUT_DIR"), "/methods.rs"));
}

#[cfg(feature = "risc0")]
pub use methods::GLYPH_CIRCUIT_GUEST_ELF as GLYPH_CIRCUIT_ELF;
#[cfg(feature = "risc0")]
pub use methods::GLYPH_CIRCUIT_GUEST_ID as GLYPH_CIRCUIT_ID;

#[cfg(not(feature = "risc0"))]
/// Empty placeholder — replaced by the real ELF when building with --features risc0.
///
/// The image ID for the GLYPH circuit. This must match the verification key
/// loaded from the on-chain VerifierVk PDA (see WS-1 + WS-2 part B in
/// `audit/IMPLEMENTATION_PLAN.md`).
pub const GLYPH_CIRCUIT_ELF: &[u8] = &[];

#[cfg(not(feature = "risc0"))]
pub const GLYPH_CIRCUIT_ID: [u32; 8] = [0u32; 8];

/// Compute the RISC Zero image_id for the embedded circuit ELF.
///
/// The guest commits this value as part of `PublicOutputs.image_id` so the
/// on-chain verifier can pin which circuit version produced a proof
/// (closes F-8).
#[cfg(feature = "risc0")]
fn compute_circuit_image_id() -> [u32; 8] {
    use risc0_zkvm::compute_image_id;
    compute_image_id(GLYPH_CIRCUIT_ELF)
        .expect("compute_image_id failed for embedded GLYPH_CIRCUIT_ELF")
        .as_words()
        .try_into()
        .expect("image_id is always 8 u32 words")
}

// ─── Public types ─────────────────────────────────────────────────────────────

/// A Groth16 proof receipt from the RISC Zero prover.
#[derive(Clone, Debug)]
pub struct Groth16Receipt {
    /// The raw RISC Zero receipt containing the Groth16 proof seal and journal.
    #[cfg(feature = "risc0")]
    pub receipt: risc0_zkvm::Receipt,
    /// Fallback when risc0 feature is not enabled.
    #[cfg(not(feature = "risc0"))]
    pub _phantom: (),
}

/// Public outputs from the proof — mirrors `glyph_common::PublicOutputs`.
#[derive(Clone, Debug)]
pub struct PublicInputs {
    pub expected_policy_commitment: [u8; 32],
    pub outputs: PublicOutputs,
}

/// Extra private inputs the guest needs to enforce the formerly-TEE-side
/// rules (token-mint Merkle inclusion + signer-present flag). Mirrors the
/// `IntentExtras` struct declared in the guest's `main.rs` — the encoded
/// bytes must round-trip via `env::read::<IntentExtras>()`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct IntentExtras {
    /// Token mints the intent claims, if any. Each must Merkle-prove against
    /// `allowed_token_mints_root`. None means the intent did not claim any
    /// token-mint constraint.
    pub allowed_tokens: Option<Vec<[u8; 32]>>,
    /// At least one of the instruction account-metas had `is_signer == true`.
    pub has_signer: bool,
    /// Inclusion proofs (one per `allowed_tokens` entry, parallel ordering).
    pub mint_inclusion_proofs: Vec<MerklePath>,
}

// ─── Proof generation ─────────────────────────────────────────────────────────

/// Generate a Groth16 proof for the GLYPH circuit.
///
/// # Inputs (private to the circuit)
/// - `intent`: The compact IntentPayload (derived from the wire TransactionIntent)
/// - `policy`: The canonical Policy (used to derive policy_commitment inside the circuit)
/// - `tx_bytes`: The raw instruction data for the target transaction (hashed as tx_hash)
///
/// # Outputs
/// Returns `(Groth16Receipt, PublicInputs)` where:
/// - `Groth16Receipt.receipt.journal.bytes` contains the borsh-encoded `PublicOutputs`
/// - `PublicInputs.outputs` is the decoded `PublicOutputs` from the journal
///
/// # Groth16 Public Input Derivation
/// The on-chain verifier computes: `PI = SHA-256(journal_bytes)`
/// The prover produces a matching Groth16 proof where the single public input == PI.
///
/// # Environment Variables
/// - `RISC0_PROVER=bonsai` — use Bonsai remote prover (fast, ~10-30s)
/// - `BONSAI_API_KEY=<key>` — required when using Bonsai
/// - `RISC0_DEV_MODE=1` — skip proving entirely for CI (no valid proof produced)
// The early `return` in the non-risc0 stub branch is required: the function has
// two cfg-gated bodies and the explicit return keeps both type-checking cleanly.
// Without `--features risc0` (how CI lints) clippy sees only the stub and flags it.
#[allow(clippy::needless_return)]
pub fn generate_proof(
    #[allow(unused_variables)] intent: IntentPayload,
    #[allow(unused_variables)] policy: Policy,
    #[allow(unused_variables)] tx_bytes: Vec<u8>,
    #[allow(unused_variables)] attested_timestamp: u64,
    #[allow(unused_variables)] prior_daily_total: u64,
    #[allow(unused_variables)] extras: IntentExtras,
) -> Result<(Groth16Receipt, PublicInputs)> {
    #[cfg(not(feature = "risc0"))]
    {
        return Err(anyhow!(
            "GLYPH_CIRCUIT_ELF is empty. Build with --features risc0 and the RISC Zero \
             toolchain installed (`rustup toolchain install risc0`). \
             For local dev without ZK, use DevProver instead."
        ));
    }

    #[cfg(feature = "risc0")]
    {
        use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};

        if GLYPH_CIRCUIT_ELF.is_empty() {
            return Err(anyhow!(
                "GLYPH_CIRCUIT_ELF is empty even with risc0 feature. \
                 This indicates a risc0-build failure during compilation."
            ));
        }

        let expected_policy_commitment = sha256(&canonical_serialize_policy(&policy));

        // The guest commits image_id into PublicOutputs so the on-chain
        // verifier can pin it via AgentRegistry::image_id (closes F-8).
        // The host derives it from the compiled ELF via risc0_binfmt::compute_image_id.
        let image_id: [u32; 8] = compute_circuit_image_id();

        // Derive the Merkle root over the policy's allowed_token_mints set,
        // matching what the guest computes when verifying inclusion proofs.
        // An empty / None set yields `[0u8; 32]`.
        let allowed_token_mints_root: [u8; 32] = match &policy.allowed_token_mints {
            Some(mints) if !mints.is_empty() => build_mint_merkle_root(mints),
            _ => [0u8; 32],
        };

        // The guest reads inputs in this exact order; deviation breaks
        // serde round-trip and corrupts the journal silently.
        let env = ExecutorEnv::builder()
            .write(&intent)
            .context("failed to write IntentPayload to executor env")?
            .write(&policy)
            .context("failed to write Policy to executor env")?
            .write(&tx_bytes)
            .context("failed to write tx_bytes to executor env")?
            .write(&extras)
            .context("failed to write IntentExtras to executor env")?
            .write(&expected_policy_commitment)
            .context("failed to write expected_policy_commitment to executor env")?
            .write(&image_id)
            .context("failed to write image_id to executor env")?
            .write(&attested_timestamp)
            .context("failed to write attested_timestamp to executor env")?
            .write(&prior_daily_total)
            .context("failed to write prior_daily_total to executor env")?
            .write(&allowed_token_mints_root)
            .context("failed to write allowed_token_mints_root to executor env")?
            .build()
            .context("failed to build ExecutorEnv")?;

        let prover = default_prover();

        // Use Groth16 proving mode — produces a BN254 proof verifiable on-chain.
        // Note: In dev mode (RISC0_DEV_MODE=1), this produces a "dev mode" receipt
        // that is NOT a real ZK proof. Never use dev mode in production.
        let prove_info = prover
            .prove_with_opts(env, GLYPH_CIRCUIT_ELF, &ProverOpts::groth16())
            .context("Groth16 proving failed. If using local CPU, this may take 5-120s.")?;

        let receipt = prove_info.receipt;

        // Decode the journal — this is the authoritative source of public
        // outputs. The guest commits Borsh bytes directly so the host, worker,
        // and on-chain verifier all hash/decode the same byte string.
        let outputs: PublicOutputs = BorshDeserialize::try_from_slice(&receipt.journal.bytes)
            .context("failed to Borsh-decode PublicOutputs from circuit journal")?;

        // Validate the circuit correctly committed the expected policy commitment.
        if outputs.policy_commitment != expected_policy_commitment {
            return Err(anyhow!(
                "circuit returned wrong policy_commitment: expected {}, got {}",
                hex::encode(expected_policy_commitment),
                hex::encode(outputs.policy_commitment),
            ));
        }

        let public_inputs = PublicInputs {
            expected_policy_commitment,
            outputs,
        };

        Ok((Groth16Receipt { receipt }, public_inputs))
    }
}
