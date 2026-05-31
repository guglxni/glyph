use anyhow::{Context, Result};
#[cfg(feature = "risc0")]
use borsh::BorshDeserialize;
use sha2::{Digest, Sha256};

use glyph_common::{
    self, hash_intent, hash_policy, IntentPayload, Policy as CanonicalPolicy, PublicOutputs,
};

use crate::types::{GlyphProofBundle, Groth16Proof, PublicInputs, TransactionIntent};

/// Trait for proof generation backends.
///
/// `tx_hash_prefix` is set by the caller (worker) after the bundle is built;
/// the prover trait no longer accepts an opaque string field.
pub trait Prover: Send + Sync {
    /// Generate a proof bundle.
    ///
    /// `attested_timestamp` is the TEE-attested unix-seconds wallclock at
    /// proof time (sourced from `TrustedClock::now` in production). The
    /// circuit commits it into `PublicOutputs` and the on-chain verifier
    /// checks it is within ±`ATTESTED_TIMESTAMP_MAX_DRIFT_SECS` of the
    /// Solana `Clock` sysvar.
    fn generate_proof(
        &self,
        intent: &TransactionIntent,
        policy: &CanonicalPolicy,
        target_data: Vec<u8>,
        attested_timestamp: u64,
    ) -> Result<GlyphProofBundle>;
}

/// Convert wire-format TransactionIntent to compact IntentPayload for canonical hashing.
/// This is the bridge between the JSON wire format and the binary ZK format.
pub fn intent_to_payload(intent: &TransactionIntent) -> Result<IntentPayload> {
    let agent_bytes = bs58::decode(&intent.agent_pubkey)
        .into_vec()
        .context("invalid base58 agent_pubkey")?;
    if agent_bytes.len() != 32 {
        anyhow::bail!("agent_pubkey must be 32 bytes");
    }
    let mut agent_pubkey = [0u8; 32];
    agent_pubkey.copy_from_slice(&agent_bytes);

    // Nonce is a hex string — hash it to get deterministic 32 bytes
    let nonce = sha256_array(intent.nonce.as_bytes());

    let program_bytes = bs58::decode(&intent.action.target_program)
        .into_vec()
        .context("invalid base58 target_program")?;
    if program_bytes.len() != 32 {
        anyhow::bail!("target_program must be 32 bytes");
    }
    let mut target_program = [0u8; 32];
    target_program.copy_from_slice(&program_bytes);

    Ok(IntentPayload {
        agent_pubkey,
        nonce,
        target_program,
        max_lamports: intent.constraints.max_lamports,
        max_slippage_bps: intent.constraints.max_slippage_bps,
        num_accounts: intent.action.accounts.len() as u16,
        expiry: intent.expiry,
    })
}

// ─── RISC Zero Prover ────────────────────────────────────────────────────────

/// RISC Zero prover — generates real Groth16 proofs via the circuit host.
///
/// # Production Use
/// This prover calls into `glyph_circuit_host::generate_proof()` which invokes the
/// RISC Zero zkVM (STARK) and then wraps the proof in Groth16 (via Bonsai or local GPU).
///
/// # Proving Time
/// - Local CPU: 5–120s depending on circuit complexity and hardware
/// - Bonsai (cloud): 10–30s
/// - GPU prover: 2–10s
///
/// Set `RISC0_PROVER=bonsai` and `BONSAI_API_KEY=...` to use the Bonsai remote prover.
#[cfg(feature = "risc0")]
pub struct RiscZeroProver;

#[cfg(feature = "risc0")]
impl RiscZeroProver {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(feature = "risc0")]
impl Prover for RiscZeroProver {
    fn generate_proof(
        &self,
        intent: &TransactionIntent,
        policy: &CanonicalPolicy,
        target_data: Vec<u8>,
        attested_timestamp: u64,
    ) -> Result<GlyphProofBundle> {
        let payload = intent_to_payload(intent)?;
        let policy_commitment = hash_policy(policy);
        let intent_hash_val = hash_intent(&payload);
        let tx_hash = sha256_array(&target_data);
        let agent_pubkey = payload.agent_pubkey;
        let nonce = payload.nonce;

        // Build the IntentExtras the guest expects: signer flag + (for
        // future use) mint-inclusion proofs. Token-mint enforcement still
        // requires the SDK to surface allowed_tokens with Merkle paths; the
        // worker currently does not have inclusion proofs ready, so we send
        // None and rely on the on-chain `InsufficientRuleCoverage` mask to
        // gate any policy that DOES require it.
        let has_signer = intent.action.accounts.iter().any(|a| a.is_signer);
        let extras = glyph_circuit_host::IntentExtras {
            allowed_tokens: None,
            has_signer,
            mint_inclusion_proofs: Vec::new(),
        };

        // `prior_daily_total` is the worker's view of today's spend BEFORE
        // this intent. The on-chain `DailyBucket` PDA will be checked
        // against this value (closes the daily_volume part of F-23). The
        // worker layer still tracks volume off-circuit; once the
        // `DailyBucket` PDA is wired the worker will read the prior total
        // from chain. For now we pass 0 — the in-circuit check still
        // enforces `projected <= policy.max_daily_volume_lamports`.
        let prior_daily_total: u64 = 0;

        // ── Call RISC Zero host to generate the Groth16 proof ──────────────
        let (groth16_proof, _public_inputs) = glyph_circuit_host::generate_proof(
            payload,
            policy.clone(),
            target_data.clone(),
            attested_timestamp,
            prior_daily_total,
            extras,
        )
        .context("RISC Zero proof generation failed")?;

        // ── Extract the journal bytes from the receipt ──────────────────────
        // The receipt journal contains borsh-encoded PublicOutputs committed by the circuit.
        // The on-chain verifier re-derives the Groth16 public input as SHA-256(journal_bytes).
        let journal_bytes = groth16_proof.receipt.journal.bytes.clone();

        // Cross-check: the circuit's committed policy_commitment must match
        let decoded_outputs: PublicOutputs = BorshDeserialize::try_from_slice(&journal_bytes)
            .context("failed to decode PublicOutputs from RISC Zero journal")?;

        // Cross-check: the circuit's committed policy_commitment must match
        if decoded_outputs.policy_commitment != policy_commitment {
            anyhow::bail!(
                "circuit journal policy_commitment mismatch: expected {}, got {}",
                hex::encode(policy_commitment),
                hex::encode(decoded_outputs.policy_commitment),
            );
        }

        // ── Extract Groth16 proof points from the receipt seal ──────────────
        let inner = groth16_proof
            .receipt
            .inner
            .groth16()
            .context("receipt is not a Groth16 receipt — did you set ProverOpts::groth16()?")?;
        let seal = &inner.seal;

        // Pass `None` for expected_selector: the raw `inner.groth16().seal`
        // returned by `risc0-zkvm` 1.2.x is the unwrapped 256-byte form (no
        // selector prefix). If a future risc0 version starts returning the
        // 260-byte encoded form, callers must supply the expected
        // verifier-parameters digest prefix here. Documented in
        // `docs/zk-references.md`.
        let (proof_a, proof_b, proof_c) = extract_groth16_points(seal, None)
            .context("failed to extract Groth16 proof points from seal")?;

        let proof = Groth16Proof {
            a: proof_a,
            b: proof_b,
            c: proof_c,
        };

        let public_inputs = PublicInputs {
            policy_commitment,
            intent_hash: intent_hash_val,
            agent_pubkey,
            nonce,
            tx_hash,
        };

        Ok(GlyphProofBundle {
            proof,
            journal_bytes,
            public_inputs,
            signed_transaction: target_data,
            tx_hash_prefix: [0u8; 16],
            worker_attestation: None,
        })
    }
}

// ─── Dev Prover ──────────────────────────────────────────────────────────────

/// Deterministic prover for integration testing — NO real ZK proof.
///
/// This prover generates a fake but structurally valid proof bundle.
/// The DevProver's output will NOT pass on-chain verification;
/// it is intended only for local development and unit testing without
/// the RISC Zero toolchain installed.
///
/// # Usage
/// Start the worker with `GLYPH_PROVER=dev` or compile without the `risc0` feature.
pub struct DevProver;

impl DevProver {
    pub fn new() -> Self {
        Self
    }
}

impl Prover for DevProver {
    fn generate_proof(
        &self,
        intent: &TransactionIntent,
        policy: &CanonicalPolicy,
        target_data: Vec<u8>,
        attested_timestamp: u64,
    ) -> Result<GlyphProofBundle> {
        let payload = intent_to_payload(intent)?;
        let policy_commitment = hash_policy(policy);
        let intent_hash_val = hash_intent(&payload);
        let tx_hash = sha256_array(&target_data);
        let agent_pubkey = payload.agent_pubkey;
        let nonce = payload.nonce;

        // Build a fake journal that mirrors what the real circuit commits.
        // This allows SDK integration tests to exercise the full bundle format.
        let fake_outputs = PublicOutputs {
            policy_commitment,
            intent_hash: intent_hash_val,
            agent_pubkey,
            nonce,
            tx_hash,
            expiry: intent.expiry,
            // DevProver tags its journal with the all-zero image_id; the
            // on-chain verifier rejects these in production registries.
            image_id: [0u32; 8],
            attested_timestamp,
            daily_bucket_id: attested_timestamp / glyph_common::SECONDS_PER_DAY,
            prior_daily_total: 0,
            circuit_rule_bitmap: 0,
            failure_code: glyph_common::CircuitFailureCode::None as u8,
        };
        let journal_bytes = borsh::BorshSerialize::try_to_vec(&fake_outputs)
            .context("failed to borsh-serialize fake PublicOutputs")?;

        // Deterministic fake proof bytes derived from public inputs
        let proof_seed = sha256_joined(&[
            &policy_commitment,
            &intent_hash_val,
            &agent_pubkey,
            &nonce,
            &tx_hash,
        ]);

        let proof = Groth16Proof {
            a: expand_bytes::<64>(&proof_seed, b"a"),
            b: expand_bytes::<128>(&proof_seed, b"b"),
            c: expand_bytes::<64>(&proof_seed, b"c"),
        };

        let public_inputs = PublicInputs {
            policy_commitment,
            intent_hash: intent_hash_val,
            agent_pubkey,
            nonce,
            tx_hash,
        };

        Ok(GlyphProofBundle {
            proof,
            journal_bytes,
            public_inputs,
            signed_transaction: target_data,
            tx_hash_prefix: [0u8; 16],
            worker_attestation: None,
        })
    }
}

// ─── Seal extraction ─────────────────────────────────────────────────────────

/// Expected RISC Zero v1.2.x Groth16 raw seal length (no selector prefix).
/// Layout: 64 (G1: A) + 128 (G2: B) + 64 (G1: C) = 256 bytes.
#[cfg(feature = "risc0")]
pub(crate) const RAW_GROTH16_SEAL_LEN: usize = 256;

/// Length of the selector prefix prepended by `risc0_zkvm::sha::encode_seal`
/// (a.k.a. the Boundless / Steel "encoded seal" wrapper). Equal to the first
/// 4 bytes of the verifier-parameters digest for the proof system.
#[cfg(feature = "risc0")]
pub(crate) const SELECTOR_LEN: usize = 4;

/// Extract Groth16 (A, B, C) points from a RISC Zero seal.
///
/// Closes F-15. Two on-the-wire shapes are accepted:
///
/// 1. **Raw Groth16 seal** — exactly 256 bytes. This is the format produced by
///    `Receipt::inner.groth16().seal` in `risc0-zkvm` 1.2.x and is the format
///    we always emit from the `RiscZeroProver` path below.
/// 2. **Encoded seal** — 260 bytes. The first 4 bytes are the proving-system
///    selector (`verifier_parameters_digest[..4]`). We **require** that
///    selector to match `expected_selector` so a PLONK / FFLONK / future
///    proving system with a coincidentally-260-byte seal is rejected with a
///    clear error rather than silently mis-parsed as Groth16.
///
/// The previous heuristic (`if seal.len() == 260 { 4 } else { 0 }`) was
/// fragile: it accepted any 260-byte seal regardless of selector. The new
/// version makes the proving-system check explicit.
#[cfg(feature = "risc0")]
fn extract_groth16_points(
    seal: &[u8],
    expected_selector: Option<[u8; SELECTOR_LEN]>,
) -> Result<([u8; 64], [u8; 128], [u8; 64])> {
    let data: &[u8] = match seal.len() {
        RAW_GROTH16_SEAL_LEN => seal,
        len if len == RAW_GROTH16_SEAL_LEN + SELECTOR_LEN => {
            let mut got = [0u8; SELECTOR_LEN];
            got.copy_from_slice(&seal[..SELECTOR_LEN]);
            match expected_selector {
                Some(exp) if exp == got => &seal[SELECTOR_LEN..],
                Some(exp) => anyhow::bail!(
                    "Groth16 seal selector mismatch: expected {:02x?}, got {:02x?} \
                     (proving-system tag rejected — refusing to parse as Groth16)",
                    exp,
                    got,
                ),
                None => anyhow::bail!(
                    "Groth16 seal carries selector {:02x?} but no expected selector \
                     was supplied; refusing to skip it (closes F-15 silent-parse path)",
                    got,
                ),
            }
        }
        other => anyhow::bail!(
            "unexpected RISC Zero seal length: {} bytes (want {} or {})",
            other,
            RAW_GROTH16_SEAL_LEN,
            RAW_GROTH16_SEAL_LEN + SELECTOR_LEN,
        ),
    };

    let mut a = [0u8; 64];
    let mut b = [0u8; 128];
    let mut c = [0u8; 64];
    a.copy_from_slice(&data[..64]);
    b.copy_from_slice(&data[64..192]);
    c.copy_from_slice(&data[192..256]);
    Ok((a, b, c))
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn sha256_array(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn sha256_joined(chunks: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for chunk in chunks {
        hasher.update(chunk);
    }
    hasher.finalize().into()
}

#[cfg(all(test, feature = "risc0"))]
mod seal_tests {
    use super::*;

    fn fake_seal(prefix: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(prefix.len() + RAW_GROTH16_SEAL_LEN);
        v.extend_from_slice(prefix);
        v.extend(std::iter::repeat(0xABu8).take(RAW_GROTH16_SEAL_LEN));
        v
    }

    #[test]
    fn raw_seal_parses() {
        let seal = fake_seal(&[]);
        let res = extract_groth16_points(&seal, None);
        assert!(res.is_ok());
    }

    #[test]
    fn encoded_seal_without_selector_rejected() {
        let seal = fake_seal(&[0xDE, 0xAD, 0xBE, 0xEF]);
        assert!(extract_groth16_points(&seal, None).is_err());
    }

    #[test]
    fn encoded_seal_with_matching_selector_accepted() {
        let sel = [0xDE, 0xAD, 0xBE, 0xEF];
        let seal = fake_seal(&sel);
        assert!(extract_groth16_points(&seal, Some(sel)).is_ok());
    }

    #[test]
    fn encoded_seal_with_wrong_selector_rejected() {
        let sel = [0xDE, 0xAD, 0xBE, 0xEF];
        let seal = fake_seal(&sel);
        assert!(extract_groth16_points(&seal, Some([0, 0, 0, 0])).is_err());
    }

    #[test]
    fn unexpected_length_rejected() {
        let seal = vec![0u8; 100];
        assert!(extract_groth16_points(&seal, None).is_err());
    }
}

fn expand_bytes<const N: usize>(seed: &[u8; 32], label: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let mut filled = 0usize;
    let mut counter: u32 = 0;
    while filled < N {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(label);
        hasher.update(counter.to_le_bytes());
        let block: [u8; 32] = hasher.finalize().into();
        let remaining = N - filled;
        let take = remaining.min(block.len());
        out[filled..filled + take].copy_from_slice(&block[..take]);
        filled += take;
        counter = counter.saturating_add(1);
    }
    out
}
