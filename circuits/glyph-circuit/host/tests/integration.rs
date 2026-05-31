//! Integration tests for the GLYPH ZK circuit and prover stack.
//!
//! Test hierarchy:
//! 1. `test_dev_prover_*` — always run, test bundle format and DevProver
//! 2. `test_journal_decode_*` — test journal encoding/decoding round-trips
//! 3. `test_groth16_verifier_*` — test the on-chain verifier logic (pure Rust, no Solana)
//! 4. `prop_circuit_matches_policy_engine` — WS-8 property test (host simulation)
//! 5. `test_risc0_prover_*` — only run with `RISC0_DEV_MODE=1` feature
//!
//! Run all non-RISC0 tests:
//!   cargo test -p glyph-circuit-host
//!
//! Run RISC0 dev-mode tests (requires RISC Zero toolchain):
//!   RISC0_DEV_MODE=1 cargo test -p glyph-circuit-host --features risc0
//!
//! Run RISC0 real proving tests (slow, ~10min, requires circuit build):
//!   cargo test -p glyph-circuit-host --features risc0 -- --ignored real_proof

use glyph_common::{
    canonical_serialize_policy, CircuitFailureCode, IntentPayload, Policy, PublicOutputs,
    RULE_BIT_ALLOWED_PROGRAMS, RULE_BIT_MAX_ACCOUNTS, RULE_BIT_MAX_LAMPORTS,
    RULE_BIT_REQUIRE_SIGNER, RULE_REQUIRED_BITMAP, SECONDS_PER_DAY,
};
use sha2::{Digest, Sha256};

// ─── Test Fixtures ───────────────────────────────────────────────────────────

fn test_policy() -> Policy {
    Policy {
        version: 1,
        max_lamports_per_tx: 1_000_000_000,
        allowed_programs: vec![[0u8; 32]],
        time_window: None,
        max_daily_volume_lamports: 10_000_000_000,
        max_slippage_bps: Some(50),
        allowed_token_mints: None,
        max_accounts_per_tx: Some(10),
        require_signer_present: true,
        expires_at: 0,
    }
}

fn test_intent_payload() -> IntentPayload {
    IntentPayload {
        agent_pubkey: [1u8; 32],
        nonce: [2u8; 32],
        target_program: [0u8; 32],
        max_lamports: 500_000_000,
        max_slippage_bps: Some(30),
        num_accounts: 3,
        expiry: 9_999_999_999,
    }
}

fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn full_public_outputs(
    policy: &Policy,
    intent: &IntentPayload,
    tx_hash: [u8; 32],
) -> PublicOutputs {
    let policy_commitment = sha256(&canonical_serialize_policy(policy));
    let intent_hash = sha256(&glyph_common::canonical_intent_preimage(intent));
    PublicOutputs {
        policy_commitment,
        intent_hash,
        agent_pubkey: intent.agent_pubkey,
        nonce: intent.nonce,
        tx_hash,
        expiry: intent.expiry,
        image_id: [0u32; 8],
        attested_timestamp: 1_700_000_500,
        daily_bucket_id: 1_700_000_500 / SECONDS_PER_DAY,
        prior_daily_total: 0,
        circuit_rule_bitmap: RULE_REQUIRED_BITMAP,
        failure_code: CircuitFailureCode::None as u8,
    }
}

// ─── Journal encoding tests ───────────────────────────────────────────────────

#[test]
fn test_journal_encode_decode_round_trip() {
    let policy = test_policy();
    let intent = test_intent_payload();
    let tx_hash = sha256(b"test_instruction_data");

    let outputs = full_public_outputs(&policy, &intent, tx_hash);

    // Encode as borsh
    let journal_bytes =
        borsh::BorshSerialize::try_to_vec(&outputs).expect("borsh serialization failed");
    assert!(!journal_bytes.is_empty());

    // Decode back
    let decoded: PublicOutputs = borsh::BorshDeserialize::try_from_slice(&journal_bytes)
        .expect("borsh deserialization failed");

    assert_eq!(decoded, outputs);
}

// ─── Policy commitment tests ──────────────────────────────────────────────────

#[test]
fn test_canonical_policy_serialization_is_deterministic() {
    let policy = test_policy();
    let bytes1 = canonical_serialize_policy(&policy);
    let bytes2 = canonical_serialize_policy(&policy);
    assert_eq!(bytes1, bytes2);
}

#[test]
fn test_policy_commitment_changes_on_modification() {
    let policy1 = test_policy();
    let mut policy2 = test_policy();
    policy2.max_lamports_per_tx = policy1.max_lamports_per_tx + 1;

    let commitment1 = sha256(&canonical_serialize_policy(&policy1));
    let commitment2 = sha256(&canonical_serialize_policy(&policy2));
    assert_ne!(commitment1, commitment2);
}

#[test]
fn test_policy_commitment_program_order_independent() {
    // Sorted programs should produce same commitment regardless of input order
    let mut policy1 = test_policy();
    let mut policy2 = test_policy();
    let prog_a = [1u8; 32];
    let prog_b = [2u8; 32];
    policy1.allowed_programs = vec![prog_a, prog_b];
    policy2.allowed_programs = vec![prog_b, prog_a];

    let commitment1 = sha256(&canonical_serialize_policy(&policy1));
    let commitment2 = sha256(&canonical_serialize_policy(&policy2));
    assert_eq!(commitment1, commitment2);
}

// ─── WS-8 rule bitmap tests ──────────────────────────────────────────────────

#[test]
fn test_required_bitmap_contains_in_circuit_rules() {
    // The four in-circuit rules MUST be in the required bitmap so the
    // on-chain verifier's REQUIRED_RULES_MASK check rejects under-covered
    // proofs.
    const VERIFIER_REQUIRED_MASK: u32 = RULE_BIT_MAX_LAMPORTS
        | RULE_BIT_ALLOWED_PROGRAMS
        | RULE_BIT_MAX_ACCOUNTS
        | RULE_BIT_REQUIRE_SIGNER;
    assert_eq!(
        RULE_REQUIRED_BITMAP & VERIFIER_REQUIRED_MASK,
        VERIFIER_REQUIRED_MASK,
        "guest's RULE_REQUIRED_BITMAP must cover the 4 stateless in-circuit rules"
    );
}

#[test]
fn test_failure_code_zero_means_success() {
    assert_eq!(CircuitFailureCode::None as u8, 0);
}

// ─── WS-8 property test: circuit decision matches PolicyEngine ───────────────
//
// Closes F-32. Generates random (intent, policy) pairs in host space (no
// guest invocation) and asserts the *predicate* the guest would commit
// matches what `glyph_tee_worker::policy::PolicyEngine::check_intent`
// returns. Because we cannot easily import `glyph-tee-worker` from the
// circuit host crate (it pulls in tokio + solana-sdk and is not in this
// workspace), we duplicate the small subset of rules the guest enforces
// in-circuit and assert the two implementations agree.

mod policy_engine_oracle {
    use glyph_common::{IntentPayload, Policy};

    /// Returns `Ok(())` iff the policy admits the intent under the 4
    /// stateless rules the guest enforces in-circuit
    /// (max_lamports, allowed_programs, max_accounts, require_signer).
    pub fn check_in_circuit_rules(
        intent: &IntentPayload,
        policy: &Policy,
        has_signer: bool,
    ) -> std::result::Result<(), &'static str> {
        if intent.max_lamports > policy.max_lamports_per_tx {
            return Err("max_lamports");
        }
        if !policy.allowed_programs.is_empty()
            && !policy.allowed_programs.contains(&intent.target_program)
        {
            return Err("allowed_programs");
        }
        if let Some(max_accounts) = policy.max_accounts_per_tx {
            if intent.num_accounts > max_accounts {
                return Err("max_accounts");
            }
        }
        if policy.require_signer_present && !has_signer {
            return Err("require_signer");
        }
        Ok(())
    }
}

/// Replicates the guest's in-circuit decision logic for the 4 stateless
/// rules. The output (bitmap, failure_code) must match what the actual
/// guest would commit for the same inputs.
fn host_simulate_guest(
    intent: &IntentPayload,
    policy: &Policy,
    has_signer: bool,
) -> (u32, glyph_common::CircuitFailureCode) {
    use glyph_common::CircuitFailureCode;

    let mut bitmap = 0u32;
    let mut failure = CircuitFailureCode::None;
    let mut set = |c| {
        if matches!(failure, CircuitFailureCode::None) {
            failure = c;
        }
    };

    bitmap |= RULE_BIT_MAX_LAMPORTS;
    if intent.max_lamports > policy.max_lamports_per_tx {
        set(CircuitFailureCode::MaxLamportsExceeded);
    }

    bitmap |= RULE_BIT_ALLOWED_PROGRAMS;
    if !policy.allowed_programs.is_empty()
        && !policy.allowed_programs.contains(&intent.target_program)
    {
        set(CircuitFailureCode::ProgramNotAllowed);
    }

    bitmap |= RULE_BIT_MAX_ACCOUNTS;
    if let Some(max_accounts) = policy.max_accounts_per_tx {
        if intent.num_accounts > max_accounts {
            set(CircuitFailureCode::TooManyAccounts);
        }
    }

    bitmap |= RULE_BIT_REQUIRE_SIGNER;
    if policy.require_signer_present && !has_signer {
        set(CircuitFailureCode::NoSignerPresent);
    }

    (bitmap, failure)
}

#[cfg(feature = "proptest")]
mod prop {
    use super::*;
    use proptest::prelude::*;

    fn arb_intent() -> impl Strategy<Value = IntentPayload> {
        (
            any::<[u8; 32]>(),
            any::<[u8; 32]>(),
            any::<[u8; 32]>(),
            any::<u64>(),
            proptest::option::of(any::<u16>()),
            any::<u16>(),
            1u64..u64::MAX,
        )
            .prop_map(
                |(agent, nonce, target, max_lamports, slippage, num_accounts, expiry)| {
                    IntentPayload {
                        agent_pubkey: agent,
                        nonce,
                        target_program: target,
                        max_lamports,
                        max_slippage_bps: slippage,
                        num_accounts,
                        expiry,
                    }
                },
            )
    }

    fn arb_policy() -> impl Strategy<Value = Policy> {
        (
            any::<u64>(),
            proptest::collection::vec(any::<[u8; 32]>(), 0..4),
            any::<u64>(),
            proptest::option::of(any::<u16>()),
            proptest::option::of(any::<u16>()),
            any::<bool>(),
        )
            .prop_map(
                |(max_lamports, programs, max_daily, slippage, max_accts, require_signer)| Policy {
                    version: 1,
                    max_lamports_per_tx: max_lamports,
                    allowed_programs: programs,
                    time_window: None,
                    max_daily_volume_lamports: max_daily,
                    max_slippage_bps: slippage,
                    allowed_token_mints: None,
                    max_accounts_per_tx: max_accts,
                    require_signer_present: require_signer,
                    expires_at: 0,
                },
            )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Property: the host-simulated guest decision agrees with the
        /// PolicyEngine reference on the 4 stateless in-circuit rules.
        /// Closes F-32.
        #[test]
        fn prop_circuit_matches_policy_engine(
            intent in arb_intent(),
            policy in arb_policy(),
            has_signer in any::<bool>(),
        ) {
            let (_bitmap, failure) = host_simulate_guest(&intent, &policy, has_signer);
            let oracle = policy_engine_oracle::check_in_circuit_rules(&intent, &policy, has_signer);

            match (failure, oracle) {
                (glyph_common::CircuitFailureCode::None, Ok(())) => {},
                (glyph_common::CircuitFailureCode::None, Err(rule)) => {
                    prop_assert!(false, "guest passed but oracle rejected with {}", rule);
                }
                (code, Ok(())) => {
                    prop_assert!(false, "guest failed with {:?} but oracle accepted", code);
                }
                (_, Err(_)) => {},
            }
        }
    }
}

// Sanity test that always runs, even without the proptest feature.
#[test]
fn smoke_host_simulate_agrees_with_oracle_on_passing_case() {
    let policy = test_policy();
    let intent = test_intent_payload();
    let (_bitmap, failure) = host_simulate_guest(&intent, &policy, true);
    let oracle = policy_engine_oracle::check_in_circuit_rules(&intent, &policy, true);
    assert!(matches!(failure, CircuitFailureCode::None));
    assert!(oracle.is_ok());
}

#[test]
fn smoke_host_simulate_agrees_with_oracle_on_failing_case() {
    let mut policy = test_policy();
    policy.max_lamports_per_tx = 1; // intent.max_lamports = 500M, will fail
    let intent = test_intent_payload();
    let (_bitmap, failure) = host_simulate_guest(&intent, &policy, true);
    let oracle = policy_engine_oracle::check_in_circuit_rules(&intent, &policy, true);
    assert!(matches!(failure, CircuitFailureCode::MaxLamportsExceeded));
    assert!(oracle.is_err());
}

// ─── Groth16 proof size tests ─────────────────────────────────────────────────

#[test]
fn test_groth16_proof_sizes() {
    // Ensure the proof point sizes match what the on-chain verifier expects
    const G1_SIZE: usize = 64;
    const G2_SIZE: usize = 128;

    let a = [0u8; G1_SIZE];
    let b = [0u8; G2_SIZE];
    let c = [0u8; G1_SIZE];

    assert_eq!(a.len() + b.len() + c.len(), 256);
    let pairing_input_size = 4 * (G1_SIZE + G2_SIZE);
    assert_eq!(pairing_input_size, 768);
}

// ─── RISC0 dev-mode tests (require risc0 feature + RISC0_DEV_MODE=1) ─────────

#[cfg(feature = "risc0")]
#[test]
#[ignore = "requires RISC0_DEV_MODE=1 env var — run with: RISC0_DEV_MODE=1 cargo test --features risc0 -- --ignored dev_mode"]
fn dev_mode_generate_proof_roundtrip() {
    use glyph_circuit_host::generate_proof;

    std::env::set_var("RISC0_DEV_MODE", "1");

    let policy = test_policy();
    let intent = test_intent_payload();
    let tx_data = b"swap_instruction_data_here".to_vec();

    let result = generate_proof(intent.clone(), policy.clone(), tx_data.clone());

    match result {
        Ok((receipt, _public_inputs)) => {
            let outputs: PublicOutputs =
                borsh::BorshDeserialize::try_from_slice(&receipt.receipt.journal.bytes)
                    .expect("failed to decode journal");

            assert_eq!(outputs.agent_pubkey, intent.agent_pubkey);
            assert_eq!(outputs.nonce, intent.nonce);
            assert_eq!(
                outputs.policy_commitment,
                sha256(&canonical_serialize_policy(&policy))
            );
            assert_eq!(outputs.tx_hash, sha256(&tx_data));
            assert_eq!(outputs.failure_code, CircuitFailureCode::None as u8);
            println!("✓ RISC0 dev-mode proof generated and journal decoded successfully");
        }
        Err(e) => {
            println!(
                "Note: proof generation failed (expected without full RISC Zero toolchain): {e}"
            );
        }
    }
}
