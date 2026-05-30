//! GLYPH Integration Tests
//!
//! These tests exercise the full off-chain pipeline:
//! Intent → PolicyEngine → DevProver → GlyphProofBundle
//!
//! They do NOT require the RISC Zero toolchain (DevProver is used throughout).
//! For on-chain / devnet tests, see the `devnet` module (requires Anchor + Solana CLI).

use glyph_common::{hash_policy, canonical_serialize_policy};
use glyph_tee_worker::{
    policy::PolicyEngine,
    prover::{DevProver, Prover, intent_to_payload},
    transaction_builder::canonical_target_instruction_bytes,
    types::{
        AccountMeta, ActionType, GlyphProofBundle, IntentAction, IntentConstraints,
        TransactionIntent,
    },
};
use sha2::{Digest, Sha256};

// ─── Test Helpers ─────────────────────────────────────────────────────────────

fn usdc_mint() -> &'static str {
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
}

fn token_program() -> &'static str {
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
}

fn test_agent_pubkey() -> &'static str {
    "9xQeWvG816bUx9EPjHmaT23yvVM2ZWbrrpZb9PusVFin"
}

fn dummy_account(pubkey: &str, is_signer: bool, is_writable: bool) -> AccountMeta {
    AccountMeta {
        pubkey: pubkey.to_string(),
        is_signer,
        is_writable,
    }
}

fn make_transfer_intent() -> TransactionIntent {
    TransactionIntent {
        version: 1,
        agent_pubkey: test_agent_pubkey().to_string(),
        nonce: "deadbeef1234".to_string(),
        timestamp: 1_700_000_000,
        expiry: 1_700_003_600,
        action: IntentAction {
            action_type: ActionType::Transfer,
            target_program: token_program().to_string(),
            accounts: vec![
                dummy_account(test_agent_pubkey(), true, false),
                dummy_account("So11111111111111111111111111111111111111112", false, true),
            ],
            data: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"transfer_data_payload",
            ),
        },
        constraints: IntentConstraints {
            max_lamports: 50_000_000,
            max_slippage_bps: Some(100),
            allowed_tokens: Some(vec![usdc_mint().to_string()]),
        },
        signature: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
    }
}

fn make_policy_toml(max_lamports: u64, program: &str) -> String {
    format!(
        r#"version = 1
[rules]
max_lamports_per_tx = {max_lamports}
allowed_programs = ["{program}"]
max_daily_volume_lamports = 500000000
require_slippage_bps_lte = 200
require_signer_present = true
"#
    )
}

// ─── Test 1: End-to-End Dev Mode Pipeline ────────────────────────────────────

#[test]
fn test_e2e_dev_mode_pipeline() {
    let intent = make_transfer_intent();
    let policy_toml = make_policy_toml(100_000_000, token_program());

    let mut engine = PolicyEngine::from_toml_str(&policy_toml)
        .expect("policy should parse");

    // Policy evaluation must pass
    engine.evaluate_intent(&intent)
        .expect("intent should pass policy");

    let policy = engine.canonical_policy().clone();
    let ix_bytes = canonical_target_instruction_bytes(&intent)
        .expect("should canonicalize intent");

    let prover = DevProver::new();
    let bundle = prover.generate_proof(&intent, &policy, ix_bytes, "".to_string())
        .expect("DevProver should produce bundle");

    // Bundle structure checks
    assert_eq!(bundle.proof.a.len(), 64, "proof.a must be 64 bytes");
    assert_eq!(bundle.proof.b.len(), 128, "proof.b must be 128 bytes");
    assert_eq!(bundle.proof.c.len(), 64, "proof.c must be 64 bytes");
    assert!(!bundle.journal_bytes.is_empty(), "journal must not be empty");
    assert_eq!(
        bundle.public_inputs.policy_commitment,
        hash_policy(&policy),
        "policy_commitment must match"
    );
}

// ─── Test 2: Policy Reject — Max Lamports ────────────────────────────────────

#[test]
fn test_policy_reject_max_lamports() {
    let mut intent = make_transfer_intent();
    intent.constraints.max_lamports = 999_999_999; // exceeds policy limit of 100M

    let policy_toml = make_policy_toml(100_000_000, token_program());
    let mut engine = PolicyEngine::from_toml_str(&policy_toml).unwrap();

    assert!(
        engine.evaluate_intent(&intent).is_err(),
        "intent exceeding max_lamports must be rejected"
    );
}

// ─── Test 3: Policy Reject — Program Not Allowlisted ─────────────────────────

#[test]
fn test_policy_reject_disallowed_program() {
    let mut intent = make_transfer_intent();
    intent.action.target_program = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5Nt6f9xWh".to_string(); // not in allowlist

    let policy_toml = make_policy_toml(100_000_000, token_program());
    let mut engine = PolicyEngine::from_toml_str(&policy_toml).unwrap();

    assert!(
        engine.evaluate_intent(&intent).is_err(),
        "intent with non-allowlisted program must be rejected"
    );
}

// ─── Test 4: Instruction Binding — Program ID Change Detected ────────────────

#[test]
fn test_instruction_binding_program_id_change_detected() {
    let intent_a = make_transfer_intent();
    let mut intent_b = intent_a.clone();
    intent_b.action.target_program = "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5Nt6f9xWh".to_string();

    let bytes_a = canonical_target_instruction_bytes(&intent_a).unwrap();
    let bytes_b = canonical_target_instruction_bytes(&intent_b).unwrap();

    assert_ne!(
        Sha256::digest(&bytes_a).as_slice(),
        Sha256::digest(&bytes_b).as_slice(),
        "changing program_id must change the canonical instruction hash"
    );
}

// ─── Test 5: Instruction Binding — Account Signer Flag Change Detected ────────

#[test]
fn test_instruction_binding_account_flag_change_detected() {
    let intent_a = make_transfer_intent();
    let mut intent_b = intent_a.clone();
    // Flip is_signer on the first account
    intent_b.action.accounts[0].is_signer = false;

    let bytes_a = canonical_target_instruction_bytes(&intent_a).unwrap();
    let bytes_b = canonical_target_instruction_bytes(&intent_b).unwrap();

    assert_ne!(
        Sha256::digest(&bytes_a).as_slice(),
        Sha256::digest(&bytes_b).as_slice(),
        "changing is_signer flag must change the canonical instruction hash"
    );
}

// ─── Test 6: Instruction Binding — Data Change Detected ──────────────────────

#[test]
fn test_instruction_binding_data_change_detected() {
    let intent_a = make_transfer_intent();
    let mut intent_b = intent_a.clone();
    intent_b.action.data = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"different_data_payload",
    );

    let bytes_a = canonical_target_instruction_bytes(&intent_a).unwrap();
    let bytes_b = canonical_target_instruction_bytes(&intent_b).unwrap();

    assert_ne!(
        Sha256::digest(&bytes_a).as_slice(),
        Sha256::digest(&bytes_b).as_slice(),
        "changing instruction data must change the canonical instruction hash"
    );
}

// ─── Test 7: Policy Commitment Determinism ────────────────────────────────────

#[test]
fn test_policy_commitment_deterministic() {
    let toml = make_policy_toml(100_000_000, token_program());

    let engine_a = PolicyEngine::from_toml_str(&toml).unwrap();
    let engine_b = PolicyEngine::from_toml_str(&toml).unwrap();

    assert_eq!(
        hash_policy(engine_a.canonical_policy()),
        hash_policy(engine_b.canonical_policy()),
        "same policy TOML must always produce same commitment"
    );
}

// ─── Test 8: Policy Commitment Changes on Rule Mutation ───────────────────────

#[test]
fn test_policy_commitment_changes_on_mutation() {
    let toml_a = make_policy_toml(100_000_000, token_program());
    let toml_b = make_policy_toml(200_000_000, token_program()); // different max_lamports

    let engine_a = PolicyEngine::from_toml_str(&toml_a).unwrap();
    let engine_b = PolicyEngine::from_toml_str(&toml_b).unwrap();

    assert_ne!(
        hash_policy(engine_a.canonical_policy()),
        hash_policy(engine_b.canonical_policy()),
        "different policy rules must produce different commitments"
    );
}

// ─── Test 9: Journal Round-trip ───────────────────────────────────────────────

#[test]
fn test_journal_roundtrip_matches_public_inputs() {
    use borsh::BorshDeserialize;
    use glyph_common::PublicOutputs;

    let intent = make_transfer_intent();
    let policy_toml = make_policy_toml(100_000_000, token_program());
    let mut engine = PolicyEngine::from_toml_str(&policy_toml).unwrap();
    engine.evaluate_intent(&intent).unwrap();

    let policy = engine.canonical_policy().clone();
    let ix_bytes = canonical_target_instruction_bytes(&intent).unwrap();

    let prover = DevProver::new();
    let bundle = prover.generate_proof(&intent, &policy, ix_bytes, "".to_string()).unwrap();

    let decoded: PublicOutputs = BorshDeserialize::try_from_slice(&bundle.journal_bytes)
        .expect("journal_bytes must deserialize to PublicOutputs");

    assert_eq!(decoded.policy_commitment, bundle.public_inputs.policy_commitment);
    assert_eq!(decoded.agent_pubkey, bundle.public_inputs.agent_pubkey);
    assert_eq!(decoded.nonce, bundle.public_inputs.nonce);
    assert_eq!(decoded.tx_hash, bundle.public_inputs.tx_hash);
}

// ─── Test 10: Policy Mismatch Detected ───────────────────────────────────────

#[test]
fn test_proof_policy_commitment_reflects_policy() {
    let intent = make_transfer_intent();

    let policy_toml_a = make_policy_toml(100_000_000, token_program());
    let policy_toml_b = make_policy_toml(200_000_000, token_program());

    let engine_a = PolicyEngine::from_toml_str(&policy_toml_a).unwrap();
    let engine_b = PolicyEngine::from_toml_str(&policy_toml_b).unwrap();

    let ix_bytes_a = canonical_target_instruction_bytes(&intent).unwrap();
    let ix_bytes_b = canonical_target_instruction_bytes(&intent).unwrap();

    let prover = DevProver::new();
    let bundle_a = prover.generate_proof(&intent, engine_a.canonical_policy(), ix_bytes_a, "".to_string()).unwrap();
    let bundle_b = prover.generate_proof(&intent, engine_b.canonical_policy(), ix_bytes_b, "".to_string()).unwrap();

    assert_ne!(
        bundle_a.public_inputs.policy_commitment,
        bundle_b.public_inputs.policy_commitment,
        "proofs for different policies must have different policy_commitments"
    );
}

// ─── Test 11: VK Integrity Check Fails on Placeholder ────────────────────────

#[test]
fn test_vk_integrity_fails_on_placeholder() {
    // The VK currently contains placeholder values (all zeros for VK_HASH).
    // verify_vk_integrity() must return false in this state.
    // This test will flip to passing only once a real VK is populated.
    use glyph_verifier::groth16::vk::verify_vk_integrity;
    assert!(
        !verify_vk_integrity(),
        "verify_vk_integrity() must return false while VK contains placeholder values"
    );
}

// ─── Test 12: Daily Volume Accumulates and Rejects at Limit ──────────────────

#[test]
fn test_daily_volume_enforcement() {
    let toml = r#"
version = 1
[rules]
max_lamports_per_tx = 100000000
allowed_programs = ["TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"]
max_daily_volume_lamports = 150000000
require_signer_present = true
"#;

    let mut engine = PolicyEngine::from_toml_str(toml).unwrap();
    let mut intent = make_transfer_intent();
    intent.constraints.max_lamports = 100_000_000;

    // First intent: 100M lamports — should pass
    engine.evaluate_intent(&intent).expect("first intent must pass");

    // Second intent: would push to 200M > 150M limit — must be rejected
    assert!(
        engine.evaluate_intent(&intent).is_err(),
        "second intent must be rejected: would exceed daily volume limit"
    );
}
