//! Attestation pipeline integration test (closes WS-2 task #16).
//!
//! Exercises the full boot → policy load → attest → process intent →
//! bundle includes evidence → re-verify chain using the dev-mode
//! passphrase-sealed path so the test does not require a real Nitro / SGX
//! / SEV enclave to run in CI.
//!
//! ## What this proves
//! - `provider.compute_user_data(...)` produces a stable 32-byte digest of
//!   the (policy, agent, worker, boot_nonce, epoch) 5-tuple.
//! - `provider.attest(user_data, policy_commitment)` followed by
//!   `provider.verify_attestation(...)` round-trips for every dev vendor.
//! - A `GlyphProofBundle` can carry the resulting quote in its
//!   `worker_attestation` field (closes T6 wire-format slice).
//! - A re-verify of the embedded quote against the same policy commitment
//!   succeeds; against a mutated commitment it fails closed.
//!
//! Run with:
//!   GLYPH_SEAL_PASSPHRASE=$(printf 'pipeline-test-passphrase-32bytes!!')
//!   cargo test -p glyph-tee-worker --test attestation_pipeline_test

use glyph_common::hash_policy;
use glyph_tee_worker::policy::PolicyEngine;
use glyph_tee_worker::prover::{DevProver, Prover};
use glyph_tee_worker::types::{
    AccountMeta, ActionType, IntentAction, IntentConstraints, TransactionIntent,
};
use glyph_tee_worker::vendors::{NitroProvider, SevProvider, SgxProvider, TeeProvider};

const TEST_PASSPHRASE: &str = "pipeline-test-passphrase-32-bytes-min!!";

fn install_passphrase() {
    std::env::set_var("GLYPH_SEAL_PASSPHRASE", TEST_PASSPHRASE);
}

fn make_policy_toml() -> String {
    "[rules]\n\
     max_lamports_per_tx = 5000000000\n\
     allowed_programs = [\"11111111111111111111111111111111\"]\n\
     max_daily_volume_lamports = 50000000000\n\
     require_signer_present = true\n"
        .to_string()
}

fn make_intent() -> TransactionIntent {
    TransactionIntent {
        version: 1,
        agent_pubkey: "11111111111111111111111111111111".to_string(),
        nonce: "deadbeef".repeat(8), // 64 hex chars => 32 bytes
        timestamp: 1_700_000_000,
        expiry: 0, // 0 = no expiry — keeps the test wallclock-independent
        action: IntentAction {
            action_type: ActionType::Transfer,
            target_program: "11111111111111111111111111111111".to_string(),
            accounts: vec![AccountMeta {
                pubkey: "11111111111111111111111111111111".to_string(),
                is_signer: true,
                is_writable: true,
            }],
            data: "AAAA".to_string(),
        },
        constraints: IntentConstraints {
            max_lamports: 1_000_000_000,
            max_slippage_bps: Some(50),
            allowed_tokens: None,
        },
        signature: String::new(),
    }
}

fn boot_nonce_fixture() -> [u8; 32] {
    let mut n = [0u8; 32];
    for (i, b) in n.iter_mut().enumerate() {
        *b = i as u8;
    }
    n
}

fn run_pipeline_for_provider<P: TeeProvider>(provider: P) {
    install_passphrase();

    // Boot path: load the policy and compute its commitment.
    let engine = PolicyEngine::from_toml_str(&make_policy_toml()).expect("policy load");
    let canonical_policy = engine.canonical_policy().clone();
    let policy_commitment = hash_policy(&canonical_policy);

    // Synthetic worker + agent pubkeys (real boot path uses Ed25519 + config).
    let worker_pubkey = [0xAAu8; 32];
    let agent_pubkey = [0xBBu8; 32];
    let boot_nonce = boot_nonce_fixture();
    let epoch: u64 = 0;

    // 1. Compute user_data via the trait helper (closes T6 — vendor-specific
    //    domain string is mixed in so cross-vendor evidence cannot be
    //    substituted).
    let user_data =
        provider.compute_user_data(&policy_commitment, &agent_pubkey, &worker_pubkey, &boot_nonce, epoch);
    assert_ne!(user_data, [0u8; 32], "compute_user_data must be non-trivial");

    // 2. Attest + self-verify (defence-in-depth against vendor regression).
    let evidence = provider
        .attest(&user_data, &policy_commitment)
        .expect("attest must succeed in dev mode");
    assert!(
        provider
            .verify_attestation(&evidence, &policy_commitment)
            .expect("verify_attestation must not error in dev"),
        "self-verify must succeed for fresh evidence"
    );

    // 3. Process the intent through the dev prover and attach the quote
    //    to the bundle (mirrors what main.rs does in the request path).
    let prover = DevProver::new();
    let mut bundle = prover
        .generate_proof(&make_intent(), &canonical_policy, vec![1, 2, 3, 4], 1_700_000_500)
        .expect("dev proof generation");
    bundle.worker_attestation = Some(evidence.quote.clone());

    // 4. Bundle now carries the quote — SDK / on-chain re-verify path
    //    must succeed against the same policy commitment.
    let attached_quote = bundle
        .worker_attestation
        .as_ref()
        .expect("bundle should carry worker_attestation");
    assert_eq!(attached_quote, &evidence.quote);

    // Reconstruct an AttestationEvidence wrapper as the SDK would do
    // (vendor + timestamp_unix get rebound at re-verify time from the
    // bundle metadata; vendor here is whatever the boot evidence reported).
    let reconstructed = glyph_tee_worker::vendors::AttestationEvidence {
        vendor: evidence.vendor.clone(),
        quote: attached_quote.clone(),
        timestamp_unix: evidence.timestamp_unix,
    };
    assert!(
        provider
            .verify_attestation(&reconstructed, &policy_commitment)
            .unwrap(),
        "re-verify of bundle-attached quote must succeed against the same policy commitment"
    );

    // 5. Mutate the policy commitment by 1 bit — re-verify must fail closed.
    let mut tampered_commitment = policy_commitment;
    tampered_commitment[0] ^= 0x01;
    assert!(
        !provider
            .verify_attestation(&reconstructed, &tampered_commitment)
            .unwrap(),
        "re-verify must fail closed against a mutated policy commitment"
    );
}

#[test]
fn nitro_dev_pipeline_round_trips() {
    let provider = NitroProvider::default();
    if provider.is_real_enclave() {
        eprintln!("skipping: real Nitro device detected");
        return;
    }
    run_pipeline_for_provider(provider);
}

#[test]
fn sgx_dev_pipeline_round_trips() {
    let provider = SgxProvider::default();
    if provider.is_real_enclave() {
        eprintln!("skipping: real SGX device detected");
        return;
    }
    run_pipeline_for_provider(provider);
}

#[test]
fn sev_dev_pipeline_round_trips() {
    let provider = SevProvider::default();
    if provider.is_real_enclave() {
        eprintln!("skipping: real SEV-SNP device detected");
        return;
    }
    run_pipeline_for_provider(provider);
}

/// Cross-vendor evidence substitution must fail. A Nitro-shaped quote fed
/// into an SGX verifier (or vice versa) is rejected by the structured
/// dev-mode parser. Closes T6 (vendor binding slice).
#[test]
fn cross_vendor_evidence_substitution_rejected() {
    install_passphrase();

    let nitro = NitroProvider::default();
    let sgx = SgxProvider::default();
    if nitro.is_real_enclave() || sgx.is_real_enclave() {
        eprintln!("skipping: real TEE detected");
        return;
    }

    let policy_commitment = [0x11u8; 32];
    let worker_pubkey = [0xAAu8; 32];
    let agent_pubkey = [0xBBu8; 32];
    let boot_nonce = boot_nonce_fixture();

    let nitro_user_data =
        nitro.compute_user_data(&policy_commitment, &agent_pubkey, &worker_pubkey, &boot_nonce, 0);
    let nitro_evidence = nitro
        .attest(&nitro_user_data, &policy_commitment)
        .unwrap();

    // Nitro-shaped evidence handed to SGX must be rejected (vendor field
    // mismatch).
    assert!(
        !sgx.verify_attestation(&nitro_evidence, &policy_commitment)
            .unwrap(),
        "SGX must reject Nitro-vendor evidence"
    );
}

/// The 5-tuple binding actually changes the produced user_data. Mutating
/// any one of (policy, agent, worker, boot_nonce, epoch) must produce a
/// different digest. Closes T6 (binding slice).
#[test]
fn user_data_binding_changes_with_each_field() {
    let nitro = NitroProvider::default();
    let pc = [1u8; 32];
    let agent = [2u8; 32];
    let worker = [3u8; 32];
    let nonce = [4u8; 32];

    let baseline = nitro.compute_user_data(&pc, &agent, &worker, &nonce, 0);

    let pc2 = [9u8; 32];
    assert_ne!(baseline, nitro.compute_user_data(&pc2, &agent, &worker, &nonce, 0));

    let agent2 = [9u8; 32];
    assert_ne!(baseline, nitro.compute_user_data(&pc, &agent2, &worker, &nonce, 0));

    let worker2 = [9u8; 32];
    assert_ne!(baseline, nitro.compute_user_data(&pc, &agent, &worker2, &nonce, 0));

    let nonce2 = [9u8; 32];
    assert_ne!(baseline, nitro.compute_user_data(&pc, &agent, &worker, &nonce2, 0));

    assert_ne!(baseline, nitro.compute_user_data(&pc, &agent, &worker, &nonce, 1));
}
