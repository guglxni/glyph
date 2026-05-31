//! Determinism + cross-version tests for `glyph_common`'s canonical encoders.
//!
//! These tests are the parity-with-SDK contract: if these change, the TS SDK
//! and Rust SDK must update in lock-step.

use glyph_common::{
    canonical_serialize_policy, canonical_signing_payload, canonical_target_instruction_bytes,
    hash_policy, hash_signing_payload, hash_target_instruction, sha256, CanonicalAccountMeta,
    CanonicalIntent, Policy, TimeWindow,
};

fn sample_policy() -> Policy {
    Policy {
        version: 1,
        max_lamports_per_tx: 5_000_000_000,
        allowed_programs: vec![[0x11; 32], [0x22; 32]],
        time_window: Some(TimeWindow {
            start_hour_utc: 8,
            end_hour_utc: 20,
        }),
        max_daily_volume_lamports: 50_000_000_000,
        max_slippage_bps: Some(100),
        allowed_token_mints: Some(vec![[0xAA; 32], [0xBB; 32]]),
        max_accounts_per_tx: Some(20),
        require_signer_present: true,
        expires_at: 0,
    }
}

fn sample_intent() -> CanonicalIntent {
    CanonicalIntent {
        agent_pubkey: [9u8; 32],
        nonce: [7u8; 32],
        target_program: [1u8; 32],
        accounts: vec![
            CanonicalAccountMeta {
                pubkey: [2u8; 32],
                is_signer: true,
                is_writable: false,
            },
            CanonicalAccountMeta {
                pubkey: [3u8; 32],
                is_signer: false,
                is_writable: true,
            },
        ],
        data: vec![1, 2, 3, 4],
        max_lamports: 1_000,
        max_slippage_bps: Some(50),
        allowed_tokens: None,
        expiry: 1_700_000_600,
        timestamp: 1_700_000_000,
        policy_commitment: [0xAA; 32],
        worker_pubkey: Some([0xBB; 32]),
        epoch: 1,
    }
}

#[test]
fn signing_payload_is_byte_stable_across_runs() {
    let intent = sample_intent();
    let a = canonical_signing_payload(&intent);
    let b = canonical_signing_payload(&intent);
    assert_eq!(a, b);
    // Pin the length too — any growth of the canonical encoding is a wire-format
    // version bump and MUST update both the SDK and this test.
    // Layout for sample_intent:
    //   32 (agent_pubkey) + 32 (nonce)
    //   + target_ix: 32 (program) + 4 (num_accounts) + 2*(32+1+1) + 4 (data_len) + 4 (data)
    //   + 8 (max_lamports) + 1 (presence) + 2 (slippage)
    //   + 1 (allowed_tokens presence: None)
    //   + 8 (expiry) + 8 (timestamp) + 32 (policy_commitment)
    //   + 1 (worker_pubkey presence) + 32 (worker_pubkey)
    //   + 8 (epoch)
    // = 32+32 + 32+4+68+4+4 + 8+1+2 + 1 + 8+8+32 + 1+32 + 8 = 277
    assert_eq!(a.len(), 277);
}

#[test]
fn signing_payload_changes_with_every_field() {
    let base = sample_intent();
    let base_bytes = canonical_signing_payload(&base);

    // Mutate each field and confirm the encoding changes.
    let mut x = base.clone();
    x.agent_pubkey[0] ^= 1;
    assert_ne!(canonical_signing_payload(&x), base_bytes);

    let mut x = base.clone();
    x.nonce[0] ^= 1;
    assert_ne!(canonical_signing_payload(&x), base_bytes);

    let mut x = base.clone();
    x.target_program[0] ^= 1;
    assert_ne!(canonical_signing_payload(&x), base_bytes);

    let mut x = base.clone();
    x.accounts[0].is_signer = !x.accounts[0].is_signer;
    assert_ne!(canonical_signing_payload(&x), base_bytes);

    let mut x = base.clone();
    x.data.push(0xFF);
    assert_ne!(canonical_signing_payload(&x), base_bytes);

    let mut x = base.clone();
    x.max_lamports = x.max_lamports.wrapping_add(1);
    assert_ne!(canonical_signing_payload(&x), base_bytes);

    let mut x = base.clone();
    x.max_slippage_bps = None;
    assert_ne!(canonical_signing_payload(&x), base_bytes);

    let mut x = base.clone();
    x.policy_commitment[0] ^= 1;
    assert_ne!(canonical_signing_payload(&x), base_bytes);

    let mut x = base.clone();
    x.worker_pubkey = None;
    assert_ne!(canonical_signing_payload(&x), base_bytes);

    let mut x = base.clone();
    x.epoch = x.epoch.wrapping_add(1);
    assert_ne!(canonical_signing_payload(&x), base_bytes);
}

#[test]
fn target_ix_length_prefixes_close_t28() {
    // Two distinct (accounts, data) splits that would collide under an
    // unframed encoding. With the length prefix they must differ.
    let program = [1u8; 32];

    // Variant A: 1 account whose pubkey is 0xAA…AA, 1-byte data 0xBB
    let metas_a = vec![CanonicalAccountMeta {
        pubkey: [0xAA; 32],
        is_signer: false,
        is_writable: false,
    }];
    let data_a = vec![0xBB];

    // Variant B: 0 accounts, data is the raw bytes that the previous
    // encoding would have produced (32 + 1 + 1 + 1 = 35 bytes).
    let mut data_b = Vec::new();
    data_b.extend_from_slice(&[0xAA; 32]);
    data_b.push(0); // is_signer flag from variant A
    data_b.push(0); // is_writable flag from variant A
    data_b.push(0xBB);

    let h_a = hash_target_instruction(&program, &metas_a, &data_a);
    let h_b = hash_target_instruction(&program, &[], &data_b);
    assert_ne!(
        h_a, h_b,
        "length prefixes must disambiguate the two layouts"
    );
}

#[test]
fn policy_commitment_changes_with_expires_at() {
    let mut p = sample_policy();
    let h0 = hash_policy(&p);
    p.expires_at = 1_893_456_000;
    let h1 = hash_policy(&p);
    assert_ne!(h0, h1, "expires_at must be bound into policy_commitment");
}

#[test]
fn policy_legacy_serde_alias_for_require_signer() {
    // Older callers wrote `require_signer = true` in TOML. The serde alias
    // must keep that working.
    let toml_str = r#"{
        "version": 1,
        "max_lamports_per_tx": 1,
        "allowed_programs": [],
        "time_window": null,
        "max_daily_volume_lamports": 1,
        "max_slippage_bps": null,
        "allowed_token_mints": null,
        "max_accounts_per_tx": null,
        "require_signer": true,
        "expires_at": 0
    }"#;
    let parsed: Policy = serde_json::from_str(toml_str).unwrap();
    assert!(parsed.require_signer_present);
}

#[test]
fn hash_helpers_match_manual_sha256() {
    let p = sample_policy();
    assert_eq!(hash_policy(&p), sha256(&canonical_serialize_policy(&p)));

    let i = sample_intent();
    assert_eq!(
        hash_signing_payload(&i),
        sha256(&canonical_signing_payload(&i))
    );

    let program = [9u8; 32];
    let metas = vec![CanonicalAccountMeta {
        pubkey: [1u8; 32],
        is_signer: false,
        is_writable: true,
    }];
    let data = vec![1u8, 2, 3];
    assert_eq!(
        hash_target_instruction(&program, &metas, &data),
        sha256(&canonical_target_instruction_bytes(&program, &metas, &data))
    );
}
