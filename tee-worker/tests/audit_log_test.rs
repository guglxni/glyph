//! WS-6 — sealed append-only audit log integration tests.
//!
//! Covers the audit's acceptance criteria:
//! - append → verify_chain succeeds
//! - tamper any byte ⇒ verify_chain fails (`ChainBroken`)
//! - replay verification walks `prev_entry_hash` to genesis

use std::sync::Arc;

use ed25519_dalek::SigningKey;
use glyph_tee_worker::audit_log::{AuditEntryInner, AuditLog};
use glyph_tee_worker::vendors::{create_provider, TeeProvider};
use glyph_tee_worker::types::TeeVendor;

fn provider() -> Arc<dyn TeeProvider> {
    // Dev-mode passphrase-derived AEAD (vendors/dev_seal.rs). The unit tests
    // cover both seal+unseal round-trips already, so we can safely assume
    // it's a real AEAD here. We need a passphrase set in env for the dev
    // vendor; the existing tests rely on `GLYPH_SEAL_PASSPHRASE`.
    std::env::set_var("GLYPH_SEAL_PASSPHRASE", "audit-log-test-passphrase-32bytes-min!!");
    Arc::from(create_provider(TeeVendor::Nitro))
}

fn signing_key() -> Arc<SigningKey> {
    Arc::new(SigningKey::from_bytes(&[42u8; 32]))
}

fn make_inner(seed: u8) -> AuditEntryInner {
    AuditEntryInner {
        agent_pubkey: [seed; 32],
        intent_hash: [seed.wrapping_add(1); 32],
        policy_commitment: [seed.wrapping_add(2); 32],
        tx_hash: [seed.wrapping_add(3); 32],
    }
}

#[test]
fn append_and_verify_chain() {
    let prov = provider();
    let mut log = AuditLog::in_memory(signing_key());
    log.append(make_inner(1), 1_700_000_000, prov.as_ref()).unwrap();
    log.append(make_inner(2), 1_700_000_001, prov.as_ref()).unwrap();
    log.append(make_inner(3), 1_700_000_002, prov.as_ref()).unwrap();
    log.verify_chain(prov.as_ref()).expect("clean chain must verify");
}

#[test]
fn tampered_byte_breaks_chain() {
    let prov = provider();
    let mut log = AuditLog::in_memory(signing_key());
    log.append(make_inner(1), 1_700_000_000, prov.as_ref()).unwrap();
    log.append(make_inner(2), 1_700_000_001, prov.as_ref()).unwrap();
    let mut entries = log.read_full_chain(prov.as_ref()).unwrap();
    // Flip a single byte in the middle entry's tx_hash — this breaks both
    // the signature verification AND the prev_entry_hash for the next link.
    entries[0].tx_hash[5] ^= 0x01;
    let res = glyph_tee_worker::audit_log::verify_entries(&entries, &signing_key().verifying_key());
    assert!(res.is_err(), "tampered chain must fail verification");
}

#[test]
fn persisted_chain_replays_after_restart() {
    let prov = provider();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.audit.log.sealed");
    {
        let mut log = AuditLog::new(signing_key(), Some(path.clone()), prov.as_ref()).unwrap();
        log.append(make_inner(1), 1_700_000_000, prov.as_ref()).unwrap();
        log.append(make_inner(2), 1_700_000_001, prov.as_ref()).unwrap();
    }
    // Re-open: AuditLog::new replays + verify_entries.
    let log = AuditLog::new(signing_key(), Some(path.clone()), prov.as_ref()).unwrap();
    assert_eq!(log.sequence_high(), 1);
    log.verify_chain(prov.as_ref()).expect("chain on disk must verify");
}

#[test]
fn merkle_root_changes_with_appends() {
    let prov = provider();
    let mut log = AuditLog::in_memory(signing_key());
    let root_empty = log.merkle_root(prov.as_ref()).unwrap();
    assert_eq!(root_empty, [0u8; 32]);
    log.append(make_inner(1), 1_700_000_000, prov.as_ref()).unwrap();
    let root1 = log.merkle_root(prov.as_ref()).unwrap();
    assert_ne!(root1, [0u8; 32]);
    log.append(make_inner(2), 1_700_000_001, prov.as_ref()).unwrap();
    let root2 = log.merkle_root(prov.as_ref()).unwrap();
    assert_ne!(root1, root2, "appending must change the merkle root");
}
