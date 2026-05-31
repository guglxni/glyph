//! Dev-mode passphrase-derived AEAD sealing for vendor adapters.
//!
//! ============================================================================
//! DEV-ONLY — DO NOT USE IN PRODUCTION
//! ============================================================================
//!
//! This module exists to replace the identity-passthrough `seal`/`unseal`
//! that previously shipped in the dev arms of all three vendor providers
//! (`nitro.rs`, `sgx.rs`, `sev.rs`). The identity passthrough was tracked as
//! audit findings T3 and T5 (in `audit/AUDIT_TEE.md`):
//!
//! > T3 — CRITICAL — In dev / staging mode, `seal`/`unseal` are identity
//! > functions on all three vendors — sealed policy file is plaintext on disk
//! > and silently consumed as if sealed.
//! >
//! > T5 — CRITICAL — No KMS / NSM / vTPM-derived sealing key exists.
//!
//! ## What this module is
//!
//! - A shared helper used by every vendor provider's *dev* `seal`/`unseal`.
//! - Derives a 32-byte AEAD key from a passphrase (`GLYPH_SEAL_PASSPHRASE`)
//!   using **Argon2id** with library defaults.
//! - Encrypts/decrypts with **ChaCha20-Poly1305** (IETF, 12-byte nonce, 16-byte tag).
//! - Output layout: `salt:16 || nonce:12 || ciphertext_with_tag`.
//!
//! ## What this module is NOT
//!
//! - It is **not** a substitute for a TEE-bound sealing key. The passphrase
//!   lives in an env-var on the host; a host compromise reads the passphrase
//!   and trivially unseals everything. In production, sealing must be
//!   performed by a key that is *bound to the TEE measurement* and never
//!   leaves the enclave (Nitro KMS with PCR-bound key policy, SGX EGETKEY,
//!   SEV-SNP vTPM or KMS-with-attestation).
//! - This is a "fail loud, not silent" stop-gap that lets dev/staging
//!   environments surface tampering (decryption fails on any bit-flip),
//!   which the previous identity passthrough could not.
//!
//! ## Why a passphrase at all?
//!
//! The audit explicitly recommended this construction:
//!
//! > As a stop-gap for dev mode, derive a key with `argon2id` from a
//! > high-entropy `GLYPH_SEAL_PASSPHRASE` env-var and AEAD-encrypt with
//! > `chacha20poly1305`. Fail if the passphrase is shorter than 32 bytes
//! > or the env-var is unset.  — `audit/AUDIT_TEE.md` T5
//!
//! ## Threat model (dev mode)
//!
//! - **In scope:** Detect bit-flip / file replacement of sealed blobs on
//!   disk. A tampered blob fails AEAD verification and `dev_unseal_*`
//!   returns `Err`.
//! - **Out of scope:** Host compromise, side-channel attacks on the
//!   passphrase, or any threat where the attacker has read access to
//!   `GLYPH_SEAL_PASSPHRASE`. For those, you need a real TEE.

use anyhow::{anyhow, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
/// Minimum passphrase length enforced at the call sites. A passphrase shorter
/// than this is rejected before it ever reaches Argon2; the audit pins this
/// value at 32 bytes (T5).
pub const MIN_PASSPHRASE_LEN: usize = 32;

/// Domain separation tag mixed into the AEAD's associated-data so that a
/// ciphertext sealed under one Glyph version cannot be unsealed under another.
const DEV_SEAL_AAD: &[u8] = b"GLYPH:dev_seal:v1";

/// Derive a 32-byte ChaCha20-Poly1305 key from a passphrase + salt using
/// Argon2id with default parameters.
fn derive_key(passphrase: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::default());
    let mut out = [0u8; KEY_LEN];
    argon
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|e| anyhow!("argon2id derivation failed: {e}"))?;
    Ok(out)
}

/// Seal `plaintext` under a passphrase. The output is
/// `salt:16 || nonce:12 || ciphertext_with_tag`.
///
/// ## DEV-ONLY
/// See module docs. This is not a substitute for TEE-bound sealing; it exists
/// so that dev/staging environments fail loudly on tampering instead of
/// silently accepting plaintext as "sealed".
pub fn dev_seal_with_passphrase(passphrase: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(anyhow!(
            "GLYPH_SEAL_PASSPHRASE too short ({} bytes, need >= {})",
            passphrase.len(),
            MIN_PASSPHRASE_LEN
        ));
    }

    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut nonce_bytes);

    let key_bytes = derive_key(passphrase, &salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(
            nonce,
            Payload {
                msg: plaintext,
                aad: DEV_SEAL_AAD,
            },
        )
        .map_err(|e| anyhow!("chacha20poly1305 encrypt failed: {e}"))?;

    let mut out = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Unseal a ciphertext previously produced by [`dev_seal_with_passphrase`].
///
/// Fails loudly (returns `Err`) on any of:
/// - passphrase too short
/// - input shorter than `salt + nonce + tag` overhead
/// - AEAD authentication failure (tampered ciphertext, wrong passphrase,
///   wrong salt/nonce).
///
/// ## DEV-ONLY
/// See module docs.
pub fn dev_unseal_with_passphrase(passphrase: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
    if passphrase.len() < MIN_PASSPHRASE_LEN {
        return Err(anyhow!(
            "GLYPH_SEAL_PASSPHRASE too short ({} bytes, need >= {})",
            passphrase.len(),
            MIN_PASSPHRASE_LEN
        ));
    }
    if ciphertext.len() < SALT_LEN + NONCE_LEN + 16 {
        return Err(anyhow!(
            "sealed blob too short: {} bytes (need >= {})",
            ciphertext.len(),
            SALT_LEN + NONCE_LEN + 16
        ));
    }
    let (salt, rest) = ciphertext.split_at(SALT_LEN);
    let (nonce_bytes, ct_and_tag) = rest.split_at(NONCE_LEN);

    let key_bytes = derive_key(passphrase, salt)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    let nonce = Nonce::from_slice(nonce_bytes);

    cipher
        .decrypt(
            nonce,
            Payload {
                msg: ct_and_tag,
                aad: DEV_SEAL_AAD,
            },
        )
        .map_err(|e| anyhow!("chacha20poly1305 decrypt failed (tampered or wrong passphrase): {e}"))
}

/// Read `GLYPH_SEAL_PASSPHRASE` from the environment and validate length.
///
/// Returns a clear error if the env-var is unset or shorter than 32 bytes.
pub fn passphrase_from_env() -> Result<Vec<u8>> {
    let pass = std::env::var("GLYPH_SEAL_PASSPHRASE").map_err(|_| {
        anyhow!(
            "GLYPH_SEAL_PASSPHRASE env-var not set (dev sealing requires a passphrase \
             of at least {} bytes)",
            MIN_PASSPHRASE_LEN
        )
    })?;
    if pass.len() < MIN_PASSPHRASE_LEN {
        return Err(anyhow!(
            "GLYPH_SEAL_PASSPHRASE too short ({} bytes, need >= {})",
            pass.len(),
            MIN_PASSPHRASE_LEN
        ));
    }
    Ok(pass.into_bytes())
}

/// Cross-module test helper: a mutex used by all vendor tests that mutate
/// `GLYPH_SEAL_PASSPHRASE` to serialize env mutation. Without this, parallel
/// test execution races between `set_var` / `remove_var` across modules.
#[cfg(test)]
pub(crate) static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_PASS: &[u8] = b"this-is-a-test-passphrase-32-bytes!!!";

    #[test]
    fn round_trip_short_payload() {
        let pt = b"hello, glyph";
        let ct = dev_seal_with_passphrase(TEST_PASS, pt).unwrap();
        // layout: 16 salt || 12 nonce || ct+tag (>=16 tag)
        assert!(ct.len() >= 16 + 12 + 16 + pt.len());
        let pt2 = dev_unseal_with_passphrase(TEST_PASS, &ct).unwrap();
        assert_eq!(pt, pt2.as_slice());
    }

    #[test]
    fn round_trip_empty_payload() {
        let ct = dev_seal_with_passphrase(TEST_PASS, b"").unwrap();
        let pt = dev_unseal_with_passphrase(TEST_PASS, &ct).unwrap();
        assert_eq!(pt, Vec::<u8>::new());
    }

    #[test]
    fn round_trip_large_payload() {
        let pt = vec![0xABu8; 8192];
        let ct = dev_seal_with_passphrase(TEST_PASS, &pt).unwrap();
        let pt2 = dev_unseal_with_passphrase(TEST_PASS, &ct).unwrap();
        assert_eq!(pt, pt2);
    }

    #[test]
    fn rejects_short_passphrase_seal() {
        let r = dev_seal_with_passphrase(b"too-short", b"x");
        assert!(r.is_err());
    }

    #[test]
    fn rejects_short_passphrase_unseal() {
        let ct = dev_seal_with_passphrase(TEST_PASS, b"x").unwrap();
        let r = dev_unseal_with_passphrase(b"too-short", &ct);
        assert!(r.is_err());
    }

    #[test]
    fn rejects_tampered_ciphertext() {
        let mut ct = dev_seal_with_passphrase(TEST_PASS, b"hello").unwrap();
        // Flip a bit in the encrypted body (after salt+nonce).
        let idx = 16 + 12 + 1;
        ct[idx] ^= 0x01;
        assert!(dev_unseal_with_passphrase(TEST_PASS, &ct).is_err());
    }

    #[test]
    fn rejects_wrong_passphrase() {
        let ct = dev_seal_with_passphrase(TEST_PASS, b"hello").unwrap();
        let other = b"another-32-byte-passphrase!!!!!!!!!!";
        assert!(dev_unseal_with_passphrase(other, &ct).is_err());
    }

    #[test]
    fn rejects_truncated_blob() {
        let r = dev_unseal_with_passphrase(TEST_PASS, b"too-short");
        assert!(r.is_err());
    }

    #[test]
    fn distinct_seals_under_same_passphrase() {
        // Different salt/nonce per seal → distinct ciphertexts even for same pt.
        let a = dev_seal_with_passphrase(TEST_PASS, b"x").unwrap();
        let b = dev_seal_with_passphrase(TEST_PASS, b"x").unwrap();
        assert_ne!(a, b);
    }
}
