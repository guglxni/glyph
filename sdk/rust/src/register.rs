//! WS-9 — Delegator-signed agent registration helpers.
//!
//! The on-chain `register_agent` instruction requires an Ed25519 signature
//! from the *delegator* — the human principal granting the agent its
//! authority — over a canonical delegation payload (see
//! `glyph_verifier::delegation_signing_payload`).
//!
//! This module exposes:
//! - [`delegation_signing_payload`] — pure function reproducing the on-chain
//!   payload byte layout. Available even when `ed25519-dalek`/`solana-sdk`
//!   are not desired.
//! - [`build_register_agent_instructions`] — builds the `(ed25519_ix,
//!   register_agent_ix)` pair the SDK caller adds to a transaction.
//!
//! See `docs/delegation-model.md` for the three-token correspondence with
//! Tobin South's paper.
use ed25519_dalek::{Signer as DalekSigner, SigningKey};
use solana_sdk::ed25519_instruction::new_ed25519_instruction;
use solana_sdk::instruction::Instruction;
use solana_sdk::pubkey::Pubkey;

/// Reproduces the canonical bytes signed by the delegator. Must stay
/// byte-for-byte identical to `glyph_verifier::delegation_signing_payload`
/// on-chain.
pub fn delegation_signing_payload(
    agent_pubkey: &Pubkey,
    policy_commitment: &[u8; 32],
    image_id: &[u32; 8],
    delegation_expiry: i64,
    scope_hash: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20 + 32 + 32 + 32 + 8 + 32);
    buf.extend_from_slice(b"GLYPH:DELEGATION:v1:");
    buf.extend_from_slice(agent_pubkey.as_ref());
    buf.extend_from_slice(policy_commitment);
    for limb in image_id.iter() {
        buf.extend_from_slice(&limb.to_be_bytes());
    }
    buf.extend_from_slice(&delegation_expiry.to_le_bytes());
    buf.extend_from_slice(scope_hash);
    buf
}

/// Inputs needed to build a `register_agent` instruction pair.
pub struct RegisterAgentRequest<'a> {
    pub agent_pubkey: Pubkey,
    pub policy_commitment: [u8; 32],
    pub image_id: [u32; 8],
    pub delegation_expiry: i64,
    /// The delegator's signing key. Stays in-process — used only to sign
    /// the canonical payload, then the public part is included in the
    /// instruction so the on-chain program can match.
    pub delegator_signing_key: &'a SigningKey,
}

/// Output: the Ed25519 precompile instruction (must be sibling to the
/// `register_agent` instruction in the same transaction) and the canonical
/// payload bytes (useful if the caller wants to attach them to the program
/// instruction's data).
pub struct RegisterAgentInstructions {
    pub ed25519_ix: Instruction,
    pub payload: Vec<u8>,
    pub delegator_pubkey: [u8; 32],
    pub delegator_signature: [u8; 64],
}

/// Build the Ed25519 precompile instruction that authorizes the agent
/// registration. The caller is responsible for assembling the actual
/// `glyph_verifier::register_agent` instruction (the SDK does not depend on
/// `glyph_verifier`'s Anchor types directly to keep the dependency surface
/// small).
pub fn build_register_agent_instructions(
    req: RegisterAgentRequest<'_>,
) -> RegisterAgentInstructions {
    let scope_hash = [0u8; 32];
    let payload = delegation_signing_payload(
        &req.agent_pubkey,
        &req.policy_commitment,
        &req.image_id,
        req.delegation_expiry,
        &scope_hash,
    );

    let signature = req.delegator_signing_key.sign(&payload);
    let delegator_pubkey = req
        .delegator_signing_key
        .verifying_key()
        .to_bytes();

    // `new_ed25519_instruction` constructs a precompile instruction with the
    // (pubkey, signature, message) layout expected by the on-chain
    // `verify_ed25519_precompile` helper.
    let ed25519_ix = new_ed25519_instruction(req.delegator_signing_key, &payload);

    RegisterAgentInstructions {
        ed25519_ix,
        payload,
        delegator_pubkey,
        delegator_signature: signature.to_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;

    #[test]
    fn payload_layout_is_stable() {
        let agent = Pubkey::new_from_array([1u8; 32]);
        let pc = [2u8; 32];
        let image_id = [0u32; 8];
        let expiry = 1_700_000_500i64;
        let scope = [0u8; 32];
        let p1 = delegation_signing_payload(&agent, &pc, &image_id, expiry, &scope);
        let p2 = delegation_signing_payload(&agent, &pc, &image_id, expiry, &scope);
        assert_eq!(p1, p2);
        // 20 + 32 + 32 + 32 + 8 + 32 = 156 bytes
        assert_eq!(p1.len(), 156);
        assert_eq!(&p1[..20], b"GLYPH:DELEGATION:v1:");
    }

    #[test]
    fn signature_round_trips() {
        let key = SigningKey::generate(&mut OsRng);
        let req = RegisterAgentRequest {
            agent_pubkey: Pubkey::new_from_array([7u8; 32]),
            policy_commitment: [9u8; 32],
            image_id: [0u32; 8],
            delegation_expiry: 9_999_999_999,
            delegator_signing_key: &key,
        };
        let out = build_register_agent_instructions(req);
        assert_eq!(out.payload.len(), 156);
        assert_eq!(out.delegator_pubkey, key.verifying_key().to_bytes());

        // Verify the signature with dalek to confirm we signed the right bytes.
        use ed25519_dalek::{Verifier, VerifyingKey, Signature};
        let vk = VerifyingKey::from_bytes(&out.delegator_pubkey).unwrap();
        let sig = Signature::from_bytes(&out.delegator_signature);
        vk.verify(&out.payload, &sig).unwrap();
    }
}
