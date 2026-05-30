//! BN254 G2 subgroup check (off-chain pre-bundle validation).
//!
//! ## Why this lives off-chain
//!
//! Solana 1.18.x's `alt_bn128` syscalls only expose **G1** addition and
//! multiplication — there is no G2 scalar-multiplication primitive. The naive
//! `r·P == identity` subgroup check on G2 would require ≈ 2.9M CU of pure-Rust
//! Fp2 arithmetic, which exceeds the per-transaction compute budget.
//!
//! The production posture is therefore:
//!
//! 1. **On-chain** (Solana program): on-curve check via the Fp2 twist
//!    equation `y² = x³ + 3/(9+u)`. Range checks per coordinate. This catches
//!    points that are off-curve or have out-of-range coordinates.
//!    See `programs/glyph-verifier/src/groth16/verifier.rs::validate_g2`.
//!
//! 2. **Off-chain (this module)**: full subgroup membership check
//!    `r·P == identity` performed inside the TEE worker before the proof
//!    bundle is emitted to the SDK / on-chain. A worker that detects an
//!    off-subgroup G2 point refuses to ship the bundle, returning an
//!    explicit error.
//!
//! 3. **Off-chain (SDK)**: defence-in-depth — the SDK re-runs the same check
//!    before signing the submission transaction. A malicious worker that
//!    bypassed step (2) is still caught at the client boundary.
//!
//! ## Trust model
//!
//! The on-chain verifier trusts that *any* bundle that reaches it has had
//! step (2) or step (3) performed. The combination of TEE attestation +
//! mTLS-fronted intake + this check inside the TEE means an attacker who
//! wants to inject an off-subgroup G2 must compromise either the SDK
//! signing key or the TEE (both protected by separate trust roots).
//!
//! ## Closes
//!
//! `audit/AUDIT_ZK.md` F-4 (G2 slice). Documented in
//! `docs/zk-references.md` after this module landed.

use anyhow::{anyhow, Result};
use ark_bn254::{Fq, Fq2, G2Affine};
use ark_ec::AffineRepr;
use ark_ff::PrimeField;

/// Encoded G2 point as it appears in the proof bundle: 128 bytes laid out
/// `[x.c1 || x.c0 || y.c1 || y.c0]` in **big-endian**, matching Solana's
/// `alt_bn128` syscall convention.
pub type G2Bytes = [u8; 128];

/// Decode a 128-byte big-endian Solana-convention G2 point into an
/// `ark-bn254` `G2Affine` representative.
pub fn decode_g2_solana(bytes: &G2Bytes) -> Result<G2Affine> {
    // All-zero encoding is the identity in Solana convention.
    if bytes.iter().all(|&b| b == 0) {
        return Ok(G2Affine::identity());
    }

    // Arkworks reads field elements as little-endian; Solana stores big-endian.
    let mut x_c1 = bytes[0..32].to_vec();
    let mut x_c0 = bytes[32..64].to_vec();
    let mut y_c1 = bytes[64..96].to_vec();
    let mut y_c0 = bytes[96..128].to_vec();
    x_c1.reverse();
    x_c0.reverse();
    y_c1.reverse();
    y_c0.reverse();

    let x_c0 = Fq::from_le_bytes_mod_order(&x_c0);
    let x_c1 = Fq::from_le_bytes_mod_order(&x_c1);
    let y_c0 = Fq::from_le_bytes_mod_order(&y_c0);
    let y_c1 = Fq::from_le_bytes_mod_order(&y_c1);

    let x = Fq2::new(x_c0, x_c1);
    let y = Fq2::new(y_c0, y_c1);

    let p = G2Affine::new_unchecked(x, y);
    if !p.is_on_curve() {
        return Err(anyhow!("G2 point is not on the curve"));
    }
    Ok(p)
}

/// Verify a G2 point is in the prime-order subgroup of order r.
///
/// Returns `Ok(())` when `r·P == O`, `Err` otherwise.
///
/// Implementation note: `ark-bn254` exposes a constant-time subgroup-check
/// optimisation via `is_in_correct_subgroup_assuming_on_curve()` which uses
/// the Frobenius endomorphism shortcut for BN curves (Bowe 2019). We use
/// that here — it costs ~50 µs per check on modern hardware.
pub fn check_g2_subgroup(bytes: &G2Bytes) -> Result<()> {
    let p = decode_g2_solana(bytes)?;
    if p.is_zero() {
        return Ok(());
    }

    // BN-curve fast subgroup check via Frobenius endomorphism.
    // ark-ec exposes this on `Affine` types via the curve config.
    if !p.is_in_correct_subgroup_assuming_on_curve() {
        return Err(anyhow!("G2 point is not in the prime-order subgroup"));
    }

    Ok(())
}

/// Verify all four G2 points used by the Groth16 verifier:
/// `proof_b`, plus the VK's `beta_g2`, `gamma_g2`, `delta_g2`.
///
/// Called inside the TEE worker immediately after `prover.generate_proof()`
/// returns, before the bundle is sealed and emitted.
pub fn check_bundle_g2(
    proof_b: &G2Bytes,
    vk_beta_g2: &G2Bytes,
    vk_gamma_g2: &G2Bytes,
    vk_delta_g2: &G2Bytes,
) -> Result<()> {
    check_g2_subgroup(proof_b).map_err(|e| anyhow!("proof_b: {e}"))?;
    check_g2_subgroup(vk_beta_g2).map_err(|e| anyhow!("vk.beta_g2: {e}"))?;
    check_g2_subgroup(vk_gamma_g2).map_err(|e| anyhow!("vk.gamma_g2: {e}"))?;
    check_g2_subgroup(vk_delta_g2).map_err(|e| anyhow!("vk.delta_g2: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::G2Projective;
    use ark_ec::CurveGroup;
    use ark_ff::{BigInteger, UniformRand};
    use rand::SeedableRng;
    use rand::rngs::StdRng;

    /// Helper: encode an `ark-bn254` G2 point into Solana's 128-byte big-endian layout.
    fn encode_g2_solana(p: &G2Affine) -> G2Bytes {
        let mut out = [0u8; 128];
        if p.is_zero() {
            return out;
        }
        let (x, y) = p.xy().unwrap();

        for (idx, fq) in [&x.c1, &x.c0, &y.c1, &y.c0].iter().enumerate() {
            let le = fq.into_bigint().to_bytes_le();
            let mut be = [0u8; 32];
            for (i, &b) in le.iter().take(32).enumerate() {
                be[31 - i] = b;
            }
            out[idx * 32..(idx + 1) * 32].copy_from_slice(&be);
        }
        out
    }

    #[test]
    fn identity_passes() {
        let zero = [0u8; 128];
        check_g2_subgroup(&zero).expect("identity is in every subgroup");
    }

    #[test]
    fn random_subgroup_point_passes() {
        let mut rng = StdRng::seed_from_u64(42);
        for _ in 0..5 {
            let p = G2Projective::rand(&mut rng).into_affine();
            let bytes = encode_g2_solana(&p);
            check_g2_subgroup(&bytes).expect("rand G2 generator-mul point passes");
        }
    }

    #[test]
    fn off_curve_point_rejected() {
        // Arbitrary (x, y) that almost certainly isn't on the BN254 G2 twist.
        // Pick x = 1, y = 1 in both coords.
        let mut bytes = [0u8; 128];
        bytes[31] = 1; // x.c1 LSB
        bytes[63] = 1; // x.c0 LSB
        bytes[95] = 1; // y.c1 LSB
        bytes[127] = 1; // y.c0 LSB
        assert!(check_g2_subgroup(&bytes).is_err());
    }
}
