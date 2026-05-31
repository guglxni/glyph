//! Extract the Groth16 Verification Key from the RISC Zero GLYPH circuit.
//!
//! Closes F-24 / F-25.
//!
//! ## Usage
//!
//! ```bash
//! # Real extraction (requires the RISC Zero toolchain + a real proof):
//! cargo run -p extract-vk --features risc0 -- \
//!     --out programs/glyph-verifier/src/groth16/vk_real.rs
//!
//! # Deliberately invalid stub (NEVER commit the output):
//! cargo run -p extract-vk -- \
//!     --out /tmp/vk_real_invalid.rs
//! ```
//!
//! The output is a Rust source file pinned at
//! `programs/glyph-verifier/src/groth16/vk_real.rs`. Enable the verifier's
//! `real-vk` cargo feature so it links the file and exposes
//! `GLYPH_VK_REAL = Some(_)`.
//!
//! ## Real path (`--features risc0`)
//!
//! 1. Load `risc0_zkvm::Groth16ReceiptVerifierParameters::default()` so we can
//!    capture both the BN254 Groth16 verifying key **and** the auxiliary
//!    `control_root` + `bn254_control_id` digests. The latter two are needed
//!    on-chain to derive the 5 Groth16 public-input scalars
//!    `(a0, a1, c0, c1, id_bn254_fr)` from any concrete (image_id, journal).
//! 2. Pull the VK bytes out of the wrapper via
//!    `VerifyingKey::ark_verifying_key()`.
//! 3. Serialize each affine point in Solana's alt_bn128 big-endian layout
//!    (alpha_g1 64 || beta_g2 128 || gamma_g2 128 || delta_g2 128 ||
//!    ic[0..=5] each 64) plus the two 32-byte digest fields, and write the
//!    file.
//!
//! ## Stub path (no `risc0` feature)
//!
//! Emits a VK whose every byte is `0xFF`. This is **deliberately invalid** —
//! `0xFF * 32` is greater than the BN254 base prime `p`, so the verifier's
//! `validate_g1` / `validate_g2` reject it before any pairing math runs. The
//! script prints a loud banner to stderr saying "do not commit"; the test
//! `vk_safety::placeholder_vk_alpha_g1_is_off_curve` and the on-chain
//! `validate_g1` check guarantee a CI failure if anyone ignores the warning.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;

/// On-chain VK payload (mirrors `Groth16VerifyingKey` in the verifier).
#[derive(Debug, Clone)]
pub struct ExtractedVk {
    pub image_id: [u32; 8],
    pub alpha_g1: [u8; 64],
    pub beta_g2: [u8; 128],
    pub gamma_g2: [u8; 128],
    pub delta_g2: [u8; 128],
    /// 6 × G1 IC entries (constant + 5 per-public-input).
    pub ic: [[u8; 64]; 6],
    /// `Groth16ReceiptVerifierParameters.control_root` (32 BE bytes).
    pub control_root: [u8; 32],
    /// `Groth16ReceiptVerifierParameters.bn254_control_id` (32 BE bytes).
    pub bn254_control_id: [u8; 32],
    pub prover_version: String,
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let mut out_path: Option<PathBuf> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" => {
                out_path = Some(PathBuf::from(args.next().context("--out requires a path")?));
            }
            "-h" | "--help" => {
                eprintln!(
                    "Usage: extract-vk --out <path/to/vk_real.rs>\n\
                     Run with --features risc0 to extract a real VK; otherwise a \
                     deliberately-invalid 0xFF VK is written and CI will reject it."
                );
                return Ok(());
            }
            other => bail!("unknown argument: {other}"),
        }
    }
    let out_path =
        out_path.unwrap_or_else(|| PathBuf::from("programs/glyph-verifier/src/groth16/vk_real.rs"));

    let vk = extract_vk()?;
    let source = render_vk_source(&vk)?;

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("creating parent dir for {}", out_path.display()))?;
    }
    fs::write(&out_path, source).with_context(|| format!("writing {}", out_path.display()))?;
    eprintln!(
        "wrote {} (vk_hash={})",
        out_path.display(),
        hex::encode(vk_hash(&vk))
    );
    Ok(())
}

// ─── Real extraction (RISC Zero) ────────────────────────────────────────────

#[cfg(feature = "risc0")]
fn extract_vk() -> Result<ExtractedVk> {
    // Pull the full Groth16ReceiptVerifierParameters so we get the VK *plus*
    // the `control_root` and `bn254_control_id` digests that the on-chain
    // public-input derivation needs. The wrapping Groth16 VK is deterministic
    // and identical across all guests (it proves "this STARK is valid"); the
    // two digest fields are similarly the network-wide RISC Zero parameters
    // for the current prover version. Per-guest identity stays in `image_id`.
    let params = risc0_zkvm::Groth16ReceiptVerifierParameters::default();
    let vk_wrapper = &params.verifying_key;
    let ark_vk = vk_wrapper.ark_verifying_key();
    let vk = serialize_ark_vk(&ark_vk)?;

    // Digest fields: RISC Zero's `Digest` stores its bytes as 8 LE u32 limbs
    // (`as_bytes()` returns the LE wire bytes). We preserve those bytes
    // verbatim into the emitted VK; the on-chain `split_digest_be` /
    // `bn254_control_id_to_fr` helpers handle the reverse-to-BE step the same
    // way `risc0_groth16::split_digest` does.
    let control_root = digest_to_bytes(&params.control_root);
    let bn254_control_id = digest_to_bytes(&params.bn254_control_id);

    let image_id = glyph_circuit_host::GLYPH_CIRCUIT_ID;
    let prover_version = format!("risc0-zkvm {}", risc0_zkvm::VERSION);

    eprintln!(
        "extracted real VK: image_id={:08x}{:08x}.., prover_version={}",
        image_id[0], image_id[1], prover_version
    );
    eprintln!("  ic vector length: {}", ark_vk.gamma_abc_g1.len());
    eprintln!("  control_root      = {}", hex::encode(control_root));
    eprintln!("  bn254_control_id  = {}", hex::encode(bn254_control_id));

    Ok(ExtractedVk {
        image_id,
        alpha_g1: vk.alpha_g1,
        beta_g2: vk.beta_g2,
        gamma_g2: vk.gamma_g2,
        delta_g2: vk.delta_g2,
        ic: vk.ic,
        control_root,
        bn254_control_id,
        prover_version,
    })
}

#[cfg(feature = "risc0")]
struct VkBytes {
    alpha_g1: [u8; 64],
    beta_g2: [u8; 128],
    gamma_g2: [u8; 128],
    delta_g2: [u8; 128],
    ic: [[u8; 64]; 6],
}

#[cfg(feature = "risc0")]
fn digest_to_bytes(d: &risc0_zkvm::sha::Digest) -> [u8; 32] {
    let raw = d.as_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    out
}

/// Convert an Fq element to a 32-byte big-endian array (Solana's alt_bn128 layout).
#[cfg(feature = "risc0")]
fn fq_to_be(x: &ark_bn254::Fq) -> [u8; 32] {
    use ark_ff::{BigInteger, PrimeField};
    let bigint = x.into_bigint();
    let le = bigint.to_bytes_le();
    let mut out = [0u8; 32];
    for (i, &b) in le.iter().take(32).enumerate() {
        out[31 - i] = b;
    }
    out
}

/// Solana alt_bn128 G1 layout: `[x_be: 32 || y_be: 32]`.
#[cfg(feature = "risc0")]
fn g1_to_alt_bn128(p: &ark_bn254::G1Affine) -> Result<[u8; 64]> {
    use ark_ec::AffineRepr;
    if p.is_zero() {
        return Ok([0u8; 64]); // point at infinity
    }
    let (x, y) = p.xy().expect("non-zero G1 point has xy");
    let mut out = [0u8; 64];
    out[0..32].copy_from_slice(&fq_to_be(&x));
    out[32..64].copy_from_slice(&fq_to_be(&y));
    Ok(out)
}

/// Solana alt_bn128 G2 layout: `[x.c1_be || x.c0_be || y.c1_be || y.c0_be]`,
/// each 32 bytes BE.
#[cfg(feature = "risc0")]
fn g2_to_alt_bn128(p: &ark_bn254::G2Affine) -> Result<[u8; 128]> {
    use ark_ec::AffineRepr;
    if p.is_zero() {
        return Ok([0u8; 128]);
    }
    let (x, y) = p.xy().expect("non-zero G2 point has xy");
    let mut out = [0u8; 128];
    out[0..32].copy_from_slice(&fq_to_be(&x.c1));
    out[32..64].copy_from_slice(&fq_to_be(&x.c0));
    out[64..96].copy_from_slice(&fq_to_be(&y.c1));
    out[96..128].copy_from_slice(&fq_to_be(&y.c0));
    Ok(out)
}

#[cfg(feature = "risc0")]
fn serialize_ark_vk(vk: &ark_groth16::VerifyingKey<ark_bn254::Bn254>) -> Result<VkBytes> {
    if vk.gamma_abc_g1.len() < 6 {
        bail!(
            "VK has fewer than 6 IC entries ({}); a RISC Zero v1.2.x Groth16 \
             receipt carries 5 public inputs so IC must have length 6 \
             (1 constant + 5 per-input).",
            vk.gamma_abc_g1.len()
        );
    }
    let mut ic = [[0u8; 64]; 6];
    for (i, entry) in ic.iter_mut().enumerate() {
        *entry = g1_to_alt_bn128(&vk.gamma_abc_g1[i])?;
    }
    Ok(VkBytes {
        alpha_g1: g1_to_alt_bn128(&vk.alpha_g1)?,
        beta_g2: g2_to_alt_bn128(&vk.beta_g2)?,
        gamma_g2: g2_to_alt_bn128(&vk.gamma_g2)?,
        delta_g2: g2_to_alt_bn128(&vk.delta_g2)?,
        ic,
    })
}

// ─── Stub path (no risc0 feature) ───────────────────────────────────────────

#[cfg(not(feature = "risc0"))]
fn extract_vk() -> Result<ExtractedVk> {
    eprintln!();
    eprintln!("════════════════════════════════════════════════════════════════");
    eprintln!("  WARNING: extract-vk built without --features risc0");
    eprintln!("  Emitting a DELIBERATELY INVALID VK (every byte 0xFF).");
    eprintln!("  This file MUST NOT be committed.");
    eprintln!("  The on-chain validate_g1 / validate_g2 checks will reject it,");
    eprintln!("  and the vk_safety integration test will refuse to ship it.");
    eprintln!("════════════════════════════════════════════════════════════════");
    eprintln!();

    Ok(ExtractedVk {
        image_id: [0u32; 8],
        alpha_g1: [0xFFu8; 64],
        beta_g2: [0xFFu8; 128],
        gamma_g2: [0xFFu8; 128],
        delta_g2: [0xFFu8; 128],
        ic: [[0xFFu8; 64]; 6],
        control_root: [0xFFu8; 32],
        bn254_control_id: [0xFFu8; 32],
        prover_version: "INVALID-STUB-DO-NOT-COMMIT".to_string(),
    })
}

// ─── Source rendering ───────────────────────────────────────────────────────

fn render_vk_source(vk: &ExtractedVk) -> Result<String> {
    let mut out = String::new();
    let hash = vk_hash(vk);

    out.push_str("//! AUTO-GENERATED by scripts/extract-vk. Do not edit by hand.\n");
    out.push_str(&format!("//! VK SHA-256: {}\n", hex::encode(hash)));
    out.push_str(&format!(
        "//! image_id (BE u32): {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x} {:08x}\n",
        vk.image_id[0],
        vk.image_id[1],
        vk.image_id[2],
        vk.image_id[3],
        vk.image_id[4],
        vk.image_id[5],
        vk.image_id[6],
        vk.image_id[7],
    ));
    out.push_str(&format!("//! prover_version: {}\n", vk.prover_version));
    out.push_str(&format!(
        "//! control_root:      {}\n",
        hex::encode(vk.control_root)
    ));
    out.push_str(&format!(
        "//! bn254_control_id:  {}\n",
        hex::encode(vk.bn254_control_id)
    ));
    out.push_str("//!\n");
    out.push_str("//! If any byte below is 0xFF, this file was emitted by the no-risc0 stub\n");
    out.push_str("//! path and must NOT be linked into a release build. The verifier's\n");
    out.push_str("//! `validate_g1` will reject it; CI's `vk_safety` test enforces this.\n\n");

    out.push_str("use super::Groth16VerifyingKey;\n\n");
    out.push_str("pub const GLYPH_VK_REAL_INNER: Groth16VerifyingKey = Groth16VerifyingKey {\n");
    out.push_str(&format!(
        "    alpha_g1: {},\n",
        format_byte_array(&vk.alpha_g1)
    ));
    out.push_str(&format!(
        "    beta_g2: {},\n",
        format_byte_array(&vk.beta_g2)
    ));
    out.push_str(&format!(
        "    gamma_g2: {},\n",
        format_byte_array(&vk.gamma_g2)
    ));
    out.push_str(&format!(
        "    delta_g2: {},\n",
        format_byte_array(&vk.delta_g2)
    ));
    out.push_str("    ic: [\n");
    for entry in vk.ic.iter() {
        out.push_str(&format!("        {},\n", format_byte_array(entry)));
    }
    out.push_str("    ],\n");
    out.push_str(&format!(
        "    control_root: {},\n",
        format_byte_array(&vk.control_root)
    ));
    out.push_str(&format!(
        "    bn254_control_id: {},\n",
        format_byte_array(&vk.bn254_control_id)
    ));
    out.push_str("};\n\n");
    out.push_str(&format!(
        "pub const GLYPH_VK_REAL_HASH: [u8; 32] = {};\n",
        format_byte_array(&hash)
    ));
    out.push_str(&format!(
        "pub const GLYPH_VK_REAL_IMAGE_ID: [u32; 8] = {};\n",
        format_u32_array(&vk.image_id)
    ));
    out.push_str(&format!(
        "pub const GLYPH_VK_REAL_PROVER_VERSION: &str = {:?};\n",
        vk.prover_version
    ));
    out.push_str(&format!(
        "pub const GLYPH_VK_REAL_CONTROL_ROOT: [u8; 32] = {};\n",
        format_byte_array(&vk.control_root)
    ));
    out.push_str(&format!(
        "pub const GLYPH_VK_REAL_BN254_CONTROL_ID: [u8; 32] = {};\n",
        format_byte_array(&vk.bn254_control_id)
    ));

    Ok(out)
}

fn vk_hash(vk: &ExtractedVk) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(vk.alpha_g1);
    h.update(vk.beta_g2);
    h.update(vk.gamma_g2);
    h.update(vk.delta_g2);
    for entry in vk.ic.iter() {
        h.update(entry);
    }
    h.update(vk.control_root);
    h.update(vk.bn254_control_id);
    h.finalize().into()
}

fn format_byte_array(bytes: &[u8]) -> String {
    let mut s = String::from("[\n");
    for chunk in bytes.chunks(8) {
        s.push_str("        ");
        for b in chunk {
            s.push_str(&format!("0x{:02x}, ", b));
        }
        s.push('\n');
    }
    s.push_str("    ]");
    s
}

fn format_u32_array(words: &[u32; 8]) -> String {
    let mut s = String::from("[");
    for (i, w) in words.iter().enumerate() {
        if i > 0 {
            s.push_str(", ");
        }
        s.push_str(&format!("0x{:08x}", w));
    }
    s.push(']');
    s
}
