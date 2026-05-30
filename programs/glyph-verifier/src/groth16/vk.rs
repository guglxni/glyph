//! RISC Zero BN254 Groth16 Verification Key for the GLYPH circuit.
//!
//! ═══════════════════════════════════════════════════════════════════════════════
//! WS-2 (F-1, F-9, F-24, F-25, F-30) — VK lifecycle
//! ═══════════════════════════════════════════════════════════════════════════════
//!
//! The Groth16 VK is **no longer a `pub const`** consumed directly by the
//! verifier. Instead, the canonical VK lives in a PDA (`VerifierVk`, see
//! `crate::lib`) so it can be rotated under multisig + timelock governance
//! without an Anchor program upgrade. Closes F-9.
//!
//! Two compile-time constants survive in this file:
//!
//! 1. `GLYPH_VK_PLACEHOLDER` — the historical hand-rolled DEV VK with off-curve
//!    points (kept *only* as a known-bad fixture for the safety test in
//!    `tests/vk_safety.rs`). It MUST never be installed in a `VerifierVk`
//!    account on a live cluster — the on-curve checks in
//!    `groth16::verifier::validate_g1` will reject it at verify time, and the
//!    safety test makes "ship the placeholder" a build-time failure.
//!
//! 2. `GLYPH_VK_REAL: Option<&Groth16VerifyingKey>` — `Some(_)` only after the
//!    real VK has been baked in by `scripts/extract-vk` running against a real
//!    RISC Zero proof. When `Some`, the operator can call `seed_vk` once at
//!    bootstrap to populate the `VerifierVk` PDA without going through the
//!    multisig flow. After that, the multisig+timelock is the **only** path to
//!    rotate the VK. Closes F-1, F-24, F-25.
//!
//! The ASCII-tagged `GLYPH_IMAGE_ID` (`HTOR_DEV_...`) has been removed
//! (closes F-30). The image_id is now a runtime field on `VerifierVk` and is
//! pinned per-agent on `AgentRegistry.image_id`.
//!
//! ## VK Wire Format (RISC Zero BN254 Groth16)
//! - alpha_g1: G1 point (alpha) — 64 bytes
//! - beta_g2:  G2 point (beta)  — 128 bytes
//! - gamma_g2: G2 point (gamma) — 128 bytes
//! - delta_g2: G2 point (delta) — 128 bytes
//! - ic[0..=5]: 6 × G1 (1 constant + 5 per-input)   — 6 × 64 bytes
//! - control_root:     [u8; 32] (RISC Zero `Groth16ReceiptVerifierParameters.control_root`)
//! - bn254_control_id: [u8; 32] (RISC Zero `Groth16ReceiptVerifierParameters.bn254_control_id`)
//!
//! All field elements are big-endian, matching Solana's `alt_bn128` syscall
//! convention (G2 layout: x.c1 || x.c0 || y.c1 || y.c0).
//!
//! ## RISC Zero 5-public-input layout (correctness fix)
//!
//! A RISC Zero Groth16 receipt carries **5** public inputs into the Groth16
//! verifier, not 1. The on-chain verifier must therefore evaluate
//!
//! ```text
//!     vk_x = IC[0] + s0*IC[1] + s1*IC[2] + s2*IC[3] + s3*IC[4] + s4*IC[5]
//! ```
//!
//! where `(s0, s1, s2, s3, s4) = (a0, a1, c0, c1, id_bn254_fr)` derived per
//! `risc0_zkvm/src/receipt/groth16.rs` (1.2.6) — see `docs/zk-references.md`
//! and the `split_digest_be` / `bn254_control_id_to_fr` helpers in
//! `groth16::verifier`.

use anchor_lang::prelude::*;

// ═══════════════════════════════════════════════════════════════════════════════
// Compile-time VK type (used by the verifier and by the PDA)
// ═══════════════════════════════════════════════════════════════════════════════

/// In-memory Groth16 VK shape used by `groth16::verifier::verify_groth16`.
///
/// We keep this as a borrowed-friendly POD struct so the verifier can take a
/// `&Groth16VerifyingKey` regardless of whether the bytes came from the
/// historical const, the real-VK const, or the on-chain `VerifierVk` PDA.
///
/// `ic` has **6** entries: `IC[0]` is the constant term and `IC[1..=5]` map to
/// the five RISC Zero public inputs `(a0, a1, c0, c1, id_bn254_fr)`.
///
/// `control_root` and `bn254_control_id` are the
/// `Groth16ReceiptVerifierParameters` values that the host needs to derive the
/// 5 public-input scalars from the agent's image_id + journal at verify time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Groth16VerifyingKey {
    pub alpha_g1: [u8; 64],
    pub beta_g2: [u8; 128],
    pub gamma_g2: [u8; 128],
    pub delta_g2: [u8; 128],
    /// 1 + 5 IC entries (constant + per-public-input).
    pub ic: [[u8; 64]; 6],
    /// RISC Zero `Groth16ReceiptVerifierParameters::control_root` — 32-byte
    /// digest (BE) used to derive (a0, a1) via `split_digest_be`.
    pub control_root: [u8; 32],
    /// RISC Zero `Groth16ReceiptVerifierParameters::bn254_control_id` — 32-byte
    /// digest (BE) used to derive `id_bn254_fr` via `bn254_control_id_to_fr`.
    pub bn254_control_id: [u8; 32],
}

/// Backwards-compatible alias for the legacy name. New code should prefer
/// `Groth16VerifyingKey`.
pub type VerifyingKey = Groth16VerifyingKey;

// ═══════════════════════════════════════════════════════════════════════════════
// PLACEHOLDER VK — DEV ONLY, KNOWN-BAD POINTS
// ═══════════════════════════════════════════════════════════════════════════════
//
// ⚠️  CRITICAL SECURITY WARNING ⚠️
//
// Every G1/G2 point below is intentionally off the BN254 curve. This constant
// exists ONLY so that:
//   * legacy callers compile during the migration window;
//   * the safety test in `tests/vk_safety.rs` can assert that `validate_g1`
//     rejects it (so any regression that re-introduces the placeholder into
//     the live verify path fails CI immediately).
//
// If you are reading this in a deployment context: the on-chain `VerifierVk`
// PDA must hold a REAL VK. The placeholder must NEVER be `seed_vk`'d.
// ═══════════════════════════════════════════════════════════════════════════════

const PLACEHOLDER_IC_ENTRY: [u8; 64] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
];

/// Hand-rolled "DEV" VK with off-curve points. Used only by the safety test.
pub const GLYPH_VK_PLACEHOLDER: Groth16VerifyingKey = Groth16VerifyingKey {
    // (0, 2): off-curve (4 != 0 + 3 mod p)
    alpha_g1: [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    ],

    beta_g2: [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    ],

    gamma_g2: [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ],

    delta_g2: [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ],

    ic: [
        PLACEHOLDER_IC_ENTRY,
        PLACEHOLDER_IC_ENTRY,
        PLACEHOLDER_IC_ENTRY,
        PLACEHOLDER_IC_ENTRY,
        PLACEHOLDER_IC_ENTRY,
        PLACEHOLDER_IC_ENTRY,
    ],

    control_root: [0u8; 32],
    bn254_control_id: [0u8; 32],
};

// ═══════════════════════════════════════════════════════════════════════════════
// REAL VK — populated by scripts/extract-vk after a real RISC Zero proof
// ═══════════════════════════════════════════════════════════════════════════════
//
// `extract-vk` writes a sibling file `vk_real.rs` exporting
// `pub const GLYPH_VK_REAL_INNER: Groth16VerifyingKey = …;` plus the
// SHA-256 of the bytes as a banner comment. We `cfg`-include it when present;
// otherwise `GLYPH_VK_REAL` stays `None` and the on-chain verifier refuses to
// initialize without going through the multisig flow.
//
// NOTE: The include path is gated on the file's existence at build time. The
// real-VK file is intentionally **not** committed until extraction runs
// against the real prover output.

#[cfg(feature = "real-vk")]
#[path = "vk_real.rs"]
mod vk_real;

/// `Some(&vk)` once a real VK has been extracted via `scripts/extract-vk` and
/// the `real-vk` feature is enabled. `None` in default builds — the verifier
/// must be bootstrapped via the multisig + timelock flow instead.
#[cfg(feature = "real-vk")]
pub const GLYPH_VK_REAL: Option<&'static Groth16VerifyingKey> = Some(&vk_real::GLYPH_VK_REAL_INNER);

#[cfg(not(feature = "real-vk"))]
pub const GLYPH_VK_REAL: Option<&'static Groth16VerifyingKey> = None;

// ═══════════════════════════════════════════════════════════════════════════════
// VerifierVk PDA — runtime-mutable VK store
// ═══════════════════════════════════════════════════════════════════════════════

/// On-chain Groth16 verification key, stored in a singleton PDA at seeds
/// `[b"verifier_vk"]`.
///
/// The verifier loads the VK from this account at every `verify_and_execute`
/// call. Updates are gated by `VkMultisig` + a 24-hour timelock.
#[account]
pub struct VerifierVk {
    /// G1 alpha (64 bytes).
    pub alpha_g1: [u8; 64],
    /// G2 beta (128 bytes).
    pub beta_g2: [u8; 128],
    /// G2 gamma (128 bytes).
    pub gamma_g2: [u8; 128],
    /// G2 delta (128 bytes).
    pub delta_g2: [u8; 128],
    /// 6 × G1 IC entries (constant + 5 per-public-input).
    pub ic: [[u8; 64]; 6],
    /// RISC Zero `Groth16ReceiptVerifierParameters.control_root` (BE digest).
    pub control_root: [u8; 32],
    /// RISC Zero `Groth16ReceiptVerifierParameters.bn254_control_id` (BE digest).
    pub bn254_control_id: [u8; 32],
    /// SHA-256 hash of the serialized VK bytes (alpha || beta || gamma ||
    /// delta || ic[0..6] || control_root || bn254_control_id). Convenience
    /// for off-chain integrity checks.
    pub vk_hash: [u8; 32],
    /// RISC Zero circuit image_id this VK was extracted for.
    pub image_id: [u32; 8],
    /// Free-form prover-version string (e.g. `"risc0-zkvm 1.2.6"`). Bounded
    /// to 64 bytes via the size constant below.
    pub prover_version: String,
    /// PDA bump.
    pub bump: u8,
}

impl VerifierVk {
    pub const SEED_PREFIX: &'static [u8] = b"verifier_vk";
    /// Maximum prover_version string length (incl. 4-byte borsh length prefix).
    pub const MAX_PROVER_VERSION_LEN: usize = 64;
    /// Account size budget. discriminator (8) + alpha (64) + beta (128) +
    /// gamma (128) + delta (128) + ic (6 * 64) + control_root (32) +
    /// bn254_control_id (32) + vk_hash (32) + image_id (32) +
    /// (4-byte borsh String len + 64 chars) + bump (1).
    pub const SIZE: usize =
        8 + 64 + 128 + 128 + 128 + (6 * 64) + 32 + 32 + 32 + 32 + (4 + Self::MAX_PROVER_VERSION_LEN) + 1;
}

/// Inner VK payload used by the `propose_vk_update` instruction. Mirrors
/// `Groth16VerifyingKey` but is `AnchorSerialize`/`AnchorDeserialize` so it
/// can travel over the wire as instruction args.
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct VerifierVkInner {
    pub alpha_g1: [u8; 64],
    pub beta_g2: [u8; 128],
    pub gamma_g2: [u8; 128],
    pub delta_g2: [u8; 128],
    pub ic: [[u8; 64]; 6],
    pub control_root: [u8; 32],
    pub bn254_control_id: [u8; 32],
    pub prover_version: String,
}

impl VerifierVkInner {
    /// Compute SHA-256 over the canonical concatenation of VK bytes.
    pub fn compute_hash(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(self.alpha_g1);
        h.update(self.beta_g2);
        h.update(self.gamma_g2);
        h.update(self.delta_g2);
        for entry in &self.ic {
            h.update(entry);
        }
        h.update(self.control_root);
        h.update(self.bn254_control_id);
        h.finalize().into()
    }
}

/// Read-only view: copy out a `Groth16VerifyingKey` from the PDA. The verifier
/// uses this every call so it can pass `&Groth16VerifyingKey` to the existing
/// pairing code without holding a borrow on the Anchor `Account` across the
/// syscall.
pub fn read_vk(verifier_vk: &VerifierVk) -> Groth16VerifyingKey {
    Groth16VerifyingKey {
        alpha_g1: verifier_vk.alpha_g1,
        beta_g2: verifier_vk.beta_g2,
        gamma_g2: verifier_vk.gamma_g2,
        delta_g2: verifier_vk.delta_g2,
        ic: verifier_vk.ic,
        control_root: verifier_vk.control_root,
        bn254_control_id: verifier_vk.bn254_control_id,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// VkMultisig PDA — governance over VK rotations
// ═══════════════════════════════════════════════════════════════════════════════

/// Maximum number of multisig signers (fixed-size for predictable account
/// layout). Choose 5 to allow a 2-of-3 or 3-of-5 quorum without account
/// resizing.
pub const VK_MULTISIG_MAX_SIGNERS: usize = 5;

/// Maximum approvals tracked on a pending update. Capped at the signer set
/// size so the borsh layout is bounded.
pub const VK_MULTISIG_MAX_APPROVALS: usize = VK_MULTISIG_MAX_SIGNERS;

/// 24-hour timelock between `propose_vk_update` and `execute_vk_update`.
pub const VK_TIMELOCK_SECONDS: i64 = 24 * 60 * 60;

/// A pending VK rotation. Cleared on `execute_vk_update` (success) or
/// `cancel_vk_update` (out of scope here — operators redeploy multisig if a
/// proposal must be aborted before timelock).
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct PendingVkUpdate {
    /// SHA-256 of the proposed VK bytes (used to bind approvals to a specific
    /// candidate; signers approve a hash, not the live `pending_update.vk`).
    pub new_vk_hash: [u8; 32],
    /// Image_id to install with the new VK.
    pub new_image_id: [u32; 8],
    /// Unix timestamp at which the proposal was made.
    pub proposed_at: i64,
    /// Multisig signers that have approved this hash. The proposer is
    /// implicitly the first approver.
    pub approved_signers: Vec<Pubkey>,
    /// Full proposed VK bytes — kept inline so `execute_vk_update` does not
    /// need to re-receive them and risk a TOCTOU between approval and exec.
    pub vk: VerifierVkInner,
}

/// Multisig governance account for VK rotations. Singleton at seeds
/// `[b"vk_multisig"]`.
#[account]
pub struct VkMultisig {
    /// Authorized signers (zero-padded; only the first `signer_count` entries
    /// are live).
    pub signers: [Pubkey; VK_MULTISIG_MAX_SIGNERS],
    /// Number of live signer entries (≤ `VK_MULTISIG_MAX_SIGNERS`).
    pub signer_count: u8,
    /// Number of approvals required to execute a pending update.
    pub threshold: u8,
    /// Optional in-flight proposal.
    pub pending_update: Option<PendingVkUpdate>,
    /// PDA bump.
    pub bump: u8,
}

impl VkMultisig {
    pub const SEED_PREFIX: &'static [u8] = b"vk_multisig";

    /// Conservative size budget. discriminator (8) + signers (32 * 5) +
    /// signer_count (1) + threshold (1) + Option<PendingVkUpdate> (1 tag +
    /// 32 vk_hash + 32 image_id + 8 proposed_at + (4 + 32 * 5) approvals +
    /// VerifierVkInner: alpha(64) + beta(128) + gamma(128) + delta(128) +
    /// ic(6 * 64) + control_root(32) + bn254_control_id(32) +
    /// (4 + 64 prover_ver)) + bump (1).
    pub const SIZE: usize = 8
        + 32 * VK_MULTISIG_MAX_SIGNERS
        + 1
        + 1
        + 1
        + 32
        + 32
        + 8
        + (4 + 32 * VK_MULTISIG_MAX_APPROVALS)
        + 64
        + 128
        + 128
        + 128
        + (6 * 64)
        + 32
        + 32
        + (4 + VerifierVk::MAX_PROVER_VERSION_LEN)
        + 1;

    /// Returns true iff `signer` is one of the live multisig signers.
    pub fn contains(&self, signer: &Pubkey) -> bool {
        self.signers
            .iter()
            .take(self.signer_count as usize)
            .any(|s| s == signer)
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Compatibility helpers (deprecated path — prefer the PDA)
// ═══════════════════════════════════════════════════════════════════════════════

/// Returns the placeholder image_id (all zero). Operators should pin their
/// per-agent image_id from the proof's journal instead.
///
/// Retained for downstream call sites that expected a free function. Prefer
/// reading `VerifierVk.image_id` from the PDA in new code.
pub fn get_image_id() -> [u32; 8] {
    [0u32; 8]
}

/// Stub kept for source-compat with the old VK-integrity check. Returns
/// `false` unconditionally because there is no longer a hardcoded VK to
/// integrity-check against — the source of truth is the on-chain PDA.
///
/// Callers should instead validate the PDA's `vk_hash` field against an
/// off-chain expected value when bootstrapping.
pub fn verify_vk_integrity() -> bool {
    false
}
