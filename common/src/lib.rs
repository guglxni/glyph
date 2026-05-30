//! GLYPH canonical types and serialization — SINGLE SOURCE OF TRUTH.
//!
//! This crate is consumed by:
//!   * `glyph-tee-worker` — to evaluate intents, build canonical signing payloads,
//!     and compute tx_hash.
//!   * `glyph-circuit-{host,guest}` — to compute commitments inside the ZK circuit.
//!   * `glyph-verifier` (Solana BPF program) — to recompute the canonical
//!     instruction hash on-chain when binding the proof to the next instruction.
//!   * `glyph-sdk` (Rust) and downstream TS SDK (via test vectors).
//!
//! All canonical encodings here are length-prefixed, fixed-order, little-endian.
//! No JSON, no Borsh-derive on the wire — we hand-roll the byte layout so it
//! is reproducible byte-for-byte across every language and target.

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ═══════════════════════════════════════════════════════════════════════════════
// Policy types
// ═══════════════════════════════════════════════════════════════════════════════

/// Canonical policy definition — the SINGLE SOURCE OF TRUTH.
/// Used by TEE worker for evaluation, ZK circuit for commitment verification,
/// and on-chain program for commitment storage.
///
/// The SHA-256 of canonical_serialize_policy(policy) is stored on-chain as policy_commitment.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct Policy {
    pub version: u32,
    /// Maximum lamports allowed per single transaction
    pub max_lamports_per_tx: u64,
    /// Allowed program IDs (as 32-byte pubkeys). Empty = allow all.
    pub allowed_programs: Vec<[u8; 32]>,
    /// Time window restriction (UTC hours). None = no restriction.
    pub time_window: Option<TimeWindow>,
    /// Maximum total lamports per UTC day
    pub max_daily_volume_lamports: u64,
    /// Maximum slippage in basis points. None = no slippage check.
    pub max_slippage_bps: Option<u16>,
    /// Allowed token mint addresses. None = no token restriction.
    pub allowed_token_mints: Option<Vec<[u8; 32]>>,
    /// Maximum accounts per transaction. None = no limit.
    pub max_accounts_per_tx: Option<u16>,
    /// Whether at least one signer must be present in account list.
    /// (Renamed from `require_signer` — old TOML key still accepted via serde alias.)
    #[serde(alias = "require_signer")]
    pub require_signer_present: bool,
    /// Policy expiry timestamp (unix seconds). 0 = no expiry.
    pub expires_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct TimeWindow {
    pub start_hour_utc: u8,
    pub end_hour_utc: u8,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Intent types (compact, for circuit)
// ═══════════════════════════════════════════════════════════════════════════════

/// Compact intent representation used for deterministic hashing inside the circuit.
/// The worker converts wire-format `TransactionIntent` into this before hashing.
/// The circuit receives this directly.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct IntentPayload {
    pub agent_pubkey: [u8; 32],
    pub nonce: [u8; 32],
    pub target_program: [u8; 32],
    pub max_lamports: u64,
    pub max_slippage_bps: Option<u16>,
    pub num_accounts: u16,
    pub expiry: u64,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Canonical instruction account meta (for tx_hash binding)
// ═══════════════════════════════════════════════════════════════════════════════

/// Canonical account metadata used in the transaction-binding hash.
///
/// The SDK (string-based) and the worker (typed) both project into this shape
/// before calling `canonical_target_instruction_bytes`. The on-chain verifier
/// reconstructs the same bytes from the next instruction in the transaction.
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct CanonicalAccountMeta {
    pub pubkey: [u8; 32],
    pub is_signer: bool,
    pub is_writable: bool,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Canonical signing payload (the bytes the agent signs over)
// ═══════════════════════════════════════════════════════════════════════════════

/// The full intent + binding context that the agent's Ed25519 key signs over.
///
/// This is the SINGLE SOURCE OF TRUTH for the SDK ↔ worker signing handshake.
/// The SDK constructs one of these, calls `canonical_signing_payload`, signs
/// the resulting bytes, and ships the wire-format `TransactionIntent`. The
/// worker reconstructs the same `CanonicalIntent` and reverifies.
///
/// `policy_commitment`, `worker_pubkey`, and `epoch` are bound into the
/// signature so a delegation cannot be replayed across policy/epoch/worker
/// boundaries (closes AUDIT_TEE T10).
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub struct CanonicalIntent {
    pub agent_pubkey: [u8; 32],
    pub nonce: [u8; 32],
    pub target_program: [u8; 32],
    pub accounts: Vec<CanonicalAccountMeta>,
    pub data: Vec<u8>,
    pub max_lamports: u64,
    pub max_slippage_bps: Option<u16>,
    pub allowed_tokens: Option<Vec<[u8; 32]>>,
    pub expiry: u64,
    pub timestamp: u64,
    pub policy_commitment: [u8; 32],
    pub worker_pubkey: Option<[u8; 32]>,
    pub epoch: u64,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Public outputs (circuit journal)
// ═══════════════════════════════════════════════════════════════════════════════

/// Granular per-rule failure codes set by the guest circuit. Closes F-33.
///
/// The guest no longer aborts on a rule failure — it sets `failure_code` to a
/// non-zero value, commits `PublicOutputs`, and the on-chain verifier rejects
/// based on the code (so failure modes are diagnosable rather than indistinct
/// `panic!`s).
#[repr(u8)]
#[derive(Clone, Copy, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub enum CircuitFailureCode {
    None = 0,
    MaxLamportsExceeded = 1,
    ProgramNotAllowed = 2,
    OutsideTimeWindow = 3,
    DailyVolumeExceeded = 4,
    SlippageExceeded = 5,
    TokenMintNotAllowed = 6,
    TooManyAccounts = 7,
    NoSignerPresent = 8,
    ExpiryExceeded = 9,
    InvalidPolicyCommitment = 10,
    InvalidIntentSignature = 11,
}

impl Default for CircuitFailureCode {
    fn default() -> Self {
        Self::None
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Circuit-rule bitmap (closes F-23)
// ═══════════════════════════════════════════════════════════════════════════════
//
// The guest sets a bit in `circuit_rule_bitmap` for every rule it actually
// enforced. The on-chain verifier rejects proofs whose bitmap is missing any
// rule from the configured `RULE_REQUIRED_BITMAP`. This makes "circuit-out"
// rules visible to the verifier and prevents a compromised worker from
// silently downgrading.

pub const RULE_BIT_MAX_LAMPORTS: u32          = 1 << 0;
pub const RULE_BIT_ALLOWED_PROGRAMS: u32      = 1 << 1;
pub const RULE_BIT_TIME_WINDOW: u32           = 1 << 2;
pub const RULE_BIT_DAILY_VOLUME: u32          = 1 << 3;
pub const RULE_BIT_SLIPPAGE: u32              = 1 << 4;
pub const RULE_BIT_ALLOWED_TOKEN_MINTS: u32   = 1 << 5;
pub const RULE_BIT_MAX_ACCOUNTS: u32          = 1 << 6;
pub const RULE_BIT_REQUIRE_SIGNER: u32        = 1 << 7;
pub const RULE_BIT_POLICY_EXPIRY: u32         = 1 << 8;

/// Default required bitmap: all 8 stateless rules + `time_window`,
/// `daily_volume`, `allowed_token_mints` (the previously TEE-side rules now
/// in-circuit). The on-chain verifier compares
/// `(public_outputs.circuit_rule_bitmap & RULE_REQUIRED_BITMAP) ==
///  RULE_REQUIRED_BITMAP` and rejects on mismatch.
pub const RULE_REQUIRED_BITMAP: u32 =
      RULE_BIT_MAX_LAMPORTS
    | RULE_BIT_ALLOWED_PROGRAMS
    | RULE_BIT_TIME_WINDOW
    | RULE_BIT_DAILY_VOLUME
    | RULE_BIT_SLIPPAGE
    | RULE_BIT_ALLOWED_TOKEN_MINTS
    | RULE_BIT_MAX_ACCOUNTS
    | RULE_BIT_REQUIRE_SIGNER
    | RULE_BIT_POLICY_EXPIRY;

/// Maximum drift between `attested_timestamp` (TEE-attested) and the on-chain
/// `Clock::unix_timestamp` that the verifier accepts. ±5 minutes.
pub const ATTESTED_TIMESTAMP_MAX_DRIFT_SECS: i64 = 300;

/// Number of seconds in a UTC day. Used to derive `daily_bucket_id`.
pub const SECONDS_PER_DAY: u64 = 86_400;

/// Public outputs committed by the ZK circuit.
///
/// Beyond the original 5 hashes, the journal carries:
/// - `expiry` and `image_id` so the on-chain verifier can enforce them
///   without trusting the caller (closes F-8, F-18, F-22).
/// - `attested_timestamp` and `daily_bucket_id` so `time_window` and
///   `daily_volume` (formerly TEE-side rules) are bound by the proof
///   (closes F-23 partial).
/// - `prior_daily_total` so the on-chain verifier can update the
///   per-agent `DailyBucket` PDA monotonically.
/// - `circuit_rule_bitmap` so the verifier can require the full 8-rule set
///   (closes F-23).
/// - `failure_code` so rule failures are surfaced explicitly instead of as
///   indistinct `panic!`s (closes F-33).
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct PublicOutputs {
    pub policy_commitment: [u8; 32],
    pub intent_hash: [u8; 32],
    pub agent_pubkey: [u8; 32],
    pub nonce: [u8; 32],
    pub tx_hash: [u8; 32],
    pub expiry: u64,
    pub image_id: [u32; 8],
    /// TEE-attested unix timestamp (seconds) at proof time. The on-chain
    /// verifier checks this is within ±`ATTESTED_TIMESTAMP_MAX_DRIFT_SECS`
    /// of `Clock::unix_timestamp`.
    pub attested_timestamp: u64,
    /// `attested_timestamp / SECONDS_PER_DAY` — the UTC bucket the daily
    /// volume rule was evaluated against.
    pub daily_bucket_id: u64,
    /// Daily lamports spent before this intent. The on-chain `DailyBucket`
    /// PDA must equal this value at verify time; the verifier writes
    /// `prior_daily_total + intent.max_lamports` after success.
    pub prior_daily_total: u64,
    /// Per-rule enforcement bitmap (see `RULE_BIT_*` / `RULE_REQUIRED_BITMAP`).
    pub circuit_rule_bitmap: u32,
    /// Granular failure code; `None` = success. The verifier rejects any
    /// non-`None` proof with `CircuitRuleFailure`.
    pub failure_code: u8,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Canonical serialization — Policy
// ═══════════════════════════════════════════════════════════════════════════════

/// Deterministic serialization of Policy for commitment hashing.
/// Field order is fixed. Vectors are sorted before encoding.
pub fn canonical_serialize_policy(policy: &Policy) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);

    // version (4 bytes LE)
    buf.extend_from_slice(&policy.version.to_le_bytes());

    // max_lamports_per_tx (8 bytes LE)
    buf.extend_from_slice(&policy.max_lamports_per_tx.to_le_bytes());

    // allowed_programs (sorted, length-prefixed)
    let mut programs = policy.allowed_programs.clone();
    programs.sort_unstable();
    buf.extend_from_slice(&(programs.len() as u32).to_le_bytes());
    for p in &programs {
        buf.extend_from_slice(p);
    }

    // time_window (optional)
    match &policy.time_window {
        Some(tw) => {
            buf.push(1);
            buf.push(tw.start_hour_utc);
            buf.push(tw.end_hour_utc);
        }
        None => buf.push(0),
    }

    // max_daily_volume_lamports
    buf.extend_from_slice(&policy.max_daily_volume_lamports.to_le_bytes());

    // max_slippage_bps (optional)
    match policy.max_slippage_bps {
        Some(v) => {
            buf.push(1);
            buf.extend_from_slice(&v.to_le_bytes());
        }
        None => buf.push(0),
    }

    // allowed_token_mints (optional, sorted)
    match &policy.allowed_token_mints {
        Some(mints) => {
            buf.push(1);
            let mut sorted = mints.clone();
            sorted.sort_unstable();
            buf.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
            for m in &sorted {
                buf.extend_from_slice(m);
            }
        }
        None => buf.push(0),
    }

    // max_accounts_per_tx (optional)
    match policy.max_accounts_per_tx {
        Some(v) => {
            buf.push(1);
            buf.extend_from_slice(&v.to_le_bytes());
        }
        None => buf.push(0),
    }

    // require_signer_present
    buf.push(u8::from(policy.require_signer_present));

    // expires_at
    buf.extend_from_slice(&policy.expires_at.to_le_bytes());

    buf
}

// ═══════════════════════════════════════════════════════════════════════════════
// Canonical serialization — IntentPayload (circuit-side hash)
// ═══════════════════════════════════════════════════════════════════════════════

/// Deterministic serialization of IntentPayload for intent hashing.
pub fn canonical_intent_preimage(intent: &IntentPayload) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(&intent.agent_pubkey);
    buf.extend_from_slice(&intent.nonce);
    buf.extend_from_slice(&intent.target_program);
    buf.extend_from_slice(&intent.max_lamports.to_le_bytes());
    match intent.max_slippage_bps {
        Some(v) => {
            buf.push(1);
            buf.extend_from_slice(&v.to_le_bytes());
        }
        None => buf.push(0),
    }
    buf.extend_from_slice(&intent.num_accounts.to_le_bytes());
    buf.extend_from_slice(&intent.expiry.to_le_bytes());
    buf
}

// ═══════════════════════════════════════════════════════════════════════════════
// Canonical serialization — Target instruction (tx_hash binding)
// ═══════════════════════════════════════════════════════════════════════════════

/// Canonical byte serialization of the target instruction used for tx_hash binding.
///
/// Layout (all integers little-endian, byte-for-byte stable across BPF / x86 / wasm):
///
/// ```text
///   target_program_id   : 32 bytes
///   num_accounts        : u32 LE
///   for each account:
///     pubkey            : 32 bytes
///     is_signer         : u8  (0/1)
///     is_writable       : u8  (0/1)
///   data_len            : u32 LE
///   data                : data_len bytes
/// ```
///
/// The `num_accounts` and `data_len` length prefixes close T28 (length-extension
/// ambiguity in the previous unframed encoding).
pub fn canonical_target_instruction_bytes(
    target_program: &[u8; 32],
    accounts: &[CanonicalAccountMeta],
    data: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32 + 4 + accounts.len() * 34 + 4 + data.len());
    buf.extend_from_slice(target_program);
    buf.extend_from_slice(&(accounts.len() as u32).to_le_bytes());
    for a in accounts {
        buf.extend_from_slice(&a.pubkey);
        buf.push(u8::from(a.is_signer));
        buf.push(u8::from(a.is_writable));
    }
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
    buf
}

/// Convenience: SHA-256 of `canonical_target_instruction_bytes(...)`.
pub fn hash_target_instruction(
    target_program: &[u8; 32],
    accounts: &[CanonicalAccountMeta],
    data: &[u8],
) -> [u8; 32] {
    sha256(&canonical_target_instruction_bytes(target_program, accounts, data))
}

// ═══════════════════════════════════════════════════════════════════════════════
// Canonical serialization — Signing payload
// ═══════════════════════════════════════════════════════════════════════════════

/// Bytes the agent signs to authorize a `CanonicalIntent`.
///
/// Layout (all integers little-endian):
///
/// ```text
///   agent_pubkey                 : 32
///   nonce                        : 32
///   target_program               : 32
///   num_accounts                 : u32 LE
///   for each account:
///     pubkey                     : 32
///     is_signer                  : u8
///     is_writable                : u8
///   data_len                     : u32 LE
///   data                         : data_len
///   max_lamports                 : u64 LE
///   max_slippage_bps presence    : u8
///   max_slippage_bps             : u16 LE   (only if presence == 1)
///   allowed_tokens presence      : u8
///   allowed_tokens count         : u32 LE   (only if presence == 1)
///   allowed_tokens entries       : 32 bytes each (sorted)
///   expiry                       : u64 LE
///   timestamp                    : u64 LE
///   policy_commitment            : 32
///   worker_pubkey presence       : u8
///   worker_pubkey                : 32       (only if presence == 1)
///   epoch                        : u64 LE
/// ```
pub fn canonical_signing_payload(intent: &CanonicalIntent) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);

    buf.extend_from_slice(&intent.agent_pubkey);
    buf.extend_from_slice(&intent.nonce);

    // Reuse the target-instruction encoding for the program/accounts/data
    // section so signature scope and tx_hash scope share a substring — easier
    // to audit, easier to reuse helpers.
    buf.extend_from_slice(&canonical_target_instruction_bytes(
        &intent.target_program,
        &intent.accounts,
        &intent.data,
    ));

    buf.extend_from_slice(&intent.max_lamports.to_le_bytes());

    match intent.max_slippage_bps {
        Some(v) => {
            buf.push(1);
            buf.extend_from_slice(&v.to_le_bytes());
        }
        None => buf.push(0),
    }

    match &intent.allowed_tokens {
        Some(tokens) => {
            buf.push(1);
            let mut sorted = tokens.clone();
            sorted.sort_unstable();
            buf.extend_from_slice(&(sorted.len() as u32).to_le_bytes());
            for t in &sorted {
                buf.extend_from_slice(t);
            }
        }
        None => buf.push(0),
    }

    buf.extend_from_slice(&intent.expiry.to_le_bytes());
    buf.extend_from_slice(&intent.timestamp.to_le_bytes());
    buf.extend_from_slice(&intent.policy_commitment);

    match &intent.worker_pubkey {
        Some(pk) => {
            buf.push(1);
            buf.extend_from_slice(pk);
        }
        None => buf.push(0),
    }

    buf.extend_from_slice(&intent.epoch.to_le_bytes());

    buf
}

// ═══════════════════════════════════════════════════════════════════════════════
// Hashing helpers
// ═══════════════════════════════════════════════════════════════════════════════

pub fn hash_policy(policy: &Policy) -> [u8; 32] {
    sha256(&canonical_serialize_policy(policy))
}

pub fn hash_intent(intent: &IntentPayload) -> [u8; 32] {
    sha256(&canonical_intent_preimage(intent))
}

pub fn hash_signing_payload(intent: &CanonicalIntent) -> [u8; 32] {
    sha256(&canonical_signing_payload(intent))
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

// ═══════════════════════════════════════════════════════════════════════════════
// Merkle inclusion (allowed_token_mints in-circuit, closes F-23 partial)
// ═══════════════════════════════════════════════════════════════════════════════

/// One step of a sorted-pair Merkle inclusion proof.
///
/// `sibling` is the hash on the other side of this level; `is_right` is true
/// when the sibling is the right node (i.e. the leaf/sub-tree under proof
/// sits on the LEFT). The combine function is
/// `sha256(0x01 || left || right)` with a domain separator to differentiate
/// from leaf hashes (`sha256(0x00 || mint_bytes)`).
#[derive(Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize, PartialEq, Eq)]
pub struct MerklePathNode {
    pub sibling: [u8; 32],
    pub is_right: bool,
}

pub type MerklePath = Vec<MerklePathNode>;

/// Domain-separated leaf hash: `sha256(0x00 || mint_bytes)`.
pub fn merkle_leaf_hash(mint: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00u8]);
    h.update(mint);
    h.finalize().into()
}

/// Domain-separated internal node hash: `sha256(0x01 || left || right)`.
pub fn merkle_internal_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Build a Merkle root for an arbitrary mint set. Sorts the mints first (so the
/// root is order-independent, matching `canonical_serialize_policy`'s sort) and
/// uses duplicate-last padding when a level has an odd count.
pub fn build_mint_merkle_root(mints: &[[u8; 32]]) -> [u8; 32] {
    if mints.is_empty() {
        return [0u8; 32];
    }
    let mut sorted = mints.to_vec();
    sorted.sort_unstable();
    let mut layer: Vec<[u8; 32]> = sorted.iter().map(merkle_leaf_hash).collect();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            let left = layer[i];
            let right = if i + 1 < layer.len() { layer[i + 1] } else { layer[i] };
            next.push(merkle_internal_hash(&left, &right));
            i += 2;
        }
        layer = next;
    }
    layer[0]
}

/// Build a Merkle inclusion path for `mint` against the sorted set in `mints`.
/// Returns `None` if `mint` is not in `mints`.
pub fn build_mint_merkle_path(mint: &[u8; 32], mints: &[[u8; 32]]) -> Option<MerklePath> {
    let mut sorted = mints.to_vec();
    sorted.sort_unstable();
    let leaf_idx = sorted.iter().position(|m| m == mint)?;
    let mut layer: Vec<[u8; 32]> = sorted.iter().map(merkle_leaf_hash).collect();
    let mut idx = leaf_idx;
    let mut path = Vec::new();
    while layer.len() > 1 {
        let sibling_idx = if idx % 2 == 0 {
            // current is left; sibling is right (or self if odd-padded).
            if idx + 1 < layer.len() { idx + 1 } else { idx }
        } else {
            idx - 1
        };
        let sibling = layer[sibling_idx];
        let is_right = sibling_idx > idx; // sibling on the right side
        path.push(MerklePathNode { sibling, is_right });

        let mut next = Vec::with_capacity(layer.len().div_ceil(2));
        let mut i = 0;
        while i < layer.len() {
            let left = layer[i];
            let right = if i + 1 < layer.len() { layer[i + 1] } else { layer[i] };
            next.push(merkle_internal_hash(&left, &right));
            i += 2;
        }
        layer = next;
        idx /= 2;
    }
    Some(path)
}

/// Verify a Merkle inclusion proof. Reconstructs the root from `(mint, path)`
/// and asserts equality with `expected_root`.
pub fn verify_mint_merkle_path(
    mint: &[u8; 32],
    path: &[MerklePathNode],
    expected_root: &[u8; 32],
) -> bool {
    let mut hash = merkle_leaf_hash(mint);
    for node in path {
        hash = if node.is_right {
            merkle_internal_hash(&hash, &node.sibling)
        } else {
            merkle_internal_hash(&node.sibling, &hash)
        };
    }
    &hash == expected_root
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

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
    fn target_ix_hash_changes_when_program_changes() {
        let mut a_program = [1u8; 32];
        let b_program = [9u8; 32];
        let metas = vec![CanonicalAccountMeta {
            pubkey: [2u8; 32],
            is_signer: true,
            is_writable: false,
        }];
        let data = vec![0u8, 1, 2, 3];

        let h1 = hash_target_instruction(&a_program, &metas, &data);
        a_program = b_program;
        let h2 = hash_target_instruction(&a_program, &metas, &data);
        assert_ne!(h1, h2);
    }

    #[test]
    fn target_ix_hash_changes_when_account_flags_change() {
        let program = [1u8; 32];
        let metas_a = vec![CanonicalAccountMeta {
            pubkey: [2u8; 32],
            is_signer: true,
            is_writable: false,
        }];
        let metas_b = vec![CanonicalAccountMeta {
            pubkey: [2u8; 32],
            is_signer: false,
            is_writable: false,
        }];
        let data = vec![0u8];

        let h1 = hash_target_instruction(&program, &metas_a, &data);
        let h2 = hash_target_instruction(&program, &metas_b, &data);
        assert_ne!(h1, h2);
    }

    #[test]
    fn signing_payload_binds_policy_and_epoch() {
        let mut a = sample_intent();
        let b1 = canonical_signing_payload(&a);

        a.policy_commitment = [0xCC; 32];
        let b2 = canonical_signing_payload(&a);
        assert_ne!(b1, b2, "policy_commitment must affect payload");

        a.policy_commitment = [0xAA; 32];
        a.epoch = 42;
        let b3 = canonical_signing_payload(&a);
        assert_ne!(b1, b3, "epoch must affect payload");
    }

    #[test]
    fn signing_payload_is_deterministic() {
        let a = sample_intent();
        let b1 = canonical_signing_payload(&a);
        let b2 = canonical_signing_payload(&a);
        assert_eq!(b1, b2);
    }

    #[test]
    fn merkle_root_is_order_independent() {
        let mints = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let mut shuffled = mints.clone();
        shuffled.reverse();
        assert_eq!(build_mint_merkle_root(&mints), build_mint_merkle_root(&shuffled));
    }

    #[test]
    fn merkle_path_verifies_for_member() {
        let mints = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32], [5u8; 32]];
        let root = build_mint_merkle_root(&mints);
        for mint in &mints {
            let path = build_mint_merkle_path(mint, &mints).expect("member must have path");
            assert!(verify_mint_merkle_path(mint, &path, &root), "path for {:?} did not verify", mint);
        }
    }

    #[test]
    fn merkle_path_rejects_non_member() {
        let mints = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let root = build_mint_merkle_root(&mints);
        let outsider = [99u8; 32];
        // Constructing a path for a non-member returns None.
        assert!(build_mint_merkle_path(&outsider, &mints).is_none());
        // Even if a valid path for [1u8;32] is supplied with the outsider, the
        // recomputed root must differ.
        let path_for_one = build_mint_merkle_path(&[1u8; 32], &mints).unwrap();
        assert!(!verify_mint_merkle_path(&outsider, &path_for_one, &root));
    }

    #[test]
    fn public_outputs_borsh_includes_new_fields() {
        let outputs = PublicOutputs {
            policy_commitment: [1u8; 32],
            intent_hash: [2u8; 32],
            agent_pubkey: [3u8; 32],
            nonce: [4u8; 32],
            tx_hash: [5u8; 32],
            expiry: 1_700_000_600,
            image_id: [0u32; 8],
            attested_timestamp: 1_700_000_500,
            daily_bucket_id: 1_700_000_500 / SECONDS_PER_DAY,
            prior_daily_total: 12_345,
            circuit_rule_bitmap: RULE_REQUIRED_BITMAP,
            failure_code: CircuitFailureCode::None as u8,
        };
        let bytes = borsh::BorshSerialize::try_to_vec(&outputs).unwrap();
        let decoded: PublicOutputs = borsh::BorshDeserialize::try_from_slice(&bytes).unwrap();
        assert_eq!(decoded, outputs);
    }

    #[test]
    fn allowed_tokens_sorted_for_canonicalization() {
        let mut a = sample_intent();
        a.allowed_tokens = Some(vec![[0x33; 32], [0x11; 32], [0x22; 32]]);
        let b1 = canonical_signing_payload(&a);

        a.allowed_tokens = Some(vec![[0x11; 32], [0x22; 32], [0x33; 32]]);
        let b2 = canonical_signing_payload(&a);

        assert_eq!(b1, b2);
    }
}
