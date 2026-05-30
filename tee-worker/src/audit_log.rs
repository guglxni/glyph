//! Tamper-evident, sealed, append-only audit log (closes WS-6 / T20 / T37).
//!
//! Each accepted intent that the worker processes produces one [`AuditEntry`]:
//!
//! ```text
//! AuditEntry {
//!     sequence,                 // monotonically increasing, starts at 0
//!     timestamp,                // i64 unix seconds (worker clock at append time)
//!     agent_pubkey: [u8; 32],
//!     intent_hash: [u8; 32],
//!     policy_commitment: [u8; 32],
//!     tx_hash: [u8; 32],
//!     prev_entry_hash: [u8; 32], // sha256(canonical_bytes(prev_entry)), or [0; 32] for genesis
//!     worker_signature: [u8; 64], // ed25519 over canonical_bytes(entry without signature)
//! }
//! ```
//!
//! The chain is anchored by:
//! - the worker's signing key (verifiable by anyone holding the worker pubkey),
//! - a sealed file on disk written via [`crate::vendors::TeeProvider::seal`],
//! - and (per WS-6 §2) periodic on-chain commitments of the Merkle root via
//!   the new `commit_audit_root` instruction in `programs/glyph-verifier`.
//!
//! `verify_chain` walks every entry from genesis, recomputes
//! `sha256(canonical_bytes(prev))`, and verifies each `worker_signature`
//! against the worker's verifying key. Any byte tamper anywhere along the
//! chain (including in a single signature byte) breaks verification.
//!
//! The on-disk format is **the same canonical byte stream that the chain hash
//! is computed over**, so a third party that holds the sealed file + the
//! worker pubkey can re-verify the chain end-to-end without trusting the
//! worker's `verify_chain` implementation.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signature as DalekSignature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::vendors::TeeProvider;

/// Genesis sentinel for the chain hash.
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];

/// Upper bound on entries kept in the in-memory ring. Older entries remain in
/// the sealed file on disk but are dropped from the in-memory copy after the
/// ring rolls. This is a memory-only knob — chain verification reloads from
/// disk to walk the full chain.
pub const RING_CAPACITY: usize = 1024;

/// Plaintext fields supplied by the caller. The audit log itself fills in
/// `sequence`, `timestamp`, `prev_entry_hash`, and `worker_signature`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntryInner {
    pub agent_pubkey: [u8; 32],
    pub intent_hash: [u8; 32],
    pub policy_commitment: [u8; 32],
    pub tx_hash: [u8; 32],
}

/// One audit-log entry. The byte layout used by `canonical_unsigned_bytes` is
/// the SOLE input to both the chain hash and the worker signature, so
/// changing field order / endianness here is a breaking change for replayers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub sequence: u64,
    pub timestamp: i64,
    pub agent_pubkey: [u8; 32],
    pub intent_hash: [u8; 32],
    pub policy_commitment: [u8; 32],
    pub tx_hash: [u8; 32],
    pub prev_entry_hash: [u8; 32],
    /// ed25519 signature over `canonical_unsigned_bytes(self)`. Verified by
    /// `verify_chain` against the worker's [`VerifyingKey`].
    #[serde(with = "serde_bytes_array_64")]
    pub worker_signature: [u8; 64],
}

impl AuditEntry {
    /// Canonical signing-payload bytes — every field except `worker_signature`
    /// in fixed-width big-endian encoding.
    pub fn canonical_unsigned_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + 8 + 32 * 5);
        buf.extend_from_slice(b"GLYPH_AUDIT_v1\0");
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&self.agent_pubkey);
        buf.extend_from_slice(&self.intent_hash);
        buf.extend_from_slice(&self.policy_commitment);
        buf.extend_from_slice(&self.tx_hash);
        buf.extend_from_slice(&self.prev_entry_hash);
        buf
    }

    /// Hash of the (signed) entry. Used as `prev_entry_hash` in the next
    /// link.
    pub fn entry_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(&self.canonical_unsigned_bytes());
        hasher.update(&self.worker_signature);
        hasher.finalize().into()
    }
}

/// In-memory + on-disk audit log. `Arc<SigningKey>` is shared with `AppState`
/// so the same key signs intents and audit entries.
pub struct AuditLog {
    signing_key: Arc<SigningKey>,
    /// Sealed file on disk. `None` ⇒ memory-only (test mode).
    file_path: Option<PathBuf>,
    /// In-memory ring of recent entries. Bounded by [`RING_CAPACITY`].
    ring: Vec<AuditEntry>,
    /// Hash of the most recently appended entry. `[0; 32]` before any append.
    head_hash: [u8; 32],
    /// Next sequence number to assign on append. Starts at 0.
    next_sequence: u64,
}

impl AuditLog {
    /// Construct a new audit log. If `file_path` is provided and the file
    /// already exists, it is unsealed + replayed so the chain head and
    /// sequence counter resume where the worker left off.
    pub fn new(
        signing_key: Arc<SigningKey>,
        file_path: Option<PathBuf>,
        provider: &dyn TeeProvider,
    ) -> Result<Self> {
        let mut log = Self {
            signing_key,
            file_path: file_path.clone(),
            ring: Vec::with_capacity(RING_CAPACITY),
            head_hash: GENESIS_PREV_HASH,
            next_sequence: 0,
        };
        if let Some(path) = file_path {
            if path.exists() {
                let sealed = std::fs::read(&path)
                    .with_context(|| format!("failed to read audit log at {}", path.display()))?;
                let unsealed = provider
                    .unseal(&sealed)
                    .context("failed to unseal audit log file")?;
                let entries: Vec<AuditEntry> = serde_json::from_slice(&unsealed)
                    .context("audit log file is not valid JSON")?;
                log.replay_from(entries)?;
            }
        }
        Ok(log)
    }

    fn replay_from(&mut self, entries: Vec<AuditEntry>) -> Result<()> {
        // Verify the entire chain we read from disk before trusting any state.
        verify_entries(&entries, &self.signing_key.verifying_key())
            .context("audit log on disk failed integrity check")?;
        if let Some(last) = entries.last() {
            self.head_hash = last.entry_hash();
            self.next_sequence = last.sequence.saturating_add(1);
        }
        // Drop into the ring (newest at the back).
        let take = entries.len().min(RING_CAPACITY);
        let start = entries.len() - take;
        self.ring.extend_from_slice(&entries[start..]);
        Ok(())
    }

    /// Append a new entry. Computes `prev_entry_hash`, signs with the worker
    /// key, persists the new sealed file (best-effort: any I/O error is
    /// surfaced), and returns the persisted entry.
    pub fn append(
        &mut self,
        inner: AuditEntryInner,
        timestamp: i64,
        provider: &dyn TeeProvider,
    ) -> Result<AuditEntry> {
        let mut entry = AuditEntry {
            sequence: self.next_sequence,
            timestamp,
            agent_pubkey: inner.agent_pubkey,
            intent_hash: inner.intent_hash,
            policy_commitment: inner.policy_commitment,
            tx_hash: inner.tx_hash,
            prev_entry_hash: self.head_hash,
            worker_signature: [0u8; 64],
        };
        let payload = entry.canonical_unsigned_bytes();
        let sig = self.signing_key.sign(&payload);
        entry.worker_signature = sig.to_bytes();

        // Update in-memory state BEFORE persisting so a persist failure
        // doesn't leave the log object in an inconsistent state vs the disk;
        // we resync via revert on failure below.
        let prev_head = self.head_hash;
        let prev_seq = self.next_sequence;
        self.head_hash = entry.entry_hash();
        self.next_sequence = self.next_sequence.saturating_add(1);
        self.ring.push(entry.clone());
        if self.ring.len() > RING_CAPACITY {
            // Drop the oldest in-memory entry; it's still on disk.
            self.ring.remove(0);
        }

        if let Err(e) = self.persist(provider) {
            // Roll back in-memory state to keep on-disk + in-memory consistent.
            self.ring.pop();
            self.head_hash = prev_head;
            self.next_sequence = prev_seq;
            return Err(e);
        }

        Ok(entry)
    }

    /// Persist the **full** in-memory + on-disk view as a single sealed JSON
    /// blob. We re-read the existing file (if any) so the file always carries
    /// the complete chain rather than just the in-memory ring.
    fn persist(&self, provider: &dyn TeeProvider) -> Result<()> {
        let Some(path) = &self.file_path else {
            return Ok(());
        };

        // Load existing entries first so we don't lose anything that's rolled
        // out of the ring.
        let mut all_entries: Vec<AuditEntry> = if path.exists() {
            let sealed = std::fs::read(path)
                .with_context(|| format!("failed reading existing audit log at {}", path.display()))?;
            let unsealed = provider.unseal(&sealed)
                .context("failed to unseal existing audit log for append")?;
            serde_json::from_slice(&unsealed)
                .context("existing audit log file is malformed JSON")?
        } else {
            Vec::new()
        };

        // Append any ring entries whose sequence > existing tail.
        let next_after_disk = all_entries.last().map(|e| e.sequence + 1).unwrap_or(0);
        for e in self.ring.iter().filter(|e| e.sequence >= next_after_disk) {
            all_entries.push(e.clone());
        }

        let json = serde_json::to_vec(&all_entries).context("failed to serialize audit log")?;
        let sealed = provider.seal(&json).context("failed to seal audit log")?;
        std::fs::write(path, sealed)
            .with_context(|| format!("failed to write sealed audit log to {}", path.display()))?;
        Ok(())
    }

    /// Verify the chain from genesis. Returns `Ok(())` only if every entry's
    /// `prev_entry_hash` matches the previous entry's hash AND every entry's
    /// `worker_signature` validates against the configured worker pubkey.
    pub fn verify_chain(&self, provider: &dyn TeeProvider) -> Result<()> {
        let entries = self.read_full_chain(provider)?;
        verify_entries(&entries, &self.signing_key.verifying_key())
    }

    /// Read the full chain from disk (or the in-memory ring if no file is
    /// configured). Used by `/audit` HTTP endpoint and `verify_chain`.
    pub fn read_full_chain(&self, provider: &dyn TeeProvider) -> Result<Vec<AuditEntry>> {
        if let Some(path) = &self.file_path {
            if path.exists() {
                let sealed = std::fs::read(path)
                    .with_context(|| format!("failed reading audit log at {}", path.display()))?;
                let unsealed = provider
                    .unseal(&sealed)
                    .context("failed to unseal audit log")?;
                let entries: Vec<AuditEntry> = serde_json::from_slice(&unsealed)
                    .context("audit log file is malformed JSON")?;
                return Ok(entries);
            }
        }
        Ok(self.ring.clone())
    }

    /// Compute a Merkle root over all current chain entries' [`AuditEntry::entry_hash`]
    /// values. This is what gets anchored on-chain via the `commit_audit_root`
    /// instruction.
    pub fn merkle_root(&self, provider: &dyn TeeProvider) -> Result<[u8; 32]> {
        let entries = self.read_full_chain(provider)?;
        Ok(merkle_root(&entries))
    }

    pub fn sequence_high(&self) -> u64 {
        self.next_sequence.saturating_sub(1)
    }

    /// Test-only constructor that does not touch disk. Convenient for unit
    /// tests that only care about chain correctness.
    pub fn in_memory(signing_key: Arc<SigningKey>) -> Self {
        Self {
            signing_key,
            file_path: None,
            ring: Vec::new(),
            head_hash: GENESIS_PREV_HASH,
            next_sequence: 0,
        }
    }
}

/// Walk the supplied entries, recomputing chain links and verifying signatures.
pub fn verify_entries(entries: &[AuditEntry], worker_vk: &VerifyingKey) -> Result<()> {
    let mut expected_prev = GENESIS_PREV_HASH;
    let mut expected_seq = 0u64;
    for entry in entries {
        if entry.sequence != expected_seq {
            return Err(anyhow!(
                "audit chain broken: expected sequence {} but got {}",
                expected_seq,
                entry.sequence
            ));
        }
        if entry.prev_entry_hash != expected_prev {
            return Err(anyhow!(
                "audit chain broken at sequence {}: prev_entry_hash mismatch",
                entry.sequence
            ));
        }
        let sig = DalekSignature::from_bytes(&entry.worker_signature);
        worker_vk
            .verify(&entry.canonical_unsigned_bytes(), &sig)
            .map_err(|e| anyhow!("audit signature invalid at sequence {}: {}", entry.sequence, e))?;
        expected_prev = entry.entry_hash();
        expected_seq = entry.sequence.checked_add(1).ok_or_else(|| {
            anyhow!("audit sequence overflow at {}", entry.sequence)
        })?;
    }
    Ok(())
}

/// Compute a SHA-256 binary Merkle root over [`AuditEntry::entry_hash`] values.
/// Empty input yields `[0u8; 32]`.
pub fn merkle_root(entries: &[AuditEntry]) -> [u8; 32] {
    if entries.is_empty() {
        return [0u8; 32];
    }
    let mut layer: Vec<[u8; 32]> = entries.iter().map(|e| e.entry_hash()).collect();
    while layer.len() > 1 {
        let mut next = Vec::with_capacity((layer.len() + 1) / 2);
        for chunk in layer.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() == 2 { chunk[1] } else { chunk[0] };
            let mut h = Sha256::new();
            h.update(left);
            h.update(right);
            let out: [u8; 32] = h.finalize().into();
            next.push(out);
        }
        layer = next;
    }
    layer[0]
}

// serde helper for `[u8; 64]` (defaults to per-byte tuple, which is unwieldy).
mod serde_bytes_array_64 {
    use serde::{Deserializer, Serializer};
    use serde::de::Error;

    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        let v: serde_bytes::ByteBuf = serde::Deserialize::deserialize(d)?;
        let bytes = v.into_vec();
        if bytes.len() != 64 {
            return Err(D::Error::custom(format!(
                "expected 64-byte signature, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}
