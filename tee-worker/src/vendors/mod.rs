//! TEE vendor adapters for GLYPH.
//!
//! Three providers (Nitro, SGX, SEV-SNP) implement the [`TeeProvider`] trait.
//! Each provider has two arms — a *real-enclave* arm (production) and a *dev*
//! arm (no enclave device present). The dev arm exists so the worker can run
//! on a developer laptop without HSM access; production must enforce the real
//! arm via [`TeeProvider::require_real`] (see audit T4 / T33).

mod nitro;
mod sev;
mod sgx;

pub mod dev_seal;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use crate::types::TeeVendor;

pub use nitro::NitroProvider;
pub use sev::SevProvider;
pub use sgx::SgxProvider;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEvidence {
    pub vendor: TeeVendor,
    pub quote: Vec<u8>,
    pub timestamp_unix: u64,
}

pub trait TeeProvider: Send + Sync {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>>;
    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>>;
    fn attest(&self, user_data: &[u8], policy_commitment: &[u8; 32])
        -> Result<AttestationEvidence>;
    fn verify_attestation(
        &self,
        evidence: &AttestationEvidence,
        expected_commitment: &[u8; 32],
    ) -> Result<bool>;

    /// Whether this provider is backed by a real TEE device. The worker boot
    /// path uses this to gate `Production` runtime mode (audit T4 / T33).
    fn is_real_enclave(&self) -> bool;

    /// Refuse to proceed if this provider is not a real enclave. Default
    /// implementation calls [`TeeProvider::is_real_enclave`]; vendors may
    /// override for additional invariants.
    ///
    /// Closes audit findings T4, T33: production must fail-fast at boot
    /// rather than silently running the dev passthrough.
    fn require_real(&self) -> Result<()> {
        if self.is_real_enclave() {
            Ok(())
        } else {
            Err(anyhow!(
                "TEE provider is not running on a real enclave; refusing to operate in production mode \
                 (audit T4/T33: dev passthrough is forbidden in Production)"
            ))
        }
    }

    /// Vendor identifier for this provider. Used by the worker boot path to
    /// pick the right `compute_user_data` domain string when assembling the
    /// 5-tuple binding fed into [`TeeProvider::attest`].
    fn vendor(&self) -> crate::types::TeeVendor;

    /// Compute the 32-byte `user_data` / `report_data` field that gets
    /// embedded in the attestation document. Hashes the 5-tuple
    /// `(policy_commitment, agent_pubkey, worker_pubkey, boot_nonce, epoch)`
    /// under a vendor-specific domain string. Closes audit T6.
    ///
    /// Default impl picks the right domain via [`TeeProvider::vendor`] — every
    /// vendor produces a domain-separated digest so cross-vendor evidence
    /// cannot be substituted.
    fn compute_user_data(
        &self,
        policy_commitment: &[u8; 32],
        agent_pubkey: &[u8; 32],
        worker_pubkey: &[u8; 32],
        boot_nonce: &[u8; 32],
        epoch: u64,
    ) -> [u8; 32] {
        use crate::types::TeeVendor;
        let domain: &[u8] = match self.vendor() {
            TeeVendor::Nitro => b"GLYPH:nitro:user_data:v1:",
            TeeVendor::Sgx => b"GLYPH:sgx:report_data:v1:",
            TeeVendor::Sev => b"GLYPH:sev-snp:report_data:v1:",
        };
        compute_bound_user_data(
            domain,
            policy_commitment,
            agent_pubkey,
            worker_pubkey,
            boot_nonce,
            epoch,
        )
    }
}

pub fn create_provider(vendor: TeeVendor) -> Box<dyn TeeProvider> {
    match vendor {
        TeeVendor::Sgx => Box::new(SgxProvider::new()),
        TeeVendor::Nitro => Box::new(NitroProvider::new()),
        TeeVendor::Sev => Box::new(SevProvider::new()),
    }
}

// ---------------------------------------------------------------------------
// Structured dev-attestation helpers
// ---------------------------------------------------------------------------

/// Hash a 5-tuple of attestation context into a 32-byte `user_data` value
/// that gets embedded in the attestation document. Domain-separated per
/// vendor so cross-vendor evidence cannot be mixed.
///
/// Closes audit T6 (attestation must bind policy + agent + worker + boot
/// nonce + epoch). Used by each vendor's `compute_user_data` /
/// `compute_report_data` helpers.
pub(crate) fn compute_bound_user_data(
    domain: &[u8],
    policy_commitment: &[u8; 32],
    agent_pubkey: &[u8; 32],
    worker_pubkey: &[u8; 32],
    boot_nonce: &[u8; 32],
    epoch: u64,
) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(policy_commitment);
    hasher.update(agent_pubkey);
    hasher.update(worker_pubkey);
    hasher.update(boot_nonce);
    hasher.update(epoch.to_le_bytes());
    hasher.finalize().into()
}

/// Build a synthetic dev-mode attestation quote with the structured layout:
/// `prefix || user_data || ":policy:" || policy_commitment`.
///
/// Symmetric with [`parse_dev_attestation`] — round-trip tested per vendor.
pub(crate) fn build_dev_attestation_quote(
    prefix: &[u8],
    user_data: &[u8; 32],
    policy_commitment: &[u8; 32],
) -> Vec<u8> {
    let mut quote = Vec::with_capacity(prefix.len() + 32 + 8 + 32);
    quote.extend_from_slice(prefix);
    quote.extend_from_slice(user_data);
    quote.extend_from_slice(b":policy:");
    quote.extend_from_slice(policy_commitment);
    quote
}

/// Strict structured parser for dev-mode attestation quotes. **Replaces** the
/// previous 32-byte sliding-window scan that closed T14 / T15 / T16: the old
/// parser accepted any blob containing the expected commitment as a
/// substring, which an attacker can trivially construct.
///
/// Returns `Ok(true)` only if `quote` matches exactly:
/// `prefix || <32-byte user_data> || ":policy:" || expected_commitment`.
/// Any deviation — missing prefix, wrong marker position, extra trailing
/// bytes, mismatched commitment — returns `Ok(false)`.
///
/// Constant-time comparison on the commitment to avoid leaking match-prefix
/// length via timing.
pub(crate) fn parse_dev_attestation(
    quote: &[u8],
    prefix: &[u8],
    expected_commitment: &[u8; 32],
) -> bool {
    const MARKER: &[u8] = b":policy:";

    // Must start with the vendor-specific dev prefix.
    if !quote.starts_with(prefix) {
        return false;
    }

    // Body layout from build_dev_attestation_quote:
    // [prefix][32 bytes user_data][8 bytes ":policy:"][32 bytes commitment]
    let expected_len = prefix.len() + 32 + MARKER.len() + 32;
    if quote.len() != expected_len {
        return false;
    }

    let after_prefix = &quote[prefix.len()..];
    // user_data slot is bytes [0..32) of the post-prefix region.
    let marker_start = 32;
    let marker_end = marker_start + MARKER.len();
    if &after_prefix[marker_start..marker_end] != MARKER {
        return false;
    }
    let commitment_slice = &after_prefix[marker_end..];

    constant_time_eq::constant_time_eq(commitment_slice, expected_commitment.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_dev_attestation_parse() {
        let prefix = b"test-dev-attest:v1:";
        let user_data = [0x11u8; 32];
        let commitment = [0x22u8; 32];
        let quote = build_dev_attestation_quote(prefix, &user_data, &commitment);
        assert!(parse_dev_attestation(&quote, prefix, &commitment));
    }

    #[test]
    fn rejects_sliding_window_match() {
        // Construct a blob that *contains* the commitment as a substring
        // somewhere in the middle — the legacy windows(32) parser accepted
        // this. The structured parser must reject it.
        let prefix = b"test-dev-attest:v1:";
        let commitment = [0x33u8; 32];
        let mut blob = b"attacker-prefix:".to_vec();
        blob.extend_from_slice(&commitment);
        blob.extend_from_slice(b":suffix");
        assert!(!parse_dev_attestation(&blob, prefix, &commitment));
    }

    #[test]
    fn rejects_wrong_prefix() {
        let real_prefix = b"test-dev-attest:v1:";
        let other_prefix = b"other-dev-attest:v1:";
        let user_data = [0u8; 32];
        let commitment = [0xAAu8; 32];
        let quote = build_dev_attestation_quote(real_prefix, &user_data, &commitment);
        assert!(!parse_dev_attestation(&quote, other_prefix, &commitment));
    }

    #[test]
    fn rejects_wrong_commitment() {
        let prefix = b"test-dev-attest:v1:";
        let user_data = [0u8; 32];
        let commitment = [0xAAu8; 32];
        let other_commitment = [0xBBu8; 32];
        let quote = build_dev_attestation_quote(prefix, &user_data, &commitment);
        assert!(!parse_dev_attestation(&quote, prefix, &other_commitment));
    }

    #[test]
    fn rejects_trailing_bytes() {
        let prefix = b"test-dev-attest:v1:";
        let user_data = [0u8; 32];
        let commitment = [0xAAu8; 32];
        let mut quote = build_dev_attestation_quote(prefix, &user_data, &commitment);
        quote.push(0x00); // extra byte
        assert!(!parse_dev_attestation(&quote, prefix, &commitment));
    }

    #[test]
    fn rejects_truncated_quote() {
        let prefix = b"test-dev-attest:v1:";
        let user_data = [0u8; 32];
        let commitment = [0xAAu8; 32];
        let mut quote = build_dev_attestation_quote(prefix, &user_data, &commitment);
        quote.pop();
        assert!(!parse_dev_attestation(&quote, prefix, &commitment));
    }
}
