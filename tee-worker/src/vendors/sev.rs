//! AMD SEV-SNP TEE provider.
//!
//! ## Attestation Flow (Production)
//!
//! ```text
//! VM → /dev/sev-guest ioctl (SNP_GET_REPORT)
//!    → SNP Attestation Report (512 bytes)
//!      ├── measurement: SHA-384 of VM initial memory state
//!      ├── report_data: 64 bytes user-controlled (embed policy_commitment here)
//!      ├── guest_svn: security version number
//!      └── signature: ECDSA-P384 by VCEK (Versioned Chip Endorsement Key)
//!    → AMD Key Distribution System (KDS) → VCEK certificate + cert chain
//!    ← Verified: measurement ∈ allowlist AND report_data contains policy_commitment
//! ```
//!
//! ## Sealing (Production)
//! SEV-SNP does not have a hardware sealing mechanism equivalent to SGX EGETKEY.
//! Instead, use:
//! - A vTPM (Virtual TPM) backed by SNP attestation for key wrapping, or
//! - An external KMS (e.g., HashiCorp Vault) with SNP attestation auth.
//!
//! ## Implementation Status
//! Production paths require `/dev/sev-guest` (Linux 5.19+, AMD EPYC 3rd gen+).
//! The dev arm uses passphrase-derived AEAD via [`super::dev_seal`] (closes
//! T3/T5 dev slice) and a structured attestation parser (closes T16).

use anyhow::{anyhow, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};

use super::{
    build_dev_attestation_quote, compute_bound_user_data, dev_seal, parse_dev_attestation,
    AttestationEvidence, TeeProvider,
};
use crate::types::TeeVendor;

const DEV_PREFIX: &[u8] = b"sev-snp-dev-attest:v1:";
const REPORT_DATA_DOMAIN: &[u8] = b"GLYPH:sev-snp:report_data:v1:";

/// AMD SEV-SNP provider.
pub struct SevProvider {
    /// Whether we are running inside a real SEV-SNP VM.
    /// Detected from the presence of /dev/sev-guest.
    is_real_enclave: bool,
}

impl SevProvider {
    pub fn new() -> Self {
        let is_real_enclave = std::path::Path::new("/dev/sev-guest").exists();
        Self { is_real_enclave }
    }

    /// Compute the 32-byte field embedded into `report_data[0..32]` of the
    /// SNP attestation report (the high 32 bytes are zero-padded).
    /// Closes audit T6 by binding the 5-tuple
    /// `(policy_commitment, agent_pubkey, worker_pubkey, boot_nonce, epoch)`.
    pub fn compute_report_data(
        policy_commitment: &[u8; 32],
        agent_pubkey: &[u8; 32],
        worker_pubkey: &[u8; 32],
        boot_nonce: &[u8; 32],
        epoch: u64,
    ) -> [u8; 32] {
        compute_bound_user_data(
            REPORT_DATA_DOMAIN,
            policy_commitment,
            agent_pubkey,
            worker_pubkey,
            boot_nonce,
            epoch,
        )
    }
}

impl Default for SevProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl TeeProvider for SevProvider {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.is_real_enclave {
            Err(anyhow!(
                "SevProvider::seal — SEV-SNP sealing not yet implemented. \
                 Implement vTPM-based or KMS-based sealing for SEV-SNP."
            ))
        } else {
            let pass = dev_seal::passphrase_from_env()?;
            tracing::warn!(
                "SevProvider::seal — dev mode (passphrase AEAD); \
                 production must use vTPM/KMS sealing"
            );
            dev_seal::dev_seal_with_passphrase(&pass, plaintext)
        }
    }

    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        if self.is_real_enclave {
            Err(anyhow!(
                "SevProvider::unseal — SEV-SNP unsealing not yet implemented. \
                 Implement vTPM-based or KMS-based unsealing for SEV-SNP."
            ))
        } else {
            let pass = dev_seal::passphrase_from_env()?;
            tracing::warn!(
                "SevProvider::unseal — dev mode (passphrase AEAD); \
                 production must use vTPM/KMS unsealing"
            );
            dev_seal::dev_unseal_with_passphrase(&pass, sealed)
        }
    }

    fn attest(
        &self,
        user_data: &[u8],
        policy_commitment: &[u8; 32],
    ) -> Result<AttestationEvidence> {
        if self.is_real_enclave {
            return Err(anyhow!(
                "SevProvider::attest — SNP_GET_REPORT not yet implemented. \
                 Use the `sev` crate and /dev/sev-guest ioctl to generate SNP attestation."
            ));
        }

        tracing::warn!("SevProvider::attest — dev mode (synthetic quote)");

        let mut hasher = Sha256::new();
        hasher.update(REPORT_DATA_DOMAIN);
        hasher.update(policy_commitment);
        hasher.update(user_data);
        let bound: [u8; 32] = hasher.finalize().into();

        Ok(AttestationEvidence {
            vendor: TeeVendor::Sev,
            quote: build_dev_attestation_quote(DEV_PREFIX, &bound, policy_commitment),
            timestamp_unix: Utc::now().timestamp() as u64,
        })
    }

    fn verify_attestation(
        &self,
        evidence: &AttestationEvidence,
        expected_commitment: &[u8; 32],
    ) -> Result<bool> {
        if evidence.vendor != TeeVendor::Sev {
            return Ok(false);
        }
        if self.is_real_enclave {
            return Err(anyhow!(
                "SevProvider::verify_attestation — SNP report verification not yet implemented. \
                 Use the `sev` crate to parse the report and verify the ECDSA-P384 signature."
            ));
        }
        // Dev arm — strict structured parser (closes T16).
        Ok(parse_dev_attestation(
            &evidence.quote,
            DEV_PREFIX,
            expected_commitment,
        ))
    }

    fn is_real_enclave(&self) -> bool {
        self.is_real_enclave
    }

    fn vendor(&self) -> TeeVendor {
        TeeVendor::Sev
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_passphrase<F: FnOnce()>(f: F) {
        let _g = super::dev_seal::TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        std::env::set_var(
            "GLYPH_SEAL_PASSPHRASE",
            "test-passphrase-for-sev-vendor-only!!!!",
        );
        f();
        std::env::remove_var("GLYPH_SEAL_PASSPHRASE");
    }

    #[test]
    fn dev_seal_round_trip_with_fixed_passphrase() {
        with_passphrase(|| {
            let p = SevProvider {
                is_real_enclave: false,
            };
            let pt = b"sev-policy-bytes";
            let ct = p.seal(pt).unwrap();
            assert_ne!(ct, pt);
            let pt2 = p.unseal(&ct).unwrap();
            assert_eq!(pt, pt2.as_slice());
        });
    }

    #[test]
    fn dev_attestation_legit_quote_verifies() {
        let p = SevProvider {
            is_real_enclave: false,
        };
        let commitment = [0x88u8; 32];
        let ev = p.attest(b"snp-bound", &commitment).unwrap();
        assert!(p.verify_attestation(&ev, &commitment).unwrap());
    }

    #[test]
    fn dev_attestation_rejects_sliding_window() {
        let p = SevProvider {
            is_real_enclave: false,
        };
        let commitment = [0x99u8; 32];
        let mut blob = b"attacker-prefix:".to_vec();
        blob.extend_from_slice(&commitment);
        blob.extend_from_slice(b":suffix");
        let ev = AttestationEvidence {
            vendor: TeeVendor::Sev,
            quote: blob,
            timestamp_unix: 0,
        };
        assert!(!p.verify_attestation(&ev, &commitment).unwrap());
    }

    #[test]
    fn dev_attestation_rejects_wrong_commitment() {
        let p = SevProvider {
            is_real_enclave: false,
        };
        let real = [0x11u8; 32];
        let other = [0x12u8; 32];
        let ev = p.attest(b"x", &real).unwrap();
        assert!(!p.verify_attestation(&ev, &other).unwrap());
    }

    #[test]
    fn dev_attestation_rejects_wrong_vendor_prefix() {
        // Build a Nitro-shaped quote and feed to the SEV provider.
        let p = SevProvider {
            is_real_enclave: false,
        };
        let commitment = [0xDDu8; 32];
        let user_data = [0u8; 32];
        let mut quote = b"nitro-dev-attest:v1:".to_vec();
        quote.extend_from_slice(&user_data);
        quote.extend_from_slice(b":policy:");
        quote.extend_from_slice(&commitment);
        let ev = AttestationEvidence {
            vendor: TeeVendor::Sev,
            quote,
            timestamp_unix: 0,
        };
        assert!(!p.verify_attestation(&ev, &commitment).unwrap());
    }

    #[test]
    fn require_real_fails_in_dev() {
        let p = SevProvider {
            is_real_enclave: false,
        };
        assert!(p.require_real().is_err());
    }
}
