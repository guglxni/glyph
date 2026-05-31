//! Intel SGX TEE provider.
//!
//! ## Attestation Flow (Production)
//!
//! ```text
//! enclave → EREPORT instruction → SGX Report
//!         → Quoting Enclave (QE) → SGX Quote (ECDSA or EPID)
//!         → Intel PCS/PCCS → Collateral (TCBInfo, QEIdentity, CRLs)
//!         ← Verified SGX Quote with enclave measurement
//! ```
//!
//! ## Sealing (Production)
//! Uses SGX Sealing Keys derived from EGETKEY(KEYNAME=SEAL_KEY):
//! - Sealed data is bound to the enclave's MRENCLAVE (code measurement)
//! - Only the exact same enclave binary can unseal
//!
//! ## Implementation Status
//! Production paths require the Intel SGX SDK / Open Enclave SDK and SGX
//! hardware. Without it the production arm returns `Err`. The dev arm uses
//! passphrase-derived AEAD via [`super::dev_seal`] (closes T3/T5 dev slice)
//! and a structured attestation parser (closes T15).

use anyhow::{anyhow, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};

use super::{
    build_dev_attestation_quote, compute_bound_user_data, dev_seal, parse_dev_attestation,
    AttestationEvidence, TeeProvider,
};
use crate::types::TeeVendor;

const DEV_PREFIX: &[u8] = b"sgx-dev-attest:v1:";
const REPORT_DATA_DOMAIN: &[u8] = b"GLYPH:sgx:report_data:v1:";

/// Intel SGX provider.
pub struct SgxProvider {
    /// Whether we are running inside a real SGX enclave.
    /// Detected from the presence of /dev/sgx_enclave or similar device.
    is_real_enclave: bool,
}

impl SgxProvider {
    pub fn new() -> Self {
        let is_real_enclave = std::path::Path::new("/dev/sgx_enclave").exists()
            || std::path::Path::new("/dev/isgx").exists();
        Self { is_real_enclave }
    }

    /// Compute the 32-byte `report_data` field embedded in the SGX quote.
    /// Closes audit T6 by binding the 5-tuple
    /// `(policy_commitment, agent_pubkey, worker_pubkey, boot_nonce, epoch)`
    /// under domain `GLYPH:sgx:report_data:v1:`.
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

impl Default for SgxProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl TeeProvider for SgxProvider {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.is_real_enclave {
            // Production: sgx_seal_data() with policy SGX_KEYPOLICY_MRENCLAVE.
            // Requires Intel SGX SDK / Open Enclave runtime and SGX hardware.
            Err(anyhow!(
                "SgxProvider::seal — SGX sealing not yet implemented. \
                 Use sgx_seal_data() from Intel SGX SDK with SGX_KEYPOLICY_MRENCLAVE."
            ))
        } else {
            let pass = dev_seal::passphrase_from_env()?;
            tracing::warn!(
                "SgxProvider::seal — dev mode (passphrase AEAD); \
                 production must use EGETKEY-derived sealing"
            );
            dev_seal::dev_seal_with_passphrase(&pass, plaintext)
        }
    }

    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        if self.is_real_enclave {
            Err(anyhow!(
                "SgxProvider::unseal — SGX unsealing not yet implemented. \
                 Use sgx_unseal_data() from Intel SGX SDK."
            ))
        } else {
            let pass = dev_seal::passphrase_from_env()?;
            tracing::warn!(
                "SgxProvider::unseal — dev mode (passphrase AEAD); \
                 production must use EGETKEY-derived unsealing"
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
            // Production: sgx_create_report() + sgx_get_quote() (DCAP/ECDSA).
            return Err(anyhow!(
                "SgxProvider::attest — SGX quote generation not yet implemented. \
                 Use Intel DCAP sgx_get_quote() for ECDSA attestation."
            ));
        }

        tracing::warn!("SgxProvider::attest — dev mode (synthetic quote)");

        // Bind user_data + policy_commitment into the dev quote so the
        // structured parser in verify_attestation can match exactly.
        let mut hasher = Sha256::new();
        hasher.update(REPORT_DATA_DOMAIN);
        hasher.update(policy_commitment);
        hasher.update(user_data);
        let bound: [u8; 32] = hasher.finalize().into();

        Ok(AttestationEvidence {
            vendor: TeeVendor::Sgx,
            quote: build_dev_attestation_quote(DEV_PREFIX, &bound, policy_commitment),
            timestamp_unix: Utc::now().timestamp() as u64,
        })
    }

    fn verify_attestation(
        &self,
        evidence: &AttestationEvidence,
        expected_commitment: &[u8; 32],
    ) -> Result<bool> {
        if evidence.vendor != TeeVendor::Sgx {
            return Ok(false);
        }
        if self.is_real_enclave {
            // Production: sgx_qv_verify_quote() from Intel DCAP QVL.
            return Err(anyhow!(
                "SgxProvider::verify_attestation — DCAP quote verification not yet implemented. \
                 Use sgx_qv_verify_quote() from Intel DCAP."
            ));
        }
        // Dev arm — strict structured parser (closes T15).
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
        TeeVendor::Sgx
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
            "test-passphrase-for-sgx-vendor-only!!!!",
        );
        f();
        std::env::remove_var("GLYPH_SEAL_PASSPHRASE");
    }

    #[test]
    fn dev_seal_round_trip_with_fixed_passphrase() {
        with_passphrase(|| {
            let p = SgxProvider {
                is_real_enclave: false,
            };
            let pt = b"sgx-policy-bytes";
            let ct = p.seal(pt).unwrap();
            assert_ne!(ct, pt);
            let pt2 = p.unseal(&ct).unwrap();
            assert_eq!(pt, pt2.as_slice());
        });
    }

    #[test]
    fn dev_attestation_legit_quote_verifies() {
        let p = SgxProvider {
            is_real_enclave: false,
        };
        let commitment = [0x55u8; 32];
        let ev = p.attest(b"some-user-data", &commitment).unwrap();
        assert!(p.verify_attestation(&ev, &commitment).unwrap());
    }

    #[test]
    fn dev_attestation_rejects_sliding_window() {
        let p = SgxProvider {
            is_real_enclave: false,
        };
        let commitment = [0x77u8; 32];
        let mut blob = b"attacker:".to_vec();
        blob.extend_from_slice(&commitment);
        blob.extend_from_slice(b":suffix");
        let ev = AttestationEvidence {
            vendor: TeeVendor::Sgx,
            quote: blob,
            timestamp_unix: 0,
        };
        assert!(!p.verify_attestation(&ev, &commitment).unwrap());
    }

    #[test]
    fn dev_attestation_rejects_wrong_commitment() {
        let p = SgxProvider {
            is_real_enclave: false,
        };
        let real = [0xA1u8; 32];
        let other = [0xA2u8; 32];
        let ev = p.attest(b"x", &real).unwrap();
        assert!(!p.verify_attestation(&ev, &other).unwrap());
    }

    #[test]
    fn dev_attestation_rejects_wrong_vendor_prefix() {
        // Build a Nitro-shaped quote and submit to SGX provider.
        let p = SgxProvider {
            is_real_enclave: false,
        };
        let commitment = [0xCCu8; 32];
        let user_data = [0u8; 32];
        let mut quote = b"nitro-dev-attest:v1:".to_vec();
        quote.extend_from_slice(&user_data);
        quote.extend_from_slice(b":policy:");
        quote.extend_from_slice(&commitment);
        let ev = AttestationEvidence {
            vendor: TeeVendor::Sgx,
            quote,
            timestamp_unix: 0,
        };
        // Mismatched prefix → reject.
        assert!(!p.verify_attestation(&ev, &commitment).unwrap());
    }

    #[test]
    fn require_real_fails_in_dev() {
        let p = SgxProvider {
            is_real_enclave: false,
        };
        assert!(p.require_real().is_err());
    }
}
