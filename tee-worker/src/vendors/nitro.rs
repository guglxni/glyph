//! AWS Nitro Enclaves TEE provider.
//!
//! ## Attestation Flow (Production, gated behind `nitro-prod` feature)
//!
//! ```text
//! enclave → /dev/nsm (NSM driver)
//!          → NSM_GetAttestationDocument(user_data = compute_user_data(...))
//!          → COSE_Sign1 document (cbor-encoded)
//!          ← Certificate chain: Enclave Cert → Intermediate → AWS Nitro Root CA
//! ```
//!
//! ## Verification Flow (Production)
//!
//! 1. Decode COSE_Sign1 CBOR envelope (`coset` crate).
//! 2. Extract certificate chain from `cabundle` field.
//! 3. Verify chain up to the AWS Nitro Root CA (vendored at
//!    `tee-worker/assets/nitro_root_ca.pem`).
//! 4. Verify COSE signature with leaf cert public key.
//! 5. Check `pcrs` map (PCR0/PCR1/PCR2) against expected enclave image.
//! 6. Check `user_data` field equals the expected commitment.
//! 7. Check `timestamp` is within ±5 minutes of `chrono::Utc::now()`.
//!
//! ## Sealing (Production)
//! AWS KMS with an attestation-bound key policy. `kms:Encrypt` /
//! `kms:Decrypt` IAM conditions require matching PCR values; the policy is
//! updated whenever the enclave image is rebuilt.
//!
//! ## Implementation status
//! - **Default build:** dev arms only; `attest_real`/`verify_attestation_real`/
//!   `seal_real`/`unseal_real` return `Err("requires --features nitro-prod")`.
//! - **`nitro-prod` feature:** code paths against documented APIs are present
//!   (`#[cfg(feature = "nitro-prod")]` blocks). Real Nitro hardware is
//!   required to test; CI verifies default-feature compilation only.

use anyhow::{anyhow, Result};
use chrono::Utc;
use sha2::{Digest, Sha256};

use super::{
    build_dev_attestation_quote, compute_bound_user_data, dev_seal, parse_dev_attestation,
    AttestationEvidence, TeeProvider,
};
use crate::types::TeeVendor;

const DEV_PREFIX: &[u8] = b"nitro-dev-attest:v1:";
const USER_DATA_DOMAIN: &[u8] = b"GLYPH:nitro:user_data:v1:";

/// AWS Nitro Enclaves provider.
pub struct NitroProvider {
    /// Whether we are running inside a real Nitro Enclave.
    /// Detected from the presence of /dev/nsm.
    is_real_enclave: bool,
}

impl NitroProvider {
    pub fn new() -> Self {
        let is_real_enclave = std::path::Path::new("/dev/nsm").exists();
        Self { is_real_enclave }
    }

    /// Compute the 32-byte `user_data` field bound into the attestation
    /// document. Hashes 5-tuple under domain
    /// `GLYPH:nitro:user_data:v1:` (closes audit T6):
    ///   `(policy_commitment, agent_pubkey, worker_pubkey, boot_nonce, epoch)`.
    pub fn compute_user_data(
        policy_commitment: &[u8; 32],
        agent_pubkey: &[u8; 32],
        worker_pubkey: &[u8; 32],
        boot_nonce: &[u8; 32],
        epoch: u64,
    ) -> [u8; 32] {
        compute_bound_user_data(
            USER_DATA_DOMAIN,
            policy_commitment,
            agent_pubkey,
            worker_pubkey,
            boot_nonce,
            epoch,
        )
    }

    // -------------------------------------------------------------------
    // Production code paths (gated behind `nitro-prod` feature flag).
    // These call documented AWS APIs and require real Nitro hardware.
    // -------------------------------------------------------------------

    /// Production attestation against `/dev/nsm`. Returns the raw
    /// CBOR-encoded COSE_Sign1 document as `quote`.
    pub fn attest_real(
        &self,
        user_data: &[u8],
        _policy_commitment: &[u8; 32],
    ) -> Result<AttestationEvidence> {
        #[cfg(feature = "nitro-prod")]
        {
            use aws_nitro_enclaves_nsm_api::api::{Request, Response};
            use aws_nitro_enclaves_nsm_api::driver::{nsm_init, nsm_process_request};
            use rand::RngCore;

            let fd = nsm_init();
            if fd < 0 {
                return Err(anyhow!("nsm_init failed: returned fd={}", fd));
            }

            let mut nonce = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut nonce);

            let req = Request::Attestation {
                user_data: Some(user_data.to_vec().into()),
                nonce: Some(nonce.to_vec().into()),
                public_key: None,
            };
            let resp = nsm_process_request(fd, req);
            let doc = match resp {
                Response::Attestation { document } => document,
                other => return Err(anyhow!("unexpected NSM response: {:?}", other)),
            };

            Ok(AttestationEvidence {
                vendor: TeeVendor::Nitro,
                quote: doc,
                timestamp_unix: Utc::now().timestamp() as u64,
            })
        }
        #[cfg(not(feature = "nitro-prod"))]
        {
            let _ = user_data;
            Err(anyhow!(
                "nitro production paths require --features nitro-prod"
            ))
        }
    }

    /// Production verification of a Nitro COSE_Sign1 attestation document.
    ///
    /// Implementation outline (inside `nitro-prod`):
    ///   1. `coset::CoseSign1::from_slice(&evidence.quote)`
    ///   2. Extract certificate chain from the protected header / payload
    ///      `cabundle` field.
    ///   3. Validate chain anchors to the vendored AWS Nitro Root CA at
    ///      `tee-worker/assets/nitro_root_ca.pem` (TODO: keep current per
    ///      <https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html>).
    ///   4. Verify COSE signature with the leaf certificate's public key.
    ///   5. CBOR-decode the payload to an `AttestationDocument`.
    ///   6. Validate timestamp drift (≤ 5 min vs. `Utc::now()`).
    ///   7. Verify the embedded `user_data` field equals
    ///      `expected_commitment`.
    pub fn verify_attestation_real(
        &self,
        _evidence: &AttestationEvidence,
        _expected_commitment: &[u8; 32],
    ) -> Result<bool> {
        #[cfg(feature = "nitro-prod")]
        {
            use coset::CborSerializable;
            use coset::CoseSign1;

            // Step 1: parse COSE_Sign1.
            let cose = CoseSign1::from_slice(&_evidence.quote)
                .map_err(|e| anyhow!("CoseSign1::from_slice: {e:?}"))?;

            // Step 2-7: full verification requires `x509-parser`, AWS Nitro
            // Root CA, and ring/p384 verification. These are scaffolded here;
            // a real implementation (which requires Nitro hardware to test)
            // performs:
            //   - cert chain parse via x509-parser
            //   - root anchoring via PEM-loaded AWS Nitro CA
            //   - COSE signature verify
            //   - CBOR payload parse
            //   - timestamp drift check
            //   - user_data == expected_commitment
            //
            // For now the scaffold returns Ok(false) until the chain
            // verification is wired against real test vectors. This is
            // *intentionally* fail-closed.
            let _ = cose;
            tracing::warn!(
                "NitroProvider::verify_attestation_real — chain verification scaffold; \
                 requires real Nitro test vectors. Returning fail-closed."
            );
            Ok(false)
        }
        #[cfg(not(feature = "nitro-prod"))]
        {
            Err(anyhow!(
                "nitro production paths require --features nitro-prod"
            ))
        }
    }

    /// Production sealing via AWS KMS Encrypt with an EncryptionContext
    /// bound to `(agent_pubkey, policy_commitment, image_id)`.
    pub fn seal_real(&self, _plaintext: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "nitro-prod")]
        {
            // Implementation outline:
            //   let config = aws_config::load_from_env().await;
            //   let client = aws_sdk_kms::Client::new(&config);
            //   let resp = client.encrypt()
            //       .key_id(env!("GLYPH_KMS_KEY_ID"))
            //       .plaintext(Blob::new(plaintext))
            //       .encryption_context("agent_pubkey", hex::encode(agent_pk))
            //       .encryption_context("policy_commitment", hex::encode(pc))
            //       .send().await?;
            //   Ok(resp.ciphertext_blob.unwrap().into_inner())
            //
            // Requires async runtime + IAM with PCR-bound key policy.
            Err(anyhow!(
                "NitroProvider::seal_real — KMS encrypt scaffolded behind `nitro-prod`; \
                 requires async runtime + key-id config; not yet wired."
            ))
        }
        #[cfg(not(feature = "nitro-prod"))]
        {
            Err(anyhow!(
                "nitro production paths require --features nitro-prod"
            ))
        }
    }

    /// Production unseal — KMS Decrypt analogue of [`Self::seal_real`].
    pub fn unseal_real(&self, _ciphertext: &[u8]) -> Result<Vec<u8>> {
        #[cfg(feature = "nitro-prod")]
        {
            Err(anyhow!(
                "NitroProvider::unseal_real — KMS decrypt scaffolded behind `nitro-prod`; \
                 requires async runtime + key-id config; not yet wired."
            ))
        }
        #[cfg(not(feature = "nitro-prod"))]
        {
            Err(anyhow!(
                "nitro production paths require --features nitro-prod"
            ))
        }
    }
}

impl Default for NitroProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl TeeProvider for NitroProvider {
    fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        if self.is_real_enclave {
            self.seal_real(plaintext)
        } else {
            // Dev arm: passphrase-derived AEAD (replaces identity
            // passthrough — closes audit T3/T5).
            let pass = dev_seal::passphrase_from_env()?;
            tracing::warn!(
                "NitroProvider::seal — dev mode (passphrase AEAD); \
                 production must use KMS sealing"
            );
            dev_seal::dev_seal_with_passphrase(&pass, plaintext)
        }
    }

    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        if self.is_real_enclave {
            self.unseal_real(sealed)
        } else {
            let pass = dev_seal::passphrase_from_env()?;
            tracing::warn!(
                "NitroProvider::unseal — dev mode (passphrase AEAD); \
                 production must use KMS unsealing"
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
            return self.attest_real(user_data, policy_commitment);
        }

        // Dev arm — produce a structured synthetic quote that
        // [`parse_dev_attestation`] can verify exactly. The legacy
        // sliding-window parser is gone (T14).
        tracing::warn!("NitroProvider::attest — dev mode (synthetic quote)");
        // The legacy dev path bound `user_data || policy_commitment`. We keep
        // a SHA-256 binding so dev-mode evidence still ties an arbitrary
        // input slice to the commitment, but the structured parser in
        // verify_attestation no longer scans for sliding windows.
        let mut hasher = Sha256::new();
        hasher.update(USER_DATA_DOMAIN);
        hasher.update(policy_commitment);
        hasher.update(user_data);
        let bound: [u8; 32] = hasher.finalize().into();

        Ok(AttestationEvidence {
            vendor: TeeVendor::Nitro,
            quote: build_dev_attestation_quote(DEV_PREFIX, &bound, policy_commitment),
            timestamp_unix: Utc::now().timestamp() as u64,
        })
    }

    fn verify_attestation(
        &self,
        evidence: &AttestationEvidence,
        expected_commitment: &[u8; 32],
    ) -> Result<bool> {
        if evidence.vendor != TeeVendor::Nitro {
            return Ok(false);
        }
        if self.is_real_enclave {
            return self.verify_attestation_real(evidence, expected_commitment);
        }
        // Dev arm — strict structured parser (closes T14).
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
        TeeVendor::Nitro
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
            "test-passphrase-for-nitro-vendor-only!!",
        );
        f();
        std::env::remove_var("GLYPH_SEAL_PASSPHRASE");
    }

    #[test]
    fn dev_seal_round_trip_with_fixed_passphrase() {
        with_passphrase(|| {
            let p = NitroProvider {
                is_real_enclave: false,
            };
            let pt = b"glyph-policy-bytes";
            let ct = p.seal(pt).unwrap();
            assert_ne!(ct, pt);
            let pt2 = p.unseal(&ct).unwrap();
            assert_eq!(pt, pt2.as_slice());
        });
    }

    #[test]
    fn dev_attestation_legit_quote_verifies() {
        let p = NitroProvider {
            is_real_enclave: false,
        };
        let commitment = [0x11u8; 32];
        let ev = p.attest(b"hello", &commitment).unwrap();
        assert!(p.verify_attestation(&ev, &commitment).unwrap());
    }

    #[test]
    fn dev_attestation_rejects_sliding_window() {
        // Legacy bug: any blob containing the commitment as a 32-byte
        // substring used to verify. The structured parser must reject it.
        let p = NitroProvider {
            is_real_enclave: false,
        };
        let commitment = [0x42u8; 32];
        let mut blob = b"attacker-prefix:".to_vec();
        blob.extend_from_slice(&commitment);
        blob.extend_from_slice(b":suffix");
        let ev = AttestationEvidence {
            vendor: TeeVendor::Nitro,
            quote: blob,
            timestamp_unix: 0,
        };
        assert!(!p.verify_attestation(&ev, &commitment).unwrap());
    }

    #[test]
    fn dev_attestation_rejects_wrong_commitment() {
        let p = NitroProvider {
            is_real_enclave: false,
        };
        let real = [0x01u8; 32];
        let other = [0x02u8; 32];
        let ev = p.attest(b"hello", &real).unwrap();
        assert!(!p.verify_attestation(&ev, &other).unwrap());
    }

    #[test]
    fn dev_attestation_rejects_wrong_vendor_prefix() {
        // Build a quote with an SGX-style prefix and feed it to the Nitro
        // verifier. The vendor field on the evidence struct is also wrong.
        let p = NitroProvider {
            is_real_enclave: false,
        };
        let commitment = [0xAAu8; 32];
        let user_data = [0u8; 32];
        let mut quote = b"sgx-dev-attest:v1:".to_vec();
        quote.extend_from_slice(&user_data);
        quote.extend_from_slice(b":policy:");
        quote.extend_from_slice(&commitment);
        let ev = AttestationEvidence {
            vendor: TeeVendor::Sgx, // wrong vendor
            quote,
            timestamp_unix: 0,
        };
        assert!(!p.verify_attestation(&ev, &commitment).unwrap());
    }

    #[test]
    fn require_real_fails_in_dev() {
        let p = NitroProvider {
            is_real_enclave: false,
        };
        assert!(p.require_real().is_err());
    }

    #[test]
    fn compute_user_data_changes_with_each_input() {
        let pc = [1u8; 32];
        let agent = [2u8; 32];
        let worker = [3u8; 32];
        let nonce = [4u8; 32];
        let a = NitroProvider::compute_user_data(&pc, &agent, &worker, &nonce, 0);
        let b = NitroProvider::compute_user_data(&pc, &agent, &worker, &nonce, 1);
        assert_ne!(a, b);
        let c = NitroProvider::compute_user_data(&[9u8; 32], &agent, &worker, &nonce, 0);
        assert_ne!(a, c);
    }
}
