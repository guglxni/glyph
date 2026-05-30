use anchor_lang::prelude::*;

#[error_code]
pub enum GlyphError {
    // ═══════════════════════════════════════════════════════════════════════
    // Groth16 / Cryptographic Errors (6000-6009)
    // ═══════════════════════════════════════════════════════════════════════
    #[msg("Groth16 proof verification failed - pairing check did not converge to identity")]
    Groth16PairingFailed = 6000,
    
    #[msg("Invalid G1 point - point is not on curve or is identity")]
    Groth16InvalidG1Point = 6001,
    
    #[msg("Invalid G2 point - point is not on curve")]
    Groth16InvalidG2Point = 6002,
    
    #[msg("Proof verification returned unexpected result")]
    Groth16UnexpectedResult = 6003,
    
    #[msg("Alt BN128 syscall failed")]
    AltBn128SyscallFailed = 6004,
    
    #[msg("Invalid proof format - proof points are invalid")]
    InvalidProofFormat = 6005,
    
    #[msg("Proof verification failed")]
    ProofVerificationFailed = 6006,

    // ═══════════════════════════════════════════════════════════════════════
    // Journal / Public Input Errors (6010-6019)
    // ═══════════════════════════════════════════════════════════════════════
    #[msg("Failed to decode journal bytes - invalid borsh encoding")]
    InvalidJournalEncoding = 6010,
    
    #[msg("Journal hash mismatch - computed hash does not match expected")]
    JournalHashMismatch = 6011,
    
    #[msg("Policy commitment mismatch - proof was generated for different policy")]
    PolicyCommitmentMismatch = 6012,
    
    #[msg("Agent pubkey mismatch - proof was generated for different agent")]
    AgentPubkeyMismatch = 6013,

    // ═══════════════════════════════════════════════════════════════════════
    // Instruction Binding Errors (6020-6029)
    // ═══════════════════════════════════════════════════════════════════════
    #[msg("Transaction hash binding failed - next instruction does not match proof")]
    TxHashBindingFailed = 6020,
    
    #[msg("Instructions sysvar access failed")]
    InstructionsSysvarFailed = 6021,
    
    #[msg("No next instruction found - verify_and_execute must be followed by target instruction")]
    MissingNextInstruction = 6022,
    
    #[msg("Instruction index calculation overflow")]
    InstructionIndexOverflow = 6023,

    // ═══════════════════════════════════════════════════════════════════════
    // Nonce / Replay Protection Errors (6030-6039)
    // ═══════════════════════════════════════════════════════════════════════
    #[msg("Nonce already consumed - transaction has been replayed")]
    NonceAlreadyConsumed = 6030,
    
    #[msg("Nonce PDA initialization failed - nonce may already exist")]
    NonceInitializationFailed = 6031,
    
    #[msg("Policy epoch mismatch - policy was updated, nonce from old epoch")]
    PolicyEpochMismatch = 6032,
    
    #[msg("Nonce cannot be zero")]
    ZeroNonce = 6033,

    // ═══════════════════════════════════════════════════════════════════════
    // Agent Registry Errors (6040-6049)
    // ═══════════════════════════════════════════════════════════════════════
    #[msg("Agent not registered")]
    AgentNotRegistered = 6040,
    
    #[msg("Agent is not active")]
    AgentNotActive = 6041,
    
    #[msg("Agent already registered")]
    AgentAlreadyRegistered = 6042,
    
    #[msg("Authorization failed - signer is not the agent")]
    Unauthorized = 6043,
    
    #[msg("Policy epoch overflow")]
    PolicyEpochOverflow = 6044,

    // ═══════════════════════════════════════════════════════════════════════
    // TEE Attestation Errors (6050-6069)
    // ═══════════════════════════════════════════════════════════════════════
    #[msg("Invalid attestation type")]
    InvalidAttestationType = 6050,
    
    #[msg("Attestation too short")]
    AttestationTooShort = 6051,
    
    #[msg("Invalid attestation format")]
    InvalidAttestationFormat = 6052,
    
    #[msg("Invalid attestation document")]
    InvalidAttestationDocument = 6053,
    
    #[msg("Attestation missing user data")]
    AttestationMissingUserData = 6054,
    
    #[msg("Attestation user data mismatch - policy commitment not found")]
    AttestationUserDataMismatch = 6055,
    
    #[msg("Attestation expired or not yet valid")]
    AttestationExpired = 6056,
    
    #[msg("Unsupported attestation version")]
    UnsupportedAttestationVersion = 6057,
    
    #[msg("Certificate chain verification failed")]
    CertificateChainVerificationFailed = 6058,
    
    #[msg("COSE signature verification failed")]
    CoseSignatureVerificationFailed = 6059,
    
    #[msg("PCR measurement not in allowlist")]
    PcrMeasurementNotAllowed = 6060,
    
    #[msg("Attestation commitment mismatch - attestation does not bind to expected policy commitment")]
    AttestationCommitmentMismatch = 6061,

    // ═══════════════════════════════════════════════════════════════════════
    // Compute Budget Errors (6070-6079)
    // ═══════════════════════════════════════════════════════════════════════
    #[msg("Insufficient compute budget - need at least 1,400,000 CUs for Groth16 verification")]
    InsufficientComputeBudget = 6070,
    
    #[msg("Compute meter unavailable")]
    ComputeMeterUnavailable = 6071,

    // ═══════════════════════════════════════════════════════════════════════
    // Policy Errors (6080-6089)
    // ═══════════════════════════════════════════════════════════════════════
    #[msg("Policy expired")]
    PolicyExpired = 6080,

    #[msg("Invalid policy commitment")]
    InvalidPolicyCommitment = 6081,

    /// Verifier globally paused by authority. Closes WS-7 dead `paused` flag.
    #[msg("Verifier is paused")]
    Paused = 6082,

    /// Proof's committed expiry is in the past relative to on-chain Clock.
    /// Closes F-18, F-22.
    #[msg("Proof expired — committed expiry timestamp is in the past")]
    ProofExpired = 6083,

    /// Circuit image_id committed in proof does not match the agent's pinned
    /// image_id in `AgentRegistry`. Closes F-8.
    #[msg("Circuit image_id mismatch — proof generated with different circuit version")]
    ImageIdMismatch = 6084,

    /// Verifying-key integrity check failed (SHA-256 of `GLYPH_VK` does not
    /// match the hardcoded `GLYPH_VK_HASH`). Closes F-3.
    #[msg("Verifying key integrity check failed")]
    VkIntegrityFailed = 6085,

    // ═══════════════════════════════════════════════════════════════════════
    // Feature / Mode Errors (6090-6099)
    // ═══════════════════════════════════════════════════════════════════════
    #[msg("Dev mode not allowed in production")]
    DevModeNotAllowed = 6090,

    #[msg("Feature not yet implemented")]
    NotImplemented = 6091,

    // ═══════════════════════════════════════════════════════════════════════
    // VK lifecycle / multisig (6100-6109) — closes F-1, F-9, F-24, F-25
    // ═══════════════════════════════════════════════════════════════════════
    /// `VerifierVk` PDA has not been seeded yet (or was zeroed). The verifier
    /// refuses to process proofs in this state. Bootstrap via `seed_vk` (when
    /// `GLYPH_VK_REAL` is baked in) or via the multisig+timelock path.
    #[msg("VerifierVk PDA is uninitialized; rotate via multisig before verifying")]
    VkNotInitialized = 6100,

    /// Pending VK update has not satisfied the 24-hour timelock yet.
    #[msg("VK timelock has not elapsed (24h required between propose and execute)")]
    TimelockNotElapsed = 6101,

    /// Pending VK update has fewer approvals than the multisig threshold.
    #[msg("Insufficient multisig approvals to execute VK update")]
    InsufficientApprovals = 6102,

    /// Multisig configuration is invalid (e.g. threshold > signer_count, or
    /// duplicate signers).
    #[msg("Invalid multisig configuration")]
    InvalidMultisigConfig = 6103,

    /// The instruction signer is not one of the multisig signers.
    #[msg("Signer is not a member of the VK multisig")]
    NotAMultisigSigner = 6104,

    /// A VK update is already pending; reject double-propose.
    #[msg("A VK update is already pending; execute or wait for it to clear")]
    PendingUpdateExists = 6105,

    /// No pending VK update; cannot approve or execute.
    #[msg("No pending VK update to approve or execute")]
    NoPendingUpdate = 6106,

    /// Caller has already approved the pending update.
    #[msg("Signer has already approved this pending update")]
    AlreadyApproved = 6107,

    /// `prover_version` string exceeds the on-chain bound.
    #[msg("prover_version exceeds maximum length")]
    ProverVersionTooLong = 6108,

    /// `seed_vk` was called but `GLYPH_VK_REAL` is not baked into this build.
    #[msg("Real VK is not baked in; rebuild extract-vk against a real proof")]
    RealVkUnavailable = 6109,

    // ═══════════════════════════════════════════════════════════════════════
    // WS-8 circuit-coverage / failure surfacing (6113-6119 — last 3 reserved)
    // ═══════════════════════════════════════════════════════════════════════
    /// The circuit's `circuit_rule_bitmap` is missing one or more rules
    /// required by `RULE_REQUIRED_BITMAP`. Closes F-23.
    #[msg("Circuit rule bitmap is missing required rule(s) — proof under-covered")]
    InsufficientRuleCoverage = 6114,

    /// The circuit committed a non-zero `failure_code`. Closes F-33.
    /// The inner code (one of `CircuitFailureCode`) identifies which rule
    /// the guest decided fails the intent.
    #[msg("Circuit reported a policy-rule failure (see CircuitFailureCode)")]
    CircuitFailure = 6115,

    /// The delegator did not present a valid ed25519 signature over the
    /// canonical delegation payload during `register_agent`. Closes WS-9.
    #[msg("Delegator signature missing or invalid")]
    InvalidDelegatorSignature = 6116,

    /// `attested_timestamp` committed by the circuit deviates from the
    /// on-chain `Clock::unix_timestamp` by more than
    /// `ATTESTED_TIMESTAMP_MAX_DRIFT_SECS` (±5 min). Closes the WS-8 attested
    /// time-window enforcement path (proof must be paired with a fresh
    /// TEE-attested timestamp; an old or future timestamp is rejected).
    #[msg("Attested timestamp drift vs Clock exceeds ±300s — proof rejected")]
    AttestedTimestampDriftTooLarge = 6117,

    // ═══════════════════════════════════════════════════════════════════════
    // WS-6 audit anchor errors (6110-6119)
    // ═══════════════════════════════════════════════════════════════════════
    /// Audit root must be non-zero (genesis is meaningless to anchor).
    #[msg("Audit root must not be all-zeros")]
    InvalidAuditRoot = 6110,

    /// `anchored_at` deviates from the on-chain Clock by more than ±5 min.
    #[msg("Audit root anchored_at timestamp drift exceeds 5 minutes vs Clock")]
    AuditRootStale = 6111,

    /// Each commit must strictly increase `sequence_high`.
    #[msg("Audit sequence_high must monotonically increase across commits")]
    AuditSequenceMonotonicViolation = 6112,

    /// Anchor count counter overflowed u64. Realistically unreachable.
    #[msg("Audit anchor count overflowed u64")]
    AuditAnchorOverflow = 6113,
}

// Legacy error mapping for backwards compatibility
impl GlyphError {
    /// Returns true if this is a critical security error that should halt processing
    pub fn is_security_error(&self) -> bool {
        matches!(self,
            GlyphError::Groth16PairingFailed |
            GlyphError::PolicyCommitmentMismatch |
            GlyphError::TxHashBindingFailed |
            GlyphError::NonceAlreadyConsumed |
            GlyphError::Unauthorized |
            GlyphError::AgentNotActive |
            GlyphError::AttestationUserDataMismatch
        )
    }

    /// Returns true if this error suggests a compute budget issue
    pub fn is_compute_error(&self) -> bool {
        matches!(self,
            GlyphError::InsufficientComputeBudget |
            GlyphError::AltBn128SyscallFailed
        )
    }
}
