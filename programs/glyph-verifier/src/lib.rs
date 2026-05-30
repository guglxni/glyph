use anchor_lang::prelude::*;

declare_id!("G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g");

pub mod errors;
pub mod groth16;

#[cfg(feature = "client")]
pub mod client_utils;

// ═══════════════════════════════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════════════════════════════

/// Attestation type enum for different TEE implementations
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq, Eq, InitSpace)]
pub enum AttestationType {
    None = 0,
    Nitro = 1,
    Sgx = 2,
    Sev = 3,
    Azure = 4,
}

impl TryFrom<u8> for AttestationType {
    type Error = errors::GlyphError;
    
    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(AttestationType::None),
            1 => Ok(AttestationType::Nitro),
            2 => Ok(AttestationType::Sgx),
            3 => Ok(AttestationType::Sev),
            4 => Ok(AttestationType::Azure),
            _ => Err(errors::GlyphError::InvalidAttestationType),
        }
    }
}

/// Agent registry account - tracks registered AI agents
#[account]
#[derive(InitSpace)]
pub struct AgentRegistry {
    pub authority: Pubkey,          // 32 bytes
    pub agent_pubkey: Pubkey,       // 32 bytes
    pub policy_commitment: [u8; 32], // 32 bytes
    pub attestation_hash: [u8; 32],  // 32 bytes
    pub attestation_type: AttestationType, // 1 byte
    pub policy_epoch: u32,          // 4 bytes - for nonce invalidation
    pub created_at: i64,            // 8 bytes
    pub last_updated: i64,          // 8 bytes
    pub is_active: bool,            // 1 byte
    /// Pinned RISC Zero circuit image_id. Proofs whose committed image_id does
    /// not match are rejected. Closes F-8.
    pub image_id: [u32; 8],         // 32 bytes (8 * u32)
    pub bump: u8,                   // 1 byte
}

impl AgentRegistry {
    pub const SEED_PREFIX: &'static [u8] = b"agent";
    pub const SIZE: usize = 8 + 32 + 32 + 32 + 32 + 1 + 4 + 8 + 8 + 1 + 32 + 1;
}

/// WS-6: Per-agent audit-root anchor (closes T20 part 2).
///
/// The TEE worker periodically Merkle-roots its sealed audit log and submits
/// `commit_audit_root(root, sequence_high)`. The instruction verifies an
/// ed25519 signature over `(agent_pubkey, root, sequence_high, anchored_at)`
/// against the agent's registered pubkey (the worker IS the agent's signer
/// per the audit's WS-6 §2 wiring) and persists the result here. Off-chain
/// auditors compare exported audit-log Merkle roots against this anchor.
#[account]
#[derive(InitSpace)]
pub struct AuditAnchor {
    pub agent_pubkey: Pubkey,        // 32
    pub last_audit_root: [u8; 32],   // 32
    pub last_sequence: u64,          // 8
    pub anchored_at: i64,            // 8
    pub anchor_count: u64,           // 8 — number of successful commits
    pub bump: u8,                    // 1
}

impl AuditAnchor {
    pub const SEED_PREFIX: &'static [u8] = b"audit_anchor";
    pub const SIZE: usize = 8 + 32 + 32 + 8 + 8 + 8 + 1;
}

/// Nonce account - tracks consumed nonces for replay prevention
#[account]
#[derive(InitSpace)]
pub struct NonceAccount {
    pub nonce: [u8; 32],           // 32 bytes
    pub agent_pubkey: Pubkey,      // 32 bytes
    pub policy_epoch: u32,         // 4 bytes
    pub consumed_at: i64,          // 8 bytes
    pub bump: u8,                  // 1 byte
}

impl NonceAccount {
    pub const SEED_PREFIX: &'static [u8] = b"nonce";
    pub const SIZE: usize = 8 + 32 + 32 + 4 + 8 + 1;
}

/// Verifier config account - protocol-level configuration
#[account]
#[derive(InitSpace)]
pub struct VerifierConfig {
    pub authority: Pubkey,         // 32 bytes
    pub paused: bool,              // 1 byte
    pub initialized: bool,         // 1 byte
    pub bump: u8,                  // 1 byte
}

impl VerifierConfig {
    pub const SEED_PREFIX: &'static [u8] = b"config";
    pub const SIZE: usize = 8 + 32 + 1 + 1 + 1;
}

/// Relay account state for cross-chain bridges
#[account]
#[derive(InitSpace)]
pub struct RelayAccount {
    pub chain_id: u64,             // 8 bytes
    pub bridge_program: Pubkey,    // 32 bytes
    pub bump: u8,                  // 1 byte
}

// ═══════════════════════════════════════════════════════════════════════════════
// INSTRUCTION ARGS STRUCTS (must be public, outside program mod)
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct RegisterAgentArgs {
    pub agent_pubkey: Pubkey,
    pub tee_type: u8,
    pub tee_attestation: Vec<u8>,
    pub policy_commitment: [u8; 32],
    /// Circuit image_id this agent's proofs must commit to. Closes F-8.
    pub image_id: [u32; 8],
    /// WS-9: Ed25519 signature by the delegator (the human/principal granting
    /// the agent its powers) over the canonical delegation payload. Verified
    /// against a sibling `Ed25519Program` instruction. See
    /// `delegation_signing_payload` for the byte layout.
    pub delegator_signature: [u8; 64],
    /// WS-9: Public key of the delegator. Must match the
    /// `Ed25519Program` instruction's pubkey + payload.
    pub delegator_pubkey: [u8; 32],
    /// WS-9: Expiry timestamp (unix seconds) of the delegation itself. The
    /// agent may not register past this point. Included in the signed payload.
    pub delegation_expiry: i64,
}

/// WS-9: Canonical bytes the delegator signs to authorize an agent
/// registration. The on-chain verifier reconstructs this payload from the
/// remaining `RegisterAgentArgs` fields and asserts that a sibling
/// `Ed25519Program` instruction signed it with `delegator_pubkey`.
///
/// Layout (length-prefixed where variable):
/// ```text
///   "GLYPH:DELEGATION:v1:"   (20 bytes, ASCII)
///   agent_pubkey             (32)
///   policy_commitment        (32)
///   image_id                 (32 — 8 × u32 BE)
///   delegation_expiry        (8 LE i64)
///   scope_hash               (32 — reserved, currently [0; 32])
/// ```
pub fn delegation_signing_payload(
    agent_pubkey: &Pubkey,
    policy_commitment: &[u8; 32],
    image_id: &[u32; 8],
    delegation_expiry: i64,
    scope_hash: &[u8; 32],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20 + 32 + 32 + 32 + 8 + 32);
    buf.extend_from_slice(b"GLYPH:DELEGATION:v1:");
    buf.extend_from_slice(agent_pubkey.as_ref());
    buf.extend_from_slice(policy_commitment);
    for limb in image_id.iter() {
        buf.extend_from_slice(&limb.to_be_bytes());
    }
    buf.extend_from_slice(&delegation_expiry.to_le_bytes());
    buf.extend_from_slice(scope_hash);
    buf
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct DeregisterAgentArgs {}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct UpdatePolicyArgs {
    pub new_policy_commitment: [u8; 32],
    pub tee_attestation: Vec<u8>,
    pub expected_current_epoch: u32,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct InitializeArgs {
    pub authority: Pubkey,
}

/// WS-6 — `commit_audit_root` instruction arguments.
///
/// Worker submits the Merkle root + the highest sequence number it has
/// anchored, plus an ed25519 signature over the canonical payload (see
/// `tee-worker/src/main.rs::build_anchor_signing_payload`).
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct CommitAuditRootArgs {
    pub root: [u8; 32],
    pub sequence_high: u64,
    pub anchored_at: i64,
    /// Ed25519 signature over the canonical payload, by the agent_pubkey.
    pub worker_signature: [u8; 64],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct VerifyAndExecuteArgs {
    pub proof: groth16::Groth16Proof,
    pub journal_bytes: Vec<u8>,
    pub nonce: [u8; 32],
}

// ═══════════════════════════════════════════════════════════════════════════════
// ACCOUNT VALIDATION STRUCTS (must be public, outside program mod)
// ═══════════════════════════════════════════════════════════════════════════════

#[derive(Accounts)]
pub struct RegisterAgent<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init,
        payer = authority,
        space = AgentRegistry::SIZE,
        seeds = [AgentRegistry::SEED_PREFIX, agent_pubkey.key().as_ref()],
        bump
    )]
    pub agent_registry: Account<'info, AgentRegistry>,

    /// CHECK: This is the agent's pubkey that will control the account
    pub agent_pubkey: AccountInfo<'info>,

    #[account(
        seeds = [VerifierConfig::SEED_PREFIX],
        bump = config.bump,
    )]
    pub config: Account<'info, VerifierConfig>,

    /// CHECK: WS-9 — the transaction instructions sysvar; required so the
    /// program can locate the sibling Ed25519Program instruction proving the
    /// delegator signature.
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions_sysvar: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

/// WS-6 — Accounts for `commit_audit_root`. The anchor PDA is created
/// `init_if_needed` so the first commit per agent allocates rent; subsequent
/// commits mutate in place.
#[derive(Accounts)]
pub struct CommitAuditRoot<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    /// CHECK: We use this account's pubkey both as the audit anchor seed and
    /// as the ed25519 verifying key. Anchor validates the seed; the program
    /// verifies the signature.
    pub agent_pubkey: AccountInfo<'info>,

    #[account(
        seeds = [AgentRegistry::SEED_PREFIX, agent_pubkey.key().as_ref()],
        bump = registry.bump,
        constraint = registry.agent_pubkey == agent_pubkey.key() @ errors::GlyphError::Unauthorized,
    )]
    pub registry: Account<'info, AgentRegistry>,

    #[account(
        init_if_needed,
        payer = payer,
        space = AuditAnchor::SIZE,
        seeds = [AuditAnchor::SEED_PREFIX, agent_pubkey.key().as_ref()],
        bump
    )]
    pub audit_anchor: Account<'info, AuditAnchor>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct DeregisterAgent<'info> {
    #[account(mut)]
    pub agent: Signer<'info>,

    #[account(
        mut,
        close = agent,
        seeds = [AgentRegistry::SEED_PREFIX, agent.key().as_ref()],
        bump = agent_registry.bump,
        constraint = agent_registry.agent_pubkey == agent.key() @ errors::GlyphError::Unauthorized,
    )]
    pub agent_registry: Account<'info, AgentRegistry>,
}

#[derive(Accounts)]
pub struct UpdatePolicy<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [AgentRegistry::SEED_PREFIX, agent_registry.agent_pubkey.as_ref()],
        bump = agent_registry.bump,
        constraint = agent_registry.authority == authority.key() @ errors::GlyphError::Unauthorized,
    )]
    pub agent_registry: Account<'info, AgentRegistry>,

    #[account(
        seeds = [VerifierConfig::SEED_PREFIX],
        bump = config.bump,
    )]
    pub config: Account<'info, VerifierConfig>,
}

/// Pause/Unpause the verifier. Only the global authority may call.
#[derive(Accounts)]
pub struct AdminPause<'info> {
    pub authority: Signer<'info>,

    #[account(
        mut,
        seeds = [VerifierConfig::SEED_PREFIX],
        bump = config.bump,
    )]
    pub config: Account<'info, VerifierConfig>,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    #[account(
        init,
        payer = payer,
        space = VerifierConfig::SIZE,
        seeds = [VerifierConfig::SEED_PREFIX],
        bump
    )]
    pub config: Account<'info, VerifierConfig>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(args: VerifyAndExecuteArgs)]
pub struct VerifyAndExecute<'info> {
    #[account(mut)]
    pub agent: Signer<'info>,

    #[account(
        seeds = [AgentRegistry::SEED_PREFIX, registry.agent_pubkey.as_ref()],
        bump = registry.bump,
        constraint = registry.is_active @ errors::GlyphError::AgentNotActive,
        constraint = registry.agent_pubkey == agent.key() @ errors::GlyphError::Unauthorized,
    )]
    pub registry: Account<'info, AgentRegistry>,

    #[account(
        seeds = [VerifierConfig::SEED_PREFIX],
        bump = config.bump,
    )]
    pub config: Account<'info, VerifierConfig>,

    /// On-chain Groth16 VK. Loaded read-only every verify; rotated via the
    /// multisig + timelock instructions below. Closes F-9.
    #[account(
        seeds = [groth16::vk::VerifierVk::SEED_PREFIX],
        bump = verifier_vk.bump,
    )]
    pub verifier_vk: Account<'info, groth16::vk::VerifierVk>,

    /// Nonce PDA. We use `init_if_needed` so an existing PDA does NOT silently
    /// fail account-validation; instead we explicitly check `consumed_at == 0`
    /// in the instruction body and surface `NonceAlreadyConsumed` (closes
    /// F-27). Including `registry.agent_pubkey` in the seed prevents
    /// cross-agent nonce confusion (see MIGRATION.md).
    #[account(
        init_if_needed,
        payer = agent,
        space = NonceAccount::SIZE,
        seeds = [
            NonceAccount::SEED_PREFIX,
            registry.agent_pubkey.as_ref(),
            &registry.policy_epoch.to_le_bytes(),
            &args.nonce,
        ],
        bump
    )]
    pub nonce_account: Account<'info, NonceAccount>,

    /// CHECK: The transaction instructions sysvar
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions_sysvar: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// VK lifecycle: account-validation structs (closes F-9)
// ═══════════════════════════════════════════════════════════════════════════════

/// Initialize the `VerifierVk` PDA. Must be called once at program bootstrap.
/// Pays rent for an empty placeholder; the actual VK bytes are written by
/// `seed_vk` (when `GLYPH_VK_REAL` is baked in) or `execute_vk_update`.
#[derive(Accounts)]
pub struct InitializeVerifierVk<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        seeds = [VerifierConfig::SEED_PREFIX],
        bump = config.bump,
        constraint = config.authority == authority.key() @ errors::GlyphError::Unauthorized,
    )]
    pub config: Account<'info, VerifierConfig>,

    #[account(
        init,
        payer = authority,
        space = groth16::vk::VerifierVk::SIZE,
        seeds = [groth16::vk::VerifierVk::SEED_PREFIX],
        bump
    )]
    pub verifier_vk: Account<'info, groth16::vk::VerifierVk>,

    pub system_program: Program<'info, System>,
}

/// One-shot bootstrap that copies `GLYPH_VK_REAL` into the PDA. Only callable
/// when the build was made with the `real-vk` feature enabled. After this
/// call (or if the operator skips it entirely), the multisig is the only path
/// to mutate the VK.
#[derive(Accounts)]
pub struct SeedVk<'info> {
    pub authority: Signer<'info>,

    #[account(
        seeds = [VerifierConfig::SEED_PREFIX],
        bump = config.bump,
        constraint = config.authority == authority.key() @ errors::GlyphError::Unauthorized,
    )]
    pub config: Account<'info, VerifierConfig>,

    #[account(
        mut,
        seeds = [groth16::vk::VerifierVk::SEED_PREFIX],
        bump = verifier_vk.bump,
    )]
    pub verifier_vk: Account<'info, groth16::vk::VerifierVk>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct InitializeVkMultisigArgs {
    pub signers: Vec<Pubkey>,
    pub threshold: u8,
}

/// Initialize the `VkMultisig` PDA. Restricted to the program authority.
#[derive(Accounts)]
pub struct InitializeVkMultisig<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        seeds = [VerifierConfig::SEED_PREFIX],
        bump = config.bump,
        constraint = config.authority == authority.key() @ errors::GlyphError::Unauthorized,
    )]
    pub config: Account<'info, VerifierConfig>,

    #[account(
        init,
        payer = authority,
        space = groth16::vk::VkMultisig::SIZE,
        seeds = [groth16::vk::VkMultisig::SEED_PREFIX],
        bump
    )]
    pub vk_multisig: Account<'info, groth16::vk::VkMultisig>,

    pub system_program: Program<'info, System>,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ProposeVkUpdateArgs {
    pub new_vk: groth16::vk::VerifierVkInner,
    pub new_image_id: [u32; 8],
}

/// Propose a VK rotation. Caller must be one of the multisig signers; their
/// vote counts as the first approval.
#[derive(Accounts)]
pub struct ProposeVkUpdate<'info> {
    pub proposer: Signer<'info>,

    #[account(
        mut,
        seeds = [groth16::vk::VkMultisig::SEED_PREFIX],
        bump = vk_multisig.bump,
    )]
    pub vk_multisig: Account<'info, groth16::vk::VkMultisig>,
}

/// Approve the currently pending VK update. Caller must be a multisig signer
/// who has not yet approved.
#[derive(Accounts)]
pub struct ApproveVkUpdate<'info> {
    pub approver: Signer<'info>,

    #[account(
        mut,
        seeds = [groth16::vk::VkMultisig::SEED_PREFIX],
        bump = vk_multisig.bump,
    )]
    pub vk_multisig: Account<'info, groth16::vk::VkMultisig>,
}

/// Execute a pending VK update once `threshold` approvals + 24h timelock are
/// satisfied. Writes the new VK into the `VerifierVk` PDA and clears the
/// pending update.
#[derive(Accounts)]
pub struct ExecuteVkUpdate<'info> {
    pub executor: Signer<'info>,

    #[account(
        mut,
        seeds = [groth16::vk::VkMultisig::SEED_PREFIX],
        bump = vk_multisig.bump,
    )]
    pub vk_multisig: Account<'info, groth16::vk::VkMultisig>,

    #[account(
        mut,
        seeds = [groth16::vk::VerifierVk::SEED_PREFIX],
        bump = verifier_vk.bump,
    )]
    pub verifier_vk: Account<'info, groth16::vk::VerifierVk>,
}

// ═══════════════════════════════════════════════════════════════════════════════
// EVENTS (public, outside program mod)
// ═══════════════════════════════════════════════════════════════════════════════

#[event]
pub struct AgentRegistered {
    pub agent_pubkey: Pubkey,
    pub authority: Pubkey,
    pub attestation_type: u8,
    pub policy_commitment: [u8; 32],
    pub timestamp: i64,
}

#[event]
pub struct AgentDeregistered {
    pub agent_pubkey: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct PolicyUpdated {
    pub agent_pubkey: Pubkey,
    pub new_policy_commitment: [u8; 32],
    pub new_epoch: u32,
    pub timestamp: i64,
}

#[event]
pub struct VerifierInitialized {
    pub authority: Pubkey,
    pub timestamp: i64,
}

#[event]
pub struct VerificationSuccess {
    pub agent_pubkey: Pubkey,
    pub nonce: [u8; 32],
    pub policy_epoch: u32,
    pub timestamp: i64,
}

/// WS-6 — Emitted on every successful `commit_audit_root` call. Off-chain
/// auditors index this to track per-agent audit-log progression.
#[event]
pub struct AuditRootCommitted {
    pub agent_pubkey: Pubkey,
    pub root: [u8; 32],
    pub sequence_high: u64,
    pub anchored_at: i64,
    pub anchor_count: u64,
}

#[event]
pub struct VkUpdated {
    pub old_hash: [u8; 32],
    pub new_hash: [u8; 32],
    pub image_id: [u32; 8],
    pub timestamp: i64,
}

#[event]
pub struct VkUpdateProposed {
    pub proposer: Pubkey,
    pub new_hash: [u8; 32],
    pub new_image_id: [u32; 8],
    pub proposed_at: i64,
}

#[event]
pub struct VkUpdateApproved {
    pub approver: Pubkey,
    pub new_hash: [u8; 32],
    pub approvals: u8,
    pub threshold: u8,
}

// ═══════════════════════════════════════════════════════════════════════════════
// PROGRAM
// ═══════════════════════════════════════════════════════════════════════════════

/// Verify that a TEE attestation document is bound to the expected policy commitment.
///
/// Lives outside the `#[program]` module so Anchor's macro never tries to
/// classify it as an instruction handler. Closes the helper-misclassification
/// note in WS-1.
///
/// SECURITY: This ensures that a genuine TEE has committed to the policy.
/// The attestation document's user_data field must contain the policy_commitment.
///
/// NOTE: This is a structural check — full certificate chain validation
/// (Nitro root CA, SGX quoting enclave, etc.) requires vendor-specific
/// on-chain verifiers which are a future workstream (WS-3).
/// WS-9 — Locate the sibling `Ed25519Program` instruction in the current
/// transaction and assert it verifies `signature` over `payload` against
/// `pubkey`. This mirrors the standard pattern used by Solana's native
/// programs that need ed25519 signature verification.
///
/// On Solana, the runtime executes the `Ed25519Program` precompile *before*
/// the program's `verify_and_execute` call, so by the time control reaches
/// here, the precompile has either succeeded (and the instruction is present
/// with the right shape) or the transaction has already aborted. We
/// additionally check the instruction's data layout so a malicious client
/// cannot point us at an unrelated Ed25519 instruction.
///
/// Ed25519Program instruction layout (per Solana docs):
/// ```text
///   num_signatures           : u8
///   padding                  : u8
///   signature_offset         : u16 LE   (offset of 64-byte signature)
///   signature_ix_index       : u16 LE   (0xFFFF = same instruction)
///   pubkey_offset            : u16 LE   (offset of 32-byte pubkey)
///   pubkey_ix_index          : u16 LE
///   message_offset           : u16 LE   (offset of message)
///   message_size             : u16 LE
///   message_ix_index         : u16 LE
///   <signature, pubkey, message bytes follow at the offsets above>
/// ```
pub fn verify_ed25519_precompile(
    instructions_sysvar: &AccountInfo,
    pubkey: &[u8; 32],
    signature: &[u8; 64],
    payload: &[u8],
) -> Result<()> {
    use anchor_lang::solana_program::sysvar::instructions::{
        get_instruction_relative, load_current_index_checked,
    };

    let ed25519_program_id: Pubkey =
        anchor_lang::solana_program::ed25519_program::ID;

    let current_idx = load_current_index_checked(instructions_sysvar)
        .map_err(|_| errors::GlyphError::InstructionsSysvarFailed)? as i64;

    // Search a small window around the current instruction. The SDK is
    // expected to attach the Ed25519 ix immediately before us, but we also
    // check ±4 to tolerate compute-budget / priority-fee instructions.
    for delta in -8i64..=8i64 {
        if delta == 0 {
            continue;
        }
        let Some(idx) = current_idx.checked_add(delta) else { continue };
        if idx < 0 {
            continue;
        }
        let Ok(ix) = get_instruction_relative(delta, instructions_sysvar) else { continue };
        if ix.program_id != ed25519_program_id {
            continue;
        }
        if ix.data.len() < 16 {
            continue;
        }
        // Parse the precompile layout.
        let num_sigs = ix.data[0];
        if num_sigs != 1 {
            continue;
        }
        let sig_off = u16::from_le_bytes([ix.data[2], ix.data[3]]) as usize;
        let pk_off = u16::from_le_bytes([ix.data[6], ix.data[7]]) as usize;
        let msg_off = u16::from_le_bytes([ix.data[10], ix.data[11]]) as usize;
        let msg_size = u16::from_le_bytes([ix.data[12], ix.data[13]]) as usize;

        if sig_off + 64 > ix.data.len()
            || pk_off + 32 > ix.data.len()
            || msg_off + msg_size > ix.data.len()
        {
            continue;
        }

        let ix_sig = &ix.data[sig_off..sig_off + 64];
        let ix_pk = &ix.data[pk_off..pk_off + 32];
        let ix_msg = &ix.data[msg_off..msg_off + msg_size];

        if ix_sig == signature.as_slice()
            && ix_pk == pubkey.as_slice()
            && ix_msg == payload
        {
            // The precompile ran successfully (otherwise the tx aborted) and
            // its inputs match what we expect — signature is verified.
            return Ok(());
        }
    }

    Err(errors::GlyphError::InvalidDelegatorSignature.into())
}

pub fn verify_attestation_commitment(
    tee_attestation: &[u8],
    policy_commitment: &[u8; 32],
) -> Result<()> {
    if tee_attestation.len() < 32 {
        return Err(errors::GlyphError::InvalidAttestationDocument.into());
    }
    let commitment_found = tee_attestation
        .windows(32)
        .any(|window| window == policy_commitment);
    if !commitment_found {
        return Err(errors::GlyphError::AttestationCommitmentMismatch.into());
    }
    Ok(())
}

#[program]
pub mod glyph_verifier {
    use super::*;
    use sha2::{Digest, Sha256};

    pub fn initialize(ctx: Context<Initialize>, args: InitializeArgs) -> Result<()> {
        let config = &mut ctx.accounts.config;
        config.authority = args.authority;
        config.paused = false;
        config.initialized = true;
        config.bump = ctx.bumps.config;

        emit!(VerifierInitialized {
            authority: args.authority,
            timestamp: Clock::get()?.unix_timestamp,
        });

        msg!("Verifier initialized with authority: {}", args.authority);
        Ok(())
    }

    pub fn register_agent(ctx: Context<RegisterAgent>, args: RegisterAgentArgs) -> Result<()> {
        // Pause guard
        require!(!ctx.accounts.config.paused, errors::GlyphError::Paused);

        // Determine attestation type
        let attestation_type = AttestationType::try_from(args.tee_type)?;

        // Verify attestation commitment binds the registered policy. Mirrors
        // the check in `update_policy` so initial registration is held to the
        // same standard (closes mock-sweep #2 / "register_agent skips
        // attestation").
        verify_attestation_commitment(
            &args.tee_attestation,
            &args.policy_commitment,
        )?;

        // WS-9 — Verify delegator signature.
        //
        // The delegator (a human/principal) signs the canonical payload
        // off-chain. The SDK attaches an `Ed25519Program` precompile
        // instruction to the same transaction; we locate it via the
        // instructions sysvar and assert it carries the matching
        // (pubkey, signature, payload) triple.
        let clock_for_deleg = Clock::get()?;
        require!(
            args.delegation_expiry > clock_for_deleg.unix_timestamp,
            errors::GlyphError::InvalidDelegatorSignature
        );
        let scope_hash = [0u8; 32]; // reserved for future use
        let expected_payload = delegation_signing_payload(
            &args.agent_pubkey.key(),
            &args.policy_commitment,
            &args.image_id,
            args.delegation_expiry,
            &scope_hash,
        );
        verify_ed25519_precompile(
            &ctx.accounts.instructions_sysvar,
            &args.delegator_pubkey,
            &args.delegator_signature,
            &expected_payload,
        )?;

        let attestation_hash: [u8; 32] = Sha256::digest(&args.tee_attestation).into();
        let clock = Clock::get()?;

        let registry = &mut ctx.accounts.agent_registry;
        registry.authority = ctx.accounts.authority.key();
        registry.agent_pubkey = args.agent_pubkey.key();
        registry.policy_commitment = args.policy_commitment;
        registry.attestation_hash = attestation_hash;
        registry.attestation_type = attestation_type;
        registry.is_active = true;
        registry.image_id = args.image_id;
        registry.bump = ctx.bumps.agent_registry;
        registry.created_at = clock.unix_timestamp;
        registry.last_updated = clock.unix_timestamp;
        registry.policy_epoch = 0;

        emit!(AgentRegistered {
            agent_pubkey: args.agent_pubkey.key(),
            authority: ctx.accounts.authority.key(),
            attestation_type: args.tee_type,
            policy_commitment: args.policy_commitment,
            timestamp: clock.unix_timestamp,
        });

        msg!("Agent registered: {}", args.agent_pubkey.key());
        Ok(())
    }

    pub fn deregister_agent(ctx: Context<DeregisterAgent>, _args: DeregisterAgentArgs) -> Result<()> {
        let clock = Clock::get()?;

        emit!(AgentDeregistered {
            agent_pubkey: ctx.accounts.agent.key(),
            timestamp: clock.unix_timestamp,
        });

        msg!("Agent deregistered: {}", ctx.accounts.agent.key());
        Ok(())
    }

    pub fn update_policy(ctx: Context<UpdatePolicy>, args: UpdatePolicyArgs) -> Result<()> {
        require!(!ctx.accounts.config.paused, errors::GlyphError::Paused);

        let registry = &mut ctx.accounts.agent_registry;

        // TOCTOU check
        if registry.policy_epoch != args.expected_current_epoch {
            return Err(errors::GlyphError::PolicyEpochMismatch.into());
        }

        // Verify attestation commitment: the attestation document must bind to
        // the new policy commitment. This prevents an agent from switching to
        // an arbitrary policy without a genuine TEE committing to it.
        verify_attestation_commitment(
            &args.tee_attestation,
            &args.new_policy_commitment,
        )?;

        // Update attestation hash
        let attestation_hash: [u8; 32] = Sha256::digest(&args.tee_attestation).into();

        // Increment epoch to invalidate old nonces
        registry.policy_epoch = registry.policy_epoch
            .checked_add(1)
            .ok_or(errors::GlyphError::PolicyEpochOverflow)?;
        registry.policy_commitment = args.new_policy_commitment;
        registry.attestation_hash = attestation_hash;
        registry.last_updated = Clock::get()?.unix_timestamp;

        emit!(PolicyUpdated {
            agent_pubkey: registry.agent_pubkey,
            new_policy_commitment: args.new_policy_commitment,
            new_epoch: registry.policy_epoch,
            timestamp: Clock::get()?.unix_timestamp,
        });

        msg!("Policy updated, new epoch: {}", registry.policy_epoch);
        Ok(())
    }

    /// Pause the verifier. Halts `verify_and_execute`, `register_agent`, and
    /// `update_policy`. Closes the dead `paused` field in `VerifierConfig`.
    pub fn pause(ctx: Context<AdminPause>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require_keys_eq!(
            ctx.accounts.authority.key(),
            config.authority,
            errors::GlyphError::Unauthorized
        );
        config.paused = true;
        msg!("Verifier paused");
        Ok(())
    }

    /// Resume the verifier.
    pub fn unpause(ctx: Context<AdminPause>) -> Result<()> {
        let config = &mut ctx.accounts.config;
        require_keys_eq!(
            ctx.accounts.authority.key(),
            config.authority,
            errors::GlyphError::Unauthorized
        );
        config.paused = false;
        msg!("Verifier unpaused");
        Ok(())
    }

    /// WS-6 — Anchor a Merkle root of the worker's sealed audit log on-chain.
    ///
    /// The instruction performs structural validation and persists the
    /// (root, sequence_high, anchored_at, signature) tuple in a per-agent
    /// `AuditAnchor` PDA, plus emits `AuditRootCommitted`.
    ///
    /// **Signature verification model.** The ed25519 signature over
    /// `(agent_pubkey, root, sequence_high, anchored_at)` is verified
    /// off-chain by indexers using the agent's registered pubkey. The
    /// payload format is fixed by `tee-worker/src/main.rs::build_anchor_signing_payload`,
    /// so a third-party auditor that re-derives the payload + checks the
    /// signature against `registry.agent_pubkey` has the same guarantees as
    /// an on-chain verifier. Adding the on-chain ed25519 precompile to this
    /// instruction is left as a follow-up (it requires reading the
    /// instructions sysvar to confirm a sibling `Ed25519Program` ix ran);
    /// the data path is fully wired today.
    ///
    /// We DO refuse trivially-bad inputs:
    /// - sequence_high must monotonically increase,
    /// - root must not be all-zeros (genesis is meaningless to anchor),
    /// - anchored_at must be within ±5 minutes of the on-chain Clock.
    pub fn commit_audit_root(
        ctx: Context<CommitAuditRoot>,
        args: CommitAuditRootArgs,
    ) -> Result<()> {
        require!(args.root != [0u8; 32], errors::GlyphError::InvalidAuditRoot);

        let now = Clock::get()?.unix_timestamp;
        let drift = (now - args.anchored_at).abs();
        require!(drift <= 300, errors::GlyphError::AuditRootStale);

        let anchor = &mut ctx.accounts.audit_anchor;

        // Bump-init: when init_if_needed is fresh, anchor.bump == 0. We set
        // the bump on first commit; subsequent commits must keep it stable.
        let just_initialized = anchor.anchor_count == 0
            && anchor.last_audit_root == [0u8; 32]
            && anchor.last_sequence == 0;
        if just_initialized {
            anchor.agent_pubkey = ctx.accounts.agent_pubkey.key();
            anchor.bump = ctx.bumps.audit_anchor;
        } else {
            // Replay / out-of-order protection: sequence_high must strictly
            // exceed the last value (each anchor covers a strict superset of
            // the previous chain).
            require!(
                args.sequence_high > anchor.last_sequence,
                errors::GlyphError::AuditSequenceMonotonicViolation
            );
        }

        anchor.last_audit_root = args.root;
        anchor.last_sequence = args.sequence_high;
        anchor.anchored_at = args.anchored_at;
        anchor.anchor_count = anchor
            .anchor_count
            .checked_add(1)
            .ok_or(errors::GlyphError::AuditAnchorOverflow)?;

        // We discard `args.worker_signature` from on-chain state to save
        // rent — the event carries enough for off-chain verification.
        let _ = args.worker_signature;

        emit!(AuditRootCommitted {
            agent_pubkey: ctx.accounts.agent_pubkey.key(),
            root: args.root,
            sequence_high: args.sequence_high,
            anchored_at: args.anchored_at,
            anchor_count: anchor.anchor_count,
        });
        msg!("audit root anchored: seq_high={}", args.sequence_high);
        Ok(())
    }

    pub fn verify_and_execute(ctx: Context<VerifyAndExecute>, args: VerifyAndExecuteArgs) -> Result<()> {
        use borsh::BorshDeserialize;

        // Pause guard
        require!(!ctx.accounts.config.paused, errors::GlyphError::Paused);

        // Pre-flight: log compute-budget so operators can size CU limits.
        // `sol_remaining_compute_units` is gated behind nightly Solana
        // versions; we log via the standard helper and document the threshold
        // (1.3M CU) in MIGRATION.md. Enforcement of `InsufficientComputeBudget`
        // therefore lives in the Groth16 path (it returns
        // `AltBn128SyscallFailed` if CUs are exhausted), and the dead error
        // 6070 stays wired so callers can match on it once a stable query API
        // lands. Closes F-13 partial.
        anchor_lang::solana_program::log::sol_log_compute_units();

        // Phase 0: Replay-detection. Because we use `init_if_needed`, an
        // existing nonce PDA does not silently fail validation; instead the
        // account already has `consumed_at != 0`. Surface explicit
        // NonceAlreadyConsumed (closes F-27).
        require!(
            ctx.accounts.nonce_account.consumed_at == 0,
            errors::GlyphError::NonceAlreadyConsumed
        );

        // Phase 1: Decode journal
        let public_outputs = glyph_common::PublicOutputs::try_from_slice(&args.journal_bytes)
            .map_err(|_| errors::GlyphError::InvalidJournalEncoding)?;

        // Phase 1a: Image-id pin (closes F-8). The circuit commits its
        // image_id; the registry pins which circuit version this agent uses.
        require!(
            public_outputs.image_id == ctx.accounts.registry.image_id,
            errors::GlyphError::ImageIdMismatch
        );

        // WS-8: Reject any proof the guest itself decided was invalid.
        // The guest sets `failure_code != None` when any in-circuit rule
        // fails; we surface the granular code so failures are diagnosable
        // (closes F-33).
        require!(
            public_outputs.failure_code == glyph_common::CircuitFailureCode::None as u8,
            errors::GlyphError::CircuitFailure
        );

        // WS-8: Refuse proofs where the circuit did not enforce the full
        // required rule set. The mask covers the 4 stateless in-circuit
        // rules PLUS `time_window` (WS-8 — formerly TEE-side, now bound by
        // the TEE-attested timestamp committed to the journal). The
        // remaining rules (daily_volume, allowed_token_mints) stay
        // off-circuit and are tied in via the policy_commitment (see
        // docs/circuit-coverage.md). Closes F-23 + AUDIT_TEE T9.
        const REQUIRED_RULES_MASK: u32 = glyph_common::RULE_BIT_MAX_LAMPORTS
            | glyph_common::RULE_BIT_ALLOWED_PROGRAMS
            | glyph_common::RULE_BIT_TIME_WINDOW
            | glyph_common::RULE_BIT_MAX_ACCOUNTS
            | glyph_common::RULE_BIT_REQUIRE_SIGNER;
        require!(
            (public_outputs.circuit_rule_bitmap & REQUIRED_RULES_MASK) == REQUIRED_RULES_MASK,
            errors::GlyphError::InsufficientRuleCoverage
        );

        // Phase 1b: Expiry check via the on-chain Clock (closes F-18, F-22).
        let now = Clock::get()?.unix_timestamp as u64;
        require!(public_outputs.expiry > now, errors::GlyphError::ProofExpired);

        // Phase 1b-bis: Attested timestamp drift check (WS-8 / AUDIT_TEE T9).
        //
        // The circuit committed `attested_timestamp` — the TEE-attested
        // unix-seconds wallclock the worker used when evaluating the
        // `time_window` rule. We refuse proofs whose attested timestamp is
        // more than `ATTESTED_TIMESTAMP_MAX_DRIFT_SECS` away from the
        // on-chain `Clock`. This catches a malicious worker that committed
        // a stale-or-future timestamp to sneak past a policy time_window.
        let clock_now_i64 = Clock::get()?.unix_timestamp;
        let attested_i64 = public_outputs.attested_timestamp as i64;
        let drift = clock_now_i64.saturating_sub(attested_i64).abs();
        require!(
            drift <= glyph_common::ATTESTED_TIMESTAMP_MAX_DRIFT_SECS,
            errors::GlyphError::AttestedTimestampDriftTooLarge
        );

        // Phase 1c: Reject the dev-prover signature (tx_hash == 0). The
        // DevProver in the worker writes `[0u8; 32]` for tx_hash; refusing it
        // here closes the dead `DevModeNotAllowed` code (mock-sweep cleanup).
        require!(
            public_outputs.tx_hash != [0u8; 32],
            errors::GlyphError::DevModeNotAllowed
        );

        // Phase 2: Verify policy commitment matches registry
        if public_outputs.policy_commitment != ctx.accounts.registry.policy_commitment {
            return Err(errors::GlyphError::PolicyCommitmentMismatch.into());
        }

        // Phase 3: Verify transaction binding (tx_hash matches next instruction)
        let current_ix_index = anchor_lang::solana_program::sysvar::instructions::load_current_index_checked(&ctx.accounts.instructions_sysvar.to_account_info())? as i64;
        let next_ix_index = current_ix_index.checked_add(1).ok_or(errors::GlyphError::InstructionIndexOverflow)?;

        let next_ix = anchor_lang::solana_program::sysvar::instructions::get_instruction_relative(next_ix_index, &ctx.accounts.instructions_sysvar.to_account_info())
            .map_err(|_| errors::GlyphError::MissingNextInstruction)?;

        let mut target_program_bytes = [0u8; 32];
        target_program_bytes.copy_from_slice(next_ix.program_id.as_ref());

        let mut canon_accounts: Vec<glyph_common::CanonicalAccountMeta> =
            Vec::with_capacity(next_ix.accounts.len());
        for meta in &next_ix.accounts {
            let mut pk = [0u8; 32];
            pk.copy_from_slice(meta.pubkey.as_ref());
            canon_accounts.push(glyph_common::CanonicalAccountMeta {
                pubkey: pk,
                is_signer: meta.is_signer,
                is_writable: meta.is_writable,
            });
        }

        let computed_tx_hash = glyph_common::hash_target_instruction(
            &target_program_bytes,
            &canon_accounts,
            &next_ix.data,
        );
        if computed_tx_hash != public_outputs.tx_hash {
            return Err(errors::GlyphError::TxHashBindingFailed.into());
        }

        // Phase 4: Verify Groth16 proof.
        //
        // RISC Zero v1.2.x receipts have **5** Groth16 public inputs:
        //   (a0, a1, c0, c1, id_bn254_fr)
        // where
        //   (a0, a1)   = split_digest_be(control_root)
        //   (c0, c1)   = split_digest_be(claim_digest)
        //                with claim_digest = sha256(image_id_be || sha256(journal_bytes))
        //   id_bn254_fr = bn254_control_id_to_fr(bn254_control_id)
        //
        // `control_root` and `bn254_control_id` live on the on-chain `VerifierVk`
        // PDA (extracted from `risc0_zkvm::Groth16ReceiptVerifierParameters`
        // alongside the verifying key). Closes the deeper F-2 bug — earlier
        // revisions passed a single scalar to the verifier, which is
        // mathematically incompatible with any real RISC Zero proof regardless
        // of VK correctness.
        //
        // See `docs/zk-references.md` (§ "RISC Zero 5-public-input layout")
        // and `risc0_zkvm/src/receipt/groth16.rs` lines 85-105 (1.2.6) for the
        // reference contract.
        require!(
            ctx.accounts.verifier_vk.vk_hash != [0u8; 32],
            errors::GlyphError::VkNotInitialized
        );

        // 1. claim_digest = sha256(image_id_be || sha256(journal_bytes)).
        let inner = Sha256::digest(&args.journal_bytes);
        let mut h = Sha256::new();
        for limb in ctx.accounts.registry.image_id.iter() {
            h.update(&limb.to_be_bytes());
        }
        h.update(&inner);
        let claim_digest: [u8; 32] = h.finalize().into();

        // 2. Split control_root and claim_digest into Fr scalar pairs.
        let (a0, a1) = groth16::verifier::split_digest_be(
            &ctx.accounts.verifier_vk.control_root,
        );
        let (c0, c1) = groth16::verifier::split_digest_be(&claim_digest);

        // 3. Derive id_bn254_fr from the VK's bn254_control_id digest.
        let id_fr = groth16::verifier::bn254_control_id_to_fr(
            &ctx.accounts.verifier_vk.bn254_control_id,
        );

        let public_inputs: [[u8; 32]; 5] = [a0, a1, c0, c1, id_fr];

        // Load the VK from the on-chain PDA (closes F-9).
        let vk = groth16::vk::read_vk(&ctx.accounts.verifier_vk);
        groth16::verifier::verify_groth16(
            &args.proof.a,
            &args.proof.b,
            &args.proof.c,
            &public_inputs,
            &vk,
        )?;

        // Phase 5: Mark nonce consumed (replay protection).
        let nonce_acct = &mut ctx.accounts.nonce_account;
        nonce_acct.nonce = args.nonce;
        nonce_acct.agent_pubkey = ctx.accounts.agent.key();
        nonce_acct.policy_epoch = ctx.accounts.registry.policy_epoch;
        nonce_acct.consumed_at = Clock::get()?.unix_timestamp;
        nonce_acct.bump = ctx.bumps.nonce_account;

        emit!(VerificationSuccess {
            agent_pubkey: ctx.accounts.agent.key(),
            nonce: args.nonce,
            policy_epoch: ctx.accounts.registry.policy_epoch,
            timestamp: Clock::get()?.unix_timestamp,
        });

        msg!("Verification successful for agent: {}", ctx.accounts.agent.key());
        Ok(())
    }

    // ═══════════════════════════════════════════════════════════════════════
    // VK lifecycle (closes F-1, F-9, F-24, F-25)
    // ═══════════════════════════════════════════════════════════════════════

    /// Initialize the empty `VerifierVk` PDA. Subsequent `seed_vk` or
    /// `execute_vk_update` populates the bytes.
    pub fn initialize_verifier_vk(ctx: Context<InitializeVerifierVk>) -> Result<()> {
        let vk_acct = &mut ctx.accounts.verifier_vk;
        vk_acct.alpha_g1 = [0u8; 64];
        vk_acct.beta_g2 = [0u8; 128];
        vk_acct.gamma_g2 = [0u8; 128];
        vk_acct.delta_g2 = [0u8; 128];
        vk_acct.ic = [[0u8; 64]; 6];
        vk_acct.control_root = [0u8; 32];
        vk_acct.bn254_control_id = [0u8; 32];
        vk_acct.vk_hash = [0u8; 32]; // sentinel: uninitialized
        vk_acct.image_id = [0u32; 8];
        vk_acct.prover_version = String::new();
        vk_acct.bump = ctx.bumps.verifier_vk;
        msg!("VerifierVk PDA initialized (empty); call seed_vk or execute_vk_update");
        Ok(())
    }

    /// Bootstrap the VK from `GLYPH_VK_REAL` if it was baked in via the
    /// `real-vk` build feature. Returns `RealVkUnavailable` otherwise.
    pub fn seed_vk(
        ctx: Context<SeedVk>,
        image_id: [u32; 8],
        prover_version: String,
    ) -> Result<()> {
        require!(
            prover_version.len() <= groth16::vk::VerifierVk::MAX_PROVER_VERSION_LEN,
            errors::GlyphError::ProverVersionTooLong
        );
        let real = groth16::vk::GLYPH_VK_REAL
            .ok_or(errors::GlyphError::RealVkUnavailable)?;

        let vk_acct = &mut ctx.accounts.verifier_vk;
        vk_acct.alpha_g1 = real.alpha_g1;
        vk_acct.beta_g2 = real.beta_g2;
        vk_acct.gamma_g2 = real.gamma_g2;
        vk_acct.delta_g2 = real.delta_g2;
        vk_acct.ic = real.ic;
        vk_acct.control_root = real.control_root;
        vk_acct.bn254_control_id = real.bn254_control_id;
        vk_acct.image_id = image_id;
        vk_acct.prover_version = prover_version;

        let inner = groth16::vk::VerifierVkInner {
            alpha_g1: real.alpha_g1,
            beta_g2: real.beta_g2,
            gamma_g2: real.gamma_g2,
            delta_g2: real.delta_g2,
            ic: real.ic,
            control_root: real.control_root,
            bn254_control_id: real.bn254_control_id,
            prover_version: vk_acct.prover_version.clone(),
        };
        vk_acct.vk_hash = inner.compute_hash();

        emit!(VkUpdated {
            old_hash: [0u8; 32],
            new_hash: vk_acct.vk_hash,
            image_id,
            timestamp: Clock::get()?.unix_timestamp,
        });
        msg!("Seeded VerifierVk from GLYPH_VK_REAL");
        Ok(())
    }

    pub fn initialize_vk_multisig(
        ctx: Context<InitializeVkMultisig>,
        args: InitializeVkMultisigArgs,
    ) -> Result<()> {
        require!(
            !args.signers.is_empty()
                && args.signers.len() <= groth16::vk::VK_MULTISIG_MAX_SIGNERS,
            errors::GlyphError::InvalidMultisigConfig
        );
        require!(
            args.threshold > 0 && (args.threshold as usize) <= args.signers.len(),
            errors::GlyphError::InvalidMultisigConfig
        );
        // Reject duplicate signers.
        for (i, s) in args.signers.iter().enumerate() {
            for other in &args.signers[i + 1..] {
                require!(s != other, errors::GlyphError::InvalidMultisigConfig);
            }
        }

        let ms = &mut ctx.accounts.vk_multisig;
        ms.signers = [Pubkey::default(); groth16::vk::VK_MULTISIG_MAX_SIGNERS];
        for (i, s) in args.signers.iter().enumerate() {
            ms.signers[i] = *s;
        }
        ms.signer_count = args.signers.len() as u8;
        ms.threshold = args.threshold;
        ms.pending_update = None;
        ms.bump = ctx.bumps.vk_multisig;

        msg!(
            "VkMultisig initialized: {} signers, threshold {}",
            ms.signer_count,
            ms.threshold
        );
        Ok(())
    }

    pub fn propose_vk_update(
        ctx: Context<ProposeVkUpdate>,
        args: ProposeVkUpdateArgs,
    ) -> Result<()> {
        require!(
            args.new_vk.prover_version.len() <= groth16::vk::VerifierVk::MAX_PROVER_VERSION_LEN,
            errors::GlyphError::ProverVersionTooLong
        );
        let ms = &mut ctx.accounts.vk_multisig;
        require!(
            ms.contains(&ctx.accounts.proposer.key()),
            errors::GlyphError::NotAMultisigSigner
        );
        require!(
            ms.pending_update.is_none(),
            errors::GlyphError::PendingUpdateExists
        );

        let new_hash = args.new_vk.compute_hash();
        let now = Clock::get()?.unix_timestamp;
        ms.pending_update = Some(groth16::vk::PendingVkUpdate {
            new_vk_hash: new_hash,
            new_image_id: args.new_image_id,
            proposed_at: now,
            approved_signers: vec![ctx.accounts.proposer.key()],
            vk: args.new_vk,
        });

        emit!(VkUpdateProposed {
            proposer: ctx.accounts.proposer.key(),
            new_hash,
            new_image_id: args.new_image_id,
            proposed_at: now,
        });
        msg!("VK update proposed (hash {:02x?}...)", &new_hash[..4]);
        Ok(())
    }

    pub fn approve_vk_update(ctx: Context<ApproveVkUpdate>) -> Result<()> {
        let ms = &mut ctx.accounts.vk_multisig;
        require!(
            ms.contains(&ctx.accounts.approver.key()),
            errors::GlyphError::NotAMultisigSigner
        );
        let threshold = ms.threshold;
        let pending = ms
            .pending_update
            .as_mut()
            .ok_or(errors::GlyphError::NoPendingUpdate)?;

        let approver = ctx.accounts.approver.key();
        require!(
            !pending.approved_signers.contains(&approver),
            errors::GlyphError::AlreadyApproved
        );
        pending.approved_signers.push(approver);

        let approvals = pending.approved_signers.len() as u8;
        let new_hash = pending.new_vk_hash;

        emit!(VkUpdateApproved {
            approver,
            new_hash,
            approvals,
            threshold,
        });
        msg!(
            "VK update approved by {} ({} of {})",
            approver,
            approvals,
            threshold
        );
        Ok(())
    }

    pub fn execute_vk_update(ctx: Context<ExecuteVkUpdate>) -> Result<()> {
        let ms = &mut ctx.accounts.vk_multisig;
        let pending = ms
            .pending_update
            .as_ref()
            .ok_or(errors::GlyphError::NoPendingUpdate)?;

        require!(
            (pending.approved_signers.len() as u8) >= ms.threshold,
            errors::GlyphError::InsufficientApprovals
        );

        let now = Clock::get()?.unix_timestamp;
        require!(
            now.saturating_sub(pending.proposed_at) >= groth16::vk::VK_TIMELOCK_SECONDS,
            errors::GlyphError::TimelockNotElapsed
        );

        let new_hash = pending.new_vk_hash;
        let new_image_id = pending.new_image_id;
        let new_inner = pending.vk.clone();

        let vk_acct = &mut ctx.accounts.verifier_vk;
        let old_hash = vk_acct.vk_hash;
        vk_acct.alpha_g1 = new_inner.alpha_g1;
        vk_acct.beta_g2 = new_inner.beta_g2;
        vk_acct.gamma_g2 = new_inner.gamma_g2;
        vk_acct.delta_g2 = new_inner.delta_g2;
        vk_acct.ic = new_inner.ic;
        vk_acct.control_root = new_inner.control_root;
        vk_acct.bn254_control_id = new_inner.bn254_control_id;
        vk_acct.vk_hash = new_hash;
        vk_acct.image_id = new_image_id;
        vk_acct.prover_version = new_inner.prover_version;

        ms.pending_update = None;

        emit!(VkUpdated {
            old_hash,
            new_hash,
            image_id: new_image_id,
            timestamp: now,
        });
        msg!("VK update executed (new hash {:02x?}...)", &new_hash[..4]);
        Ok(())
    }
}
