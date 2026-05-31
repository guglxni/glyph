use serde::{Deserialize, Serialize};
use serde_with::{serde_as, Bytes};
use zeroize::Zeroize;

/// Structured transaction intent produced by the LLM.
/// This is the core data structure that flows through the entire pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionIntent {
    pub version: u8,
    pub agent_pubkey: String,
    pub nonce: String,
    pub timestamp: u64,
    pub expiry: u64,
    pub action: IntentAction,
    pub constraints: IntentConstraints,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentAction {
    #[serde(rename = "type")]
    pub action_type: ActionType,
    pub target_program: String,
    pub accounts: Vec<AccountMeta>,
    pub data: String, // base64 encoded
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionType {
    Swap,
    Transfer,
    Stake,
    CpiCall,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountMeta {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentConstraints {
    pub max_lamports: u64,
    pub max_slippage_bps: Option<u16>,
    pub allowed_tokens: Option<Vec<String>>,
}

/// Groth16 proof components (BN254 field encoding, big-endian).
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Groth16Proof {
    #[serde_as(as = "Bytes")]
    pub a: [u8; 64],
    #[serde_as(as = "Bytes")]
    pub b: [u8; 128],
    #[serde_as(as = "Bytes")]
    pub c: [u8; 64],
}

/// Public inputs derived from the circuit journal — kept for local validation
/// and logging only. The on-chain verifier derives these from `journal_bytes`.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    #[serde_as(as = "Bytes")]
    pub policy_commitment: [u8; 32],
    #[serde_as(as = "Bytes")]
    pub intent_hash: [u8; 32],
    #[serde_as(as = "Bytes")]
    pub agent_pubkey: [u8; 32],
    #[serde_as(as = "Bytes")]
    pub nonce: [u8; 32],
    #[serde_as(as = "Bytes")]
    pub tx_hash: [u8; 32],
}

/// Complete proof bundle: proof + journal bytes + signed transaction.
///
/// ## Key upgrade (Placeholder → Real ZK)
/// The on-chain verifier now receives `journal_bytes` — the raw borsh-encoded
/// `PublicOutputs` committed by the ZK circuit via `env::commit()`. This prevents
/// a subtle attack where a caller submits a valid proof but mismatched public_inputs:
/// the program derives public inputs FROM the journal bytes itself, binding the
/// Groth16 proof to the actual committed outputs.
///
/// ## Worker attestation (closes T6)
/// `worker_attestation` carries the *boot-time* TEE quote produced by
/// `provider.attest(user_data, policy_commitment)` where `user_data` binds the
/// 5-tuple `(policy_commitment, agent_pubkey, worker_pubkey, boot_nonce, epoch)`.
/// SDK clients (and the on-chain `register_agent` / `update_policy` instructions)
/// re-verify the quote against the live `policy_commitment` to confirm the
/// bundle was produced inside a real enclave running the registered policy.
/// `None` is permitted in `Dev` mode only — `Staging` and `Production` always
/// attach evidence.
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlyphProofBundle {
    /// Groth16 proof (a, b, c) from the RISC Zero prover.
    pub proof: Groth16Proof,
    /// Raw borsh-encoded PublicOutputs committed by the circuit via env::commit().
    /// The on-chain verifier derives the Groth16 public input as SHA-256(journal_bytes).
    pub journal_bytes: Vec<u8>,
    /// Cached decoded public inputs for local use (logging, policy checks, etc.)
    pub public_inputs: PublicInputs,
    /// The signed target transaction bytes (the instruction data that was proven).
    #[serde_as(as = "Bytes")]
    pub signed_transaction: Vec<u8>,
    /// Bounded prefix of tx_hash for client-side correlation. Closes F-19, F-29.
    /// This is NOT a Solana transaction signature — it's the first 16 bytes
    /// of `public_inputs.tx_hash` for log/debug purposes only.
    #[serde_as(as = "Bytes")]
    pub tx_hash_prefix: [u8; 16],
    /// Boot-time TEE attestation quote bound to
    /// `(policy_commitment, agent_pubkey, worker_pubkey, boot_nonce, epoch)`.
    /// Closes T6: SDK and on-chain verifier re-verify this against the live
    /// policy commitment. `None` only in `Dev` mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_attestation: Option<Vec<u8>>,
}

/// TEE vendor selection
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum TeeVendor {
    Sgx,
    Nitro,
    Sev,
}

/// Runtime mode — controls security enforcement level.
///
/// # Production Safety
/// In `Production` mode, the worker enforces:
/// - GLYPH_PROVER=risc0 (DevProver is forbidden)
/// - RISC0_DEV_MODE must not be set
/// - Binary must be compiled with --features risc0
/// - TEE attestation must be real (vendor stubs rejected)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum RuntimeMode {
    /// Local development — DevProver allowed, no attestation enforcement
    Dev,
    /// Pre-production — real prover preferred, warnings for dev fallback
    Staging,
    /// Production — fail-closed on any non-production configuration
    Production,
}

/// Worker configuration loaded from environment/config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkerConfig {
    pub tee_vendor: TeeVendor,
    pub policy_path: String,
    pub keypair_path: String,
    pub listen_addr: String,
    pub solana_rpc_url: String,
    #[serde(default = "default_runtime_mode")]
    pub runtime_mode: RuntimeMode,
    /// Base58-encoded Ed25519 pubkey of the *delegator/agent* this worker
    /// attests on behalf of. Bound into the boot-time attestation 5-tuple
    /// (closes T6) so the on-chain `register_agent` instruction can verify
    /// the quote was produced for the correct agent.
    ///
    /// `None` is allowed in `Dev` mode — the worker substitutes its own
    /// pubkey for boot purposes. `Staging`/`Production` require this to be
    /// set explicitly.
    #[serde(default)]
    pub agent_pubkey: Option<String>,
    /// Whether the keypair file at `keypair_path` is sealed (closes T21).
    /// When `true`, the worker boot path calls `provider.unseal()` on the
    /// raw bytes before parsing. Production deployments **must** either set
    /// this flag (paired with a `.sealed` file) or use in-enclave key
    /// generation; plaintext keypairs on disk are rejected.
    #[serde(default)]
    pub keypair_sealed: bool,
}

/// Default runtime mode for deserialization paths.
///
/// Closes mock-sweep "default `Dev` runtime mode": absent or omitted runtime
/// modes are treated as **Production**. Operators must explicitly opt down to
/// `Dev` or `Staging` in config or env.
fn default_runtime_mode() -> RuntimeMode {
    RuntimeMode::Production
}

/// Response sent back to the SDK client
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum WorkerResponse {
    #[serde(rename = "success")]
    Success { bundle: GlyphProofBundle },
    #[serde(rename = "error")]
    Error { code: String, message: String },
}

/// Identifier for a single policy rule. The numeric value is stable and
/// surfaced to clients as `rule_id` so SDKs can map errors to a rule.
///
/// Closes T25 (granular policy violation discriminator).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum PolicyRule {
    /// Rule 1: per-tx maximum lamports.
    MaxLamportsPerTx = 1,
    /// Rule 2: caller program must be in the allowlist.
    AllowedPrograms = 2,
    /// Rule 3: time window (UTC hours).
    TimeWindow = 3,
    /// Rule 4: aggregate daily volume cap.
    MaxDailyVolumeLamports = 4,
    /// Rule 5: required maximum slippage.
    RequireSlippageBpsLte = 5,
    /// Rule 6: token mint allowlist.
    AllowedTokenMints = 6,
    /// Rule 7: maximum number of accounts in the tx.
    MaxAccountsPerTx = 7,
    /// Rule 8: at least one signer must be present.
    RequireSignerPresent = 8,
    /// Rule 9: policy expiry (TOML-level).
    PolicyExpired = 9,
}

impl PolicyRule {
    pub fn id(self) -> u8 {
        self as u8
    }
}

/// Granular policy violation. Surfaces a numeric `rule_id` (1..=9) so SDKs can
/// map an error code without parsing free-form messages. `reason` is a short
/// developer-facing diagnostic. Closes T25.
#[derive(Debug, Clone)]
pub struct PolicyViolation {
    pub rule_id: u8,
    pub reason: String,
}

impl PolicyViolation {
    pub fn new(rule: PolicyRule, reason: impl Into<String>) -> Self {
        Self {
            rule_id: rule.id(),
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Policy violation (rule {}): {}",
            self.rule_id, self.reason
        )
    }
}

impl std::error::Error for PolicyViolation {}

/// Backwards-compatible alias for code paths that haven't migrated yet.
/// New code should prefer `PolicyViolation` + `PolicyRule`.
pub type PolicyViolationError = PolicyViolation;

/// Worker-side nonce-reuse error. The on-chain nonce PDA is the authoritative
/// gate, but the worker also rejects any (agent_pubkey, nonce) pair it has
/// recently signed for, so a compromised worker / front-end cannot mint
/// multiple bundles for the same intent. Closes T17.
#[derive(Debug, Clone)]
pub struct NonceReused {
    pub agent_pubkey: [u8; 32],
    pub nonce: [u8; 32],
}

impl std::fmt::Display for NonceReused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "nonce already seen for this agent")
    }
}

impl std::error::Error for NonceReused {}

/// Best-effort secret cleanup helper.
pub fn zeroize_bytes(bytes: &mut [u8]) {
    bytes.zeroize();
}
