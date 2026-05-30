use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use solana_sdk::pubkey::Pubkey;
use solana_sdk::signature::Signer;
use solana_sdk::signer::keypair::Keypair;

use glyph_common::{
    canonical_signing_payload, CanonicalAccountMeta, CanonicalIntent,
};

use crate::errors::GlyphSdkError;
use crate::types::{AccountMeta, IntentAction, IntentConstraints, TransactionIntent};

#[derive(Debug, Clone, Copy)]
pub enum ActionType {
    Swap,
    Transfer,
    Stake,
    CpiCall,
}

impl ActionType {
    fn as_str(self) -> &'static str {
        match self {
            Self::Swap => "swap",
            Self::Transfer => "transfer",
            Self::Stake => "stake",
            Self::CpiCall => "cpi_call",
        }
    }
}

#[derive(Debug, Clone)]
pub struct IntentBuilder {
    version: u8,
    action_type: Option<ActionType>,
    target_program: Option<String>,
    accounts: Vec<AccountMeta>,
    data: String,
    max_lamports: Option<u64>,
    max_slippage_bps: Option<u16>,
    allowed_tokens: Option<Vec<String>>,
    ttl: Duration,
    nonce: Option<[u8; 32]>,
    policy_commitment: [u8; 32],
    worker_pubkey: Option<[u8; 32]>,
    epoch: u64,
}

impl Default for IntentBuilder {
    fn default() -> Self {
        Self {
            version: 1,
            action_type: None,
            target_program: None,
            accounts: Vec::new(),
            data: String::new(),
            max_lamports: None,
            max_slippage_bps: None,
            allowed_tokens: None,
            ttl: Duration::from_secs(60),
            nonce: None,
            policy_commitment: [0u8; 32],
            worker_pubkey: None,
            epoch: 0,
        }
    }
}

impl IntentBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn version(mut self, version: u8) -> Self {
        self.version = version;
        self
    }

    pub fn action_type(mut self, action_type: ActionType) -> Self {
        self.action_type = Some(action_type);
        self
    }

    pub fn target_program(mut self, target_program: impl Into<String>) -> Self {
        self.target_program = Some(target_program.into());
        self
    }

    pub fn account(mut self, account: AccountMeta) -> Self {
        self.accounts.push(account);
        self
    }

    pub fn accounts(mut self, accounts: impl IntoIterator<Item = AccountMeta>) -> Self {
        self.accounts.extend(accounts);
        self
    }

    pub fn data(mut self, data: impl Into<String>) -> Self {
        self.data = data.into();
        self
    }

    pub fn max_lamports(mut self, max_lamports: u64) -> Self {
        self.max_lamports = Some(max_lamports);
        self
    }

    pub fn max_slippage_bps(mut self, max_slippage_bps: u16) -> Self {
        self.max_slippage_bps = Some(max_slippage_bps);
        self
    }

    pub fn allowed_tokens(mut self, allowed_tokens: Vec<String>) -> Self {
        self.allowed_tokens = Some(allowed_tokens);
        self
    }

    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Override the random nonce — useful for tests and replay-recovery.
    /// Closes AUDIT_SDK F-11.
    pub fn with_nonce(mut self, nonce: [u8; 32]) -> Self {
        self.nonce = Some(nonce);
        self
    }

    /// Bind the policy commitment that the worker is expected to be enforcing.
    /// Without this, a delegation could be replayed against a worker running
    /// a different policy. Required for parity with the worker-side check.
    pub fn policy_commitment(mut self, policy_commitment: [u8; 32]) -> Self {
        self.policy_commitment = policy_commitment;
        self
    }

    /// Bind the worker's Ed25519 public key the agent expects to be talking to.
    pub fn worker_pubkey(mut self, worker_pubkey: [u8; 32]) -> Self {
        self.worker_pubkey = Some(worker_pubkey);
        self
    }

    pub fn epoch(mut self, epoch: u64) -> Self {
        self.epoch = epoch;
        self
    }

    pub fn build(self, agent_keypair: &Keypair) -> Result<TransactionIntent, GlyphSdkError> {
        let action_type = self.action_type.ok_or_else(|| {
            GlyphSdkError::IntentBuildError("action_type is required".to_string())
        })?;

        let target_program = self.target_program.ok_or_else(|| {
            GlyphSdkError::IntentBuildError("target_program is required".to_string())
        })?;

        let target_program_pk = target_program.parse::<Pubkey>().map_err(|_| {
            GlyphSdkError::IntentBuildError(
                "target_program must be a valid Solana pubkey".to_string(),
            )
        })?;

        let max_lamports = self.max_lamports.ok_or_else(|| {
            GlyphSdkError::IntentBuildError("max_lamports is required".to_string())
        })?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| GlyphSdkError::IntentBuildError(format!("invalid system clock: {e}")))?
            .as_secs();

        let expiry = now
            .checked_add(self.ttl.as_secs())
            .ok_or_else(|| GlyphSdkError::IntentBuildError("expiry overflow".to_string()))?;

        let nonce_bytes: [u8; 32] = match self.nonce {
            Some(n) => n,
            None => Keypair::new().pubkey().to_bytes(),
        };
        let nonce_hex = hex::encode(nonce_bytes);

        // Decode account pubkeys for the canonical payload, while preserving
        // the wire-format string accounts in the intent itself.
        let mut canonical_accounts = Vec::with_capacity(self.accounts.len());
        for meta in &self.accounts {
            let pk = meta.pubkey.parse::<Pubkey>().map_err(|_| {
                GlyphSdkError::IntentBuildError(format!(
                    "invalid account pubkey: {}",
                    meta.pubkey
                ))
            })?;
            canonical_accounts.push(CanonicalAccountMeta {
                pubkey: pk.to_bytes(),
                is_signer: meta.is_signer,
                is_writable: meta.is_writable,
            });
        }

        let data_bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.data)
            .map_err(|e| {
                GlyphSdkError::IntentBuildError(format!("data must be base64: {e}"))
            })?;

        let allowed_tokens_bytes = match &self.allowed_tokens {
            Some(tokens) => {
                let mut out = Vec::with_capacity(tokens.len());
                for t in tokens {
                    let pk = t.parse::<Pubkey>().map_err(|_| {
                        GlyphSdkError::IntentBuildError(format!(
                            "allowed_token is not a valid pubkey: {t}"
                        ))
                    })?;
                    out.push(pk.to_bytes());
                }
                Some(out)
            }
            None => None,
        };

        let action = IntentAction {
            action_type: action_type.as_str().to_string(),
            target_program,
            accounts: self.accounts,
            data: self.data,
        };

        let constraints = IntentConstraints {
            max_lamports,
            max_slippage_bps: self.max_slippage_bps,
            allowed_tokens: self.allowed_tokens,
        };

        let canonical = CanonicalIntent {
            agent_pubkey: agent_keypair.pubkey().to_bytes(),
            nonce: nonce_bytes,
            target_program: target_program_pk.to_bytes(),
            accounts: canonical_accounts,
            data: data_bytes,
            max_lamports,
            max_slippage_bps: self.max_slippage_bps,
            allowed_tokens: allowed_tokens_bytes,
            expiry,
            timestamp: now,
            policy_commitment: self.policy_commitment,
            worker_pubkey: self.worker_pubkey,
            epoch: self.epoch,
        };

        let payload = canonical_signing_payload(&canonical);
        let signature = agent_keypair.sign_message(&payload);

        let intent = TransactionIntent {
            version: self.version,
            agent_pubkey: agent_keypair.pubkey().to_string(),
            nonce: nonce_hex,
            timestamp: now,
            expiry,
            action,
            constraints,
            signature: base64::engine::general_purpose::STANDARD.encode(signature.as_ref()),
        };

        Ok(intent)
    }
}
