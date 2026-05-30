use serde::{Deserialize, Serialize};
use solana_sdk::signer::keypair::Keypair;

/// Configuration for the GLYPH client.
#[derive(Debug)]
pub struct GlyphConfig {
    /// Solana RPC endpoint URL
    pub solana_rpc_url: String,
    /// TEE worker endpoint (TCP address or URL)
    pub tee_endpoint: String,
    /// Agent's Ed25519 keypair for signing intents
    pub agent_keypair: Keypair,
}

/// Structured transaction intent sent to the TEE worker.
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
    pub action_type: String,
    pub target_program: String,
    pub accounts: Vec<AccountMeta>,
    pub data: String,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_slippage_bps: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_tokens: Option<Vec<String>>,
}

/// Groth16 proof components
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Groth16Proof {
    pub a: [u8; 64],
    pub b: [u8; 128],
    pub c: [u8; 64],
}

/// Public inputs for the ZK circuit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicInputs {
    pub policy_commitment: [u8; 32],
    pub intent_hash: [u8; 32],
    pub agent_pubkey: [u8; 32],
    pub nonce: [u8; 32],
    pub tx_hash: [u8; 32],
}

/// Complete proof bundle returned after execution.
///
/// `tx_hash_prefix` is a bounded 16-byte correlator (first 16 bytes of
/// `public_inputs.tx_hash`); it is **not** a Solana transaction signature.
/// Closes F-19, F-29.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlyphProofBundle {
    pub proof: Groth16Proof,
    pub public_inputs: PublicInputs,
    pub signed_transaction: Vec<u8>,
    pub tx_hash_prefix: [u8; 16],
}

/// Response from the TEE worker
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "status")]
pub enum WorkerResponse {
    #[serde(rename = "success")]
    Success { bundle: GlyphProofBundle },
    #[serde(rename = "error")]
    Error { code: String, message: String },
}
