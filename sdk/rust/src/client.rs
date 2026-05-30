use std::sync::Arc;

use solana_client::rpc_client::RpcClient;
use solana_sdk::signature::Signature;
use solana_sdk::signer::keypair::Keypair;
use solana_sdk::transaction::Transaction;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::errors::GlyphSdkError;
use crate::types::{GlyphConfig, GlyphProofBundle, TransactionIntent, WorkerResponse};

#[derive(Debug)]
pub struct GlyphClient {
    config: GlyphConfig,
    tee_addr: String,
    rpc_client: Arc<RpcClient>,
}

impl GlyphClient {
    pub fn new(config: GlyphConfig) -> Result<Self, GlyphSdkError> {
        if config.solana_rpc_url.trim().is_empty() {
            return Err(GlyphSdkError::ConfigError(
                "solana_rpc_url cannot be empty".to_string(),
            ));
        }

        if config.tee_endpoint.trim().is_empty() {
            return Err(GlyphSdkError::ConfigError(
                "tee_endpoint cannot be empty".to_string(),
            ));
        }

        let tee_addr = normalize_tee_endpoint(&config.tee_endpoint)?;
        let rpc_client = Arc::new(RpcClient::new(config.solana_rpc_url.clone()));

        Ok(Self {
            config,
            tee_addr,
            rpc_client,
        })
    }

    pub fn agent_keypair(&self) -> &Keypair {
        &self.config.agent_keypair
    }

    pub async fn execute(&self, intent: TransactionIntent) -> Result<GlyphProofBundle, GlyphSdkError> {
        let mut stream = TcpStream::connect(&self.tee_addr)
            .await
            .map_err(|e| GlyphSdkError::TeeConnectionError(e.to_string()))?;

        let request = serde_json::to_vec(&intent)
            .map_err(|e| GlyphSdkError::SerializationError(e.to_string()))?;

        stream
            .write_all(&request)
            .await
            .map_err(|e| GlyphSdkError::TeeConnectionError(e.to_string()))?;

        stream
            .shutdown()
            .await
            .map_err(|e| GlyphSdkError::TeeConnectionError(e.to_string()))?;

        let mut response_bytes = Vec::with_capacity(8 * 1024);
        stream
            .read_to_end(&mut response_bytes)
            .await
            .map_err(|e| GlyphSdkError::TeeConnectionError(e.to_string()))?;

        if response_bytes.is_empty() {
            return Err(GlyphSdkError::TeeConnectionError(
                "empty response from TEE worker".to_string(),
            ));
        }

        let response: WorkerResponse = serde_json::from_slice(&response_bytes)
            .map_err(|e| GlyphSdkError::SerializationError(e.to_string()))?;

        match response {
            WorkerResponse::Success { bundle } => Ok(bundle),
            WorkerResponse::Error { code, message } => {
                Err(GlyphSdkError::TeeWorkerError { code, message })
            }
        }
    }

    pub async fn submit_to_solana(&self, bundle: &GlyphProofBundle) -> Result<Signature, GlyphSdkError> {
        let tx: Transaction = bincode::deserialize(&bundle.signed_transaction)
            .map_err(|e| GlyphSdkError::SerializationError(e.to_string()))?;

        let rpc_client = Arc::clone(&self.rpc_client);
        tokio::task::spawn_blocking(move || {
            rpc_client
                .send_and_confirm_transaction(&tx)
                .map_err(|e| GlyphSdkError::SubmitError(e.to_string()))
        })
        .await
        .map_err(|e| GlyphSdkError::SubmitError(format!("join error: {e}")))?
    }
}

fn normalize_tee_endpoint(endpoint: &str) -> Result<String, GlyphSdkError> {
    let trimmed = endpoint.trim();

    if let Some(value) = trimmed.strip_prefix("tcp://") {
        return Ok(value.to_string());
    }

    if let Some(value) = trimmed.strip_prefix("http://") {
        return Ok(value.to_string());
    }

    if let Some(value) = trimmed.strip_prefix("https://") {
        return Ok(value.to_string());
    }

    if !trimmed.contains(':') {
        return Err(GlyphSdkError::ConfigError(
            "tee_endpoint must include host:port".to_string(),
        ));
    }

    Ok(trimmed.to_string())
}
