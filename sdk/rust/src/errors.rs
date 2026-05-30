use thiserror::Error;

#[derive(Error, Debug)]
pub enum GlyphSdkError {
    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Intent building error: {0}")]
    IntentBuildError(String),

    #[error("Signing error: {0}")]
    SigningError(String),

    #[error("TEE connection error: {0}")]
    TeeConnectionError(String),

    #[error("TEE worker returned error: {code} - {message}")]
    TeeWorkerError { code: String, message: String },

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Solana RPC error: {0}")]
    RpcError(String),

    #[error("Transaction submission error: {0}")]
    SubmitError(String),
}
