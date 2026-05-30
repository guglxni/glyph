//! # GLYPH SDK
//!
//! The official Rust SDK for the GLYPH verifiable AI agent framework on Solana.
//!
//! GLYPH binds an LLM reasoning engine, a TEE policy enforcer, and a ZK proof
//! verifier into a single composable stack for trustless on-chain agent execution.
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use glyph_sdk::{ActionType, GlyphClient, GlyphConfig, IntentBuilder};
//! use solana_sdk::signer::keypair::Keypair;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = GlyphConfig {
//!         solana_rpc_url: "https://api.devnet.solana.com".to_string(),
//!         tee_endpoint: "http://localhost:8088".to_string(),
//!         agent_keypair: Keypair::new(),
//!     };
//!
//!     let client = GlyphClient::new(config)?;
//!
//!     let intent = IntentBuilder::new()
//!         .action_type(ActionType::Transfer)
//!         .target_program("11111111111111111111111111111111")
//!         .max_lamports(1_000_000_000)
//!         .build(client.agent_keypair())?;
//!
//!     let bundle = client.execute(intent).await?;
//!     println!("tx_hash prefix: {}", hex::encode(bundle.tx_hash_prefix));
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod errors;
pub mod intent;
pub mod register;
pub mod types;

pub use client::GlyphClient;
pub use errors::GlyphSdkError;
pub use intent::{ActionType, IntentBuilder};
pub use types::*;
