//! Bootstrap the VK-rotation governance on devnet (closes the governance
//! POLISH gap).
//!
//! The on-chain `initialize_vk_multisig` instruction requires the protocol
//! `VerifierConfig` PDA to already exist with `config.authority == authority`.
//! This tool performs the full bootstrap, idempotently:
//!
//!   1. `initialize { authority }`        -> creates the `config` PDA
//!                                           (skipped if it already exists).
//!   2. `initialize_vk_multisig { signers, threshold }`
//!                                        -> creates the `vk_multisig` PDA
//!                                           (skipped if it already exists).
//!
//! Minimal valid multisig: a 1-of-1 whose sole signer is the deployer/authority
//! wallet. The instruction's own validation requires:
//!
//!   * threshold >= 1                                       (we use 1)
//!   * signers.len() >= threshold                           (1 signer)
//!   * signers.len() <= VK_MULTISIG_MAX_SIGNERS (== 5)      (1 <= 5)
//!   * no duplicate signers                                 (single entry)
//!
//! The timelock is NOT a parameter -- it is a fixed 24-hour const enforced
//! between `propose_vk_update` and `execute_vk_update`.
//!
//! Instructions are encoded by hand (no dependency on the program crate's
//! anchor-generated `accounts`/`instruction` modules): the 8-byte anchor
//! discriminator is `sha256("global:<snake_case_name>")[..8]`, followed by the
//! Borsh-encoded argument struct. Account ordering matches the program's
//! `#[derive(Accounts)]` definitions.
//!
//! Usage:
//!   solana config set --url devnet
//!   cargo run --manifest-path scripts/init-multisig/Cargo.toml
//!
//! Environment overrides (all optional):
//!   GLYPH_RPC_URL   RPC endpoint            (default: https://api.devnet.solana.com)
//!   GLYPH_KEYPAIR   authority keypair path  (default: ~/.config/solana/id.json)
//!   GLYPH_THRESHOLD multisig threshold      (default: 1)
//!   GLYPH_SIGNERS   comma-separated signer pubkeys (default: authority only)

use std::str::FromStr;

use anyhow::{Context, Result};
use borsh::BorshSerialize;
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{read_keypair_file, Keypair},
    signer::Signer as _,
    system_program,
    transaction::Transaction,
};

const PROGRAM_ID: &str = "G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g";

/// Anchor's 8-byte instruction discriminator: `sha256("global:<name>")[..8]`.
fn discriminator(name: &str) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(format!("global:{name}").as_bytes());
    let d = h.finalize();
    let mut out = [0u8; 8];
    out.copy_from_slice(&d[..8]);
    out
}

/// `InitializeArgs { authority: Pubkey }`
#[derive(BorshSerialize)]
struct InitializeArgs {
    authority: [u8; 32],
}

/// `InitializeVkMultisigArgs { signers: Vec<Pubkey>, threshold: u8 }`
#[derive(BorshSerialize)]
struct InitializeVkMultisigArgs {
    signers: Vec<[u8; 32]>,
    threshold: u8,
}

fn ix_data<T: BorshSerialize>(name: &str, args: &T) -> Result<Vec<u8>> {
    let mut data = discriminator(name).to_vec();
    args.serialize(&mut data)?;
    Ok(data)
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn explorer_tx(sig: &str) -> String {
    format!("https://explorer.solana.com/tx/{sig}?cluster=devnet")
}

fn main() -> Result<()> {
    let program_id = Pubkey::from_str(PROGRAM_ID)?;

    let rpc_url = env_or("GLYPH_RPC_URL", "https://api.devnet.solana.com");
    let keypair_path = std::env::var("GLYPH_KEYPAIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{home}/.config/solana/id.json")
    });
    let threshold: u8 = env_or("GLYPH_THRESHOLD", "1")
        .parse()
        .context("GLYPH_THRESHOLD")?;

    let authority: Keypair = read_keypair_file(&keypair_path)
        .map_err(|e| anyhow::anyhow!("failed to read keypair {keypair_path}: {e}"))?;
    let authority_pk = authority.pubkey();

    let signers: Vec<Pubkey> = match std::env::var("GLYPH_SIGNERS") {
        Ok(list) if !list.trim().is_empty() => list
            .split(',')
            .map(|s| Pubkey::from_str(s.trim()))
            .collect::<std::result::Result<_, _>>()
            .context("GLYPH_SIGNERS parse")?,
        _ => vec![authority_pk],
    };

    // PDAs (seeds must match the on-chain program).
    let (config, _) = Pubkey::find_program_address(&[b"config"], &program_id);
    let (vk_multisig, _) = Pubkey::find_program_address(&[b"vk_multisig"], &program_id);

    println!("Program:         {program_id}");
    println!("RPC:             {rpc_url}");
    println!("Authority:       {authority_pk}");
    println!("config PDA:      {config}");
    println!("vk_multisig PDA: {vk_multisig}");
    println!("Signers:         {signers:?}");
    println!("Threshold:       {threshold}\n");

    let client = RpcClient::new_with_commitment(rpc_url.clone(), CommitmentConfig::confirmed());

    // ── Step 1: ensure VerifierConfig exists ────────────────────────────────
    if client.get_account(&config).is_ok() {
        println!("[1/2] config PDA already initialized -- skipping `initialize`.");
    } else {
        println!("[1/2] Submitting `initialize` (creates config PDA) ...");
        let data = ix_data(
            "initialize",
            &InitializeArgs {
                authority: authority_pk.to_bytes(),
            },
        )?;
        // Accounts: payer (signer, mut), config (mut), system_program.
        let ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(authority_pk, true),
                AccountMeta::new(config, false),
                AccountMeta::new_readonly(system_program::ID, false),
            ],
            data,
        };
        let bh = client.get_latest_blockhash()?;
        let tx = Transaction::new_signed_with_payer(&[ix], Some(&authority_pk), &[&authority], bh);
        let sig = client
            .send_and_confirm_transaction_with_spinner(&tx)
            .context("initialize send_and_confirm")?;
        println!("      OK config initialized. Tx: {sig}");
        println!("         {}", explorer_tx(&sig.to_string()));
    }

    // ── Step 2: ensure VkMultisig exists ────────────────────────────────────
    if client.get_account(&vk_multisig).is_ok() {
        println!("[2/2] vk_multisig PDA already initialized -- nothing to do.");
        println!(
            "\nVkMultisig: https://explorer.solana.com/address/{vk_multisig}?cluster=devnet"
        );
        return Ok(());
    }

    println!("[2/2] Submitting `initialize_vk_multisig` ...");
    let data = ix_data(
        "initialize_vk_multisig",
        &InitializeVkMultisigArgs {
            signers: signers.iter().map(|s| s.to_bytes()).collect(),
            threshold,
        },
    )?;
    // Accounts: authority (signer, mut), config, vk_multisig (mut), system_program.
    let ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(authority_pk, true),
            AccountMeta::new_readonly(config, false),
            AccountMeta::new(vk_multisig, false),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    };
    let bh = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(&[ix], Some(&authority_pk), &[&authority], bh);
    let sig = client
        .send_and_confirm_transaction_with_spinner(&tx)
        .context("initialize_vk_multisig send_and_confirm")?;

    println!("\nOK VkMultisig initialized.");
    println!("Tx signature: {sig}");
    println!("Explorer:     {}", explorer_tx(&sig.to_string()));
    println!("VkMultisig:   https://explorer.solana.com/address/{vk_multisig}?cluster=devnet");
    Ok(())
}
