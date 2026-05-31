//! GLYPH end-to-end devnet driver.
//!
//! Performs, against the already-deployed `glyph_verifier` program on Solana
//! devnet, the FULL flow with a REAL RISC Zero Groth16 proof:
//!
//!   1. `register_agent`  — pins policy_commitment + image_id, with an
//!      AttestationType::None attestation document that embeds the
//!      policy_commitment (so the on-chain `verify_attestation_commitment`
//!      passes) and a real Ed25519 delegator signature attached as a sibling
//!      precompile instruction (so `verify_ed25519_precompile` passes).
//!
//!   2. `verify_and_execute` — instruction 1 of a 2-instruction transaction:
//!        ix0 = ComputeBudget set_compute_unit_limit(1_400_000)
//!        ix1 = verify_and_execute(proof, journal_bytes, nonce)
//!        ix2 = the bound target instruction (System transfer) whose canonical
//!              hash equals the proof's committed tx_hash.
//!
//! Inputs come from `proof.json` produced by the `gen_proof` host binary, plus
//! the deployer/authority keypair (also used as the agent + delegator here for
//! simplicity on devnet).
//!
//! Run:
//!   cargo run --manifest-path scripts/e2e-devnet/Cargo.toml -- \
//!       --proof scripts/e2e-devnet/proof.json \
//!       --keypair ~/.config/solana/id.json \
//!       --rpc https://api.devnet.solana.com
//!
//! Honest by design: it prints exactly which step succeeded and the on-chain
//! error if a step fails. Writes a machine-readable summary to result.json.

use std::str::FromStr;

use anyhow::{anyhow, Context as _, Result};
use borsh::BorshSerialize;
use sha2::{Digest, Sha256};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    compute_budget::ComputeBudgetInstruction,
    ed25519_program,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_program,
    sysvar,
    transaction::Transaction,
};

const PROGRAM_ID: &str = "G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g";

#[derive(serde::Deserialize)]
struct ProofJson {
    image_id_u32: [u32; 8],
    policy_commitment_hex: String,
    journal_bytes_hex: String,
    proof_a_hex: String,
    proof_b_hex: String,
    proof_c_hex: String,
    target_program_hex: String,
    ix_data_hex: String,
    from_hex: String,
    to_hex: String,
    nonce_hex: String,
    #[allow(dead_code)]
    decoded_tx_hash_hex: String,
}

#[derive(BorshSerialize)]
struct RegisterAgentArgs {
    agent_pubkey: [u8; 32],
    tee_type: u8,
    tee_attestation: Vec<u8>,
    policy_commitment: [u8; 32],
    image_id: [u32; 8],
    delegator_signature: [u8; 64],
    delegator_pubkey: [u8; 32],
    delegation_expiry: i64,
}

#[derive(BorshSerialize)]
struct Groth16Proof {
    a: [u8; 64],
    b: [u8; 128],
    c: [u8; 64],
}

#[derive(BorshSerialize)]
struct VerifyAndExecuteArgs {
    proof: Groth16Proof,
    journal_bytes: Vec<u8>,
    nonce: [u8; 32],
}

fn anchor_disc(name: &str) -> [u8; 8] {
    let h = Sha256::digest(format!("global:{name}").as_bytes());
    let mut d = [0u8; 8];
    d.copy_from_slice(&h[..8]);
    d
}

fn hexb(s: &str) -> Result<Vec<u8>> {
    Ok(hex::decode(s.trim()).context("hex decode")?)
}
fn hex32(s: &str) -> Result<[u8; 32]> {
    let v = hexb(s)?;
    if v.len() != 32 {
        return Err(anyhow!("need 32 bytes got {}", v.len()));
    }
    let mut o = [0u8; 32];
    o.copy_from_slice(&v);
    Ok(o)
}

/// Mirror of on-chain `delegation_signing_payload`.
fn delegation_payload(
    agent: &Pubkey,
    policy_commitment: &[u8; 32],
    image_id: &[u32; 8],
    expiry: i64,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(20 + 32 + 32 + 32 + 8 + 32);
    buf.extend_from_slice(b"GLYPH:DELEGATION:v1:");
    buf.extend_from_slice(agent.as_ref());
    buf.extend_from_slice(policy_commitment);
    for limb in image_id.iter() {
        buf.extend_from_slice(&limb.to_be_bytes());
    }
    buf.extend_from_slice(&expiry.to_le_bytes());
    buf.extend_from_slice(&[0u8; 32]); // scope_hash
    buf
}

fn main() -> Result<()> {
    let mut proof_path = String::from("scripts/e2e-devnet/proof.json");
    let mut keypair_path =
        format!("{}/.config/solana/id.json", std::env::var("HOME").unwrap_or_default());
    let mut rpc = String::from("https://api.devnet.solana.com");
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--proof" => proof_path = args.next().context("--proof")?,
            "--keypair" => keypair_path = args.next().context("--keypair")?,
            "--rpc" => rpc = args.next().context("--rpc")?,
            other => return Err(anyhow!("unknown arg {other}")),
        }
    }

    let program_id = Pubkey::from_str(PROGRAM_ID)?;
    let client = RpcClient::new_with_commitment(rpc.clone(), CommitmentConfig::confirmed());

    let payer = read_keypair(&keypair_path)?;
    // For this devnet demo the deployer wallet plays authority + agent + delegator.
    let authority = &payer;
    let agent = &payer;
    let agent_pk = agent.pubkey();

    let pj: ProofJson =
        serde_json::from_str(&std::fs::read_to_string(&proof_path).context("read proof.json")?)
            .context("parse proof.json")?;

    let policy_commitment = hex32(&pj.policy_commitment_hex)?;
    let image_id = pj.image_id_u32;
    let journal_bytes = hexb(&pj.journal_bytes_hex)?;
    let proof_a: [u8; 64] = hexb(&pj.proof_a_hex)?.try_into().map_err(|_| anyhow!("a len"))?;
    let proof_b: [u8; 128] = hexb(&pj.proof_b_hex)?.try_into().map_err(|_| anyhow!("b len"))?;
    let proof_c: [u8; 64] = hexb(&pj.proof_c_hex)?.try_into().map_err(|_| anyhow!("c len"))?;
    let target_program = Pubkey::new_from_array(hex32(&pj.target_program_hex)?);
    let ix_data = hexb(&pj.ix_data_hex)?;
    let from = Pubkey::new_from_array(hex32(&pj.from_hex)?);
    let to = Pubkey::new_from_array(hex32(&pj.to_hex)?);
    let nonce = hex32(&pj.nonce_hex)?;

    // The proof was generated for agent == proof.agent_hex; the registry agent
    // must match what the journal commits. We use the payer as the agent, so
    // proof.json must have been generated with --agent <payer_pubkey_hex>.
    println!("== GLYPH e2e devnet ==");
    println!("program        : {program_id}");
    println!("payer/authority: {agent_pk}");
    println!("policy_commit  : {}", hex::encode(policy_commitment));
    println!("image_id (hex) : {}", image_id.iter().map(|w| format!("{w:08x}")).collect::<Vec<_>>().join(""));

    // ── PDAs ────────────────────────────────────────────────────────────────
    let (config_pda, _) = Pubkey::find_program_address(&[b"config"], &program_id);
    let (registry_pda, _) =
        Pubkey::find_program_address(&[b"agent", agent_pk.as_ref()], &program_id);
    let (verifier_vk_pda, _) = Pubkey::find_program_address(&[b"verifier_vk"], &program_id);

    let mut result = serde_json::json!({
        "program_id": program_id.to_string(),
        "agent": agent_pk.to_string(),
        "config_pda": config_pda.to_string(),
        "registry_pda": registry_pda.to_string(),
        "verifier_vk_pda": verifier_vk_pda.to_string(),
        "rpc": rpc,
    });

    // ── STEP 1: register_agent (skip if already registered) ──────────────────
    let already = client.get_account(&registry_pda).is_ok();
    if already {
        println!("[register] registry PDA already exists — skipping registration");
        result["register_skipped_existing"] = serde_json::json!(true);
    } else {
        let delegation_expiry = now_unix() + 86_400;
        // Attestation document for AttestationType::None: must be >=32 bytes and
        // contain the 32-byte policy_commitment somewhere (verify_attestation_commitment).
        let mut attestation = Vec::new();
        attestation.extend_from_slice(b"GLYPH-DEV-ATTESTATION-NONE-v1\0\0\0");
        attestation.extend_from_slice(&policy_commitment);
        attestation.extend_from_slice(b"\0\0\0\0");

        // Ed25519 delegator signature over the canonical payload. The deployer
        // wallet is the delegator; its keypair is the same `payer` keypair.
        let payload = delegation_payload(&agent_pk, &policy_commitment, &image_id, delegation_expiry);
        // The delegator is the payer wallet. We sign the canonical payload with
        // its Ed25519 key (solana Keypair signs ed25519 over arbitrary bytes),
        // and hand-build the Ed25519Program precompile instruction the on-chain
        // `verify_ed25519_precompile` expects as a sibling.
        let delegator_pubkey = payer.pubkey().to_bytes();
        let sig = payer.sign_message(&payload);
        let mut delegator_signature = [0u8; 64];
        delegator_signature.copy_from_slice(sig.as_ref());
        let ed_ix = build_ed25519_precompile_ix(&delegator_pubkey, &delegator_signature, &payload);

        let reg_args = RegisterAgentArgs {
            agent_pubkey: agent_pk.to_bytes(),
            tee_type: 0, // AttestationType::None
            tee_attestation: attestation,
            policy_commitment,
            image_id,
            delegator_signature,
            delegator_pubkey,
            delegation_expiry,
        };
        let mut data = anchor_disc("register_agent").to_vec();
        reg_args.serialize(&mut data)?;

        let reg_ix = Instruction {
            program_id,
            accounts: vec![
                AccountMeta::new(authority.pubkey(), true),       // authority (signer, mut)
                AccountMeta::new(registry_pda, false),            // agent_registry (mut)
                AccountMeta::new_readonly(agent_pk, false),       // agent_pubkey
                AccountMeta::new_readonly(config_pda, false),     // config
                AccountMeta::new_readonly(sysvar::instructions::id(), false), // instructions sysvar
                AccountMeta::new_readonly(system_program::id(), false),
            ],
            data,
        };

        let bh = client.get_latest_blockhash()?;
        let tx = Transaction::new_signed_with_payer(
            &[ed_ix, reg_ix],
            Some(&authority.pubkey()),
            &[authority],
            bh,
        );
        println!("[register] sending register_agent ...");
        match client.send_and_confirm_transaction(&tx) {
            Ok(sig) => {
                println!("[register] OK sig={sig}");
                println!("[register] https://explorer.solana.com/tx/{sig}?cluster=devnet");
                result["register_sig"] = serde_json::json!(sig.to_string());
            }
            Err(e) => {
                println!("[register] FAILED: {e}");
                result["register_error"] = serde_json::json!(e.to_string());
                std::fs::write(
                    "scripts/e2e-devnet/result.json",
                    serde_json::to_string_pretty(&result)?,
                )?;
                return Err(anyhow!("register_agent failed: {e}"));
            }
        }
    }

    // ── STEP 2: verify_and_execute ───────────────────────────────────────────
    let nonce_seed_epoch: u32 = 0; // freshly-registered agents have epoch 0
    let (nonce_pda, _) = Pubkey::find_program_address(
        &[
            b"nonce",
            agent_pk.as_ref(),
            &nonce_seed_epoch.to_le_bytes(),
            &nonce,
        ],
        &program_id,
    );
    result["nonce_pda"] = serde_json::json!(nonce_pda.to_string());

    let ve_args = VerifyAndExecuteArgs {
        proof: Groth16Proof { a: proof_a, b: proof_b, c: proof_c },
        journal_bytes: journal_bytes.clone(),
        nonce,
    };
    let mut ve_data = anchor_disc("verify_and_execute").to_vec();
    ve_args.serialize(&mut ve_data)?;

    let verify_ix = Instruction {
        program_id,
        accounts: vec![
            AccountMeta::new(agent_pk, true),                  // agent (signer, mut)
            AccountMeta::new_readonly(registry_pda, false),    // registry
            AccountMeta::new_readonly(config_pda, false),      // config
            AccountMeta::new_readonly(verifier_vk_pda, false), // verifier_vk
            AccountMeta::new(nonce_pda, false),                // nonce_account (mut, init_if_needed)
            AccountMeta::new_readonly(sysvar::instructions::id(), false),
            AccountMeta::new_readonly(system_program::id(), false),
        ],
        data: ve_data,
    };

    // The bound target instruction: System transfer from `from` to `to`.
    // Its canonical hash MUST equal the proof's committed tx_hash. The proof was
    // generated over canonical_target_instruction_bytes(system, [from(s,w),to(w)], ix_data).
    let target_ix = Instruction {
        program_id: target_program,
        accounts: vec![
            AccountMeta::new(from, true),
            AccountMeta::new(to, false),
        ],
        data: ix_data.clone(),
    };

    // Sanity: locally recompute the canonical tx hash the verifier will derive.
    {
        use glyph_common::{hash_target_instruction, CanonicalAccountMeta};
        let metas = vec![
            CanonicalAccountMeta { pubkey: from.to_bytes(), is_signer: true, is_writable: true },
            CanonicalAccountMeta { pubkey: to.to_bytes(), is_signer: false, is_writable: true },
        ];
        let h = hash_target_instruction(&target_program.to_bytes(), &metas, &ix_data);
        println!("[verify] local canonical tx_hash = {}", hex::encode(h));
        println!("[verify] proof   committed tx_hash = {}", pj.decoded_tx_hash_hex);
        result["local_tx_hash"] = serde_json::json!(hex::encode(h));
        result["proof_tx_hash"] = serde_json::json!(pj.decoded_tx_hash_hex);
    }

    let cu_ix = ComputeBudgetInstruction::set_compute_unit_limit(1_400_000);
    let bh = client.get_latest_blockhash()?;
    let tx = Transaction::new_signed_with_payer(
        &[cu_ix, verify_ix, target_ix],
        Some(&agent_pk),
        &[agent],
        bh,
    );

    println!("[verify] sending verify_and_execute (2-ix bound tx) ...");
    match client.send_and_confirm_transaction(&tx) {
        Ok(sig) => {
            println!("[verify] SUCCESS sig={sig}");
            println!("[verify] https://explorer.solana.com/tx/{sig}?cluster=devnet");
            result["verify_sig"] = serde_json::json!(sig.to_string());
            result["verify_success"] = serde_json::json!(true);
        }
        Err(e) => {
            println!("[verify] FAILED: {e}");
            result["verify_error"] = serde_json::json!(e.to_string());
            result["verify_success"] = serde_json::json!(false);
        }
    }

    // Read back nonce PDA to prove state changed.
    if let Ok(acct) = client.get_account(&nonce_pda) {
        result["nonce_pda_bytes"] = serde_json::json!(acct.data.len());
        result["nonce_pda_exists_after"] = serde_json::json!(true);
    }

    std::fs::write(
        "scripts/e2e-devnet/result.json",
        serde_json::to_string_pretty(&result)?,
    )?;
    println!("wrote scripts/e2e-devnet/result.json");
    Ok(())
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn read_keypair(path: &str) -> Result<Keypair> {
    let expanded = if let Some(stripped) = path.strip_prefix("~/") {
        format!("{}/{}", std::env::var("HOME").unwrap_or_default(), stripped)
    } else {
        path.to_string()
    };
    let bytes: Vec<u8> = serde_json::from_str(&std::fs::read_to_string(&expanded)?)
        .context("keypair json")?;
    Keypair::from_bytes(&bytes).map_err(|e| anyhow!("keypair: {e}"))
}

/// Hand-build the Ed25519Program precompile instruction. Layout matches what
/// `verify_ed25519_precompile` (on-chain) parses and what the Solana runtime's
/// ed25519 precompile verifies:
///
///   [0]    num_signatures = 1
///   [1]    padding        = 0
///   [2..16] Ed25519SignatureOffsets (14 bytes):
///       signature_offset(u16) sig_ix(u16) pubkey_offset(u16) pk_ix(u16)
///       message_offset(u16) message_size(u16) message_ix(u16)
///   then  pubkey(32) || signature(64) || message(N)
///
/// All instruction indices are 0xFFFF (= "this instruction").
fn build_ed25519_precompile_ix(pubkey: &[u8; 32], signature: &[u8; 64], message: &[u8]) -> Instruction {
    const HEADER: usize = 16;
    let pk_off = HEADER as u16;
    let sig_off = (HEADER + 32) as u16;
    let msg_off = (HEADER + 32 + 64) as u16;
    let msg_size = message.len() as u16;
    let here = u16::MAX;

    let mut data = Vec::with_capacity(HEADER + 32 + 64 + message.len());
    data.push(1u8); // num signatures
    data.push(0u8); // padding
    data.extend_from_slice(&sig_off.to_le_bytes());
    data.extend_from_slice(&here.to_le_bytes());
    data.extend_from_slice(&pk_off.to_le_bytes());
    data.extend_from_slice(&here.to_le_bytes());
    data.extend_from_slice(&msg_off.to_le_bytes());
    data.extend_from_slice(&msg_size.to_le_bytes());
    data.extend_from_slice(&here.to_le_bytes());
    data.extend_from_slice(pubkey);
    data.extend_from_slice(signature);
    data.extend_from_slice(message);

    Instruction {
        program_id: ed25519_program::id(),
        accounts: vec![],
        data,
    }
}
