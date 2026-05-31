//! GLYPH e2e proof generator.
//!
//! Generates a REAL RISC Zero Groth16 proof for a valid System-Program
//! transfer intent that satisfies the multi-protocol example policy, and dumps
//! everything the on-chain `verify_and_execute` flow needs into a JSON file.
//!
//! Run (requires the RISC Zero toolchain; RISC0_DEV_MODE must be UNSET):
//!     cargo run -p glyph-circuit-host --features risc0 --bin gen_proof -- \
//!         --agent <AGENT_PUBKEY_BASE58_AS_32_HEX> \
//!         --out scripts/e2e-devnet/proof.json
//!
//! The agent pubkey, target accounts and instruction data are passed as hex
//! (32-byte) values so this binary needs no base58 dependency. The companion
//! `scripts/e2e-devnet` crate computes those and invokes this binary.

#[cfg(not(feature = "risc0"))]
fn main() {
    eprintln!("gen_proof requires --features risc0 (real proving). Aborting.");
    std::process::exit(2);
}

#[cfg(feature = "risc0")]
fn main() -> anyhow::Result<()> {
    use anyhow::{anyhow, Context};
    use glyph_common::{
        canonical_target_instruction_bytes, hash_policy, CanonicalAccountMeta, IntentPayload,
        Policy, PublicOutputs, TimeWindow,
    };
    use glyph_circuit_host::{generate_proof, IntentExtras, GLYPH_CIRCUIT_ID};

    // ── Parse args ──────────────────────────────────────────────────────────
    let mut out_path = String::from("scripts/e2e-devnet/proof.json");
    let mut agent_hex: Option<String> = None;
    let mut agent_keypair: Option<String> = None;
    let mut from_hex: Option<String> = None;
    let mut to_hex: Option<String> = None;
    let mut nonce_hex: Option<String> = None;
    let mut lamports: u64 = 1_000_000; // 0.001 SOL transfer
    let mut expiry: u64 = 0;
    let mut attested_timestamp: u64 = 0;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out" => out_path = args.next().context("--out needs value")?,
            "--agent" => agent_hex = Some(args.next().context("--agent needs value")?),
            "--agent-keypair" => agent_keypair = Some(args.next().context("--agent-keypair needs value")?),
            "--from" => from_hex = Some(args.next().context("--from needs value")?),
            "--to" => to_hex = Some(args.next().context("--to needs value")?),
            "--nonce" => nonce_hex = Some(args.next().context("--nonce needs value")?),
            "--lamports" => lamports = args.next().context("--lamports")?.parse()?,
            "--expiry" => expiry = args.next().context("--expiry")?.parse()?,
            "--attested" => attested_timestamp = args.next().context("--attested")?.parse()?,
            other => return Err(anyhow!("unknown arg {other}")),
        }
    }

    fn hex32(s: &str) -> anyhow::Result<[u8; 32]> {
        let v = hex::decode(s).context("bad hex")?;
        if v.len() != 32 {
            return Err(anyhow::anyhow!("expected 32 bytes, got {}", v.len()));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&v);
        Ok(out)
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();
    if expiry == 0 {
        expiry = now + 3600; // 1h
    }
    if attested_timestamp == 0 {
        attested_timestamp = now;
    }

    let agent = match (&agent_hex, &agent_keypair) {
        (Some(h), _) => hex32(h)?,
        (None, Some(path)) => {
            // Solana keypair JSON is a 64-byte array; bytes 32..64 are the pubkey.
            let kp: Vec<u8> = serde_json::from_str(&std::fs::read_to_string(path)?)?;
            if kp.len() != 64 {
                return Err(anyhow!("keypair json must be 64 bytes, got {}", kp.len()));
            }
            let mut a = [0u8; 32];
            a.copy_from_slice(&kp[32..64]);
            a
        }
        (None, None) => [3u8; 32],
    };
    let from = match &from_hex {
        Some(h) => hex32(h)?,
        None => agent,
    };
    let to = match &to_hex {
        Some(h) => hex32(h)?,
        None => [9u8; 32],
    };
    let nonce = match &nonce_hex {
        Some(h) => hex32(h)?,
        None => [7u8; 32],
    };

    // System Program id = all zeros (11111111111111111111111111111111).
    let system_program = [0u8; 32];

    // System Program "transfer" instruction data: u32 tag=2 (LE) + u64 lamports (LE).
    let mut ix_data = Vec::with_capacity(12);
    ix_data.extend_from_slice(&2u32.to_le_bytes());
    ix_data.extend_from_slice(&lamports.to_le_bytes());

    // Transfer accounts: [from (signer, writable), to (writable)].
    let accounts = vec![
        CanonicalAccountMeta { pubkey: from, is_signer: true, is_writable: true },
        CanonicalAccountMeta { pubkey: to, is_signer: false, is_writable: true },
    ];

    // The bytes the circuit hashes as tx_hash MUST equal what the on-chain
    // verifier reconstructs from the next instruction:
    //   sha256(canonical_target_instruction_bytes(program, accounts, data)).
    let tx_bytes = canonical_target_instruction_bytes(&system_program, &accounts, &ix_data);

    // Policy mirrors examples/multi-protocol/policy.toml (System program allowed).
    let token_program = bs58_like_tokenkeg();
    let memo_program = bs58_like_memo();
    let policy = Policy {
        version: 1,
        max_lamports_per_tx: 1_000_000_000,
        allowed_programs: vec![system_program, token_program, memo_program],
        time_window: Some(TimeWindow { start_hour_utc: 0, end_hour_utc: 23 }),
        max_daily_volume_lamports: 5_000_000_000,
        max_slippage_bps: None,
        allowed_token_mints: None,
        max_accounts_per_tx: None,
        require_signer_present: true,
        expires_at: 0,
    };
    let policy_commitment = hash_policy(&policy);

    let intent = IntentPayload {
        agent_pubkey: agent,
        nonce,
        target_program: system_program,
        max_lamports: lamports,
        max_slippage_bps: None,
        num_accounts: accounts.len() as u16,
        expiry,
    };

    let extras = IntentExtras {
        allowed_tokens: None,
        has_signer: true, // the `from` account is a signer
        mint_inclusion_proofs: Vec::new(),
    };

    eprintln!("[gen_proof] image_id (from compiled guest) = {:08x?}", GLYPH_CIRCUIT_ID);
    eprintln!("[gen_proof] policy_commitment = {}", hex::encode(policy_commitment));
    eprintln!("[gen_proof] generating REAL Groth16 proof (this can take minutes)...");
    let t0 = std::time::Instant::now();

    let (receipt, public_inputs) = generate_proof(
        intent,
        policy.clone(),
        tx_bytes.clone(),
        attested_timestamp,
        0, // prior_daily_total
        extras,
    )
    .context("real proof generation failed")?;
    let elapsed = t0.elapsed();
    eprintln!("[gen_proof] proof generated in {:.1}s", elapsed.as_secs_f64());

    // Journal bytes (borsh PublicOutputs) — the on-chain verifier decodes these.
    let journal_bytes = receipt.receipt.journal.bytes.clone();
    let decoded: PublicOutputs = borsh::BorshDeserialize::try_from_slice(&journal_bytes)
        .context("decode journal")?;
    if decoded.failure_code != 0 {
        return Err(anyhow!("circuit reported failure_code={}", decoded.failure_code));
    }

    // Extract Groth16 seal points (raw 256-byte seal).
    let inner = receipt
        .receipt
        .inner
        .groth16()
        .context("not a groth16 receipt")?;
    let seal = &inner.seal;
    if seal.len() != 256 {
        return Err(anyhow!("unexpected seal length {} (want 256)", seal.len()));
    }
    let proof_a = &seal[0..64];
    let proof_b = &seal[64..192];
    let proof_c = &seal[192..256];

    // Verify the proof's committed image_id matches the compiled guest's image_id.
    let img_matches = decoded.image_id == GLYPH_CIRCUIT_ID;
    eprintln!("[gen_proof] journal.image_id matches compiled guest: {img_matches}");

    let json = serde_json::json!({
        "image_id_u32": GLYPH_CIRCUIT_ID,
        "image_id_hex_be": GLYPH_CIRCUIT_ID.iter().map(|w| format!("{w:08x}")).collect::<Vec<_>>().join(""),
        "policy_commitment_hex": hex::encode(policy_commitment),
        "journal_bytes_hex": hex::encode(&journal_bytes),
        "proof_a_hex": hex::encode(proof_a),
        "proof_b_hex": hex::encode(proof_b),
        "proof_c_hex": hex::encode(proof_c),
        "tx_bytes_hex": hex::encode(&tx_bytes),
        "target_program_hex": hex::encode(system_program),
        "ix_data_hex": hex::encode(&ix_data),
        "from_hex": hex::encode(from),
        "to_hex": hex::encode(to),
        "agent_hex": hex::encode(agent),
        "nonce_hex": hex::encode(nonce),
        "lamports": lamports,
        "expiry": expiry,
        "attested_timestamp": attested_timestamp,
        "prover_version": format!("risc0-zkvm {}", risc0_zkvm::VERSION),
        "decoded_failure_code": decoded.failure_code,
        "decoded_circuit_rule_bitmap": decoded.circuit_rule_bitmap,
        "decoded_tx_hash_hex": hex::encode(decoded.tx_hash),
        "proof_gen_secs": elapsed.as_secs_f64(),
        "_public_inputs_policy_commitment_hex": hex::encode(public_inputs.outputs.policy_commitment),
    });

    if let Some(parent) = std::path::Path::new(&out_path).parent() {
        std::fs::create_dir_all(parent).ok();
    }
    std::fs::write(&out_path, serde_json::to_string_pretty(&json)?)
        .with_context(|| format!("writing {out_path}"))?;
    eprintln!("[gen_proof] wrote {out_path}");
    Ok(())
}

// TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA decoded to 32 bytes.
#[cfg(feature = "risc0")]
fn bs58_like_tokenkeg() -> [u8; 32] {
    // hardcoded base58 decode of the SPL Token program id
    [
        0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79,
        0xac, 0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff,
        0x00, 0xa9,
    ]
}

// MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr decoded to 32 bytes.
#[cfg(feature = "risc0")]
fn bs58_like_memo() -> [u8; 32] {
    [
        0x05, 0x4a, 0x53, 0x5a, 0x99, 0x29, 0x21, 0x06, 0x4d, 0x24, 0xe8, 0x71, 0x60, 0xda, 0x38,
        0x7c, 0x7c, 0x35, 0xb5, 0xdd, 0xbc, 0x92, 0xbb, 0x81, 0xe4, 0x1f, 0xa8, 0x40, 0x41, 0x05,
        0x44, 0x8d,
    ]
}
