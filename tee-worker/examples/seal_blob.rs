//! Sealing helper used by `scripts/seal-keypair.sh` (closes T21).
//!
//! Reads a plaintext blob, calls `provider.seal()` on the configured
//! TEE vendor, and writes the sealed bytes to disk. Picks the vendor from
//! `GLYPH_TEE_VENDOR` (`nitro`|`sgx`|`sev`).
//!
//! In dev mode this routes through `dev_seal::dev_seal_with_passphrase`
//! (Argon2id + ChaCha20-Poly1305 keyed off `GLYPH_SEAL_PASSPHRASE`). In
//! production the real vendor seal path is used.
//!
//! Run via:
//!   cargo run --example seal_blob -- --input keypair.json --output keypair.json.sealed

use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use glyph_tee_worker::types::TeeVendor;
use glyph_tee_worker::vendors::create_provider;

fn parse_args() -> Result<(PathBuf, PathBuf)> {
    let mut args = std::env::args().skip(1);
    let mut input: Option<PathBuf> = None;
    let mut output: Option<PathBuf> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--input" => input = args.next().map(PathBuf::from),
            "--output" => output = args.next().map(PathBuf::from),
            other => return Err(anyhow!("unexpected arg: {other}")),
        }
    }
    Ok((
        input.ok_or_else(|| anyhow!("--input is required"))?,
        output.ok_or_else(|| anyhow!("--output is required"))?,
    ))
}

fn pick_vendor() -> Result<TeeVendor> {
    match std::env::var("GLYPH_TEE_VENDOR")
        .map_err(|_| anyhow!("GLYPH_TEE_VENDOR must be set (nitro|sgx|sev)"))?
        .to_lowercase()
        .as_str()
    {
        "nitro" => Ok(TeeVendor::Nitro),
        "sgx" => Ok(TeeVendor::Sgx),
        "sev" => Ok(TeeVendor::Sev),
        other => Err(anyhow!("unknown GLYPH_TEE_VENDOR: {other}")),
    }
}

fn main() -> Result<()> {
    let (input_path, output_path) = parse_args()?;
    let vendor = pick_vendor()?;
    let provider = create_provider(vendor);

    let plaintext = std::fs::read(&input_path)
        .with_context(|| format!("failed to read {}", input_path.display()))?;

    let sealed = provider
        .seal(&plaintext)
        .context("provider.seal failed (check GLYPH_SEAL_PASSPHRASE in dev mode)")?;

    std::fs::write(&output_path, sealed)
        .with_context(|| format!("failed to write {}", output_path.display()))?;

    eprintln!(
        "sealed {} bytes -> {} ({:?} provider)",
        plaintext.len(),
        output_path.display(),
        provider.vendor()
    );
    Ok(())
}
