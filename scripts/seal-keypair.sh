#!/usr/bin/env bash
# scripts/seal-keypair.sh — seal a plaintext worker keypair under the
# configured TEE provider so it can be loaded with GLYPH_KEYPAIR_SEALED=1.
# Closes audit AUDIT_TEE.md T21 (worker keypair plaintext on disk).
#
# Usage:
#   scripts/seal-keypair.sh <input-keypair.json> <output-keypair.json.sealed>
#
# Env:
#   GLYPH_TEE_VENDOR        (required) — nitro | sgx | sev
#   GLYPH_SEAL_PASSPHRASE   (dev only) — passphrase for dev_seal AEAD
#                                        (must be >= 32 bytes)
#
# Notes:
# - In production, sealing should be performed by an in-enclave helper that
#   uses the real TEE-bound key (Nitro KMS, SGX EGETKEY, SEV vTPM/KMS).
#   This script's `--features` arm is the dev-mode passphrase path used
#   for laptop development and CI integration tests.
# - Output filename SHOULD end in `.sealed` so the worker auto-detects the
#   sealed format (load_signing_key in tee-worker/src/main.rs).

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <input-keypair.json> <output-keypair.json.sealed>" >&2
    exit 2
fi

INPUT="$1"
OUTPUT="$2"

if [[ -z "${GLYPH_TEE_VENDOR:-}" ]]; then
    echo "FATAL: GLYPH_TEE_VENDOR must be set (nitro|sgx|sev)" >&2
    exit 1
fi

if [[ -z "${GLYPH_SEAL_PASSPHRASE:-}" ]]; then
    echo "FATAL: GLYPH_SEAL_PASSPHRASE must be set (>= 32 bytes; dev-mode AEAD)" >&2
    exit 1
fi

if [[ ! -f "$INPUT" ]]; then
    echo "FATAL: input keypair not found: $INPUT" >&2
    exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# Build the sealing helper if needed and run it. The helper is a tiny
# Rust binary (compiled out of the tee-worker crate test harness) that
# wraps `provider.seal()` for the configured vendor.
cargo run -q --manifest-path "$REPO_ROOT/tee-worker/Cargo.toml" --example seal_blob -- \
    --input "$INPUT" --output "$OUTPUT"

echo "sealed keypair written to $OUTPUT"
echo "→ start the worker with GLYPH_KEYPAIR_PATH=$OUTPUT GLYPH_KEYPAIR_SEALED=1"
