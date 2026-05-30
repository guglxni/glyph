#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
# GLYPH — "one policy, ANY Solana program" demo
# ═══════════════════════════════════════════════════════════════════════════════
# Runs the REAL glyph-tee-worker PolicyEngine + glyph_common canonicalization
# against ONE policy and FOUR intents that target FOUR different programs.
#
# Proves:
#   * the SAME policy_commitment is produced for every intent, and
#   * the 3 in-allowlist programs are ALLOWED while the out-of-policy one is DENIED
#
# No devnet, no network, no mocks of the policy logic. Always reproducible.
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# Resolve repo root from this script's location (scripts/ -> repo root).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== GLYPH multi-protocol demo ==="
echo "repo: ${REPO_ROOT}"
echo

cargo run \
  --example multi_protocol_demo \
  --manifest-path "${REPO_ROOT}/tee-worker/Cargo.toml"
