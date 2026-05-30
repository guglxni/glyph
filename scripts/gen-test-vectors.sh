#!/usr/bin/env bash
# Regenerate canonical-byte test vectors from sdk/test-vectors/{intents,policies}/*.input.json.
#
# Usage:
#   bash scripts/gen-test-vectors.sh
#
# Output:
#   sdk/test-vectors/intents/<n>.canonical.bytes
#   sdk/test-vectors/intents/<n>.signed.json
#   sdk/test-vectors/policies/<n>.canonical.bytes
#   sdk/test-vectors/policies/<n>.signed.json
#
# These pin the byte-level encoding contract between the Rust SDK, the TEE
# worker, and the TS SDK. CI should run this script and assert no diff.

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

cargo run --quiet \
  -p glyph-common \
  --features vector-gen \
  --bin gen-test-vectors -- \
  sdk/test-vectors

echo "[ok] regenerated test vectors under sdk/test-vectors/"
