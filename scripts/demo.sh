#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# GLYPH AI Agent Infrastructure — Colosseum Frontier Hackathon Demo
# ═══════════════════════════════════════════════════════════════════════════════
# DEMO ONLY — DO NOT BASE PRODUCTION DEPLOYMENT ON THIS SCRIPT.
# This script simulates the full end-to-end verifiable AI flow for showcase
# purposes; it skips production safety gates (no real attestation, dev prover,
# placeholder RPC). Production deploys MUST follow `aidlc-docs/RUNBOOK.md`.
# ═══════════════════════════════════════════════════════════════════════════════
# This script simulates the full end-to-end verifiable AI flow:
# 1. Start the TEE Worker in production-guarded mode.
# 2. Build and sign an Intent using the TypeScript SDK.
# 3. Request a ZK Proof (Groth16 BN254) from the TEE.
# 4. Verify the proof and execute the transaction on Solana Localnet.
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${RED}WARNING: DEMO ONLY — DO NOT BASE PRODUCTION DEPLOYMENT ON THIS SCRIPT.${NC}"
echo -e "${BLUE}=== GLYPH Verifiable AI Pipeline Demo ===${NC}\n"

# 1. Build the Solana Anchor Program
echo -e "${GREEN}[1/4] Building On-Chain Verifier (Anchor)...${NC}"
cd programs/glyph-verifier
if anchor build; then
  echo "Anchor build complete."
else
  echo -e "\n${RED}FATAL: Anchor build failed. Aborting demo.${NC}"
  exit 1
fi
cd ../..

# 2. Start the TEE Worker (in background)
echo -e "\n${GREEN}[2/4] Booting TEE Worker (Simulated SGX/Nitro enclave)...${NC}"
# We use dev-mode for the demo to bypass hardware checks, but the architecture is identical
export GLYPH_MODE=dev
export GLYPH_PROVER=dev 
cd tee-worker
cargo run --bin glyph-tee-worker &
WORKER_PID=$!
sleep 3 # Wait for server to bind
cd ..

# 3. Generate Intent & Fetch Proof (TypeScript SDK)
echo -e "\n${GREEN}[3/4] Agent SDK generating intent & requesting Groth16 Proof...${NC}"
cd sdk/typescript
# Compile SDK quickly
npm install --silent
npx tsc
# We run a quick demonstration script using the compiled SDK to hit the worker
cat << 'EOF' > run_demo.js
const { Keypair } = require('@solana/web3.js');
const { IntentBuilder } = require('./dist/intent.js');
const { GlyphClient } = require('./dist/client.js');

async function main() {
  const kp = Keypair.generate();
  console.log(`Agent Pubkey: ${kp.publicKey.toBase58()}`);
  
  const client = new GlyphClient({
    connection: null, // Simulated
    teeEndpoint: 'tcp://127.0.0.1:8088',
    agentKeypair: kp,
  });

  const intent = new IntentBuilder()
    .actionType('transfer')
    .targetProgram('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA')
    .accounts([{ pubkey: kp.publicKey.toBase58(), is_signer: true, is_writable: true }])
    .data('AQIDBAU=')
    .maxLamports(500000n)
    .build(kp);
    
  console.log("\n[Intent Signed]:", intent.signature.slice(0,32) + "...");
  console.log("Requesting Proof from TEE...");
  
  try {
    const bundle = await client.execute(intent);
    console.log("✅ Proof Received!");
    console.log(`[ZK tx_hash prefix]: ${Buffer.from(bundle.tx_hash_prefix).toString('hex')}`);
    console.log(`[Public Inputs]:`, bundle.public_inputs);
  } catch (err) {
    console.error("Worker Error:", err.message);
  }
}
main();
EOF

node run_demo.js
cd ../..

# 4. Clean up
echo -e "\n${GREEN}[4/4] Shutting down TEE Worker...${NC}"
kill $WORKER_PID
wait $WORKER_PID 2>/dev/null || true

echo -e "\n${BLUE}=== Demo Complete! ===${NC}"
echo "In a live environment, the bundle is submitted to the Solana RPC,"
echo "the Anchor program verifies the BN254 Groth16 pairing on-chain,"
echo "and atomically invokes the CPI target."
