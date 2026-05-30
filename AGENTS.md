# GLYPH — AI-DLC Project Workflow

> Using AWS AI-Driven Development Life Cycle (AI-DLC) methodology.

## Active Work

**Current Phase: 🔵 HARDENING — Gap Closure In Progress**

See `aidlc-docs/zk-upgrade-design.md` for the ZK design document.  
See `docs/production-migration-blueprint.md` for the full hardening plan.


---

## Quick Commands

```bash
# Run all non-ZK tests (always works)
cargo test -p glyph-circuit-host
cargo test --manifest-path tee-worker/Cargo.toml

# Build with real ZK (requires RISC Zero toolchain)
rustup toolchain install risc0
cargo build -p glyph-circuit-host --features risc0

# Run dev-mode ZK test (fast, no real proof)
RISC0_DEV_MODE=1 cargo test -p glyph-circuit-host --features risc0 -- --ignored dev_mode

# Extract the real VK after circuit build
cargo run --bin extract-vk --features risc0 \
  --manifest-path scripts/extract-vk/Cargo.toml > /tmp/vk_output.rs
# Then paste the output into programs/glyph-verifier/src/groth16/vk.rs

# Build the Anchor program (glyph-verifier)
cd programs/glyph-verifier && anchor build

# Run TEE worker in dev mode (DevProver, no ZK)
GLYPH_MODE=dev GLYPH_PROVER=dev cargo run --bin glyph-tee-worker

# Run TEE worker with real ZK + production mode enforcement
GLYPH_MODE=production GLYPH_PROVER=risc0 \
cargo run --bin glyph-tee-worker \
  --features risc0 --manifest-path tee-worker/Cargo.toml

# Test that production mode guard rejects DevProver (expect FATAL panic)
GLYPH_MODE=production GLYPH_PROVER=dev cargo run --bin glyph-tee-worker 2>&1 | grep FATAL

# Scan for placeholder VK (should return nothing for production builds)
grep -rn "PLACEHOLDER" programs/glyph-verifier/src/groth16/
```

---

## Architecture

```
Agent SDK
    │ TransactionIntent (signed JSON)
    ▼
TEE Worker (tee-worker/src/)
    ├── policy.rs        ← Stateless rules 1-6 evaluated in circuit
    │                      Stateful rules (time_window, daily_volume) evaluated here
    ├── prover.rs        ← RiscZeroProver | DevProver
    │     └── glyph_circuit_host::generate_proof()
    │           └── RISC Zero zkVM → STARK → Groth16 (BN254)
    └── transaction_builder.rs  ← Builds verify_and_execute ix with journal_bytes
            │
            ▼
    Solana Transaction (2 instructions):
    [0] glyph-verifier::verify_and_execute(proof, journal_bytes)
    [1] target_program::target_instruction(data)  ← proven by tx_hash

On-chain (programs/glyph-verifier/src/)
    ├── instructions/verify_and_execute.rs
    │     ├── Decode journal_bytes → PublicOutputs
    │     ├── Check policy_commitment == AgentRegistry.policy_commitment
    │     ├── Check agent_pubkey matches registry
    │     ├── Verify tx_hash == SHA-256(program_id || accounts || data)  ← FULL instruction hash
    │     ├── groth16::verify_groth16(a, b, c, SHA-256(journal_bytes))
    │     │     └── alt_bn128_pairing(4 pairs) ← REAL BN254 pairing
    │     └── Init nonce PDA (atomic replay prevention)
    └── groth16/
          ├── verifier.rs  ← BN254 Groth16 pairing via Solana syscalls
          └── vk.rs        ← Circuit verification key (update after circuit rebuild)
```

---

## ZK Upgrade Checklist

- [x] Guest circuit (`circuits/glyph-circuit/guest/src/main.rs`) — evaluates 6 stateless policy rules
- [x] Host prover (`circuits/glyph-circuit/host/src/lib.rs`) — feature-gated real proof generation
- [x] `build.rs` — risc0-build embeds guest ELF when `risc0` feature enabled
- [x] `tee-worker/src/prover.rs` — `RiscZeroProver` extracts journal_bytes from receipt
- [x] `tee-worker/src/types.rs` — `GlyphProofBundle` includes `journal_bytes` + `RuntimeMode` enum
- [x] `tee-worker/src/transaction_builder.rs` — sends `journal_bytes` in VerifyAndExecuteArgs
- [x] `programs/glyph-verifier/src/groth16/verifier.rs` — real BN254 pairing via alt_bn128 syscalls
- [x] `programs/glyph-verifier/src/groth16/vk.rs` — VK structure + real `verify_vk_integrity()` (SHA-256 hash check)
- [x] `programs/glyph-verifier/src/lib.rs` — full instruction hash binding (program_id+accounts+data)
- [x] `programs/glyph-verifier/src/lib.rs` — attestation commitment check on `update_policy`
- [x] `tee-worker/src/main.rs` — production mode guard (GLYPH_MODE=production rejects DevProver)
- [x] `tee-worker/src/vendors/` — Nitro/SGX/SEV fail-safe in production, real flow documented
- [x] `scripts/extract-vk/` — utility to generate real VK from compiled circuit
- [x] `.github/workflows/ci.yml` — CI pipeline with lint, test, placeholder-scan, prod-mode guard test
- [x] `tests/integration/pipeline_tests.rs` — 12 integration tests covering full off-chain pipeline
- [ ] **REQUIRED**: Run `extract-vk` after circuit build to populate real VK bytes in `vk.rs`
- [ ] **REQUIRED**: Install RISC Zero toolchain: `rustup toolchain install risc0`
- [ ] **REQUIRED**: Set Compute Budget to 1.4M CU in all transactions calling `verify_and_execute`
- [ ] **REQUIRED**: Implement KMS sealing in `tee-worker/src/vendors/nitro.rs` (NSM ioctl)
- [ ] **REQUIRED**: Implement SGX DCAP quote verification in `tee-worker/src/vendors/sgx.rs`
- [ ] **REQUIRED**: Implement SNP report verification in `tee-worker/src/vendors/sev.rs`

---

## Security Notes

### What the ZK upgrade provides
- **Real Groth16 soundness**: Proving a false statement requires breaking BN254 discrete log
- **Journal binding**: On-chain verifier reconstructs `PI = SHA-256(journal_bytes)` — no way to submit valid proof with wrong public inputs
- **Instruction binding**: `tx_hash = SHA-256(program_id || accounts || data)` — full canonical instruction hash
- **Replay resistance**: Nonce PDA initialized atomically
- **Production mode**: `GLYPH_MODE=production` enforces real ZK proving and rejects DevProver/RISC0_DEV_MODE
- **Attestation commitment**: `update_policy` verifies TEE attestation is bound to new policy commitment

### What is NOT yet in the circuit (TEE-enforced only)
- `time_window` (requires real-time clock)
- `daily_volume` (requires cross-request state)
- `allowed_token_mints` (requires token account introspection)

These are enforced by the TEE worker at the transport layer. Future work: bring them
into circuit via oracle commitment or state-hash schemes.
