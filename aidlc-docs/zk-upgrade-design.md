# GLYPH: Placeholder Groth16 → Real ZK Upgrade

**AI-DLC Phase: Construction**  
**Status: In Progress**  
**Date: 2026-04-02**

---

## Problem Statement

The `verify_groth16_proof` function in `programs/glyph-verifier/src/instructions/verify_and_execute.rs`
is a **format-only stub** — it checks that proof bytes are non-zero but performs no cryptographic
pairing check. This means any non-zero proof bytes pass verification, making the on-chain
security guarantee completely hollow.

Similarly, `GLYPH_CIRCUIT_ELF` in `circuits/glyph-circuit/host/src/lib.rs` is a hardcoded
empty slice, so `generate_proof()` returns an error unconditionally.

---

## Architecture Decision

### Option A: Solana Native `sol_verify_groth16` Syscall (PREFERRED — Future)
Solana has proposed a native `sol_verify_groth16` syscall (pending SIMD). When available,
this is 1 CU-cheap and validator-validated. We scaffold for this path.

### Option B: On-chain Groth16 via `ark-groth16` + BN254 (CURRENT — Practical)
Use the `ark-groth16` / `ark-bn254` crates. Fits in ~450ms with Compute Budget 1.4M.
The RISC Zero Groth16 proof is over BN254 — direct compatibility.

### Option C: Delegate to RISC Zero's Bonsai Relay (FALLBACK)
The Bonsai relay posts a Groth16 proof on Solana via their on-chain verifier program.
Simpler but adds a dependency on Bonsai infra.

**Decision: Implement Option B now (ark-bn254), design interfaces for Option A drop-in.**

---

## Implementation Plan

### Layer 1 — Guest ELF Embedding (Off-chain Circuit)
**File:** `circuits/glyph-circuit/host/build.rs`
- Use `risc0_build::embed_methods()` to compile and embed the guest binary
- Build feature flag: `risc0-build` feature activates real ELF embedding

### Layer 2 — Host Prover (Off-chain ZK proof generation)
**Files:**
- `circuits/glyph-circuit/host/src/lib.rs` — fix `GLYPH_CIRCUIT_ELF` + real `generate_proof`
- `circuits/glyph-circuit/host/src/prover.rs` — add `RealProver` using `risc0-zkvm` Groth16 backend
- `tee-worker/src/prover.rs` — wire `RiscZeroProver` to use `RealProver`

### Layer 3 — On-chain Groth16 Verifier (The KEY upgrade)
**Files:**
- `programs/glyph-verifier/src/groth16/mod.rs` — BN254 Groth16 verifier
- `programs/glyph-verifier/src/groth16/vk.rs` — hardcoded RISC Zero BN254 verification key
- `programs/glyph-verifier/src/groth16/pairing.rs` — BN254 pairing via ark-bn254
- `programs/glyph-verifier/src/instructions/verify_and_execute.rs` — replace stub

### Layer 4 — Public Input Hashing (Proof-circuit alignment)
The RISC Zero Groth16 prover commits `SHA-256(journal_bytes)` as the single public input.
The on-chain verifier must hash `PublicOutputs` the same way.

### Layer 5 — Proof Bundle Format (Wire format)
The `GlyphProofBundle` must carry:
- `proof.a` (G1, 64 bytes), `proof.b` (G2, 128 bytes), `proof.c` (G1, 64 bytes)  
- `journal_bytes: Vec<u8>` — the raw RISC Zero journal (borsh-encoded PublicOutputs)
- `image_id: [u8; 32]` — the guest ELF image ID (bound in the VK)

---

## Security Properties (Post-Upgrade)

| Guarantee | Mechanism |
|---|---|
| Policy compliance | ZK circuit enforces all 6 stateless rules — proven in TEE |
| Policy commitment binding | `SHA256(canonical_policy)` is a public input to the circuit |
| Agent identity binding | `agent_pubkey` committed in the circuit journal |
| Replay prevention | Nonce PDA initialized atomically on-chain |
| Instruction binding | `SHA256(next_ix.data)` committed as `tx_hash` in circuit |
| TEE attestation | Stored in AgentRegistry at registration |
| ZK proof soundness | Groth16 over BN254, RISC Zero trusted setup |

---

## Known Limitations Post-Upgrade

- `time_window`, `daily_volume`, `allowed_token_mints` still enforced only by TEE worker,
  not in circuit (they require real-time state). Document explicitly in comments.
- Groth16 proof generation is slow (~5-60s on CPU). For production: use Bonsai remote proving
  or a dedicated GPU prover machine.
- `GLYPH_CIRCUIT_ELF` requires `risc0-build` toolchain (RISC V target). CI needs to install it.
