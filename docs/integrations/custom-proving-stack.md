# Integration: Custom Proving Stack (Alternatives to RISC Zero)

Out-of-scope integration design for GLYPH v1. Tracks the abstraction
boundary for swapping zk-proving backends.

## 1. Paper Reference

- Tobin South, *Private, Verifiable, and Auditable AI Systems*
  (arXiv:2509.00085), Chapter 2 §"Verifiable evaluations of ML models"
  (`verifyevals.tex`):
  - Built on the **ezkl** toolkit + **Halo2** + **KZG** SRS (Perpetual
    Powers of Tau). The thesis explicitly does **not** lock the choice;
    §"Security Properties" lists the abstract properties (correctness,
    soundness, weight confidentiality, integrity, non-repudiation,
    succinctness, non-interactivity) that any valid replacement must
    satisfy.
  - §"Aggregation" — a Halo2 aggregation circuit produces a single
    proof. Choice of aggregator is implementation-defined.
- Chapter 2 §"Partial ZK" (`partialzk.tex`) — selective proving over
  LoRA / head layers (`BAx`, `HWx`) is orthogonal to the proving system
  used; any zkVM or circuit DSL that supports the target arithmetic
  works.

External grounding (verify version-specific details before implementing —
this space evolves quickly):
- **RISC Zero zkVM** (current GLYPH backend) — RISC-V guest, STARK proof
  wrapped to Groth16 BN254 for cheap on-chain verification.
- **SP1 zkVM** (Succinct Labs, 2024) — RISC-V guest similarly to RISC
  Zero, but proves via Plonky3 / FRI, wrapped to a Plonk-style on-chain
  proof. Different proving system, similar developer ergonomics.
- **Noir** (Aztec) — circuit DSL; backends include `barretenberg` (UltraHonk),
  Plonky3. Solana verifier support is not native and would need building.
- **Halo2** with KZG commitment scheme — used by ezkl; requires KZG
  trusted setup (powers of tau). On-chain verification on Solana
  requires BLS12-381 pairing support which (as of 2025-2026) is not a
  native Solana syscall — verify current state before assuming.

## 2. Current GLYPH State

GLYPH uses **RISC Zero zkVM v1.2.x** (`circuits/glyph-circuit/Cargo.toml`)
with a Groth16 BN254 wrapper for on-chain verification
(`programs/glyph-verifier/src/groth16/`). The on-chain verifier uses
Solana's `alt_bn128` precompiles for the BN254 pairing
(`groth16/verifier.rs`).

The TEE worker already abstracts proving behind a `Prover` trait
(`tee-worker/src/prover.rs`):

```rust
pub trait Prover {
    fn prove(&self, inputs: &PublicInputs) -> Result<ProofBundle>;
}
```

with `MockProver` (default) and `RiscZeroProver` (gated behind the
`risc0` cargo feature). Public inputs are computed in
`tee-worker/src/prover.rs` and are **proving-system-agnostic**:

```text
policy_commitment ‖ intent_hash ‖ agent_pubkey ‖ nonce ‖ tx_hash
```

This is the correct abstraction boundary; the bundle is already
agnostic.

## 3. Proposed Integration

Three concrete alternatives, all behind cargo features:

1. **SP1 zkVM (Succinct).** Same RISC-V guest model as RISC Zero —
   `circuits/glyph-circuit/guest/src/main.rs` would compile largely
   unchanged. Requires a new Solana verifier for SP1's Plonk wrapper.
2. **Noir + Plonky3.** Rewrite the guest as a Noir program; circuit is
   smaller / faster but the developer ergonomics are different (custom
   DSL vs. plain Rust). Requires a fresh Solana verifier.
3. **Halo2 + KZG.** Rewrite as a Halo2 circuit (ezkl-style). KZG
   commitment removes the need for a per-circuit trusted setup but
   requires BLS12-381 pairing support on-chain. **Unverified — flag:**
   Solana's `alt_bn128` syscall supports BN254 only as of writing;
   BLS12-381 verifier would currently need to be emulated in BPF
   (expensive) or wait for a syscall extension.

The `Prover` trait stays unchanged; the change is purely a new impl
plus a new on-chain verifier module:

```rust
pub enum ProofSystem {
    RiscZeroGroth16 = 1,   // current
    Sp1Plonk        = 2,
    NoirPlonky3     = 3,
    Halo2Kzg        = 4,
}
```

The `ProofBundle` already conceptually maps to this via the
`proof_kind` discriminator (currently implicit because there is only
one backend).

## 4. Wire Format / API Surface

`ProofBundle` (off-chain) gains an explicit discriminator:

```rust
pub struct ProofBundle {
    pub proof_kind: ProofSystem,        // NEW
    pub proof: Vec<u8>,                 // existing
    pub public_inputs: PublicInputs,    // existing, unchanged
    pub signed_transaction: Vec<u8>,    // existing
}
```

On-chain: a new instruction discriminator per proving system. The
`verify_and_execute` entrypoint dispatches:

```rust
match proof_kind {
    ProofSystem::RiscZeroGroth16 => groth16::verify_bn254(&proof, &public_inputs, &vk),
    ProofSystem::Sp1Plonk        => sp1::verify(&proof, &public_inputs, &vk),
    ProofSystem::NoirPlonky3     => noir::verify(&proof, &public_inputs, &vk),
    ProofSystem::Halo2Kzg        => halo2::verify(&proof, &public_inputs, &vk),
}
```

Each verifier needs its own VK PDA (the existing VK PDA in
`programs/glyph-verifier/` is RISC Zero / Groth16 specific).

## 5. Implementation Plan / Workstream

- **Owner:** TEE worker + verifier program maintainers. **Deferred to
  v2 / v3.** The current `Prover` trait is correctly abstracted; no
  pre-emptive refactor needed.
- **Phases:**
  1. Add the `ProofSystem` enum and `proof_kind` field; default to
     `RiscZeroGroth16`. Backwards compatible.
  2. **Optional path — SP1.** Lowest-friction port (same RISC-V guest).
     Build a Solana SP1 verifier (Succinct publishes one; verify
     compatibility with current Solana program model).
  3. **Optional path — Halo2/KZG.** Wait for BLS12-381 syscall support
     on Solana, OR use a coprocessor relay (the `Bonsai`-style pattern
     — submit the heavy proof off-chain, post a succinct on-chain
     attestation). This is also Halo2's natural deployment on EVM L2s.
  4. Per-system VK extraction tooling. The current `extract-vk` binary
     is RISC Zero specific; each new system needs its own.
- **Out of scope:** changing the public-input schema. Any new prover
  must commit to the same `(policy_commitment, intent_hash,
  agent_pubkey, nonce, tx_hash)` tuple.

## 6. Risks & Trade-offs

- **Each switch re-does the on-chain verifier.** This is the largest
  cost. Solana program changes are governance-sensitive; the existing
  Wave-2 work (VK PDA + multisig timelock) means any new verifier
  ships behind the same timelock.
- **Trusted setup re-ceremony for KZG.** Halo2/KZG requires a Perpetual
  Powers of Tau setup. Reusing the existing PPOT is fine for BN254
  but BLS12-381 requires the BLS12-381 transcript — verify the
  intended ceremony is sufficient.
- **STARK-based systems (SP1, Plonky3) have larger proofs.** Wrapping
  to a Plonk-style on-chain verifier mitigates this but adds a
  wrapping step (cost in proving time).
- **Tooling maturity.** RISC Zero v1.x is well-tested; SP1 is newer;
  Noir's Solana story is least mature. Migration risk scales
  accordingly.
- **Halo2 + Solana is currently impractical** (unverified — flag).
  BLS12-381 native syscall support on Solana would need to land for
  this path to be cost-effective. Until then, the coprocessor /
  Bonsai-relay pattern is the practical bridge.
- **Public-input commitment is the stable contract.** As long as every
  prover commits to the canonical tuple, the worker, SDK, and
  off-chain audit pipeline are agnostic — this is the single most
  important invariant to preserve across any proving-system swap.
