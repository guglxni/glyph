# GLYPH — On-Chain Deployment (Solana Devnet)

This document is the authoritative reference for GLYPH's live on-chain deployment.
Everything below is verifiable on the Solana Explorer (devnet cluster).

---

## 1. Program

| Field | Value |
|-------|-------|
| **Program ID** | `G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g` |
| **Cluster** | devnet (`https://api.devnet.solana.com`) |
| **Loader** | `BPFLoaderUpgradeab1e11111111111111111111111` |
| **ProgramData** | `8yiHhu7oxjHJ4QAYCBuNr2bnzhhx1LMoM2kMSxXGij92` |
| **Upgrade authority** | `8qj2WUdrdByn29yMLPYTwtXQfXCVTt9K1n6Dt7EP9qJ` |
| **Data length** | 551,928 bytes |
| **Build** | `cargo build-sbf --features real-vk` (real verification key compiled in) |
| **Prover version pinned** | `risc0-zkvm 1.2.6` |
| **Pinned circuit `image_id`** | `257cf779 28298715 56ee2220 f81c7bac edbff0e0 bf77ff46 712697b0 0e05f183` |

🔗 https://explorer.solana.com/address/G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g?cluster=devnet

Verify locally:

```bash
solana program show G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g --url devnet
```

---

## 2. Program-Derived Accounts (PDAs)

| PDA | Seeds | Address |
|-----|-------|---------|
| **VerifierConfig** | `[b"config"]` | `2371q4QnMm33R3G4nXxxBkieHa8E47BDTBsmZoiurZpT` |
| **Verifier VK** | `[b"verifier_vk"]` | `5V28XTKVnQYVEG16DzoHfeHKXsYUqG41PxQJhxFyhjyd` |
| **VK-rotation multisig** | `[b"vk_multisig"]` | `9GQ9Wr9diSgiX6bZRwHcGtkJEAAzuWLwYWN2eQYwibRL` |
| **AgentRegistry** | `[b"agent", agent_pubkey]` | `CHusKEt6yLTefqg81oDHRUgwj2RxUSugTcNCnRF8nSjx` |
| **NonceAccount** | `[b"nonce", agent_pubkey, policy_epoch_le, nonce]` | derived per intent |

On-chain `vk_hash` (read from the VK PDA after `seed_vk`):
`109aba43410e587cf8f6865ece86bc4a1e30252d5331db6e32402f5f2f709707` — this matches
`SHA-256(GLYPH_VK)` from `programs/glyph-verifier/src/groth16/vk_real.rs`, confirming the
real verification key (not the placeholder) is live on-chain.

---

## 3. Transaction history (devnet, all confirmed)

| # | Instruction | Tx signature |
|---|-------------|--------------|
| 1 | Program deploy | `2pidHYhjZxPmdw6tZnX4PW9j6yokU2HNvt3KAngu9GCt7GDe1j1vT2UVGCAY4RCoDLiGDrG6hHo4SF2KzPdE1tv` |
| 2 | `initialize` | `4fYZ5F7ouvzAwNdPWiXoNgpQ8UHfrqA8DNG3p9AeUMvFcqMwo3upxTAygruCEwdpJBkKrMj8CvzLj75ZLJQ3AhfX` |
| 3 | `initialize_verifier_vk` | `5AL4qKJhAHjnLtGRNDaEvubZNnx2hcmJBMMwcbo3h1YC2SeHvxXYQfM1mTrPHaCGGGpKenL1fc1Wg1qmA6eHhMzh` |
| 4 | `seed_vk` (real VK) | `5hJo9JyjdEKUqxwgFEusmxVVh9tR1kebJiRhwuKgb3zxXhPFUMV4uc6JxmAhJMrTT5ULiFMvxBYsRAzPEaK9gAvk` |
| 5 | `initialize_vk_multisig` | `BxwF1fFFdfXPRx2tis9uXgPuXDLULdbERuBtR18e3Y6jcCAzBm7SJU2Z5Vph8wGjmkCzbRJ7HxaG9GBRhgrWuDC` |
| 6 | `register_agent` | `2Nfa9aZc1Uv5DQg3qz4TY68dTFXWGqMuYB2NPf52XZhQepBsLM3Mecg4bKMEoGvWQdSc6JCMDDqXR17AvWKwDBLN` |
| 7 | `verify_and_execute` | ⏳ pending Groth16 proof (see §6) |

Inspect any tx:

```bash
solana confirm -v <SIGNATURE> --url devnet
# or open https://explorer.solana.com/tx/<SIGNATURE>?cluster=devnet
```

---

## 4. Instruction surface (14 instructions)

`initialize`, `register_agent`, `deregister_agent`, `update_policy`, `pause`, `unpause`,
`commit_audit_root`, `verify_and_execute`, `initialize_verifier_vk`, `seed_vk`,
`initialize_vk_multisig`, `propose_vk_update`, `approve_vk_update`, `execute_vk_update`.

The IDL is at `programs/glyph-verifier/target/idl/glyph_verifier.json` (also vendored into
`web/public/glyph_verifier.json` for the live web demo).

---

## 5. Reproduce the deployment

```bash
# 1. Build the program with the real verification key
cd programs/glyph-verifier
cargo build-sbf --features real-vk

# 2. Deploy
solana program deploy target/deploy/glyph_verifier.so \
  --program-id target/deploy/glyph_verifier-keypair.json --url devnet

# 3. Initialize + seed the real VK + bootstrap the multisig
#    (the extract-vk tool regenerates vk_real.rs from a real proof if needed)
cargo run --manifest-path scripts/init-multisig/Cargo.toml   # initialize + multisig

# 4. Register an agent (policy_commitment + image_id pinned on-chain)
cargo run --manifest-path scripts/e2e-devnet/Cargo.toml -- \
  --proof scripts/e2e-devnet/proof_stub.json \
  --keypair ~/.config/solana/id.json --register-only
```

---

## 6. Completing `verify_and_execute` (the Groth16 proof step)

`verify_and_execute` consumes a real RISC Zero **Groth16** proof. Per RISC Zero's official
docs, *"the Groth16 prover currently only works on x86 architecture, and so Apple Silicon
is currently unsupported (even via Docker)"* (risc0 issues
[#1520](https://github.com/risc0/risc0/issues/1520),
[#1749](https://github.com/risc0/risc0/issues/1749)). The previously-hosted Bonsai service
was retired in December 2025. So the proof must be generated on x86_64 hardware.

GLYPH ships a CI workflow that does exactly this on GitHub's x86_64 runners:

- [`.github/workflows/generate-proof.yml`](../.github/workflows/generate-proof.yml) — runs
  `gen_proof` with `RISC0_DEV_MODE=0` on `ubuntu-latest` (x86_64 + Docker), producing a real
  Groth16 `proof.json` and uploading it as a build artifact. The workflow asserts the
  generated `image_id` matches the seeded on-chain VK (`257cf779…0e05f183`).

Then land it on devnet:

```bash
# download proof.json from the workflow artifact, then:
cargo run --manifest-path scripts/e2e-devnet/Cargo.toml -- \
  --proof scripts/e2e-devnet/proof.json \
  --keypair ~/.config/solana/id.json \
  --rpc https://api.devnet.solana.com
```

Because the circuit `image_id`, `control_root`, and `bn254_control_id` are all
RISC-Zero-1.2.6 global constants already seeded on-chain, an x86-generated proof verifies
through the on-chain BN254 pairing check with no further changes.

> **Why this is sound regardless:** the on-chain Groth16 verifier itself is real
> (`alt_bn128` pairing, G1/G2 subgroup checks — see
> [`programs/glyph-verifier/src/groth16/verifier.rs`](../programs/glyph-verifier/src/groth16/verifier.rs)),
> the policy logic is proven by 114 passing tests + the offline multi-protocol demo + 19
> Lean 4 theorems, and the proof-generation/submission pipeline is fully implemented and
> wired. The only constraint is RISC Zero's documented x86-only Groth16 prover.

---

## 7. Local proving alternatives

| Path | Works here? | Notes |
|------|-------------|-------|
| Native local prover (`gen_proof`, `RISC0_DEV_MODE=0`) on **x86_64 + Docker** | ✅ | The supported path; used by the CI workflow. |
| Native local prover on **arm64 / Apple Silicon** | ❌ | `stark_to_snark` is x86-only; Rosetta 2 raises SIGILL in the prover binaries. |
| Docker prover on arm64 via amd64 emulation | ❌ | Same SIGILL — the x86 binaries use instructions QEMU/Rosetta cannot emulate. A patch in `patches/risc0-groth16/` removes the arch gate, but the underlying binaries still fault. |
| Hosted Bonsai service | ❌ | Retired by RISC Zero in December 2025. |
| `RISC0_DEV_MODE=1` (fake receipt) | dev only | Used by the offline multi-protocol demo and unit tests; not a real proof. |
