# GLYPH

**A verifiable policy-enforcement / guardrail layer for autonomous agents on Solana.**

GLYPH lets an autonomous agent prove — with a zero-knowledge proof — that every transaction it is about to submit was authorized by a per-agent policy *before* it touches the chain. A TEE worker evaluates the policy, a RISC Zero zkVM produces a succinct proof of correct policy evaluation, and an on-chain Solana program verifies the Groth16 proof and **cryptographically binds it to the very next instruction in the transaction**. GLYPH does not execute the agent's action itself — it gates and binds it; Solana's runtime then executes the bound instruction. No valid proof, no execution.

> **It works with any Solana program.** GLYPH is program-agnostic *by construction*: a transaction intent carries `target_program + accounts[] + data` as opaque bytes, and the verifier hashes the next instruction generically. There is no hardcoded target allowlist in the verifier or the circuit — the allowlist is per-agent TOML. Whatever your agent calls (a DEX, a lending market, a transfer, your own program), GLYPH can guard it.

---

## The problem

Autonomous agents that hold keys and move funds are a trust black box. Today you must trust:

- that the agent's off-chain logic actually ran the policy you think it did,
- that nobody tampered with the agent between decision and execution,
- that the operator isn't lying about what the agent is allowed to do.

GLYPH collapses all three into a single on-chain check: **no valid proof, no execution.**

---

## What makes this novel

- **Guardrail sidecar, not a wrapper.** GLYPH is instruction `0` in a transaction; the agent's real action is instruction `1`. The verifier hashes instruction `1` and refuses unless that hash matches what the proof committed to. It never CPIs into the target program, so it adds a verifiable gate without intercepting or re-implementing anyone's program.
- **Real on-chain Groth16 verification.** The verifier performs real BN254 pairing checks via Solana's `alt_bn128` syscalls — with G1/G2 on-curve and subgroup checks and the RISC Zero 5-public-input layout — not just format validation.
- **Defense in depth on-chain.** Beyond the pairing, `verify_and_execute` enforces image-id pinning, journal expiry against the `Clock` sysvar, attested-timestamp drift bounds, tx-hash binding to the next instruction, nonce replay protection, and a required-rules bitmask.
- **Program-agnostic horizontal layer.** One guardrail that any agent on any Solana program can adopt by writing a TOML policy — no per-protocol integration work.
- **Three independent trust roots compose.** Hardware (TEE), cryptography (ZK proof), and consensus (on-chain verifier) each have to fail for an unauthorized action to land.

---

## How it works

```
┌──────────────┐  intent  ┌───────────────────┐  guest  ┌────────────────────┐
│   Agent /    │ ───────▶ │    TEE Worker     │ ──────▶ │   RISC Zero zkVM    │
│  Application │          │  (policy engine)  │         │ (proof of policy    │
│              │          │   9 rules / TOML  │         │  evaluation)        │
└──────────────┘          └───────────────────┘         └──────────┬──────────┘
                                                                    │ Groth16 proof
                                                                    │ + journal
                                                                    ▼
                          ┌──────────────────────────────────────────────────┐
                          │              Solana Transaction                    │
                          │  ix[0] glyph-verifier::verify_and_execute (gate)   │
                          │        • BN254 pairing check (alt_bn128)           │
                          │        • image-id pin, expiry, drift, nonce        │
                          │        • hash(ix[1]) == journal.tx_hash  ◀─binds   │
                          │  ix[1] target_program::<agent action> (executes)   │
                          └──────────────────────────────────────────────────┘
```

1. **Agent** proposes a transaction intent (`target_program + accounts[] + data`).
2. **TEE worker** evaluates the per-agent TOML policy inside a trusted enclave.
3. **RISC Zero zkVM** generates a proof that the policy was evaluated correctly and commits the result to a public journal.
4. **Solana program** verifies the Groth16 proof on-chain, binds it to the next instruction, and only then permits the transaction. Solana executes the bound instruction.

---

## Trust stack

GLYPH layers three independent trust primitives. An attacker has to defeat all three.

| Layer | Primitive | Guarantee |
|-------|-----------|-----------|
| **1. Hardware** | Trusted Execution Environment (TEE) | The policy engine ran in an isolated enclave; inputs/outputs weren't tampered with. |
| **2. Cryptography** | RISC Zero zkVM (Groth16) | A succinct proof that the *correct* policy was evaluated against *this* intent and passed. |
| **3. Consensus** | On-chain Solana verifier | Real BN254 pairing verification of the proof + binding to the executed instruction, enforced by the network. |

---

## Policy DSL (9 rules)

Policies are per-agent TOML files. The engine (`tee-worker/src/policy.rs`, `PolicyRule` enum) implements **9 enforcement rules**. Rule 3 (`TimeWindow`) is enforced **in-circuit and on-chain against the `Clock` sysvar**, not by a host-side check.

| # | Rule | Parameters | Enforces |
|---|------|-----------|----------|
| 1 | `MaxLamportsPerTx` | `max_lamports: u64` | Per-transaction lamport ceiling. |
| 2 | `AllowedPrograms` | `programs: [String]` | Target program must be on the per-agent allowlist. |
| 3 | `TimeWindow` | `start_hour, end_hour: u8` | Action only within an allowed hour window (in-circuit + on-chain `Clock`). |
| 4 | `MaxDailyVolumeLamports` | `max_lamports: u64` | Rolling daily volume cap. |
| 5 | `RequireSlippageBpsLte` | `max_bps: u16` | Slippage must be ≤ N basis points. |
| 6 | `AllowedTokenMints` | `mints: [String]` | Only approved token mints may be touched. |
| 7 | `MaxAccountsPerTx` | `max_accounts: usize` | Bounds the number of accounts in the transaction. |
| 8 | `RequireSignerPresent` | `signer: String` | A required signer must be present. |
| 9 | `PolicyExpired` | `expires_at: i64` | Policy is rejected after its expiry timestamp. |

See [Policy DSL](docs/policy-dsl.md) for the full reference.

---

## Live

- **Devnet Program ID:** `G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g`
- **Live demo:** `<PENDING — will be filled after deploy>`
- **Demo video:** `<PENDING>`

---

## Setup

### Prerequisites

| Tool | Version (verified) | Purpose |
|------|--------------------|---------|
| Rust | stable (workspace builds clean) | Build the workspace crates. |
| `rzup` | 0.5.0 | RISC Zero toolchain installer. |
| `cargo-risczero` | 3.0.5 | Build/run the RISC Zero guest. |
| Solana CLI | 3.0.13 | Devnet keys, deploy, RPC. |
| Anchor CLI | 0.29.0 | Build/deploy the on-chain program. |
| Node.js | 25 | TypeScript SDK / demo tooling. |

> **Anchor version note:** the program pins `anchor-lang = 0.30.1`, while the installed `anchor-cli` is `0.29.0`. The deploy path must reconcile this (use `avm install 0.30.1 && avm use 0.30.1`, or align the lang pin to the CLI). See [docs/CAPSTONE_GAPS.md](docs/CAPSTONE_GAPS.md).

### Build the workspace

```bash
# Builds: circuits/glyph-circuit/host, common, scripts/extract-vk, tee-worker
cargo build --workspace
```

### Run the tests (114 passing)

```bash
cargo test --workspace
# 114 tests pass, 0 fail
```

> The on-chain program `programs/glyph-verifier` is a **separate** Cargo workspace and is not built by the commands above. Build it via Anchor (below).

### Build the on-chain program (with the real VK)

The verifier ships a real extracted verification key at
`programs/glyph-verifier/src/groth16/vk_real.rs` (RISC Zero `risc0-zkvm 1.2.6`, real
`alpha_g1` / `control_root` / `bn254_control_id` / `image_id`). It is compiled in only
with the `real-vk` feature; otherwise an intentionally off-curve **placeholder** VK is
used by a safety test only.

```bash
# From the program's workspace, build with the real verification key:
anchor build -- --features real-vk
# (equivalently: cargo build-sbf --features real-vk inside programs/glyph-verifier)
```

To verify real proofs on-chain, the VK must be **seeded on-chain** after deploy via the
program's `seed_vk` instruction.

### Run the TEE worker (dev mode)

```bash
cargo run -p tee-worker
# Loads a per-agent TOML policy, evaluates intents, and produces a proof + journal.
```

### Run the demo

```bash
# End-to-end examples live in examples/ ; see docs/architecture.md for the flow.
ls examples/
```

---

## Security model

- **No valid proof, no execution.** The verifier rejects the transaction unless the Groth16 proof verifies under the seeded VK.
- **Binding, not trust.** `verify_and_execute` hashes the *next* instruction and requires it to equal the tx-hash committed in the proof journal, so a valid proof cannot be replayed against a different action.
- **Replay & freshness.** Nonce replay protection, journal expiry vs `Clock`, and attested-timestamp drift bounds prevent stale or reused proofs.
- **Policy integrity.** A required-rules bitmask and image-id pinning ensure the agent ran the expected circuit and the expected mandatory rules.
- **Caveats (honest):** TEE attestation is verified off-chain (not yet wired into the on-chain verifier); on-chain enforcement is limited to what the proof commits to. See [docs/architecture.md](docs/architecture.md) §4.2.

---

## Project status / maturity

| Area | Status |
|------|--------|
| Workspace build & tests (114 passing) | ✅ Production-grade |
| On-chain Groth16 BN254 pairing verification | ✅ Real (`alt_bn128`, on-curve + subgroup checks) |
| Real extracted verification key (`vk_real.rs`) | ✅ Exists; gated by `--features real-vk`, seeded via `seed_vk` |
| Instruction binding / replay / expiry / drift / required-rules | ✅ Enforced on-chain |
| 9-rule policy engine | ✅ Implemented (`TimeWindow` in-circuit + on-chain `Clock`) |
| Program-agnostic guardrail (any Solana program) | ✅ By construction |
| Devnet deployment | 🔧 Pending (program ID reserved) |
| TEE attestation wired on-chain | 🔧 Off-chain today |
| Multi-protocol example + web demo | 🔧 Dev-mode / planned |
| Anchor 0.29 vs 0.30.1 toolchain reconciliation | 🔧 Deploy-path TODO |

Full, honest gap analysis: [docs/CAPSTONE_GAPS.md](docs/CAPSTONE_GAPS.md).

---

## Documentation

- [Architecture](docs/architecture.md)
- [Policy DSL](docs/policy-dsl.md)
- [Enhancements](docs/enhancements.md)
- [Capstone Gap Analysis](docs/CAPSTONE_GAPS.md)
- [Submission Checklist](SUBMISSION_CHECKLIST.md)

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
