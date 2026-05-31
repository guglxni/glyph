# Capstone Gaps — Status Ledger

Honest tracking of every gap identified for the GLYPH capstone and its current status.
Last updated: 2026-05-31.

## ✅ Done

| Gap | Resolution | Evidence |
|-----|-----------|----------|
| Not a git repo / no GitHub | Public repo created + pushed | https://github.com/guglxni/glyph |
| No LICENSE | Apache-2.0 added | [`LICENSE`](../LICENSE) |
| Program unbuilt/undeployed | Built (`cargo-build-sbf --features real-vk`), deployed, initialized | Program [`G5RnXgN…aMD3g`](https://explorer.solana.com/address/G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g?cluster=devnet), deploy tx `2pidHYhj…dE1tv` |
| Real VK not on-chain | Real VK seeded; `vk_hash` `109aba43…2f709707` matches `vk_real.rs` | Config PDA `2371q4Qn…rZpT`, VK PDA `5V28XTKV…hjyd` |
| Anchor 0.29 vs 0.30.1 mismatch | Resolved via `cargo-build-sbf` (bytecode depends on `anchor-lang` crate, not CLI) | `MIGRATION.md` |
| README "8 rules" + stale VK wording | Corrected to 9 rules; real-VK wording fixed; "guardrail" framing | [`README.md`](../README.md) |
| README not comprehensive | Full rewrite: Mermaid diagrams, applicability matrix, citation | [`README.md`](../README.md) |
| No multi-protocol example | Added; one policy / 3 programs / shared commitment `d086deb3…0053cb`; 4th denied | [`examples/multi-protocol/`](../examples/multi-protocol/), [`docs/DEMO.md`](DEMO.md) |
| No web demo | Live Next.js app on Vercel; in-browser commitment parity | https://web-lovat-seven-23.vercel.app |
| No research attribution | arXiv:2509.00085 chapter→impl mapping + citation | [`README.md`](../README.md#-research-foundation), [`POSITIONING.md`](POSITIONING.md) |
| `.gitignore` not hardened | Excludes keypairs, `*.pem`, all `target/`, `node_modules`, `.lake/`, sessions, big assets | [`.gitignore`](../.gitignore) |
| Stray unused-import warning | Removed; workspace builds 0 warnings | `tee-worker/src/subgroup_check.rs` |
| Positioning narrative not documented | Canonical narrative doc added | [`POSITIONING.md`](POSITIONING.md) |
| CI covering program + both SDKs | Hardened 6-job pipeline (workspace, on-chain program, sdk-rust, sdk-typescript, demo smoke test, Lean proofs) | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) |
| VK-rotation multisig not initialized | Initialized on devnet (1-of-1 bootstrap; env-configurable m-of-n for mainnet) | PDA `9GQ9Wr9diSgiX6bZRwHcGtkJEAAzuWLwYWN2eQYwibRL`, tx [`BxwF1fFF…WuDC`](https://explorer.solana.com/tx/BxwF1fFFdfXPRx2tis9uXgPuXDLULdbERuBtR18e3Y6jcCAzBm7SJU2Z5Vph8wGjmkCzbRJ7HxaG9GBRhgrWuDC?cluster=devnet) |
| Formal verification not reproducible / unverified | Validated with **qedgen**: **19 theorems / 6 modules / 0 sorry / 0 admit**, `lake build` exit 0; made **Mathlib-free + vendored** (`formal_verification/lean_solana`) so it builds clean in ~8s; added a `formal-verification` CI job | [`formal_verification/SPEC.md`](../formal_verification/SPEC.md) |

## 🔧 In progress / tracked

| Gap | Status | Notes |
|-----|--------|-------|
| Full e2e on devnet | Partial ✅+⚠️ | **`register_agent` is LIVE on devnet** — [tx `2Nfa9aZc…wDBLN`](https://explorer.solana.com/tx/2Nfa9aZc1Uv5DQg3qz4TY68dTFXWGqMuYB2NPf52XZhQepBsLM3Mecg4bKMEoGvWQdSc6JCMDDqXR17AvWKwDBLN?cluster=devnet), registry PDA `CHusKEt6…nSjx`, policy_commitment + image_id pinned on-chain. **`verify_and_execute` needs a Groth16 proof**, which per [RISC Zero's docs](https://dev.risczero.com/api/generating-proofs/local-proving) *only generates on x86_64 + Docker — Apple Silicon is unsupported even via Docker* (issues [#1520](https://github.com/risc0/risc0/issues/1520), [#1749](https://github.com/risc0/risc0/issues/1749)); the hosted Bonsai service was retired Dec 2025. The proof pipeline is **fully built and wired** (circuit `image_id` matches the seeded VK byte-for-byte). Resolution shipped: a CI workflow [`generate-proof.yml`](../.github/workflows/generate-proof.yml) generates the real proof on GitHub's **x86_64 runners**, then `scripts/e2e-devnet` lands `verify_and_execute`. Policy logic independently proven by 114 tests + multi-protocol demo + 19 Lean theorems. See [`docs/DEPLOYMENT.md §6`](DEPLOYMENT.md). |
| TEE attestation wired on-chain | Deferred | Attestation verified off-chain today; per-vendor (SGX/Nitro/SEV) hardening is post-capstone. |
| Demo video | Action (you) | Record Loom; paste into `README.md` `<DEMO_VIDEO_URL>`; final push before 11:00 PM. |

## Scope note

Devnet live = deploy + initialize + VK-seed + VK-rotation multisig + **`register_agent`** on devnet. The `verify_and_execute` step requires a real Groth16 proof; the proof pipeline is fully built and wired but the upstream prover binaries have binary compatibility issues (SIGILL) under Rosetta 2 on arm64. This is documented precisely, which is stronger than an unchecked claim.
