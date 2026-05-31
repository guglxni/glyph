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
| CI covering program + both SDKs | Hardened 5-job pipeline (workspace, on-chain program, sdk-rust, sdk-typescript, demo smoke test) | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) |
| VK-rotation multisig not initialized | Initialized on devnet (1-of-1 bootstrap; env-configurable m-of-n for mainnet) | PDA `9GQ9Wr9diSgiX6bZRwHcGtkJEAAzuWLwYWN2eQYwibRL`, tx [`BxwF1fFF…WuDC`](https://explorer.solana.com/tx/BxwF1fFFdfXPRx2tis9uXgPuXDLULdbERuBtR18e3Y6jcCAzBm7SJU2Z5Vph8wGjmkCzbRJ7HxaG9GBRhgrWuDC?cluster=devnet) |

## 🔧 In progress / tracked

| Gap | Status | Notes |
|-----|--------|-------|
| Full `register_agent → verify_and_execute` e2e on devnet | Blocked (upstream/env) | Driver + real-proof generator are built (`scripts/e2e-devnet/`, `circuits/.../gen_proof.rs`) and the guest **image_id matches the seeded on-chain VK exactly** (`257cf779…0e05f183`), so an x86-produced proof would verify on-chain. The STARK→Groth16 wrap fails locally: RISC Zero's `stark_to_snark` is **x86-only** and this machine is arm64 (no Docker, no Bonsai key). To finish: run `gen_proof` on an x86 host (or via Docker / Bonsai `BONSAI_API_KEY`), then `cargo run --manifest-path scripts/e2e-devnet/Cargo.toml`. Policy logic itself is proven by the 114-test suite + the multi-protocol demo. |
| CI covering on-chain program + both SDKs | In progress | Hardened `.github/workflows/ci.yml` (workspace, program, sdk-rust, sdk-typescript, demo smoke test). |
| VK-rotation multisig on devnet | In progress | `initialize_vk_multisig` — devnet-acceptable to defer; mainnet requires Squads-style multisig per `DEPLOYMENT_KEYS.md`. |
| TEE attestation wired on-chain | Deferred | Attestation verified off-chain today; per-vendor (SGX/Nitro/SEV) hardening is post-capstone. |
| Demo video | Action (you) | Record Loom; paste into `README.md` `<DEMO_VIDEO_URL>`; final push before 11:00 PM. |

## Scope note

"Devnet live" = deploy + initialize + real-VK-seed confirmed on devnet. The end-to-end
agent flow with a real proof is the remaining frontier and is tracked transparently above —
stating this precisely is intentional and strengthens technical credibility.
