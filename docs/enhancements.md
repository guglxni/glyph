# Enhancements Discussed (May 2026)

## Scope
This document summarizes technical, security, and narrative enhancements discussed during the GLYPH review and hackathon positioning work.

## Policy Engine
- The engine implements **nine** enforcement rules (see [Policy DSL](policy-dsl.md)): MaxLamportsPerTx, AllowedPrograms, TimeWindow, MaxDailyVolumeLamports, RequireSlippageBpsLte, AllowedTokenMints, MaxAccountsPerTx, RequireSignerPresent, PolicyExpired. Rule 3 (`TimeWindow`) is enforced in-circuit and on-chain against the `Clock` sysvar rather than by a host-side check.

## Technical and Architecture Enhancements
- ZK proving pipeline: RISC Zero zkVM -> STARK -> Groth16 on-chain verifier (real BN254 pairing via `alt_bn128`; real VK gated by `--features real-vk`, seeded via `seed_vk`).
- Instruction hash binding on-chain (program_id + accounts + data).
- Journal binding: public inputs derived as SHA-256(journal_bytes).
- Replay protection via nonce PDA on verify_and_execute.
- Policy enforcement split:
  - Stateless rules in circuit.
  - Stateful rules in TEE worker.
- Production mode enforcement: GLYPH_MODE=production rejects DevProver and RISC0_DEV_MODE.

## Hardening Requirements
- Extract and update Groth16 verification key after every circuit rebuild.
- Install RISC Zero toolchain for real proof builds.
- Set compute budget to 1.4M CU for verify_and_execute transactions.

## TEE Attestation and Sealing (Open)
- Implement KMS sealing for Nitro (NSM ioctl).
- Implement SGX DCAP quote verification.
- Implement SEV SNP report verification.

## Privacy and Claim Language Enhancements
- Avoid claiming "full on-chain privacy" unless using confidential transfers or a shielded pool.
- Prefer phrasing such as:
  - "Encrypted data with on-chain proofs."
  - "Verifiable policy enforcement without revealing inputs."
- Claim templates:
  - Privacy: "Proves policy compliance while inputs remain encrypted/off-chain."
  - Verifiable compute: "Produces receipts for policy-compliant execution."
  - Agent infra: "Binds agent actions to signed intents and verifiable rules."

## One-Fits-All Narrative Fit
- Core framing: "GLYPH is a verifiable policy-enforcement / guardrail layer for autonomous agents on Solana — it gates and binds an agent's transaction; Solana executes it. It works with any Solana program (program-agnostic by construction; per-agent TOML allowlist)."
- Positioning: "GLYPH is a universal guardrail for autonomous agents, not a single-app product."
- Competitive framing: "GLYPH does not compete with perps, prediction markets, or privacy stacks; it makes agents safe across all of them."
- Demo proof point: "One policy file, multiple target programs, same verification flow."

## OSS Evidence for Breadth
These are the **target surface GLYPH guards**, not GLYPH-shipped integrations.
- Agent tooling: https://github.com/sendaifun/solana-agent-kit
- Perps: https://github.com/drift-labs/protocol-v2
- Orderbook trading: https://github.com/Ellipsis-Labs/phoenix-v1
- Prediction markets: https://github.com/LemnLabs/solana-prediction-market-smart-contract
- Privacy / ZK infra: https://github.com/lightprotocol/light-protocol
- Core primitives: https://github.com/solana-program/token
- Developer framework: https://github.com/coral-xyz/anchor
- ZK proving stack: https://github.com/risc0/risc0

## Status — Realized (2026-05-31)
The narrative above is now backed by shipped artifacts:
- **One-fits-all proven**: `examples/multi-protocol/` + `cargo run --example multi_protocol_demo`
  shows one policy commitment guarding three unrelated programs (System / SPL Token / Memo)
  and denying a fourth — see `docs/DEMO.md`.
- **Live on devnet**: program `G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g`, real VK seeded.
- **Hosted demo**: https://web-lovat-seven-23.vercel.app (in-browser commitment parity).
- **Research basis documented**: arXiv:2509.00085 mapping in the README + `docs/POSITIONING.md`.
- Full narrative: **`docs/POSITIONING.md`**. Status ledger: **`docs/CAPSTONE_GAPS.md`**.

## Evidence Sources (FOSS, prior research)
- solana-program/token-2022 (confidential transfers)
- solana-developers/Confidential-Balances-Sample
- Lightprotocol/light-protocol (ZK compression)
- zkshinedev/zkshine (ZK privacy stack)

## Colosseum Project Repo Verification (gh CLI)
| Project | Repo | Status | License | Last push (UTC) | Strength | Notes |
| --- | --- | --- | --- | --- | --- | --- |
| Blackpool | darklakefi/darklake-monorepo (via vitorpy/cyklon) | OK | MIT | 2025-10-01 | Strong | Repo/name mismatch; confirm intended source. |
| MCPay | microchipgnu/MCPay | OK | NOASSERTION | 2026-01-21 | Weak | Active, but license not detected by GitHub; verify LICENSE file. |
| Umbra | umbra-defi/umbra-breakout-submission | 404 | N/A | N/A | Weak | Repo not found. |
| Encifher | RizeLabs/encifher-vaults | OK | None | 2025-05-16 | Weak | License missing. |
| Humanship ID | Humanship/ids-manager | OK | None | 2025-12-06 | Weak | License missing. |
| Degen Cash | spacemandev-git/degen-cash | OK | None | 2025-10-30 | Weak | License missing. |
| BlackBox | thomasmeta13/blackbox-sol | OK | None | 2025-10-31 | Weak | License missing. |
| Obscura | Agarwalpratyaksh/Obscura | 404 | N/A | N/A | Weak | Repo not found. |
| Flaek | chigozzdevv/flaek | OK | None | 2025-11-04 | Weak | License missing. |
| Hush | bidhan-a/hush | OK | MIT | 2025-06-16 | Strong | Licensed; older activity; devnet-only maturity. |

## Open Verification Items
- Confirm correct repo URLs for Umbra and Obscura.
- Confirm license metadata for MCPay if it will be used as FOSS evidence.
