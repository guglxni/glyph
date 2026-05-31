# GLYPH — Positioning & Narrative

> *GLYPH is a verifiable execution **guardrail** for any Solana program — a universal
> trust layer for autonomous agents, not a single-app product.*

This document is the canonical narrative for pitches, demo days, and fellowship/grant
review. It is deliberately precise: every claim maps to code that exists in this repo.

---

## 1. The one-line pitch

**GLYPH lets any AI agent execute on Solana safely — with policy-bounded actions and
on-chain verification.** It does not compete with perps, prediction markets, or privacy
stacks; it makes agents safe to use **across all of them**. Same proofs, same policy
engine — different target programs.

## 2. Why horizontal beats vertical

A vertical "AI trading bot" competes with a hundred bots and dies when the meta shifts.
A **horizontal trust layer** wins because:

- It is bullish-category-agnostic — perps, prediction, trading, privacy all need it.
- Its value compounds with the ecosystem: every new agent and every new program is a
  potential GLYPH user, not a competitor.
- It moves the story from "cool infra" to **"universal trust layer for agents"** — a
  far stronger and more defensible position.

## 3. What makes the claim *true* (not marketing)

GLYPH is program-agnostic **by construction**:

| Claim | Mechanism | Evidence in repo |
|-------|-----------|------------------|
| Works with any Solana program | Intent carries `target_program`/`accounts`/`data` as **opaque bytes**; no protocol parsing | `tee-worker/src/types.rs`, `transaction_builder.rs` |
| No lock-in / no custody | `verify_and_execute` is **ix[0]** that *binds* ix[1]; never CPIs into your program | `programs/glyph-verifier/src/lib.rs` |
| No hardcoded targets | Allowlist is a per-agent policy field, not baked into verifier/circuit | `policy.rs` rule 2, circuit guest |
| Same pipeline everywhere | One commitment + one prove/verify path for all programs | `examples/multi-protocol/`, the demo |

## 4. The proof point (do this in any demo)

**One policy, multiple programs, same verification flow.**

```bash
cargo run --example multi_protocol_demo --manifest-path tee-worker/Cargo.toml
```

- Same `policy_commitment` (`d086deb3…0053cb`) across System / SPL Token / Memo intents.
- The fourth intent (Jupiter, not allowlisted) is correctly **denied** (rule 2).
- Then point at the **live devnet program** and the **hosted web demo** that recomputes
  the identical commitment in-browser.

A two-minute version: show the proof-bound intent and on-chain verifier acceptance for
two different program IDs.

## 5. Competitive framing

| Others | GLYPH |
|--------|-------|
| Build *an* agent | Make *all* agents safe |
| Vertical app, one protocol | Horizontal guardrail, any protocol |
| "Trust the bot" | Cryptographic proof of policy compliance |
| Off-chain promises | On-chain enforcement |

## 6. Ecosystem evidence (breadth of applicability)

These open-source protocols are the **target surface GLYPH guards** — not GLYPH-shipped
integrations. They demonstrate that agents already want broad access, and GLYPH is the
verifiable safety layer on top.

- **Agent tooling:** [solana-agent-kit](https://github.com/sendaifun/solana-agent-kit) — 60+ actions across DeFi/NFT/perps.
- **Perps:** [drift-labs/protocol-v2](https://github.com/drift-labs/protocol-v2).
- **Orderbook:** [Ellipsis-Labs/phoenix-v1](https://github.com/Ellipsis-Labs/phoenix-v1).
- **Prediction markets:** [solana prediction-market](https://github.com/LemnLabs/solana-prediction-market-smart-contract).
- **Privacy / ZK:** [lightprotocol/light-protocol](https://github.com/lightprotocol/light-protocol).
- **Core primitives:** [solana-program/token](https://github.com/solana-program/token), [coral-xyz/anchor](https://github.com/coral-xyz/anchor).
- **Proving stack:** [risc0/risc0](https://github.com/risc0/risc0).

## 7. Research credibility

GLYPH implements the layered-accountability framework of **Tobin South's MIT dissertation,
*Private, Verifiable, and Auditable AI Systems* (arXiv:2509.00085)** — verifiable claims
about models/data via ZK (Ch. 2), private retrieval (Ch. 3), and security with agentic AI
(Ch. 4) — as live Solana infrastructure. This converts an academic framework into
deployable primitives, a stronger capstone story than either pure research or pure app
work. See the chapter→implementation mapping in the [README](../README.md#-research-foundation).

## 8. The honest line (say this — it builds trust)

Deploy + initialize + real-VK-seed are **live on devnet**. The full
`register_agent → verify_and_execute` round-trip needs a real RISC Zero proof + TEE
attestation; it is proven locally and by the 114-test suite. Precision about scope is a
feature in front of technical judges — see [`CAPSTONE_GAPS.md`](CAPSTONE_GAPS.md).
