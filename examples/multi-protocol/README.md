# One Policy, ANY Solana Program

This folder is the proof of GLYPH's core value proposition:

> **The same policy commitment and the same prove/verify pipeline guard intents
> against completely unrelated target programs — with zero protocol-specific
> code.**

## What's here

| File | Target program | Purpose |
|------|----------------|---------|
| `policy.toml` | — | ONE policy. Its SHA-256 canonical commitment is what the on-chain `AgentRegistry` PDA stores. |
| `intent-transfer.json` | System Program (`111…111`) | Native SOL transfer. **ALLOW** |
| `intent-token.json` | SPL Token (`Tokenkeg…`) | SPL token transfer. **ALLOW** |
| `intent-memo.json` | SPL Memo (`MemoSq4…`) | On-chain memo write. **ALLOW** |
| `intent-violation.json` | Jupiter v6 (`JUP6Lkb…`) | Not in the allowlist. **DENY** (rule 2) |

Three intents, three different `target_program` values, **one policy**.

## Why this proves program-agnosticism

GLYPH's `PolicyEngine` (in `tee-worker/src/policy.rs`) **never parses the target
instruction**. The intent's `data` field is opaque base64; the engine only ever
checks generic, protocol-independent rules:

- `max_lamports_per_tx`, `max_daily_volume_lamports` — spend caps
- `max_accounts_per_tx` — structural cap
- `require_signer_present` — structural requirement
- `allowed_programs` — the **only** program-aware rule, and it's a flat allowlist

Because nothing in the pipeline knows what a "swap" or a "memo" *is*, adding a
new protocol is a one-line edit to `allowed_programs` — **no new circuit, no new
verifier code, no protocol adapter**. The ZK circuit commits to the same five
public outputs (`policy_commitment`, `intent_hash`, `agent_pubkey`, `nonce`,
`tx_hash`) regardless of which program is targeted, and the on-chain verifier
binds the proof to whatever the next instruction is via `tx_hash` — again,
program-agnostically.

## Run it

From the repo root:

```bash
cargo run --example multi_protocol_demo --manifest-path tee-worker/Cargo.toml
```

This runs the **real** `PolicyEngine` and the **real** `glyph_common`
canonicalization/hashing against all four intents and prints the shared
`policy_commitment`, plus each intent's ALLOW/DENY decision, `intent_hash`, and
`tx_hash`. No devnet or network required.

See [`../../docs/DEMO.md`](../../docs/DEMO.md) for the full walkthrough and
expected output.
