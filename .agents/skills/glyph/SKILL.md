---
name: glyph
description: "Use when building, auditing, deploying, explaining, or extending GLYPH: verifiable agent guardrails, NL-to-policy compilation, policy commitments, TEE policy checks, RISC Zero/Groth16 proofs, Solana verifier flows, agent delegation, or alignment to arXiv:2509.00085v1."
---

# GLYPH

Work on GLYPH as a thesis-backed cryptographic guardrail system for autonomous agents. Keep the implementation aligned with `arXiv-2509.00085v1/` and with the repository invariants before changing code, docs, deployment, or claims.

## When to use

Use this skill for:

- Frontend or docs changes that explain GLYPH, its thesis basis, trust model, policy DSL, proof pipeline, or deployment status.
- Rust, Solana, RISC Zero, Groth16, TEE worker, verifier, or SDK changes.
- Debugging proof runs, policy commitment mismatches, journal encoding, verifier failures, and CI/deployment gaps.
- Creating agent workflows, integrations, or third-party instructions for GLYPH.

Do not use this skill for unrelated generic Solana, frontend, or cryptography work unless GLYPH is the target system.

## Operating Model

1. Classify the task: explain, frontend, policy compiler, TEE worker, circuit/prover, on-chain verifier, deployment, audit, or integration.
2. Read the minimum relevant local context before changing anything:
   - Always start with `AGENTS.md` and this `SKILL.md`.
   - For architecture or hardening: `docs/production-migration-blueprint.md`, `aidlc-docs/zk-upgrade-design.md`, and `references/repo-map.md`.
   - For thesis alignment: `references/thesis-map.md` plus the cited files in `arXiv-2509.00085v1/`.
   - For implementation safety: `references/invariants.md`.
3. Prefer Graphify or code-index tools for orientation when available. If `graphify-out/` exists, query it before broad manual exploration.
4. Make tightly scoped changes that preserve the system's cryptographic claims. Do not weaken production safeguards for demo convenience.
5. Validate with the narrowest command that proves the touched path, then broaden if the change crosses contracts.

## Core Invariants

- `policy_commitment` must remain canonical and deterministic across Rust, TypeScript, TEE worker, circuit journal, and Solana verifier.
- RISC Zero journal bytes are the public output contract. Preserve Borsh journal encoding unless every consumer is migrated together.
- `tx_hash` binds target program id, accounts, and instruction data. Never reduce it to a partial hash.
- Production mode must reject `DevProver` and `RISC0_DEV_MODE`.
- On-chain verification must keep Groth16 public input binding as `SHA-256(journal_bytes)` and must verify the seeded VK integrity.
- Replay resistance depends on nonce PDA initialization. Do not move replay checks out of the atomic verifier path.
- Stateful rules not yet in-circuit (`time_window`, `daily_volume`, token-account introspection) must be represented honestly as TEE-enforced or future work.
- Public claims must distinguish deployed, CI-proven, devnet-verified, and planned work.

## Recommended Validation

Use the smallest set that matches the change:

```bash
cargo test -p glyph-circuit-host
cargo test --manifest-path tee-worker/Cargo.toml
RISC0_DEV_MODE=1 cargo test -p glyph-circuit-host --features risc0 -- --ignored dev_mode
npm run build --prefix web
grep -rn "PLACEHOLDER" programs/glyph-verifier/src/groth16/
```

For production proof or verifier changes, inspect CI logs and record whether the proof was generated, wrapped, and consumed by the verifier. A long proof run is not success by itself.

## Agent Behavior

- Be explicit about assumptions, especially for cryptographic status, live deployment, and DNS/Vercel state.
- If a requested public-facing claim is stronger than the verified evidence, rewrite it to the strongest true claim and explain the downgrade.
- Do not expose secrets, private keys, API keys, wallet mnemonics, or Vercel/GitHub tokens in output or logs.
- When creating instructions for other agents, keep them platform-neutral: describe required files, commands, invariants, and verification loops without relying on one agent product.

## Reference Files

- `references/thesis-map.md` maps the research paper to GLYPH implementation surfaces.
- `references/repo-map.md` lists the main code paths and when to read them.
- `references/invariants.md` is the compact safety checklist for code and docs changes.
