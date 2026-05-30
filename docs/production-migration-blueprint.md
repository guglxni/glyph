# GLYPH Production Migration Blueprint

Last updated: 2026-04-21
Owner: GLYPH core team
Status: Execution plan for production hardening

## 1) Objective

This document defines the step-by-step migration of GLYPH from mixed prototype plus partially hardened code into a production-grade system that is:

1. Functionally complete for real constrained agent execution on Solana.
2. Cryptographically sound end-to-end (no placeholder proof path in production runtime).
3. Operationally reliable (observability, incident response, reproducible builds, release gates).
4. Conceptually faithful to the architecture class described by Tobin South's thesis: delegated agent execution with confidential enforcement plus cryptographic verifiability plus auditable accountability.

## 2) What "Production Grade" Means For GLYPH

GLYPH is production-ready only when all criteria below are true:

1. Real Groth16 verification is enforced on-chain with a non-placeholder verification key (VK).
2. Worker production mode cannot silently fall back to DevProver or dev-mode receipts.
3. Policy commitment, intent binding, and replay protection are all enforced both in code and by tests.
4. Attestation verification is implemented and enforced for policy registration and policy updates.
5. Devnet environment demonstrates an end-to-end execution with third-party reproducibility.
6. CI blocks releases unless all security, integration, and reproducibility checks pass.
7. Documentation reflects runtime truth (no stale statements that contradict code paths).

## 3) Conceptual Mapping To Tobin South Thesis Model

This section maps the thesis-level conceptual pillars into concrete GLYPH controls.

| Conceptual pillar | GLYPH control objective | Primary code surface | Production evidence |
| --- | --- | --- | --- |
| Constrained delegated execution | Agent can only execute within declared policy bounds | `tee-worker/src/policy.rs`, `tee-worker/src/main.rs`, `programs/glyph-verifier/src/lib.rs` | Policy mismatch and out-of-bounds intents are rejected in tests and on devnet |
| Confidential policy enforcement | Private rule evaluation and key handling in trusted runtime | `tee-worker/src/vendors/*`, `tee-worker/src/main.rs` | Verified attestation chain + sealed policy handling + no plaintext policy leakage |
| Cryptographic verifiability | On-chain verification of proof bound to public outputs | `programs/glyph-verifier/src/groth16/*`, `programs/glyph-verifier/src/lib.rs` | Valid proofs pass, malformed or mismatched proofs fail on-chain |
| Anti-replay accountability | One-time nonce consumption with epoch-bound semantics | `programs/glyph-verifier/src/lib.rs` (`NonceAccount`) | Replay attempts fail deterministically |
| Auditable delegation trail | Intent signature + policy commitment + execution events | `tee-worker/src/main.rs`, on-chain events in `programs/glyph-verifier/src/lib.rs` | End-to-end logs and event traces correlate to signed intents |

Important note: this plan targets implementation-level faithfulness to the same architecture class and security model. It does not require literal one-to-one replication of thesis wording or implementation internals.

## 4) Current Gap Snapshot (2026-04-21)

### 4.1 Cryptography and proof path

1. On-chain verifier logic uses real pairing operations in `programs/glyph-verifier/src/groth16/verifier.rs`.
2. VK material in `programs/glyph-verifier/src/groth16/vk.rs` still contains placeholder constants.
3. `verify_vk_integrity()` currently returns `true` and does not enforce runtime integrity.
4. `scripts/extract-vk/src/main.rs` still contains stubbed extraction logic in the risc0 path.

### 4.2 Worker runtime mode safety

1. Worker can run `DevProver` by default depending on feature/env selection.
2. Dev mode and production mode are not strongly separated by compile-time and runtime guards.

### 4.3 Attestation enforcement

1. Vendor providers in `tee-worker/src/vendors/` still contain TODO-level stubs.
2. Attestation validation depth is below production requirements.

### 4.4 Documentation and release hygiene

1. Existing docs include stale statements that describe Groth16 as a placeholder format check.
2. Grant artifacts are not fully isolated by ignore policy.

## 5) Migration Workstreams

## WS-1: Cryptographic Truth Path Finalization

Goal: ensure all production proof verification uses a real VK and enforceable integrity checks.

### Required changes

1. Replace placeholder VK constants in `programs/glyph-verifier/src/groth16/vk.rs` with real extracted values.
2. Implement real VK extraction in `scripts/extract-vk/src/main.rs` for risc0 builds.
3. Replace stub `verify_vk_integrity()` with deterministic checks against expected hash and image ID.
4. Add a startup or instruction-time guard that fails closed when VK integrity check fails.
5. Add regression tests for:
   - valid proof and matching journal hash,
   - proof/journal mismatch,
   - wrong VK hash,
   - wrong image ID,
   - zero-point and malformed point rejection.

### Acceptance criteria

1. `vk.rs` has no placeholder constants.
2. `extract-vk` outputs compilable VK code derived from real proving artifacts.
3. On-chain proof verification passes only for valid proofs from the current circuit image.
4. CI fails if any placeholder marker appears in `programs/glyph-verifier/src/groth16/`.

## WS-2: Production Runtime Mode Hardening

Goal: eliminate accidental non-ZK execution in production environments.

### Required changes

1. Introduce explicit runtime modes in worker config: `dev`, `staging`, `production`.
2. In `production` mode:
   - disallow `DevProver`,
   - disallow `RISC0_DEV_MODE=1`,
   - require `GLYPH_PROVER=risc0`,
   - fail fast if circuit ELF or proving backend is unavailable.
3. Add compile-time feature gate profile for production worker binary.
4. Add integration tests that assert boot failure for invalid production mode configuration.

### Acceptance criteria

1. Production binary cannot generate fake proof bundles.
2. Misconfigured environments fail closed with explicit error messages.
3. CI includes one production-mode smoke test.

## WS-3: Attestation Path Completion

Goal: transform vendor abstraction from placeholder to enforceable trust control.

### Required changes

1. Implement real attestation verification for SGX/Nitro/SEV adapters in `tee-worker/src/vendors/`.
2. Bind attestation user-data to policy commitment and relevant runtime identity.
3. Enforce attestation verification at:
   - agent registration,
   - policy update,
   - optional periodic revalidation for long-lived workers.
4. Add deterministic tests with valid and invalid attestation fixtures.

### Acceptance criteria

1. Invalid attestation chain or mismatch is always rejected.
2. Policy updates cannot bypass attestation commitment checks.
3. Security audit includes attestation validation test evidence.

## WS-4: Policy and State Completeness

Goal: move from single-node in-memory assumptions to production-safe behavior.

### Required changes

1. Externalize daily volume and policy-evaluation state from in-memory only storage.
2. Define persistence model (KV store or replicated state service) with deterministic serialization.
3. Add failure-mode behavior for persistence outages (fail closed for high-risk actions).
4. Add consistency tests for multi-worker concurrency.

### Acceptance criteria

1. Policy behavior is deterministic across worker restarts.
2. Daily volume limits are preserved across process crashes.
3. Concurrent workers do not double-spend policy budget.

## WS-5: Instruction Binding and Replay Guarantees

Goal: preserve full binding from intent to executed instruction payload and nonce semantics.

### Required changes

1. Keep canonical full-instruction hashing shared between worker and verifier paths.
2. Add golden tests for account reordering, writable/signer flips, and program ID substitution.
3. Add negative integration tests for replay attempts with same nonce and epoch.
4. Ensure epoch change invalidates stale proof bundles as designed.

### Acceptance criteria

1. Any mutation of bound instruction bytes causes verification failure.
2. Replay attempts fail deterministically in devnet integration tests.

## WS-6: SDK and External Developer Reproducibility

Goal: complete developer-facing flow for external integrators.

### Required changes

1. Complete TypeScript SDK flow in `sdk/typescript/src/`:
   - intent construction,
   - signing,
   - worker submission,
   - proof bundle transport,
   - on-chain submission helpers.
2. Add one canonical Rust SDK example and one TypeScript SDK example.
3. Add localnet and devnet integration scripts with expected outputs.
4. Add troubleshooting playbook for top setup failures.

### Acceptance criteria

1. A new developer can run the full stack with documented commands only.
2. Integration tests pass in CI and in a clean machine bootstrap.
3. At least three independent external reproductions are documented for KPI evidence.

## WS-7: CI/CD, Supply Chain, and Release Gatekeeping

Goal: enforce security and correctness gates before any deployment.

### Required changes

1. Add CI matrix:
   - unit tests,
   - integration tests,
   - Anchor build checks,
   - lint/format,
   - placeholder scanners,
   - dependency vulnerability scanning.
2. Add deterministic release process:
   - tagged artifacts,
   - checksums/signatures,
   - reproducible build script for verifier and worker binaries.
3. Add release checklist requiring successful devnet end-to-end proof verification.

### Acceptance criteria

1. No release artifact can be produced without passing all mandatory gates.
2. Build provenance and checksums are published per release.

## WS-8: Observability, Incident Response, and Runbooks

Goal: make production operations measurable and recoverable.

### Required changes

1. Define structured logs for intent lifecycle IDs and proof verification outcomes.
2. Emit metrics for:
   - policy rejects,
   - prover latency,
   - proof verification failures,
   - attestation failures,
   - nonce replay rejects.
3. Create runbooks for:
   - prover outage,
   - attestation outage,
   - VK rotation,
   - policy rollback,
   - emergency pause.
4. Define alert thresholds and paging ownership.

### Acceptance criteria

1. Incident response can identify root cause from telemetry within one on-call cycle.
2. Every critical failure mode has a documented mitigation runbook.

## WS-9: Formal Assurance and Audit Closure

Goal: tie implementation controls to machine-checked and auditor-verified invariants.

### Required changes

1. Extend Lean proofs to cover finalized proof-path and attestation assumptions.
2. Add traceability matrix: theorem -> code path -> test case -> runtime signal.
3. Re-run security audit after WS-1 through WS-4 completion.
4. Resolve all P0 and P1 issues before mainnet consideration.

### Acceptance criteria

1. Formal artifacts and audit report align with current code, not stale architecture drafts.
2. No unresolved critical findings remain.

## 6) Detailed Milestone Plan (April-May 2026)

### Milestone A (Now -> 2026-04-27)

Scope:
1. WS-1 core completion (real VK path).
2. WS-2 production mode fail-closed behavior.
3. Documentation truth update (remove stale placeholder claims).

Deliverables:
1. Real VK committed and verified.
2. Failing tests for invalid proof/VK mismatch.
3. Updated architecture and README wording aligned to runtime reality.

### Milestone B (2026-04-28 -> 2026-05-03)

Scope:
1. WS-3 attestation implementation.
2. WS-5 replay and binding deep tests.
3. Initial WS-7 CI gate hardening.

Deliverables:
1. Attestation verification integrated and enforced.
2. Replay and instruction-binding integration tests green.
3. CI gate prevents placeholder regressions.

### Milestone C (2026-05-04 -> 2026-05-08)

Scope:
1. WS-6 TypeScript SDK end-to-end completion.
2. WS-4 state persistence baseline.
3. WS-8 observability minimum viable production telemetry.

Deliverables:
1. End-to-end demo script on devnet.
2. Reproducible setup docs validated by external developers.
3. Metrics and alerting baseline deployed.

### Milestone D (2026-05-09 -> 2026-05-11)

Scope:
1. WS-9 final assurance pass.
2. Audit evidence pack.
3. Grant final tranche evidence packaging.

Deliverables:
1. Security and formal verification closure summary.
2. Public repo evidence set (tests, demo, issues/discussions).
3. Final submission package.

## 7) Test and Evidence Matrix

| Control | Test type | Minimum evidence |
| --- | --- | --- |
| Real Groth16 enforcement | On-chain integration test | Valid proof passes, tampered proof fails |
| VK integrity | Unit + integration | Wrong VK hash/image ID fails closed |
| Production mode fail-closed | Worker bootstrap tests | Dev config in prod mode exits with error |
| Attestation validation | Fixture-based tests | Invalid chain and commitment mismatch rejected |
| Instruction binding | Differential hash tests | Program/account/data mutation rejected |
| Replay protection | On-chain replay tests | Same nonce fails after first consume |
| External reproducibility | Black-box setup test | 3 independent successful runs with evidence |

## 8) Go/No-Go Checklist

A deployment candidate is NO-GO if any item below is true:

1. Any placeholder marker remains in active verifier VK or proof path.
2. `DevProver` can be selected in production mode.
3. Attestation checks are bypassable at registration or update.
4. Replay or instruction-binding regression test fails.
5. End-to-end devnet demo cannot be reproduced from docs.
6. Security audit has unresolved critical issues.

A deployment candidate is GO only when all of the above are false and all milestone deliverables are signed off.

## 9) Documentation Update Requirements

When each workstream ships, update these docs in the same pull request:

1. `README.md`
2. `docs/architecture.md`
3. `docs/SECURITY_AUDIT.md`
4. `aidlc-docs/zk-upgrade-design.md`

Rule: architecture claims must always reflect the currently executable code path.

## 10) Grant KPI Alignment

This migration plan is designed to directly satisfy the grant KPI:

1. One public devnet deployment of `glyph-verifier` with verified on-chain execution.
2. One working end-to-end demo from intent -> TEE worker -> proof -> on-chain verification.
3. Three external developers successfully run the full stack with verifiable evidence.

The KPI is achieved only if execution is based on real proof verification and production-mode safety controls, not placeholder paths.
