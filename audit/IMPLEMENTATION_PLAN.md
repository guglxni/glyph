# GLYPH Production Implementation Plan

**Date:** 2026-05-10
**Author:** Claude Opus 4.7 (1M)
**Format:** AI-DLC Construction-phase work plan
**Scope:** Make GLYPH production-ready, faithful to arXiv:2509.00085, free of mocks/fallbacks

---

## 0. Executive Summary

**Verdict:** GLYPH is **not production-ready**. The code compiles, tests pass, and the structure of the protocol is sound — but the ZK pipeline is mathematically non-functional with a real proof, the TEE worker never calls its own attestation methods, and TS-built intents fail Rust signature verification due to a wire-type mismatch. Deploying today against mainnet would either accept zero traffic (correct verifier rejects all bundles because the dev VK is off-curve) or accept malicious traffic (no on-curve / subgroup checks; placeholder VK; off-host clock).

**Audits produced** (this run):
| File | Findings | Crit | High | Med | Low/Info |
|---|---|---|---|---|---|
| [`PAPER_BRIEF.md`](./PAPER_BRIEF.md) | — | — | — | — | — |
| [`AUDIT_ZK.md`](./AUDIT_ZK.md) | 33 | 5 | 11 | 11 | 6 |
| [`AUDIT_TEE.md`](./AUDIT_TEE.md) | 40 | 8 | 13 | 13 | 6 |
| [`AUDIT_SDK.md`](./AUDIT_SDK.md) | 13 | 1 | 4 | 6 | 2 |
| [`MOCKS_AND_FALLBACKS.md`](./MOCKS_AND_FALLBACKS.md) | 33 | 0 | 8 | 14 | 11 |
| **Total (deduplicated)** | **~110** | **14** | **~30** | **~40** | **~25** |

**Top-5 blockers** (cannot ship without fixing):
1. **AUDIT_ZK F-1/F-2/F-3** — Dev VK is off-curve, public-input formula omits `image_id`, integrity check is dead code. Verifier mathematically rejects every real proof. *Without this, GLYPH cannot accept a single real intent.*
2. **AUDIT_ZK F-4** — No subgroup / on-curve check on pairing inputs. Standard sBPF Groth16 foot-gun. Soundness break.
3. **AUDIT_TEE T1/T2** — All vendor `attest`/`seal`/`unseal` production paths return `Err("not yet implemented")`, AND the worker pipeline never calls them anyway. There is no TEE attestation path at all.
4. **AUDIT_TEE T4** — `is_real_enclave` is auto-detected; production-mode check ignores it. A production binary on a host with no enclave silently runs the dev passthrough.
5. **AUDIT_SDK F-1** — `max_lamports` is a JSON number in Rust, JSON string in TS. Every TypeScript-built intent fails worker signature verification before any policy check.

**Paper alignment:** GLYPH faithfully implements the *gap* the Tobin South thesis (arXiv:2509.00085) leaves open — on-chain verification, replay protection, canonicalization, and action-transcript commitment for AI agent delegation. The thesis explicitly defers all four. GLYPH adds them. **The paper-side concepts are well-grounded; the gap-implementation is what is incomplete.**

---

## 1. Paper-to-Implementation Matrix

Cross-references thesis sections (per `audit/PAPER_BRIEF.md`) to GLYPH code state.

| Thesis concept | Thesis ref | GLYPH implementation | State |
|---|---|---|---|
| **User ID-token** (OIDC) | Ch 4, "Token-based authentication framework" | Not implemented — relies on Solana Ed25519 keypair as identity | **Not in scope.** GLYPH treats the agent owner's Solana keypair as the user identity; OIDC integration is an extension. **Decision: defer**. Document as "compatible-with-OIDC; bring-your-own-OP". |
| **Agent-ID token** | Ch 4 | `AgentRegistry` PDA in `programs/glyph-verifier/src/lib.rs` + agent Ed25519 keypair | **Implemented** as on-chain registry. Functional gap: no `image_id` pinning at registration (AUDIT_ZK F-8). |
| **Delegation Token** (signed by user, refs agent + user tokens) | Ch 4, "Delegation token… signed by the human delegator" | `Intent` signed by agent keypair, with `policy_commitment` registered on-chain by registrar | **Partial.** GLYPH binds intent → policy → agent on-chain (✓), but the *human signature* over the delegation is not present — Intent is signed by the agent operator's Solana key. To be paper-faithful, add a `delegator_signature` field that is verified at `register_agent` time. **Workstream WS-9.** |
| **Three-token reference binding (hash of)** | Ch 4 | Policy commitment hashed into intent journal | **Implemented**, but format unspecified in thesis — see GLYPH gap below. |
| **ZK proof: `Prove(pk,W,x,y)→π⊃{H(W),y}`** | Ch 2 verifyevals | `circuits/glyph-circuit/guest/src/main.rs` produces `(policy_commitment, intent_hash, agent_pubkey, nonce, tx_hash)` | **Different proof statement** — GLYPH proves *policy compliance of an intent* not *correct ML inference*. Intentional: GLYPH is the delegation/policy layer, not the model-eval layer. Document as "complementary to Ch 2". |
| **Verifiable evaluations of ML models** | Ch 2 verifyevals | Not in scope | **Out of scope.** Document. |
| **Partial ZK** (selective-layer proving) | Ch 2 partialzk | Not in scope | **Out of scope.** |
| **zkTax / portable-data three-service model** | Ch 2 zktax | Not in scope | **Out of scope.** |
| **Authenticated delegation flow** (OIDC + UMA) | Ch 4 fig OIDC-AI | Solana on-chain registry replaces OP; intent submission replaces UMA RS flow | **Partial.** GLYPH provides the on-chain RS-equivalent. Off-chain OP/OIDC integration is deferred. |
| **TEE properties (4): confidentiality, integrity, attestation, sealing** | Ch 3 communitytrans | `tee-worker/src/vendors/{nitro,sgx,sev}.rs` | **Stubs only.** All four production paths return `Err`. **Workstream WS-2.** |
| **TEE keypair externalised** | Ch 3 | `worker-keypair.json` plaintext on disk | **Worse than thesis intent** — keypair is *not* sealed. **Workstream WS-2 / WS-7.** |
| **NVIDIA H100 / GPU confidential compute** | Ch 3 | Not in scope | **Out of scope.** GLYPH is CPU-side TEE for policy enforcement, not GPU TEE for model inference. |
| **PRAG (private retrieval over MPC)** | Ch 3 PRAG | Not in scope | **Out of scope.** |
| **NLR-RAG / auditability** | Ch 3 nlrRAG | No retrieval audit trail; **no audit trail at all on intents** | **Gap (paper alignment).** Thesis explicitly requires per-component audit attestations. **Workstream WS-6.** |
| **Personhood Credentials** | Ch 4 phc | Not in scope | **Out of scope** for v1. Future hook in Delegation Token. |
| **Policy-as-structured-rule-with-NL-interface** | Ch 4 | TOML 8-rule DSL in `docs/policy-dsl.md` + `tee-worker/src/policy.rs` | **Implemented** as structured DSL. NL-to-policy LLM compiler is out of scope. |
| **"Holographic graph logs / chains of cryptographic hashes per step"** | Ch 5 | Per-intent on-chain `IntentVerified` event + `NonceAccount` PDA | **Partial.** Each verified intent emits an event. No off-chain audit log; no chain of hashes between intents per agent; no Merkle anchor. **Workstream WS-6.** |
| **Roots of trust for ZK inputs** (TEE attest / VC / signed manifest) | Ch 5 §1 | TEE-attested input (the policy commitment) | **Conceptually correct** — the policy is anchored via on-chain `policy_commitment` set by registrar. Practically: see TEE T2 (attestation never fired). **Workstream WS-2.** |
| **GLYPH gap: on-chain verification design** | Thesis says "no design given" | `programs/glyph-verifier/` Anchor program | **Implemented as the GLYPH contribution**, with caveats in AUDIT_ZK. |
| **GLYPH gap: replay protection** | Thesis: only expiry+revocation URL | `NonceAccount` PDA + epoch | **Implemented.** Caveat: nonce PDA seed missing `agent_pubkey` (AUDIT_ZK F-20). **WS-1.** |
| **GLYPH gap: canonicalization spec** | Thesis: unspecified | `canonical_target_instruction_bytes` in `tee-worker/src/transaction_builder.rs`; `canonical_serialize_policy` in `common/` | **Implemented.** Caveats: no shared crate (AUDIT_TEE T27), TS/Rust mismatch (AUDIT_SDK F-1). **WS-3.** |
| **GLYPH gap: on-chain revocation registry** | Thesis: endpoint URL only | `policy_epoch` bump in `update_policy` invalidates outstanding intents | **Implemented** as epoch counter. No CRL / Merkle accumulator; nonce-list pruning policy not specified. **Acceptable for v1.** |
| **GLYPH gap: action transcript / audit chain** | Thesis: "small attestations" | On-chain `IntentVerified` events | **Partial.** No worker-side signed log; events are not Merkle-anchored. **WS-6.** |
| **Standardization (W3C VC / OAuth Native Client)** | Conclusion | Not implemented | **Future work.** |

**Summary:** GLYPH's *architecture* is paper-faithful and fills the four named gaps. The code-level implementation has the structural correctness but is missing real cryptography in the TEE adapters, has soundness bugs in the on-chain verifier, and has SDK mismatches. **The paper alignment is conceptually solid; the production work is mechanical and well-scoped.**

---

## 2. Findings Rollup (by severity, by component)

References use the IDs from the four audit files (`F-N` for ZK & SDK, `T-N` for TEE, mock-sweep entries by file:line).

### CRITICAL (14)

| ID | Component | Summary | Plan workstream |
|---|---|---|---|
| ZK F-1 | On-chain verifier | Hardcoded "DEV" Groth16 VK; off-curve points | **WS-1** |
| ZK F-2 | On-chain verifier | Public input omits `image_id`; verifier mathematically incompatible with RISC Zero claim digest | **WS-1** |
| ZK F-3 | On-chain verifier | `verify_vk_integrity()` dead code | **WS-1** |
| ZK F-4 | On-chain verifier | No subgroup / on-curve check on pairing inputs | **WS-1** |
| ZK F-5 | TEE worker | `DevProver` in production binary; no type-level discriminator | **WS-1** |
| TEE T1 | Vendor adapters | All `attest`/`seal`/`unseal` production paths return `Err` | **WS-2** |
| TEE T2 | TEE worker | `provider.attest()` / `verify_attestation()` never called by pipeline | **WS-2** |
| TEE T3 | Vendor adapters | Dev seal/unseal are identity functions; sealed files are plaintext | **WS-2** |
| TEE T4 | TEE worker | `is_real_enclave` auto-detect; production mode does not enforce | **WS-2** |
| TEE T5 | TEE worker | No KMS / NSM / vTPM-derived sealing key exists | **WS-2** |
| TEE T6 | TEE worker | Attestation bound to nothing live (because never called) | **WS-2** |
| TEE T7 | TEE worker | Intent freshness never checked (expiry/timestamp ignored) | **WS-1** |
| TEE T8 | TEE worker | Daily volume keys on untrusted host wallclock | **WS-4** |
| SDK F-1 | TS SDK | `max_lamports` is JSON number in Rust, string in TS — every TS intent fails verify | **WS-3** |

### HIGH (≈30)

Selected highlights (full lists in audit files):
- **ZK F-7..F-15** — Empty ELF without `risc0` feature, zero `GLYPH_CIRCUIT_ID`, no VK swap, hand-rolled field math is unsound, off-curve dev VK, fragile seal version-tag, compute budget client-side only. → **WS-1**
- **ZK F-20** — Nonce PDA seed missing `agent_pubkey`. → **WS-1**
- **TEE T9..T19** — Time-window untrusted clock, volume committed before proof, error swallowing, vendor default fallthrough, attestation window-search bypass, worker keypair plaintext, plain TCP listener. → **WS-2 / WS-4 / WS-5**
- **TEE T20** — No tamper-evident audit trail. → **WS-6**
- **SDK F-2..F-5, F-9** — Optional-field JSON divergence, AccountMeta camelCase drift, Groth16Proof length unvalidated, `Policy.expires_at` invisible to TOML, no cross-language fixture tests. → **WS-3**
- **Mock sweep HIGH (8)** — Placeholder `declare_id!`, mainnet-default RPC, unused `paused` flag, register_agent skips attestation check, default `Dev` runtime mode, default `sgx` vendor. → **WS-1 / WS-7**

### MEDIUM (≈40)

Distributed across all audit files. Categorized in WS-4..WS-8 below.

### LOW / INFO (≈25)

Cleanup items. Address last (WS-10).

---

## 3. Workstreams (AI-DLC Construction Phase)

Workstreams are sized for ~1-2 week mob-programming sprints. Each has scope, file targets, acceptance criteria, and dependencies.

### **WS-1 — On-chain verifier soundness + ZK pipeline correctness**
*Priority: P0 (blocker). Closes 5 CRITICAL + 9 HIGH ZK findings.*

**Scope:**
1. Replace dev VK with a real one extracted from the actual circuit ELF (via real `extract-vk` implementation calling RISC Zero's `Receipt.verifier_parameters()`).
2. Fix public input derivation: `claim_digest = sha256(image_id_bytes || sha256(journal_bytes))`. Pin RISC Zero version (v1.x) and add a regression test against a real proof.
3. Make `verify_vk_integrity()` callable at *compile time* (`const fn` SHA-256) and assert at build via `static_assertions::const_assert!`.
4. Add explicit on-curve and subgroup checks to `verify_groth16` for all four pairing inputs (G1: `proof_a`, `proof_c`, `vk_x`; G2: `proof_b`, plus VK G2 points). Vendor or copy from Light Protocol's `groth16-solana`.
5. Replace hand-rolled `field_sub` / `g1_negate` / `reduce_scalar` with `solana_bn254::compression::prelude::*` helpers; remove the bespoke math from `verifier.rs`.
6. Move `image_id` into `AgentRegistry` (pinned at registration). Expose new error `ImageIdMismatch`.
7. Add `agent_pubkey` to the `NonceAccount` PDA seed.
8. Add on-chain `Clock::get()` check: `require!(intent.expiry > now, ProofExpired)`.
9. Move VK from `pub const` to a `VerifierConfig`-style PDA. Add `update_vk` instruction with multisig + 24h timelock. Emit `VkUpdated` event.
10. Wire `InsufficientComputeBudget` and `Groth16InvalidG1Point`/`Groth16InvalidG2Point` error returns.
11. Replace `init` with a manual existence check for `NonceAccount` so replay returns `NonceAlreadyConsumed` explicitly.
12. Gate `DevProver` behind `#[cfg(feature = "dev-prover")]`; remove from default workspace build. Add `proof_kind: ProofKind` discriminator on `GlyphProofBundle`.
13. Replace `extract-vk` script's `bail!` with real RISC Zero parameter extraction.
14. Remove non-risc0 placeholder fallback or have it write all-`0xFF` so on-curve check rejects.
15. Move `panic!` in production-mode check to a `Result`-returning `enforce_production_invariants(&config) -> Result<()>`.

**Files:**
- `programs/glyph-verifier/src/{lib.rs, errors.rs, groth16/{verifier.rs, vk.rs, mod.rs}}`
- `circuits/glyph-circuit/host/{src/lib.rs, build.rs}`
- `scripts/extract-vk/src/main.rs`
- `tee-worker/src/{prover.rs, types.rs, main.rs}`
- New: `programs/glyph-verifier/src/vk_pda.rs`, `tee-worker/src/production_check.rs`

**Acceptance criteria:**
- [ ] Real RISC Zero proof verifies on-chain in localnet integration test (`tests/integration/pipeline_tests.rs`).
- [ ] Compile-time `const_assert!` fails build if VK is the placeholder.
- [ ] `cargo bpf --release` produces a binary that rejects a known-bad off-curve proof with `Groth16InvalidG1Point`.
- [ ] `dev-prover` feature off ⇒ `DevProver` symbol does not exist in the binary.
- [ ] Two agents registered in epoch 0 can both consume nonce `0x01...` without collision.
- [ ] Replay attempt returns `NonceAlreadyConsumed` (6030), not Anchor's generic `AccountAlreadyInitialized`.
- [ ] `update_vk` requires 2-of-3 multisig + 24h timelock; localnet test asserts both.
- [ ] Expired intent (`now > expiry`) is rejected with `ProofExpired`.

**Dependencies:** None (foundational).

**Skill assignment:** `solana-dev`, `develop-secure-contracts`, `solidity-auditor` (for proxy timelock pattern).

---

### **WS-2 — TEE attestation: real Nitro path end-to-end**
*Priority: P0 (blocker). Closes 6 CRITICAL + 7 HIGH TEE findings. Nitro is the production target; SGX/SEV defer to WS-2b/c.*

**Scope:**
1. Add `aws-nitro-enclaves-nsm-api` dep; implement `NitroProvider::attest` against `/dev/nsm` NSM ioctl (`NSM_GetAttestationDocument`). Document is COSE_Sign1.
2. Implement `NitroProvider::verify_attestation` with `coset` + `x509-parser` + AWS Nitro Root CA (vendored from AWS docs). Validate: signature chain → root CA, PCR0/1/2 against an allowlist, timestamp drift ≤ 5 min, `user_data` matches expected commitment.
3. Implement `NitroProvider::seal` / `unseal` via `aws-sdk-kms` with `EncryptionContext` bound to `(agent_pubkey, policy_commitment, image_id)` and IAM condition keys requiring matching PCRs.
4. In `main.rs::main`, after policy load, call `provider.attest(b"GLYPH_BOOT_v1", &compute_user_data(...))` where `user_data` binds `(policy_commitment, agent_pubkey, worker_pubkey, boot_nonce, epoch)`. Refuse to start in `Production` if `attest` returns `Err`.
5. Add `enforce_production_invariants(&config, &provider)` that checks: `is_real_enclave` true, `attest()` succeeds, `seal/unseal` round-trips a 32-byte test value through KMS, `GLYPH_TEE_VENDOR` is explicitly set (no defaulting in production).
6. Per-vendor `require_real(&self) -> Result<()>` returns `Err` when `is_real_enclave == false`. Call from `main` for production mode.
7. Replace dev `seal`/`unseal` (currently identity passthrough) with `argon2id` KDF over `GLYPH_SEAL_PASSPHRASE` env-var (≥32 bytes required) + `chacha20poly1305` AEAD. Unseal failure must `panic` (per AUDIT_TEE T12).
8. Replace dev `verify_attestation` window-search with exact-format check: `nitro-dev-attest:v1: || user_data || :policy: || policy_commitment` parsed by structure, not substring.
9. Compare `hash(unsealed_policy)` against on-chain `AgentRegistry::policy_commitment` after every `unseal` call. Refuse to start if mismatched.
10. Seal worker keypair file (`worker-keypair.json`) with same provider. Or, ideally, generate keypair fresh inside the enclave and never persist plaintext.
11. Wire `provider.verify_attestation` self-check after every `attest` (defence in depth).
12. Wire `register_agent` (on-chain) to call `verify_attestation_commitment` before setting `policy_commitment`. (Mock sweep highest item #2.)
13. Reject `GLYPH_MODE` typos: anything not in `{production, prod, staging, dev}` ⇒ `Err`. No silent default.
14. Reject `Staging` mode without explicit `GLYPH_STAGING_ALLOW_DEV_PROVER=1` opt-in.

**Files:**
- `tee-worker/src/vendors/{nitro.rs, mod.rs}`
- `tee-worker/src/main.rs`
- `tee-worker/src/policy.rs` (T12 panic-on-tamper)
- `programs/glyph-verifier/src/lib.rs` (register_agent attestation check)
- New: `tee-worker/src/production_check.rs`
- New: `tee-worker/src/cose_verify.rs` (COSE+X.509 helpers)
- Vendored: `tee-worker/assets/nitro_root_ca.pem` (AWS Nitro Root CA)

**Acceptance criteria:**
- [ ] On a real Nitro Enclave host: worker boots, attestation document is valid COSE, certificate chain anchors to Nitro Root CA, KMS round-trips a sealed blob.
- [ ] Worker refuses to start with `is_real_enclave == false` in production mode.
- [ ] Worker refuses to start if `unseal(policy)` fails (any reason).
- [ ] `register_agent` on-chain rejects an attestation that doesn't bind the supplied `policy_commitment`.
- [ ] Worker keypair file is sealed under TEE-bound key (or never persisted).
- [ ] Localnet end-to-end test: register agent → submit intent → worker proves → on-chain verify; all attestation paths fire.

**Dependencies:** WS-1 (uses VK PDA + image_id from registry).

**Skill assignment:** `solana-dev`, `cso` (TEE threat-model review).

---

### **WS-2b — SGX DCAP attestation (slower track)**
*Priority: P1. Closes T1 (SGX), T15.*

**Scope:** Implement Intel SGX DCAP via `sgx-dcap-ql` (quote generation) + `sgx-dcap-quoteverify` (verification). Use `sgx_seal_data` / `sgx_unseal_data` with `SGX_KEYPOLICY_MRENCLAVE`. Validate TCB level + MRENCLAVE allowlist.

Defer until Nitro is shipping.

---

### **WS-2c — SEV-SNP attestation (slower track)**
*Priority: P1. Closes T1 (SEV), T16.*

**Scope:** Use `sev` crate for `SNP_GET_REPORT`; `p384` for VCEK ECDSA-P384 verification. Sealing: vTPM-bound or KMS-bound. AMD KDS for VCEK fetch.

Defer until Nitro is shipping.

---

### **WS-3 — Cross-language canonicalization unification**
*Priority: P0 (blocker for any TS user). Closes SDK F-1, F-2, F-3, F-4, F-9, TEE T27, T28.*

**Scope:**
1. Move `canonical_target_instruction_bytes` to `glyph-common` crate. Both verifier and worker import.
2. Define **one** canonical wire format, document in `docs/canonicalization.md`. Recommendation:
   - **Borsh** for binary canonical encoding (deterministic, length-prefixed).
   - JSON only for human-readable interfaces; JSON canonicalization spec uses RFC 8785 (JCS).
   - `max_lamports`: serialize as JSON **string** in JSON path (TS-friendly); Rust uses `#[serde(with = "serde_with::DisplayFromStr")]`.
3. Fix TS `AccountMeta` interface to use `is_signer` / `is_writable` (snake_case). Add lint rule.
4. Pin `Groth16Proof` byte encoding: hex strings (`0x`-prefixed, length-validated). Update both SDKs and worker.
5. Reconcile `Policy.expires_at`: either remove from canonical encoding (if not yet authored anywhere) or document in `docs/policy-dsl.md` and add to TOML schema. Recommendation: **add to TOML** as Rule 9 ("policy expiry").
6. Rename canonical `require_signer` to `require_signer_present` (matching DSL spec).
7. Add `sdk/test-vectors/` directory with cross-language fixtures. CI runs:
   - Rust SDK: build intent → emit canonical bytes → write fixture.
   - TS SDK: load same logical input → emit canonical bytes → assert byte-equal.
   - Both: load Rust-built signed intent → verify signature with `tweetnacl` / `ed25519_dalek`.
8. Length-prefix `data` in transaction-builder canonical encoding (Borsh handles this).
9. Add `IntentBuilder.with_nonce(...)` for caller-supplied nonces (both languages).

**Files:**
- `common/src/lib.rs` (move serializer here, add `canonical_target_instruction_bytes`)
- `sdk/rust/src/{intent.rs, types.rs, errors.rs}`
- `sdk/typescript/src/{intent.ts, types.ts, errors.ts (new), canonical.ts (new)}`
- `tee-worker/src/{transaction_builder.rs, main.rs, policy.rs}`
- `programs/glyph-verifier/src/lib.rs`
- New: `docs/canonicalization.md`
- New: `sdk/test-vectors/{intents,policies}/*.{json,bytes}`
- New: `scripts/gen-test-vectors.sh`

**Acceptance criteria:**
- [ ] TS-built intent → bytes equal Rust-built intent (CI test).
- [ ] TS-built signed intent verifies with Rust `ed25519_dalek::verify`.
- [ ] `cargo test --workspace -p glyph-common` passes round-trip property tests on Borsh.
- [ ] `expires_at` is either documented + parseable from TOML or removed from canonical bytes.
- [ ] No struct field rename drift between `common::Policy` and `docs/policy-dsl.md`.

**Dependencies:** None (parallel to WS-1, WS-2).

**Skill assignment:** `solana-dev`, `frontend-design-guidelines` (for TS SDK API ergonomics review).

---

### **WS-4 — Trusted clock + freshness + budget commit ordering**
*Priority: P1. Closes 4 CRITICAL/HIGH (TEE T7, T8, T9, T11) + 1 MEDIUM (T34).*

**Scope:**
1. Refactor `evaluate_intent` into `check_intent` (pure read) + `commit_intent` (mutating). Call `check_intent` before prover, `commit_intent` only after `prover.generate_proof()` returns `Ok`.
2. Bind to a TEE-attested time source. Recommendation: **Roughtime** server, signed-timestamp model. Each policy evaluation consumes a fresh signed timestamp from a server whose pubkey is committed in `policy.toml`. Verify signature inside the TEE. Refuse evaluation if timestamp drift > 60s.
3. Short-term stop-gap: persist `last_seen_date` in the volume tracker; refuse to advance until `CLOCK_MONOTONIC` shows ≥ 23h since the last day-roll.
4. Use `checked_add` on volume accumulator; explicit overflow rejection.
5. Use a single `now()` call per `evaluate_intent` invocation; pass as parameter to all rule checks.
6. Add intent freshness check in `process_intent`: `now > intent.expiry ⇒ reject`; `intent.timestamp > now + 300 ⇒ reject` (5 min future-skew tolerance).
7. Validate `start_hour_utc` / `end_hour_utc` ∈ `0..=23` at policy load.
8. Token-mint rule: reject when `policy.allowed_token_mints` is non-empty but `intent.allowed_tokens` is `None` (close T26).

**Files:**
- `tee-worker/src/policy.rs`
- `tee-worker/src/main.rs`
- New: `tee-worker/src/clock.rs` (Roughtime client + verification)
- `policy.toml` schema docs

**Acceptance criteria:**
- [ ] Volume tracker is unchanged on prover failure (test with mock `FailingProver`).
- [ ] Roughtime spoofed timestamp (signed by wrong key) is rejected.
- [ ] Host clock skew of +1 day does not advance the daily date in the volume tracker.
- [ ] Time-window with `start_hour_utc=24` is rejected at config load, not silently always-false.
- [ ] Intent omitting `allowed_tokens` against a non-empty `allowed_token_mints` policy is rejected with rule 6 discriminator.

**Dependencies:** WS-2 (uses TEE-sealed Roughtime key).

**Skill assignment:** `solana-dev`, `monitoring-expert` (clock skew alarms).

---

### **WS-5 — Network hardening: mTLS + rate limits**
*Priority: P1. Closes T18, T19, T39.*

**Scope:**
1. Replace plain TCP listener with `rustls`-fronted mTLS. Issuer pinned via env (`GLYPH_CLIENT_CA_PEM`).
2. Token-bucket per source IP: 10 intents/min/IP default.
3. In `Production` mode: enforce `listen_addr.starts_with("127.")` or `[::1]` unless `GLYPH_ALLOW_PUBLIC_BIND=1` is set explicitly + an mTLS CA is configured.
4. Replace metrics hand-rolled HTTP server with `hyper`/`axum` on a dedicated port. `0.0.0.0` bind requires explicit opt-in.
5. Length-prefixed protocol framing on the worker's intake socket (replace raw JSON over TCP).

**Files:**
- `tee-worker/src/main.rs`
- `tee-worker/src/metrics.rs`
- New: `tee-worker/src/mtls.rs`
- New: `tee-worker/src/rate_limit.rs`

**Acceptance criteria:**
- [ ] Connection without client cert is rejected at TLS handshake.
- [ ] 11th intent in 60 s from same IP returns `429 RateLimited`.
- [ ] `Production` + non-loopback bind without `GLYPH_ALLOW_PUBLIC_BIND=1` panics at boot.
- [ ] Metrics endpoint serves a clean Prometheus exposition under load test.

**Dependencies:** WS-2 (worker keypair sealing — TLS cert may live on same key).

**Skill assignment:** `solana-dev`, `cso`.

---

### **WS-6 — Tamper-evident audit trail**
*Priority: P1 (paper-faithfulness). Closes T20, T37; advances Ch 5 thesis claim.*

**Scope:**
1. Append-only sealed audit log file (`audit.log.sealed`) per worker. Each entry: `(timestamp, agent_pubkey, intent_hash, policy_commitment, prev_entry_hash, worker_signature)`.
2. Periodic on-chain commitment of `audit.log` Merkle root via `commit_audit_root(root: [u8;32])` instruction (new). Requires `worker_signature` over root.
3. Read-only `/audit` HTTP endpoint streams sealed entries. Verify chain integrity on the way out.
4. Add `glyph_attestations_total{result}`, `glyph_seal_ops_total{result}`, `glyph_unseal_ops_total{result}` counters.
5. Wire signed audit entry emission into `process_intent` AFTER successful prover output and BEFORE returning to client.

**Files:**
- New: `tee-worker/src/audit_log.rs`
- `tee-worker/src/main.rs`
- `tee-worker/src/metrics.rs`
- `programs/glyph-verifier/src/lib.rs` (new instruction)

**Acceptance criteria:**
- [ ] Tamper any byte in `audit.log.sealed` ⇒ next `/audit` read fails with `ChainBroken`.
- [ ] Replay verification: from any entry, walk `prev_entry_hash` to genesis and validate.
- [ ] On-chain `AuditRootCommitted` event includes a Merkle root that, when combined with the worker's exported audit log, lets a third party recompute the root.

**Dependencies:** WS-2 (sealing).

**Skill assignment:** `solana-dev`, `monitoring-expert`.

---

### **WS-7 — Operational hardening: pause switch, real program ID, env hygiene**
*Priority: P1. Closes mock-sweep HIGH items + various MEDIUMs.*

**Scope:**
1. **Real program ID:** generate `target/deploy/glyph_verifier-keypair.json`; replace `G1yPHveri111...` in `lib.rs`, `Anchor.toml`, and `tee-worker/src/main.rs:99-103`. Add a CI assert that `declare_id!` value equals the keypair's pubkey.
2. **Wire `paused` flag:** `require!(!ctx.accounts.config.paused, GlyphError::Paused)` at the top of `verify_and_execute`, `register_agent`, `update_policy`. Add `pause` / `unpause` instructions guarded by `config.authority` (or multisig).
3. **Remove `tmp_hash.rs`** from repo root (or move under `scripts/legacy/` with a deprecation comment).
4. **Disable demo's silent failures:** `scripts/demo.sh` should `set -e`; remove `|| echo Warning ...` swallowing of `anchor build`.
5. **Refuse mainnet RPC default:** `GLYPH_SOLANA_RPC_URL` must be set explicitly in `Production`. No default.
6. **Default `RuntimeMode::Production`** in deserialization; opt-down to `Dev` requires explicit env-var.
7. **Remove dead error codes** `DevModeNotAllowed`, `InsufficientComputeBudget` if not wired by WS-1; otherwise wire them.
8. **Strict env parsing:** all env-var loaders return `Err` on malformed value (no silent defaults).

**Files:**
- `programs/glyph-verifier/src/lib.rs`
- `Anchor.toml`
- `tee-worker/src/{main.rs, types.rs}`
- `scripts/demo.sh`
- Delete: `tmp_hash.rs`
- New: `target/deploy/glyph_verifier-keypair.json`

**Acceptance criteria:**
- [ ] `cargo build --release` of the verifier emits a program with the new program ID.
- [ ] Calling `verify_and_execute` while `config.paused == true` returns `Paused` (new error code).
- [ ] `pause` / `unpause` require `authority` signer.
- [ ] Repo grep `G1yPHveri` returns zero matches.
- [ ] CI fails if `GLYPH_SOLANA_RPC_URL` env-var defaults are restored.

**Dependencies:** WS-1 (uses VK PDA scaffolding for multisig pattern).

**Skill assignment:** `solana-dev`, `develop-secure-contracts`.

---

### **WS-8 — Formal verification refresh + circuit rule completeness**
*Priority: P2. Closes ZK F-23, F-22, F-17, F-32, F-33; advances paper alignment.*

**Scope:**
1. Move all 8 policy rules into the guest circuit (currently 6 of 9 — `time_window`, `daily_volume`, `allowed_token_mints` are TEE-side). Approach:
   - For `time_window`: commit a TEE-attested signed timestamp into the journal as a public input, prove `start <= timestamp_hour <= end`.
   - For `daily_volume`: commit a sealed daily-bucket pre-image into the journal; prove the addition is correct.
   - For `allowed_token_mints`: commit the intent's mint list into the journal; prove inclusion via a Merkle path against `policy.allowed_token_mints` (committed in policy_commitment).
2. Add `circuit_rule_bitmap: u32` to `PublicOutputs` so the on-chain verifier knows which rules were proven.
3. Update Lean 4 `Proofs/*.lean` specs in `formal_verification/` to cover:
   - The new `image_id` binding (after WS-1).
   - The `agent_pubkey` in nonce PDA seed (after WS-1).
   - The on-chain `Clock` expiry check (after WS-1).
   - The full 8-rule circuit coverage (this WS).
4. Add granular failure codes in the guest: replace `assert!`/`panic!` with explicit error codes written to a journal-side `failure_code: Option<u8>` field.
5. Add property tests / fuzz tests on the guest:
   - Property: any intent that satisfies all 8 rules produces a valid proof.
   - Property: any intent that violates any rule produces a verification failure on-chain.
   - Fuzz: randomized intent + policy → guest behaviour matches a reference `tee-worker::policy::evaluate_intent` implementation.
6. **zkFuzz integration** (per user request — applicable subset). zkFuzz is for Circom/Halo2 mutation testing; RISC Zero zkVM circuits are different. Replacement: integrate `cargo-fuzz` against the guest crate's host-side I/O contract. Document why zkFuzz proper is N/A.

**Files:**
- `circuits/glyph-circuit/guest/src/main.rs`
- `circuits/glyph-circuit/host/{src/lib.rs, tests/integration.rs}`
- `formal_verification/Proofs/*.lean`
- `formal_verification/SPEC.md`
- New: `circuits/glyph-circuit/host/fuzz/` (cargo-fuzz)

**Acceptance criteria:**
- [ ] Guest circuit constraint count for the new 8-rule version stays under 2x prior (measured via `nargo info` equivalent for RISC Zero — `cargo run --release --bin glyph-circuit-host -- --report`).
- [ ] `lake build` passes against the updated specs.
- [ ] Guest property tests pass against `tee-worker::policy::evaluate_intent` reference for 10k random inputs.
- [ ] On-chain verifier rejects a proof with `circuit_rule_bitmap` lacking a required rule.

**Dependencies:** WS-1, WS-2 (TEE-attested clock for in-circuit time check).

**Skill assignment:** `qedgen` (Lean), `solana-dev`, custom: cargo-fuzz harness.

---

### **WS-9 — Paper-faithful authenticated delegation: human delegator signature**
*Priority: P2. Advances paper alignment, optional for v1 if scope is too tight.*

**Scope:**
1. Add a `delegator_signature: [u8; 64]` field to `register_agent` instruction args.
2. Verify the signature covers `(agent_pubkey, policy_commitment, image_id, expiry, scope)` against the registrar (delegator) Solana key.
3. Document the integration path with off-chain OIDC: the delegator may be authenticated via OIDC at the off-chain control plane that *constructs* the signature payload; the on-chain side only checks the signature.
4. Update `docs/architecture.md` to reflect the three-token model: User-key (delegator) → Agent-key (registered) → Intent (signed by agent for the delegator's policy).

**Files:**
- `programs/glyph-verifier/src/lib.rs` (register_agent signature verification)
- `sdk/{rust,typescript}/src/client.rs` (registration helper)
- `docs/architecture.md`
- `docs/delegation-model.md` (new)

**Acceptance criteria:**
- [ ] `register_agent` rejects a registration whose `delegator_signature` does not verify against `tx.signers[0]` over the canonical bundle.
- [ ] Reference SDK helper produces a verifiable delegator signature.
- [ ] `architecture.md` diagram explicitly shows the three-token correspondence.

**Dependencies:** WS-1 (image_id pinning), WS-3 (canonicalization).

**Skill assignment:** `solana-dev`.

---

### **WS-10 — Cleanup: dead code, bounded fields, observability gaps**
*Priority: P3. Closes ~25 LOW/INFO findings.*

**Scope:**
- Remove `verify_vk_integrity` if unused after WS-1 makes it const-asserted.
- Bound `tx_signature: String` length OR remove field (rename to `tx_hash_prefix`).
- Loop scalar reduction in `reduce_scalar` (post-WS-1, may be obviated by `solana_bn254` helpers).
- Validate `seal` 4-byte selector against `risc0_zkvm::sha::SELECTOR_GROTH16`.
- Add log redaction layer for `tracing` (no `intent.nonce`, no `agent_pubkey` in logs).
- Add structured rule-discriminator to `PolicyViolationError`.
- Make policy-volume file path collision-free (use full filename, not `with_extension`).

**Files:** scattered. Track each in commit messages.

**Acceptance criteria:** `cargo clippy --workspace -- -D warnings` clean; `cargo audit` clean; `cargo deny` clean; no `pub` items unused.

**Dependencies:** WS-1..WS-7 done.

**Skill assignment:** `simplify`, `review-and-iterate`.

---

## 4. Phase Ordering & Time Estimates

| Phase | Workstreams | Goal | Duration estimate |
|---|---|---|---|
| **P0** | WS-1, WS-2 (Nitro), WS-3 | Make GLYPH actually work end-to-end | ~3 weeks (3 mob teams in parallel) |
| **P1** | WS-4, WS-5, WS-6, WS-7 | Production hardening | ~2 weeks |
| **P2** | WS-8, WS-9, WS-2b, WS-2c | Paper alignment + alt-vendor | ~3 weeks |
| **P3** | WS-10 | Cleanup | ~1 week |
| **External audit** | — | Pashov-style review (see §6) | 2 weeks elapsed |
| **Total** | | | ~9-11 weeks |

---

## 5. Tooling Wire-Up (per user's referenced repos/skills)

The user named several repos. Honest mapping:

| Tool | Applicability | Action |
|---|---|---|
| **Noir / Nargo** | **Not applicable** — GLYPH uses RISC Zero zkVM, not Noir. | Document why; no integration. |
| **Circom** | **Not applicable** — same reason. | Document why; no integration. |
| **SnarkJS** | **Not applicable** — same reason. | Document why; no integration. |
| **zkFuzz** | **Not directly applicable** — designed for Circom/Halo2 circuit mutation. RISC Zero guest uses Rust + STARK; mutation testing maps to `cargo-fuzz` against the guest's I/O contract. | Wire `cargo-fuzz` in WS-8. |
| **Agent Zero** | Multi-agent orchestration framework. | Out of scope for GLYPH itself — applies to the *agent layer* using GLYPH, not GLYPH's own code. Cross-link in `docs/integration-with-agents.md` (new). |
| **Matter Labs ZKP / StefanosChaliasos ZKP Security Canon** | Reference catalogues for known vulnerabilities + reference implementations. | Use as **reading list** during WS-1. Document any patterns adopted (e.g., subgroup check from a specific reference) in `docs/zk-references.md`. |
| **pashov/audits** | Audit case studies. | Use as **adversarial-review checklist** during external audit phase (§6). |
| **pashov/ai-web3-security** | AI × Web3 audit skills. | Pull skills `solidity-auditor`, `qedgen`, `cso`, `owasp-security` (all already installed locally). Use during WS-1 / WS-2 / WS-7. |
| **pashov/skills** | Various audit/review skills. | Already installed in `~/.claude/skills/`. Apply `review-and-iterate`, `simplify`, `cso` per WS as noted. |

---

## 6. External Audit Phase (post-P1)

Before any mainnet deployment, GLYPH should undergo a third-party audit. Recommendations:

1. **Pashov-Audit-Group** (or comparable): full Solana program audit covering `glyph-verifier`, with explicit ZK-pairing specialty.
2. **OtterSec / Trail of Bits / Zellic**: secondary review of the TEE worker + ZK pipeline interaction (less common specialty; pre-brief with WS-2 deliverables).
3. **ezkl / RISC Zero engineering reviews**: focused review of the proof bundle format + image_id binding + claim digest construction. RISC Zero offers an audit-cadence support program; engage early.

**Pre-audit checklist (deliverable artifacts):**
- [ ] All P0 + P1 workstreams complete.
- [ ] `audit/AUDIT_ZK.md`, `audit/AUDIT_TEE.md`, `audit/AUDIT_SDK.md` updated to reflect remediation.
- [ ] `formal_verification/SPEC.md` reflects the post-WS-8 state.
- [ ] Test coverage report ≥ 80% on `programs/`, `tee-worker/`, `circuits/`.
- [ ] CI runs green: `cargo test --workspace`, `cargo clippy --workspace -- -D warnings`, `pnpm test` in `sdk/typescript`, `lake build` in `formal_verification`.
- [ ] One full end-to-end localnet integration test of the production-mode path including Nitro attestation (run on a real Nitro Enclave).

---

## 7. AI-DLC Phase Mapping

Per AWS Labs AI-DLC structure:

- **INCEPTION** (already complete): What and why is captured in the arXiv article [2509.00085](https://arxiv.org/abs/2509.00085), `docs/architecture.md`, and the existing `aidlc-docs/zk-upgrade-design.md`.
- **CONSTRUCTION** (this document): What you're reading. Ten workstreams, four phases, ~9-11 week roadmap.
- **OPERATIONS** (deferred): Will be authored as `audit/OPERATIONS_PLAN.md` after WS-2 delivers a working TEE — will cover deployment topology (single Nitro Enclave per agent vs pool), KMS key rotation, on-chain governance, incident response runbook, monitoring SLIs/SLOs.

---

## 8. Out-of-Scope (Documented Decisions)

To prevent scope creep, the following are explicitly deferred:

1. **OIDC / W3C VC integration** — paper-faithful but not v1.
2. **NL-to-policy LLM compiler** — paper-mentioned, deferred indefinitely.
3. **Verifiable ML evals** (Ch 2 verifyevals) — separate product, not GLYPH.
4. **Partial ZK** (Ch 2 partialzk) — same.
5. **zkTax three-service redact-and-prove** (Ch 2 zktax) — same.
6. **PRAG MPC retrieval** (Ch 3 PRAG) — same.
7. **Personhood Credentials** (Ch 4 phc) — future hook in delegation token.
8. **NVIDIA H100 confidential GPU inference** — outside CPU-TEE scope.
9. **ORAM mitigation for TEE side channels** — paper says "future work"; we follow.
10. **GPU TEE attestation** — same.
11. **Multi-agent / inter-agent delegation propagation** — paper sketch, not built.
12. **SGX & SEV-SNP production adapters** — Nitro-first; SGX/SEV land in P2 (WS-2b, WS-2c).
13. **Cross-chain (EVM/Cosmos) verifier ports** — Solana is v1.
14. **Custom proving stack** — RISC Zero is the choice; revisiting it is an Inception-phase decision, not Construction.

---

## 9. Quick-Look TL;DR for the Engineering Lead

If you have ten minutes:

1. **Read `audit/AUDIT_ZK.md` §F-1, F-2, F-3, F-4** — the five lines that explain why no real proof can verify today.
2. **Read `audit/AUDIT_TEE.md` T1, T2, T4** — the three-line story of why "production mode" today is dev mode in disguise.
3. **Read `audit/AUDIT_SDK.md` F-1** — why every TS user is currently broken.
4. **Read this file §3 WS-1, WS-2, WS-3** — the three workstreams that close the above.
5. **Read this file §1 (Paper-to-Implementation Matrix)** — the row marked "GLYPH gap" entries are the value GLYPH adds beyond the thesis. They are *implemented* but with the bugs above. Once WS-1..WS-3 land, GLYPH genuinely is the on-chain extension to Tobin South's framework that the project claims to be.

That's the work. Everything else is hardening, polish, and paper-faithful extension.

---

## 10. Change Log

| Date | Author | Change |
|---|---|---|
| 2026-05-10 | Claude Opus 4.7 | Initial plan from full audit cycle (paper brief, ZK audit, TEE audit, SDK audit, mock sweep). |
