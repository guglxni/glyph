# GLYPH Architecture

This document describes the current GLYPH architecture as implemented in this repository: a verifiable policy-enforcement / guardrail layer for autonomous agents on Solana that combines a Trusted Execution Environment (TEE), deterministic policy evaluation, and real on-chain Groth16 proof verification. GLYPH gates and binds an agent's transaction; Solana's runtime executes it. It is program-agnostic by construction — a `TransactionIntent` carries `target_program + accounts[] + data` as opaque bytes, the verifier hashes the *next* instruction generically, and the only allowlist is per-agent TOML (no hardcoded target in the verifier or circuit). `verify_and_execute` is a guardrail sidecar instruction: it does **not** CPI into the target program; it cryptographically binds the proof to the next instruction, which the runtime then executes.

## 1. System Overview

GLYPH is organized into **three logical layers**:

1. **Intent Layer**
   - Produces structured `TransactionIntent` objects (from an agent/LLM/app).
   - Signs intents with an Ed25519 key.
   - Defines action + constraints for bounded execution.

2. **Execution Layer (TEE Worker + Prover)**
   - Runs in an enclave-style environment (SGX / Nitro / SEV abstraction).
   - Validates signatures and policy.
   - Builds and signs Solana transactions.
   - Produces a proof bundle with public inputs.

3. **Verification Layer (Solana Program)**
   - Maintains agent registration and policy commitments on-chain.
   - Verifies the proof/public inputs and enforces replay protection with nonce PDAs.
   - Anchors trust in on-chain state transitions.

---

## 2. High-Level Data Flow

### 2.1 LLM -> TEE -> Solana flow

```text
+----------------------+           +------------------------------+           +-------------------------------+
| Intent Source        |           | TEE Worker                   |           | Solana (glyph-verifier)       |
| (LLM / Agent / App)  |           | (Execution + Proving)        |           | (Verification + State)        |
+----------+-----------+           +---------------+--------------+           +---------------+---------------+
           |                                       |                                          |
           | 1) Create & sign TransactionIntent    |                                          |
           +-------------------------------------->|                                          |
           |                                       | 2) Verify signature                      |
           |                                       | 3) Evaluate TOML policy                  |
           |                                       | 4) Build & sign tx                       |
           |                                       | 5) Generate proof bundle                 |
           |                                       +--------------------+---------------------+
           |                                                            |
           | 6) Submit verify_and_execute + target instruction(s)       |
           +------------------------------------------------------------>| 7) Check agent registry +
                                                                        |    policy commitment
                                                                        | 8) Verify proof (stub today)
                                                                        | 9) Consume nonce PDA (anti-replay)
                                                                        |10) Emit verification event
                                                                        +-------------------------------+
```

### 2.2 Internal module view

```text
sdk/* --> tee-worker/main.rs --> policy.rs --> transaction_builder.rs --> prover.rs --> programs/glyph-verifier
                       |             |                |                    |
                       |             |                |                    +-- policy commitment + public inputs
                       |             |                +-- Solana tx assembly
                       |             +-- 9-rule policy engine
                       +-- TEE provider abstraction (vendors/{sgx,nitro,sev})
```

---

## 3. Component Descriptions

## 3.1 Intent Layer

### TransactionIntent (`tee-worker/src/types.rs`)
Primary payload flowing through the system:
- `version`, `agent_pubkey`, `nonce`, `timestamp`, `expiry`
- `action`:
  - `action_type`: `swap | transfer | stake | cpi_call`
  - `target_program`
  - `accounts[]` (`pubkey`, `is_signer`, `is_writable`)
  - `data` (base64)
- `constraints`:
  - `max_lamports`
  - `max_slippage_bps` (optional)
  - `allowed_tokens` (optional)
- `signature` (base64 Ed25519 signature)

### SDKs (`sdk/rust`, `sdk/typescript`)
- Rust SDK crate exists (`glyph-sdk`) and is currently scaffold-level.
- TypeScript SDK directory exists and is scaffold-level.
- These are the natural entry points for agent/client integration.

## 3.2 Execution Layer (TEE Worker)

### Worker runtime (`tee-worker/src/main.rs`)
Responsibilities:
- Load worker configuration from env or TOML.
- Unseal policy bytes via selected TEE provider.
- Parse policy TOML and instantiate `PolicyEngine`.
- Listen for TCP requests and process intents.
- Validate signatures, enforce policy, build and sign tx.
- Invoke prover and return `GlyphProofBundle`.

### TEE provider abstraction (`tee-worker/src/vendors`)
`TeeProvider` trait provides:
- `seal`, `unseal`
- `attest`, `verify_attestation`

Vendors currently abstracted:
- SGX
- Nitro
- SEV

### Policy engine (`tee-worker/src/policy.rs`)
- Parses TOML policy.
- Applies 9 deterministic policy rules (rule 3 `TimeWindow` is enforced in-circuit + on-chain against the `Clock` sysvar, not host-side).
- Tracks daily volume in-memory by UTC date key.
- Exposes `canonical_serialize(policy)` used for stable commitment hashing.

### Transaction builder (`tee-worker/src/transaction_builder.rs`)
Builds transaction with ordered instructions:
1. `verify_and_execute` (glyph-verifier program)
2. target program instruction from intent
3. compute budget instruction

### Prover (`tee-worker/src/prover.rs`)
- `Prover` trait abstraction.
- `MockProver` currently used by default.
- Optional `risc0` feature gates `RiscZeroProver` integration.
- Computes public inputs:
  - `policy_commitment`
  - `intent_hash`
  - `agent_pubkey`
  - `nonce`
  - `tx_hash`

## 3.3 Verification Layer (On-chain Program)

### Program entrypoints (`programs/glyph-verifier/src/lib.rs`)
- `register_agent`
- `verify_and_execute`
- `update_policy`
- `deregister_agent`

### On-chain state
- `AgentRegistry`
  - agent pubkey, policy commitment, attestation hash/type, status, timestamps
- `NonceAccount`
  - one-time nonce consumption to prevent replay
- `RelayAccount`
  - storage for large-proof relay pattern (documented in state type)

### Verification path (`verify_and_execute.rs`)
- Confirms agent registry constraints and policy commitment match.
- Validates agent pubkey alignment.
- Calls Groth16 verification function.
- Initializes nonce PDA atomically.
- Emits `IntentVerified` event.

> Current implementation note: Groth16 verification uses **real BN254 pairing** via Solana's `alt_bn128` syscalls in `groth16/verifier.rs` (on-curve + subgroup checks, RISC Zero 5-public-input layout). A **real extracted verification key** exists at `groth16/vk_real.rs` (prover version `risc0-zkvm 1.2.6`, real `alpha_g1`/`control_root`/`bn254_control_id`/`image_id`); it is compiled in with `--features real-vk`. Without that feature, `groth16/vk.rs` provides an intentionally off-curve **placeholder** used only by a safety test. Real proofs verify when the program is built with `--features real-vk` and the VK is seeded on-chain via `seed_vk`.

## 3.4 Circuit Layer (`circuits/glyph-circuit`)

- `guest` enforces deterministic policy checks and commits public outputs.
- `host` runs RISC Zero proving flow and validates expected outputs.
- Canonical encoding is used for deterministic policy/intent hashing.

---

## 4. Security Model Overview

GLYPH’s security model is defense-in-depth across cryptography, enclave isolation, deterministic policying, and on-chain replay protection.

### 4.1 Security controls

1. **Agent authenticity**
   - Every intent requires Ed25519 signature validation in worker.

2. **Policy-constrained execution**
   - Intents are filtered by explicit policy rules before tx creation.

3. **Deterministic commitments**
   - Policy commitment uses canonical serialization + SHA-256.
   - Public inputs bind policy, intent, agent key, nonce, and tx hash.

4. **Replay resistance**
   - Nonce PDA creation in `verify_and_execute` prevents nonce reuse.

5. **Attestation anchoring**
   - Agent registry stores attestation hash and attestation type.

6. **Secret hygiene**
   - Sensitive buffers (e.g., sealed policy bytes) are zeroized where implemented.

### 4.2 Important current limitations

- On-chain Groth16 verification is **real**: `verify_and_execute` performs full BN254 pairing verification via Solana's `alt_bn128` syscalls, including G1/G2 on-curve and subgroup checks and the RISC Zero 5-public-input layout (`programs/glyph-verifier/src/groth16/verifier.rs`). The only caveat is operational — the program must be built with `--features real-vk` (so the real extracted key in `groth16/vk_real.rs` is compiled in instead of the off-curve test placeholder used only by a safety test), and that VK must be seeded on-chain via the `seed_vk` instruction before real proofs will verify.
- Daily volume tracking is in-memory worker state (not yet durable/shared across replicas).
- TEE vendor implementations are abstracted; production hardening depends on backend-specific verification and operational controls.

---

## 5. Trust Boundaries

GLYPH crosses multiple trust boundaries that must be treated explicitly.

## Boundary A: Intent producer -> TEE worker
- **Assumption**: incoming payload may be malicious or malformed.
- **Controls**: strict JSON parsing, signature verification, bounded policy checks.

## Boundary B: TEE runtime internals
- **Assumption**: only enclave code and sealed data are trusted.
- **Controls**: seal/unseal, attestation evidence model, no policy plaintext persistence requirement.

## Boundary C: Worker -> Solana RPC / network
- **Assumption**: transport/network can be adversarial.
- **Controls**: signed transaction artifacts, deterministic hashing/public inputs.

## Boundary D: Off-chain proving -> on-chain verification
- **Assumption**: off-chain proof producer is untrusted unless verified.
- **Controls**: proof/public input checks in verifier program (must be cryptographically complete in production).

## Boundary E: On-chain program -> downstream CPI targets
- **Assumption**: target programs have their own trust and correctness properties.
- **Controls**: policy `allowed_programs`, account constraints, compute budget limits.

---

## 6. End-to-End Execution Summary

1. Agent creates and signs a `TransactionIntent`.
2. Worker unseals policy and validates signature.
3. Policy engine evaluates all configured constraints.
4. Worker builds + signs Solana transaction.
5. Prover creates bundle (`proof`, `public_inputs`, `signed_transaction`).
6. Client submits transaction including verifier instruction.
7. On-chain verifier checks registry + commitment, consumes nonce, and emits event.

This separation lets GLYPH keep policy logic and proving off-chain while anchoring identity, policy commitment, and anti-replay guarantees on Solana.
