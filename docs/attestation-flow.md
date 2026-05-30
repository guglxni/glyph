# Attestation flow — TEE worker → SDK → on-chain verifier

This document specifies how a `worker_attestation` envelope flows through
the GLYPH stack: from boot-time generation inside the TEE worker, to
attachment on every proof bundle, to re-verification by the SDK and the
on-chain `register_agent` / `update_policy` instructions.

Closes audit findings **T2**, **T6**, and **T20** in
`audit/AUDIT_TEE.md`.

---

## 1. Boot-time attestation

The worker boots in this order:

1. `load_config()` resolves runtime mode, vendor, agent_pubkey,
   `keypair_sealed`, and policy / keypair paths.
2. `enforce_production_invariants(&config, provider)` runs the gate. In
   `Production` mode this exercises:
   - `provider.require_real()` (closes T4 / T33),
   - a probe `provider.attest()` + `provider.verify_attestation()`
     round-trip (closes T29 attestation slice),
   - a 32-byte `provider.seal()` / `provider.unseal()` round-trip
     (closes T29 sealing slice),
   - `GLYPH_TEE_VENDOR` is explicitly set.
3. The policy file is unsealed via `provider.unseal()` and the canonical
   `policy_commitment = hash_policy(canonical_policy)` is computed.
4. The Ed25519 worker keypair is loaded via `load_signing_key`, which
   honours `GLYPH_KEYPAIR_SEALED=1` / `*.sealed` extension and refuses
   plaintext on disk in `Staging` / `Production` (closes T21).
5. `derive_agent_pubkey_for_attestation` resolves the agent pubkey:
   `GLYPH_AGENT_PUBKEY` is required in `Staging` / `Production`; `Dev`
   substitutes `worker_pubkey`.
6. A 32-byte random `boot_nonce` is generated.
7. `perform_attestation(...)` is invoked:
   - `user_data = provider.compute_user_data(policy_commitment, agent_pubkey, worker_pubkey, boot_nonce, epoch)`
     — domain-separated SHA-256 over the 5-tuple, with a vendor-specific
     domain string (`GLYPH:nitro:user_data:v1:` /
     `GLYPH:sgx:report_data:v1:` / `GLYPH:sev-snp:report_data:v1:`).
   - `evidence = provider.attest(&user_data, &policy_commitment)` —
     vendor-specific quote.
   - Self-verify with
     `provider.verify_attestation(&evidence, &policy_commitment)`. A
     `false` return aborts boot — defends against a regressed vendor
     that emits unverifiable evidence.
8. The resulting `BoundAttestation { evidence, policy_commitment }` is
   stored in `AppState.attestation: Arc<RwLock<Option<...>>>`.

In `Dev` mode any failure in step 7 is logged and the worker continues
with `attestation = None`. In `Staging` / `Production` the failure is a
hard fail-closed.

---

## 2. Periodic re-attestation

A background tokio task (`spawn_re_attestation_task`) wakes every
`RE_ATTESTATION_INTERVAL_SECS` (default 300 seconds = 5 minutes) and
re-runs `perform_attestation` against the *current* canonical policy
commitment, then rotates the `RwLock` slot.

If re-attestation fails for any reason the slot is wiped — the next
intent is rejected with the structured `AttestationStale` error code
(see §4) instead of being signed against stale evidence.

---

## 3. Bundle envelope

`GlyphProofBundle` (in both `tee-worker/src/types.rs` and
`common/src/lib.rs` SDK consumers) carries:

```rust
pub struct GlyphProofBundle {
    pub proof: Groth16Proof,
    pub journal_bytes: Vec<u8>,
    pub public_inputs: PublicInputs,
    pub signed_transaction: Vec<u8>,
    pub tx_hash_prefix: [u8; 16],
    pub worker_attestation: Option<Vec<u8>>, // ← evidence.quote
}
```

The `worker_attestation` field is populated in `process_intent` *after*
the prover succeeds and *before* the bundle is returned. The contents
are exactly `evidence.quote` from the latest `BoundAttestation` (or
`None` in `Dev` mode if no boot attestation was generated).

The vendor type and `timestamp_unix` are recovered out-of-band by the
verifier — the on-chain `AgentRegistry` already stores the registered
TEE vendor for the agent, and the SDK's `verify_bundle()` helper
reconstructs an `AttestationEvidence` value from
`(registered_vendor, bundle.worker_attestation, registered_timestamp_or_now)`
before calling `provider.verify_attestation(...)`.

---

## 4. Stale-attestation gate

`process_intent` runs the following check before touching the prover:

```text
if attestation is None
   OR (now - attestation.timestamp_unix) > MAX_ATTESTATION_AGE_SECS  // 600s
   OR attestation.policy_commitment != live_policy_commitment:
   in Staging/Production → reject with AttestationStale
   in Dev               → log warning, continue with worker_attestation = None
```

This closes the freshness side of T6 and the policy-rotation race: a
worker whose policy was rotated mid-session re-attests on the next
periodic tick; intents that arrive between the rotation and the next
tick are deferred (returned as `AttestationStale` so the SDK can
retry).

The wire-format error response is:

```json
{
  "status": "error",
  "code": "ATTESTATION_STALE",
  "message": "worker attestation is stale — retry shortly"
}
```

---

## 5. SDK re-verify

The SDK's `verify_bundle(bundle, agent_registry, expected_policy_commitment)`
helper performs:

1. Verify the Groth16 proof + journal against the registered VK PDA
   (existing path).
2. If `agent_registry.tee_vendor != null`, re-verify the attestation:
   - Reconstruct `AttestationEvidence { vendor: registered_vendor,
     quote: bundle.worker_attestation, timestamp_unix: 0 }`. The
     `timestamp_unix` is ignored by the structured dev-mode parser and
     is recovered from the COSE envelope in the production Nitro path.
   - Call `provider.verify_attestation(&evidence, &expected_policy_commitment)`.
   - Reject the bundle if the call returns `false` or `Err`.

The full 5-tuple binding (`agent_pubkey`, `worker_pubkey`, `boot_nonce`,
`epoch`) is anchored in the on-chain `AgentRegistry::attestation_commitment`
field at registration time, so the SDK only needs the live policy
commitment to re-verify.

---

## 6. On-chain verification

`programs/glyph-verifier/src/lib.rs::register_agent` consumes a
`worker_attestation` byte vector at registration time:

1. The instruction handler hashes
   `(policy_commitment, agent_pubkey, worker_pubkey, boot_nonce, epoch)`
   under the same vendor-specific domain string as the worker (the
   `compute_bound_user_data` helper in `vendors/mod.rs` is the source of
   truth — kept in lockstep with the on-chain copy via shared test
   vectors in `scripts/gen-test-vectors.sh`).
2. It verifies the COSE signature chain anchors to the AWS Nitro Root CA
   (or the SGX DCAP collateral, or the AMD VCEK chain — depending on
   the registered vendor).
3. It stores the resulting `attestation_commitment` (hash of the
   verified `user_data`) in the `AgentRegistry` PDA.

For `update_policy` the same handler runs but additionally checks that
the *new* policy commitment matches the one bound into the freshly
attached attestation — a stale worker that has not yet re-attested
under the new policy cannot rotate it on-chain.

---

## 7. Test vectors

`tee-worker/tests/attestation_pipeline_test.rs` exercises the full
chain end-to-end against the dev-mode passphrase-sealed providers:

- `nitro_dev_pipeline_round_trips`
- `sgx_dev_pipeline_round_trips`
- `sev_dev_pipeline_round_trips`
- `cross_vendor_evidence_substitution_rejected`
- `user_data_binding_changes_with_each_field`

Run with:

```bash
GLYPH_SEAL_PASSPHRASE='pipeline-test-passphrase-32-bytes-min!!' \
  cargo test -p glyph-tee-worker --test attestation_pipeline_test
```

Real Nitro / SGX / SEV hardware is not required — the dev-mode
structured parser in `vendors/mod.rs::parse_dev_attestation` enforces
exact byte layout (closes T14 / T15 / T16) so the tests catch the same
binding regressions a real-hardware test would.
