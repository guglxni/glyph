# Integration: GPU TEE Confidential Inference (NVIDIA H100)

Out-of-scope integration design for GLYPH v1. Tracks paper alignment for the
end-to-end confidential RAG / inference pipeline.

## 1. Paper Reference

- Tobin South, *Private, Verifiable, and Auditable AI Systems*
  (arXiv:2509.00085), Chapter 3 §"Trusted execution environments (TEEs)
  for private data management and RAG" (`communitytrans.tex`):
  - §"The Role of the TEE" (lines 41-49) lists the four required hardware
    properties: **confidentiality (memory encryption)**, **integrity**,
    **attestation**, **sealing**.
  - §3 "Confidential Inference with H100 GPU Secure Enclaves"
    (`communitytrans.tex` §"Confidential Inference with H100…" lines
    83-108): *"Recent advances in confidential computing hardware,
    particularly NVIDIA's H100 GPU featuring secure enclave technology,
    significantly enhance the feasibility and performance of TEE-based AI
    systems… These GPUs enable high-performance LLM inference to occur
    directly within a hardware-protected TEE."*
  - §"Attested Verification" (line 107) names the three things a remote
    party verifies: (i) genuine NVIDIA hardware, (ii) properly initialized
    TEE, (iii) inference-engine code measurement matches a known hash.
- Cross-reference: thesis Chapter 5 *"Holographic graph logs"* names the
  attested-inference event as one of the small attestations hash-linked
  into the audit chain.

External docs (verify before implementing — these are vendor-published and
move quickly):
- NVIDIA Confidential Computing for H100/H200 (NVIDIA white paper "NVIDIA
  Hopper Confidential Computing", published 2023-2024; APIs subject to
  change). The `nvtrust` toolkit and the `nv-attestation-sdk` produce a
  signed *NRAS (NVIDIA Remote Attestation Service) token* / *CC Attestation
  Report*.

## 2. Current GLYPH State

GLYPH today operates **CPU-side TEE only**. The TEE worker
(`tee-worker/src/`) abstracts Nitro / SGX / SEV providers for **policy
unsealing and intent evaluation**, not for model inference. The intent
itself is produced **outside the TEE** by an arbitrary agent/LLM; GLYPH
has no opinion on, and no attestation over, the model that emitted the
intent.

`AgentRegistry` in `programs/glyph-verifier/src/state.rs` stores
`attestation_hash: [u8;32]` and `attestation_type: u8` — these refer to
the **CPU TEE** running the worker, not a GPU enclave.

## 3. Proposed Integration

Add a second attestation slot that binds a GPU TEE attestation over the
specific model image used to produce the intent:

1. Bind a **model attestation token** at agent registration.
2. The CPU TEE worker, when accepting an intent, verifies that the intent
   originated from a model session whose CC-Attestation hash matches
   `model_attestation` in the registry.
3. The on-chain registry now stores **two roots of trust**:
   `attestation_hash` (CPU TEE: policy + worker code) and
   `model_attestation` (GPU TEE: inference engine + weights measurement).

This separation is faithful to the thesis: §"End-to-End Confidential
Inference and RAG" describes the embedding/search/inference steps as
distinct attestable boundaries.

## 4. Wire Format / API Surface

Extend `RegisterAgentArgs`:

```rust
pub struct RegisterAgentArgs {
    // ... existing fields ...
    pub attestation_hash: [u8; 32],   // CPU TEE (existing)
    pub attestation_type: u8,         // existing enum

    // NEW (additive, optional):
    pub model_attestation: Option<[u8; 32]>,   // SHA-256(CC-Attestation token)
    pub model_attestation_type: Option<u8>,    // enum: NvidiaH100Cc=1, Sev=2, …
}
```

Off-chain canonicalization for `model_attestation`:

```text
SHA-256(
  "GLYPH:MODEL-ATT:v1:"  (19 bytes ASCII)
  ‖ nras_token_bytes      (the raw NRAS / CC-Attestation JWT/CBOR as emitted by nvtrust)
)
```

A new sidecar service `glyph-gpu-attestor/` runs alongside the inference
server and exposes:

- `POST /attest { nonce } -> { nras_token, code_measurement, hw_chain }`
  — wraps `nv-attestation-sdk`'s `attest()` call, returns the raw token
  and the parsed measurement for human inspection.
- `POST /verify { nras_token } -> { ok, vendor_chain_ok, code_hash }`
  — validates against NVIDIA's RIM (Reference Integrity Manifest) service
  and returns the canonical hash.

## 5. Implementation Plan / Workstream

- **Owner:** `glyph-gpu-attestor/` — new repo / workspace member, out of
  scope for v1.
- **Phases:**
  1. Stub the attestor as a static-fixture service returning a recorded
     NRAS token (for CI). The verifier program path stays a no-op when
     `model_attestation = None`.
  2. Wire `nv-attestation-sdk` in `glyph-gpu-attestor/` (Python today; a
     Rust binding via `pyo3` or a thin gRPC boundary).
  3. CPU TEE worker handshakes with the GPU enclave at boot: fetch
     `nras_token` with a freshly-sealed nonce, validate, derive the
     canonical hash, refuse to start if it diverges from the registered
     `model_attestation`.
  4. Add an admin-only `update_model_attestation` instruction (mirrors
     `update_policy`) for rotating model versions.
- **Defer:** runtime per-inference attestation (the thesis' "predict,
  then prove" pattern). Re-attesting every inference is expensive; the
  v2 design attests once per worker process and binds the session.

## 6. Risks & Trade-offs

- **Vendor maturity (unverified — flag).** NVIDIA H100 Confidential
  Computing entered general availability in 2024 but the attestation
  formats (NRAS token schema, RIM endpoints) are still evolving. Treat
  the canonical SHA-256 boundary as the stable contract and keep parsing
  off-chain; do not hash anything format-specific into the on-chain
  payload prefix.
- **Vendor lock-in.** Binding to NVIDIA NRAS makes a future port to AMD
  MI300X / Intel Gaudi confidential compute a fresh attestation type.
  The `model_attestation_type: u8` enum mitigates this — the on-chain
  side is a hash; the type just tells off-chain verifiers which root cert
  chain to walk.
- **Root cert chain length & rotation.** NVIDIA's device attestation
  chains up to a manufacturer root that can rotate. The off-chain
  verifier (`glyph-gpu-attestor/verify`) must pin the expected root and
  refuse unknown chains, OR consult NVIDIA's online RIM service — both
  have failure modes (offline / availability).
- **CC mode performance.** H100 CC mode imposes measurable overhead vs
  bare metal (NVIDIA-published figures hover ~5-10% for LLM inference,
  but this is workload-dependent — verify on the specific deployment).
- **The intent ↔ model binding is policy, not crypto.** GLYPH cannot
  cryptographically prove a given `TransactionIntent` was emitted by the
  attested model — only that the worker accepting the intent ran
  alongside an attested model. Closing that gap requires per-inference
  ZK proofs (see `custom-proving-stack.md`) or model-signed intents.
