# Integration: Verifiable ML Model Evaluations (zkSNARK Inference Proofs)

Out-of-scope integration design for GLYPH v1. Tracks paper alignment with
the main contribution of the thesis Chapter 2.

## 1. Paper Reference

- Tobin South, *Private, Verifiable, and Auditable AI Systems*
  (arXiv:2509.00085), Chapter 2 §"Verifiable evaluations of machine
  learning models using zkSNARKs" (`verifyevals.tex`, §`sec:verifyevals`).
- **Core construction** (`verifyevals.tex` §"System Design", lines 70-92):
  - `Setup(1^λ, W, f) -> (pk, vk)` — circuit derived from the ONNX graph
    with weights $W$ as private inputs (line 73).
  - `Prove(pk, W, x, y) -> π ⊃ {H(W), y}` — proof commits to (i) the
    input/output pair, (ii) the **model weight hash $H(W)$** computed via
    *ZKG hashing* of weights per `ezkl2023zerooverheadhashing`
    (`verifyevals.tex` §"Flexible Model Setup", line 311).
  - Aggregation options (§`sec:aggregation`, lines 94-103): naive bundling,
    vanilla aggregation circuit, or *custom Halo2 aggregation circuit*
    producing a single attestation of a metric (accuracy, confusion
    matrix). The thesis flags that "this zero-knowledge aggregation step
    makes sense when posting model inferences to a blockchain" (line 101).
- **Figure `fig:fullsystem`** (`verifyevals.tex` line 82, `zkbc_diagram.png`)
  — ONNX → setup → $(pk, vk)$ → per-inference $\pi$ → aggregated attestation
  → later inferences checked against $H(W)$.
- **Figure `fig:scaling`** (`verifyevals.tex` line 157, `model_size_archon_may17th.pdf`)
  — proof time and RAM scale near-linearly with constraint count for MLP/CNN/Attn.
- **"Predict, then prove"** strategy (`verifyevals.tex` §"Scalability in
  production", lines 58-64; restated §"Proving later", line 245) — the
  witness $(x, y, H(W))$ is generated cheaply at inference time and the
  proof is finalized later (seconds to minutes).
- **Threat models** (`verifyevals.tex` §"Detailed Threat Model",
  lines 231-241): TM#1 — provider lies about a benchmark; TM#2 — provider
  swaps the model at inference. TM#2 requires a per-inference proof with
  matching $H(W)$.
- **Trusted setup** (`verifyevals.tex` §`sec:trustedsetup`, line 254-256):
  *Perpetual Powers of Tau ceremony* (`nikolaenko2024powers`) for the
  Halo2/KZG SRS — secure as long as a single contributor discards their
  toxic waste.
- **Security properties verbatim** (`verifyevals.tex` §"Security
  Properties", line 249): **correctness**, **soundness**, **confidentiality
  of the model weights**, **integrity**, **non-repudiation**,
  **succinctness**, **non-interactivity**.

## 2. Current GLYPH State

GLYPH today **does not prove ML inference**. The intent layer
(`tee-worker/src/types.rs` `TransactionIntent`, `docs/architecture.md`
§3.1) assumes the agent's LLM is already trusted: an agent produces a
`TransactionIntent` and signs it Ed25519, and the worker reasons only
about the *intent payload*, not about which model produced it.

The existing RISC Zero circuit (`circuits/glyph-circuit/guest`) proves
**policy execution over the intent**, not model inference. Public inputs
bind `policy_commitment`, `intent_hash`, `agent_pubkey`, `nonce`,
`tx_hash` (`tee-worker/src/prover.rs`) — there is no `model_hash` and no
$(x, y)$ commitment.

In short: GLYPH cryptographically anchors *what the policy decided*. It
does not anchor *which model produced the intent*. The thesis's TM#2
gap is open by design in v1.

## 3. Proposed Integration

Extend the protocol so the intent optionally carries an evaluation
commitment and a proof of inference. **Two integration modes**, each
mapping to one of the thesis's modes (challenge-after vs every-inference):

### Mode A — Challenge-After (predict-then-prove registry)

The on-chain verifier **does not check** inference proofs. A separate
off-chain `evals/` registry stores $(x_i, y_i, \pi_i)$ triples plus the
verification key for each model registered against an agent. An auditor
can challenge an agent post-hoc by submitting $(x^*, y^*, \pi^*)$ for
verification against the registered $H(W)$, mirroring `verifyevals.tex`
§`sec:challenge` lines 267-274. This is the cheap path: the on-chain
contribution is just storing `model_hash_commitment` so an auditor knows
*which model* to challenge.

### Mode B — Inline Proof (every-inference)

Every intent carries a fresh `model_eval_proof` proving the LLM produced
$y$ from $x$ on a model with hash $H(W)$. The on-chain verifier checks
**both** the GLYPH policy proof **and** the eval proof. This honours
TM#2 cryptographically but pays the full cost: ezkl proof generation
for transformer-scale models is currently 10s to minutes per inference
(`verifyevals.tex` Table `tab:examplemodels` line 137: nanoGPT prove
time = 2781 s per token, PK size = 219 GB).

## 4. Wire Format / API Surface

New optional fields on the `TransactionIntent`:

```rust
pub struct TransactionIntent {
    // ... existing fields ...
    pub model_hash_commitment: Option<[u8; 32]>,  // H(W) per ZKG hashing
    pub model_eval_proof: Option<Vec<u8>>,        // Mode B; absent in Mode A
    pub eval_commitment: Option<EvalCommitment>,  // input/output bindings
}

pub struct EvalCommitment {
    pub model_hash: [u8; 32],
    pub input_hash: [u8; 32],      // SHA-256(quantized x)
    pub output_hash: [u8; 32],     // SHA-256(quantized y)
    pub proof_blob_uri: String,    // off-chain pointer (IPFS / S3) for Mode A
}
```

Off-chain canonicalization for the eval commitment:

```text
SHA-256(
  "GLYPH:EVAL:v1:"            (15 bytes ASCII)
  ‖ model_hash                (32 bytes)
  ‖ input_hash                (32 bytes)
  ‖ output_hash               (32 bytes)
  ‖ proof_blob_uri_len (u32)  (4 bytes BE)
  ‖ proof_blob_uri_utf8       (variable)
)
```

New PDA `ModelRegistry` (off-chain initially, on-chain in v3):

```rust
pub struct ModelRegistry {
    pub model_hash: [u8; 32],          // H(W)
    pub vk_uri: String,                 // Halo2 verification key location
    pub onnx_manifest_uri: String,      // optional ONNX architecture pin
    pub srs_ceremony: u8,               // 0 = Perpetual Powers of Tau, 1 = …
    pub registered_at: i64,
}
```

## 5. Implementation Plan / Workstream

- **Owner:** new sub-project `glyph-evals/`. Likely a **v3+ deliverable**.
- **Phases:**
  1. **`glyph-evals/` scaffolding**: vendor ezkl as a Rust dependency;
     stand up an off-chain prover service that takes ONNX + weights and
     emits a $(pk, vk)$ pair plus the ZKG weight hash.
  2. **Mode A registry**: build the off-chain `evals/` registry as an
     append-only IPFS/S3 store keyed by `(agent_pubkey, model_hash)`,
     with an auditor CLI that fetches $(x, y, \pi, vk)$ and runs
     `ezkl verify` locally.
  3. **TS SDK changes**: extend the intent builder so a producer can
     optionally attach `model_hash_commitment` (Mode A) and
     `eval_commitment.proof_blob_uri`.
  4. **Mode B on-chain verifier path**: add a second `alt_bn128`
     pairing call (Halo2 → BN254-compatible aggregation) gated behind a
     feature flag in `programs/glyph-verifier/src/verify_and_execute.rs`.
     The compute-unit budget for Solana is the binding constraint here;
     aggregation circuits (per `verifyevals.tex` §`sec:aggregation`)
     reduce many inference proofs to one — likely required for Solana.
  5. **`predict-then-prove` worker mode**: the TEE worker submits the
     intent immediately and asynchronously triggers a proof job; the
     proof is settled into the registry within a configurable window.

## 6. Risks & Trade-offs

- **Proof generation cost.** Per `verifyevals.tex` Table
  `tab:examplemodels` (line 137) and `fig:scaling` (line 157), ezkl
  proof time is near-linear in $n_{con}$. Transformer-scale models
  (nanoGPT: 9.4M constraints, 2781 s per inference, 219 GB PK) are not
  viable for Mode B on Solana today. Aggregation circuits and proof
  splitting (`verifyevals.tex` §`sec:speedup` lines 391-400) are the
  thesis's named mitigations; GPU acceleration
  (`sun2024zkllm`, `ezkl2023gpu`) is the named hardware path.
- **Trusted setup ceremony.** The Halo2 KZG SRS requires the Perpetual
  Powers of Tau ceremony (`verifyevals.tex` §`sec:trustedsetup` line 255).
  GLYPH would need to either use the existing community SRS or
  participate in a fresh round. Toxic-waste assumption is documented in
  the threat model — *as long as a single contributor discards their
  toxic waste, the SRS is secure*.
- **Quantization accuracy gap.** ezkl operates over fixed-point
  arithmetic with calibration (`verifyevals.tex` §`sec:setup` line 309).
  The witness $(\tilde{x}, \tilde{y})$ can differ from the true model
  output by a few percent — agents/auditors must agree on accuracy
  bounds out-of-band.
- **Implicit architecture leak.** Per `verifyevals.tex` line 54: even
  with private weights, "the general architecture of the model (e.g.,
  whether it is a CNN or transformer) will be implicitly leaked in the
  current proof system" via the constraint table shape.
- **Solana compute-unit budget.** A single Halo2/BN254 verification
  inside Solana costs several hundred thousand CUs. Mode B requires
  aggregation, a relay account, or off-chain verification with on-chain
  attestation — the v3 design must pick one.
- **Benchmark-gaming attack.** `verifyevals.tex` §"Security Limitations"
  line 258 notes that a provider can game the benchmarks: "a model
  developer 'gamed' the system by overfitting on the benchmarks". GLYPH
  inherits this limitation — the system attests that *this model
  produced this output*, not that *this model is good*.
- **Unspecified in thesis; GLYPH proposes:** the on-chain commitment
  format (the thesis only specifies $H(W)$ and proof contents; the
  payload-prefix scheme `GLYPH:EVAL:v1:` is GLYPH-side canonicalization
  to keep the on-chain hash domain-separated from policy/intent hashes).
