# Integration: Partial ZK — Selective Layer Proving (LoRA / Classifier-Head)

Out-of-scope integration design for GLYPH v1. Extends the Mode B path of
`verifiable-ml-evals.md` with the thesis's partial-proving optimization.

## 1. Paper Reference

- Tobin South, *Private, Verifiable, and Auditable AI Systems*
  (arXiv:2509.00085), Chapter 2 §"Verifiable computation of partial AI
  systems" (`partialzk.tex`).
- **Core insight** (`partialzk.tex` lines 22-28): when only part of a
  model's weights are private, you can selectively prove only those
  parts in ZK, using intermediate public inputs/outputs to bridge the
  public backbone. *"If all the model weights (W) are private, then you
  must run a full model computation. However, if only part of the
  model's weights are private, then you can selectively prove these
  with zero-knowledge of the private weights, and use intermediate
  public inputs and outputs to rerun any needed computations for the
  public portions of the model."* (lines 24-27).
- **Three topologies** (`partialzk.tex` §`c2:fig:partial-zk`, line 21):
  - **Full model**: prove the full $Wx$ (the expensive Mode B from
    `verifiable-ml-evals.md`).
  - **LoRA-tuned model**: prove only $BAx$, the LoRA adapter side
    computation, then combine with the public backbone $W$ — *"prove
    these with zero-knowledge of the private weights"* (line 28).
  - **Fine-tuned head**: prove only the classifier head $HWx$ on top
    of a public pretrained backbone.
- **Threat — adapter reconstruction** (`partialzk.tex` lines 29-30):
  *"model weights can be reconstructed from the public input-output
  pairs if there are a sufficient number of pairs across the full
  distribution of inputs. While retraining weights is hard, its
  difficulty (and demand for data) scales with the number of parameters
  being tuned. In the same way that LoRA makes fine-tuning more
  efficient, and proof computations faster, it also makes this threat
  more feasible."* This is the documented privacy/efficiency trade-off
  and must be flagged in any deployment.
- **Cross-reference**: `verifyevals.tex` §"Security Limitations" line
  258 (benchmark gaming) and §"Detailed Threat Model" line 231 both
  apply transitively — partial ZK inherits both threat models from the
  full-model construction.
- **Figure `c2:fig:partial-zk`** (`partialzk.tex`, `LoraFT.pdf`) — three
  fine-tuning topologies and which weights need to enter the ZK circuit.

## 2. Current GLYPH State

Same as `verifiable-ml-evals.md` §2: GLYPH today proves no ML inference.
There is no `model_hash`, no $(x, y)$ commitment, no slice commitment.
The TEE worker's policy circuit (`circuits/glyph-circuit/guest`) is
entirely model-agnostic.

## 3. Proposed Integration

Extends `verifiable-ml-evals.md` **Mode B**. Rather than proving the
full model, the intent's `model_eval_proof` covers only a **private
slice** of the model. The public backbone runs in the clear; the verifier
checks (a) the slice proof, (b) that the public backbone matches the
registered backbone hash, (c) that the input/output pair is consistent
across the public-public-private composition.

Three concrete topologies, matching the thesis figure:

1. **`FullModel`** — degenerate case; equivalent to
   `verifiable-ml-evals.md` Mode B.
2. **`LoraAdapter`** — the proof covers $BAx$ for each layer where a
   LoRA adapter is attached. The public backbone $W$ is identified by
   `backbone_model_hash`; the slice (the LoRA $B$ and $A$ matrices) is
   identified by `slice_commitment`. Per-layer adapter outputs are
   public inputs to the next layer's public computation.
3. **`ClassifierHead`** — the proof covers $HWx$ at the model's final
   linear layer(s). The pretrained backbone runs publicly; only the
   classifier head's weights are private.

The agent/prover declares which topology applies at registration time,
and the on-chain `ModelRegistry` (introduced in `verifiable-ml-evals.md`
§4) stores both the backbone hash and the slice kind.

## 4. Wire Format / API Surface

New struct, replacing the simpler `EvalCommitment` when partial proving
is in effect:

```rust
pub struct PartialEvalCommitment {
    pub backbone_model_hash: [u8; 32],   // H(W_public)
    pub private_slice_kind: SliceKind,
    pub slice_commitment: [u8; 32],      // H of the private slice's weights
    pub input_hash: [u8; 32],
    pub output_hash: [u8; 32],
    pub proof_blob_uri: String,
}

#[repr(u8)]
pub enum SliceKind {
    FullModel = 0,
    LoraAdapter = 1,
    ClassifierHead = 2,
    // Reserved: 3..=255 for future topologies (adapter-tuning, prefix-tuning, etc.)
}
```

The on-chain `TransactionIntent` carries this as a `Option<PartialEvalCommitment>`
in place of the simple `EvalCommitment`; the two are mutually exclusive
and a versioned tag (`GLYPH:EVAL:v2:` for partial vs `GLYPH:EVAL:v1:`
for full) keeps the canonicalization domain separated.

Off-chain canonicalization:

```text
SHA-256(
  "GLYPH:EVAL:v2:"               (15 bytes ASCII)
  ‖ slice_kind_u8                (1 byte)
  ‖ backbone_model_hash          (32 bytes)
  ‖ slice_commitment             (32 bytes)
  ‖ input_hash                   (32 bytes)
  ‖ output_hash                  (32 bytes)
  ‖ proof_blob_uri_len (u32 BE)  (4 bytes)
  ‖ proof_blob_uri_utf8          (variable)
)
```

Extension to `ModelRegistry`:

```rust
pub struct ModelRegistry {
    pub model_hash: [u8; 32],
    pub vk_uri: String,
    pub onnx_manifest_uri: String,
    pub srs_ceremony: u8,
    pub registered_at: i64,

    // NEW for partial ZK:
    pub backbone_hash: Option<[u8; 32]>,  // present iff slice_kind != FullModel
    pub default_slice_kind: SliceKind,    // SliceKind::FullModel for full
}
```

## 5. Implementation Plan / Workstream

- **Owner:** extends `glyph-evals/` (introduced in
  `verifiable-ml-evals.md` §5). The two docs ship together as a single
  workstream; partial-ZK is the *practical* deployment path, while the
  full-model path is the *cryptographically strongest* deployment path.
- **Phases:**
  1. **Backbone canonicalization**: define a stable serialization for
     publicly-known backbones (e.g., HuggingFace model ID + commit hash,
     or ONNX file SHA-256). Required so multiple agents can share a
     backbone hash and only register their private slices.
  2. **LoRA-aware prover**: extend the off-chain ezkl wrapper to accept
     a `(W_public, B, A)` triple and emit a proof of $BAx$ only.
     Per-layer composition lives in a host orchestrator; the ZK proof
     covers only the private side computation.
  3. **ClassifierHead-aware prover**: simpler variant; the backbone
     runs in the clear up to the penultimate layer, and the head's
     linear-transform proof is generated for the final activations.
  4. **Side-channel hardener**: implement a query-budget per
     `(agent_pubkey, slice_commitment)` so an adversary cannot trivially
     submit thousands of inputs to reconstruct a low-rank LoRA adapter.
     This budget lives off-chain in v3 and may be migrated to a PDA
     counter in v4.
  5. **Auditor tooling**: extend the `glyph-evals/` CLI to verify a
     partial proof by re-running the public backbone locally and
     checking that the prover's public inputs match the prover's
     intermediate activations.

## 6. Risks & Trade-offs

- **Side-channel reconstruction of the private slice
  (`partialzk.tex` lines 29-30).** The thesis explicitly flags that
  enough public input-output pairs let an adversary reconstruct a
  low-rank adapter — **and** that this attack becomes *more* feasible
  precisely because LoRA was designed for sample-efficient learning.
  Any GLYPH deployment using `SliceKind::LoraAdapter` must publish a
  query-budget policy and ideally rate-limit per `(agent, slice)`. This
  is a documented limitation, not a fixable cryptographic weakness.
- **Selective leakage of which slice was used.** Even with the slice
  itself hidden, `SliceKind` is published on-chain — an observer learns
  *that* the agent uses a LoRA adapter vs a classifier head. This is
  acceptable for most use cases (architectural transparency is already
  a thesis-level concession per `verifyevals.tex` line 54) but should
  be acknowledged.
- **Backbone-pinning attack.** If the registered `backbone_model_hash`
  points to a HuggingFace model that the owner can swap (yanked
  versions, mirror takeover), the entire chain of trust collapses. The
  off-chain `glyph-evals/` registry must pin backbones by content
  hash, not by URL — the on-chain `backbone_hash` is the source of
  truth.
- **Composition soundness.** The thesis sketches partial ZK at a high
  level but does not give a formal proof that
  (public-backbone) ∘ (ZK-private-slice) ∘ (public-tail) is sound under
  adversarial intermediate activations. **Unspecified in thesis; GLYPH
  proposes:** the prover commits to the public backbone's activation
  hashes (as public inputs into the slice circuit), and the verifier
  recomputes them locally. This binds the slice proof to a specific
  public-side execution and prevents an adversary from running a
  *different* backbone with a valid slice proof.
- **Aggregation across topologies is hard.** A naive aggregation
  circuit that handles `FullModel`, `LoraAdapter`, and `ClassifierHead`
  uniformly is not in the thesis. Per topology, a separate aggregation
  circuit will be needed if Mode B Solana posting is desired.
- **Inherits all `verifiable-ml-evals.md` risks** (trusted setup,
  benchmark gaming, quantization, compute-unit budget).
