# Integration: zkTax-style Portable Data (TDS-Anchored Redact-and-Prove)

Out-of-scope integration design for GLYPH v1. Binds agent intents to a
trusted data source so the agent's claims about external state become
cryptographically anchored.

## 1. Paper Reference

- Tobin South, *Private, Verifiable, and Auditable AI Systems*
  (arXiv:2509.00085), Chapter 2 §"Portable data using zkSNARKs"
  (`zktax.tex`, §`sec:zktax`).
- **Three-service model** (`zktax.tex` §"Three-Service Model",
  lines 41-46):
  1. **Trusted Data Source (TDS)**: signs $H(x)$ with its private key,
     returning $(x, S)$ where $S = \text{sign}(sk, H(x))$.
  2. **Redact & Prove Service**: a ZK circuit consumes $(x, S)$ and a
     redaction/transformation specification, proves that $x' =
     \text{redact}(x)$ is consistent with the TDS-signed original,
     emitting $(x', \pi_{x'})$.
  3. **Verification Service**: given the TDS public key, the redacted
     data $x'$, the proof $\pi_{x'}$, and the signature $S$, anyone can
     verify validity.
- **Figure `fig:diagram_3services`** (`zktax.tex` line 51,
  `diagram_3services.png`) — Alice retrieves signed data from the TDS,
  brings it to Redact & Prove, then anyone uses the Verify Service to
  check authenticity.
- **Example workflow `zkTax`** (`zktax.tex` §"Example Workflow: zkTax",
  lines 54-59): the tax authority signs $x$; the taxpayer hides fields
  and proves *"My reported charitable contributions exceed \$X"*; a
  verifier checks $(x', \pi_{x'}, S)$ against the TDS public key.
- **AI training-data extension** (`zktax.tex` §`sec:ai`, lines 61-67):
  a model developer or AI consortium serves as TDS for a pretraining
  manifest; proofs over the manifest establish copyright compliance,
  bias bounds, or licensing claims.
- **Critical caveat — root of trust** (`zktax.tex` §"Implementation
  Considerations / Security assumptions", lines 73-75): *"trust also
  depends on the TDS accurately representing the original data. If the
  TDS itself publishes incorrect or incomplete data, the proofs will be
  valid relative to that original but not necessarily reflect
  real-world truth."* And from `PAPER_BRIEF.md` §2.3 (verbatim from
  `zktax.tex`): **"the ZK proof attests only to the transformation, not
  the ground-truth authenticity of the data; that authenticity comes
  from the root of trust (TDS signature, hardware attestation, or VC
  issuer)."**
- **Cross-reference**: `chapter-5.tex` §1 "Root of Trust" explicitly
  names TEE attestation, signed VC, and signed manifest as the
  three families of roots that anchor downstream ZK proofs. zkTax is
  the canonical example of the "signed manifest" family.

## 2. Current GLYPH State

GLYPH agent intents are **not bound to any data source**. An agent can
construct a `TransactionIntent` containing arbitrary `action.data` and
policy-driving claims (`max_lamports`, `allowed_tokens`,
`max_slippage_bps` in `tee-worker/src/types.rs`) with no requirement
that any of those numbers be anchored to externally signed data. The
policy engine checks structural well-formedness and the worker checks
the agent's Ed25519 signature — but the agent can lie about *what the
world looks like* with impunity.

Concrete gap: an agent can claim "my user's bank balance is at least
50 SOL, therefore this transfer is within policy" and GLYPH has no way
to verify that claim. The closest existing primitive is the
`AgentRegistry`'s `attestation_hash` (CPU TEE attestation only —
attests to the worker's code, not to any external data the worker
consumed).

## 3. Proposed Integration

Extend the `TransactionIntent` with an optional `data_provenance` field
binding the intent to one or more TDS-signed external facts. The flow:

1. **TDS registration (on-chain)**. Each known TDS (a tax authority, a
   bank's signed-statement service, an AI consortium publishing
   training-data manifests, a credit-bureau-style oracle) registers its
   public key in a new on-chain `TDSRegistry` PDA, paired with a
   monotonically increasing trust score and a human-readable label.
2. **Redact & Prove (off-chain)**. The agent (or its user) takes the
   signed source data $(x, S)$ from a TDS, runs the redact-and-prove
   service to produce $(x', \pi_{x'})$ where $x'$ contains only the
   fields the policy needs. For example, "balance $\geq$ N" rather
   than the full bank statement.
3. **Intent construction**. The agent embeds
   `DataProvenance { tds_pubkey, original_hash, redaction_proof }` into
   the intent. The TEE worker (and optionally the on-chain verifier)
   checks the proof against the registered TDS public key before
   accepting policy-relevant claims derived from $x'$.
4. **Policy integration**. The policy DSL gains primitives that
   reference provenance-bound facts. Example new rule:
   `require_provenance_for_balance_assertion = true` — when a policy
   rule depends on an external fact (e.g., a user's account balance),
   the intent **must** carry a valid `DataProvenance` whose redacted
   $x'$ contains the asserted value. Without it the worker rejects.

This composes naturally with **PRAG** (`prag-mpc-retrieval.md`): the
PRAG-retrieved documents become the $x$ that the TDS (the document
publisher) had signed earlier, allowing private retrieval *and*
authenticity attestation in the same pipeline.

## 4. Wire Format / API Surface

```rust
pub struct DataProvenance {
    pub tds_pubkey: [u8; 32],          // Ed25519 / BLS pubkey of the TDS
    pub original_hash: [u8; 32],       // H(x) — the TDS-signed digest
    pub tds_signature: [u8; 64],       // S = sign(sk_TDS, H(x))
    pub redacted_hash: [u8; 32],       // H(x')
    pub redaction_proof: Vec<u8>,      // π_{x'}
    pub circuit_id: [u8; 32],          // identifies the redact-and-prove circuit
}

pub struct TransactionIntent {
    // ... existing fields ...
    pub data_provenance: Option<DataProvenance>,
    // for compound claims, future extension: Vec<DataProvenance>.
}
```

New on-chain PDA, mirroring `AgentRegistry`:

```rust
pub struct TDSRegistry {
    pub tds_pubkey: [u8; 32],
    pub label: [u8; 32],                // ASCII, e.g. "us-irs-zktax-v1"
    pub trust_score: u16,               // 0..=10000, owner-curated
    pub circuit_allowlist: Vec<[u8;32]>, // approved redact-and-prove circuit IDs
    pub registered_at: i64,
    pub status: u8,                     // Active / Revoked
}
```

Off-chain canonicalization for `data_provenance`:

```text
SHA-256(
  "GLYPH:PROV:v1:"          (15 bytes ASCII)
  ‖ tds_pubkey              (32 bytes)
  ‖ original_hash           (32 bytes)
  ‖ redacted_hash           (32 bytes)
  ‖ circuit_id              (32 bytes)
  ‖ redaction_proof_len u32 (4 bytes BE)
  ‖ redaction_proof_bytes   (variable)
)
```

This commitment becomes a new public input on the GLYPH policy circuit
(`circuits/glyph-circuit/guest`) alongside `policy_commitment` and
`intent_hash`. The on-chain verifier checks (a) `tds_pubkey` is in
`TDSRegistry`, (b) `tds_signature` is valid over `original_hash`, and
(c) `redaction_proof` verifies against the TDS-allowlisted circuit.

## 5. Implementation Plan / Workstream

- **Owner:** new sub-project `glyph-provenance/`. Separate from
  `glyph-evals/` because the proving system used here is typically
  Groth16/PLONK with smaller circuits (sig check + Merkle-style
  redaction) — different toolchain than ezkl. Composes with PRAG
  (`prag-mpc-retrieval.md`) at the retrieval layer.
- **Phases:**
  1. **Pilot circuit**: a single redact-and-prove circuit for a fixed
     schema (e.g., a JSON bank-statement-like record) that proves
     "field $f$ $\geq$ threshold" without revealing the full record.
     Use the `circom` toolchain or `noir` — both have Groth16 backends
     compatible with Solana's `alt_bn128` syscalls.
  2. **`TDSRegistry` PDA**: implement registration / revocation /
     trust-score update by a multisig owner; document the upgrade
     path for adding new TDS keys.
  3. **TEE worker integration**: extend `tee-worker/src/policy.rs` so
     that specific policy rules can declare "this rule requires a
     valid `DataProvenance` covering field X" — a new rule kind
     parallel to the existing 8 deterministic rules.
  4. **TS SDK changes**: add a `DataProvenance` builder and a thin
     client for the off-chain Redact & Prove Service.
  5. **PRAG composition (later)**: align the TDS-signed-manifest
     pattern with PRAG-retrieved documents so the same proof anchors
     both retrieval correctness and document authenticity.
- **Dependency note:** this workstream is largely independent of
  `verifiable-ml-evals.md` / `partial-zk-selective-proving.md`. It can
  ship before or after them and addresses a different threat (lying
  about external state, not lying about model behavior).

## 6. Risks & Trade-offs

- **TDS as root of trust (`zktax.tex` lines 73-75).** The thesis
  explicitly notes that "the ZK proof attests to transformation, not
  authenticity — authenticity comes from TDS root signature". GLYPH
  inherits this entirely: a compromised or dishonest TDS produces
  cryptographically-valid-but-semantically-false attestations. The
  `TDSRegistry.trust_score` and curated `circuit_allowlist` are
  governance controls, **not** cryptographic ones.
- **TDS key compromise.** From `zktax.tex` §"Security assumptions"
  line 74: *"security relies on the TDS's private key remaining
  uncompromised"*. The on-chain registry supports revocation, but past
  intents anchored to a now-revoked TDS pubkey remain on-chain — the
  policy must consider TDS revocation timestamps when interpreting
  historical provenance.
- **TDS bootstrapping is hard.** Few real-world TDSs publish signed
  data today. `zktax.tex` §"Trusted digital infrastructure" cites
  Mexico's PKI for tax filings (`mexicoPKI`) and Estonia's e-government
  ecosystem and Open Banking (`openbanking`) — but in practice GLYPH
  will need to operate with synthetic/proxy TDSs (e.g., a custodian
  bank running a signing oracle) for early deployments. Be honest about
  this in the registry's `label` field.
- **Circuit-allowlist governance.** Allowing arbitrary redact-and-prove
  circuits opens an attack surface: a maliciously-constructed circuit
  could "redact" $x$ in a way that lets the prover sneak an unsigned
  value past the verifier. The `TDSRegistry.circuit_allowlist` mitigates
  this — each TDS pins which circuits are trusted to operate on its
  signed data. Removing a circuit from the allowlist is a governance
  action with a documented review process (multisig + timelock,
  mirroring the VK update path).
- **Replay across redactions.** Two intents from the same agent could
  reference the same TDS signature on $H(x)$ but redact differently
  ($x'_1$ vs $x'_2$). The intent-level nonce already covers replay of
  the same intent, but policy logic must explicitly account for the
  fact that *one signed $x$ can ground many derived claims*.
- **Privacy leakage from `redacted_hash`.** Posting $H(x')$ on-chain
  leaks a deterministic fingerprint of the redacted payload — two
  agents redacting the same way will collide. This is acceptable for
  most use cases but should be flagged for high-privacy deployments;
  a salted commitment is a v2 option.
- **Unspecified in thesis; GLYPH proposes:** the on-chain
  `TDSRegistry`, the `circuit_id` allowlisting, and the trust-score
  parameter. The thesis (`zktax.tex` §"Modular design", line 72) says
  *"Different Redact & Prove solutions can then be developed by
  private organizations or open-source communities"* but does not
  specify a discovery, governance, or revocation mechanism — GLYPH
  fills that gap.
- **Inter-doc composition.** This doc composes with
  `prag-mpc-retrieval.md` (PRAG retrieval surfaces the document, zkTax
  proves authenticity), with `oidc-vc-delegation.md` (a delegation
  token can itself be a TDS-signed object), and with
  `verifiable-ml-evals.md` (the model's *training data* can be
  anchored via a zkTax-style manifest per `zktax.tex` §`sec:ai`).
