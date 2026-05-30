# Integration: ORAM for TEE Memory-Access Side-Channel Mitigation

Out-of-scope integration design for GLYPH v1. Tracks paper alignment for
the side-channel hardening of the policy-evaluation step.

## 1. Paper Reference

- Tobin South, *Private, Verifiable, and Auditable AI Systems*
  (arXiv:2509.00085), Chapter 3 §"Trusted execution environments (TEEs)
  for private data management and RAG" (`communitytrans.tex`):
  - §"The Role of the TEE" (lines 41-49) — TEEs *mitigate* memory-access
    side channels when the working set fits in enclave memory.
  - §"The Role of the TEE" continues (line 49): *"For larger datasets
    exceeding enclave memory limits, techniques like Oblivious RAM
    (ORAM) could be integrated (considered future work) to obscure
    access patterns, albeit with performance overhead."*
- Thesis cite `jean2023sgxonerated` (SGX-ONERATED) — concrete
  demonstration that SGX without ORAM leaks access-pattern information.

External grounding (verify before implementing):
- Stefanov et al., *Path ORAM* (CCS 2013, doi 10.1145/2508859.2516660) —
  the standard construction.
- Ren et al., *Ring ORAM* (USENIX Security 2015) — lower bandwidth.
- Wang et al., *ZeroTrace* (NDSS 2018) — Path-ORAM hardened against
  SGX-specific side channels.

## 2. Current GLYPH State

The TEE worker (`tee-worker/src/policy.rs`) holds the unsealed policy as
**plaintext in enclave memory**. `PolicyEngine::evaluate(intent)` walks an
8-rule chain (`tee-worker/src/policy.rs`, methods `check_allowed_programs`,
`check_max_lamports`, `check_max_slippage_bps`, etc.) and short-circuits
on the **first matching deny**. An adversary with a cache-side-channel
or page-fault trace against the host can therefore *learn which rule
fired* even though they cannot read the rule contents.

This is the textbook SGX-ONERATED scenario: confidentiality of contents
without obliviousness of access patterns.

For GLYPH's current 8-rule DSL (documented in `docs/policy-dsl.md`) the
leak is small — at most 3 bits of side-channel-recoverable rule index
per intent. But for any future expansion (per-allowed-token tables,
per-allowed-program ACLs growing to dozens or hundreds of entries) the
leak becomes meaningful.

## 3. Proposed Integration

Add an **opt-in Path-ORAM client** layered between `PolicyEngine` and the
policy-store. The TEE worker becomes a Path-ORAM client; rule
evaluation reads via `oram.read(block_id)` instead of direct memory
access. The eviction path is uniform across all rule branches.

Key design decisions:

1. **Granularity:** one ORAM block per *policy field* (one block for
   `allowed_programs`, one for `allowed_tokens`, …). Bucket size tuned to
   the largest field.
2. **Recursive position-map:** standard Path-ORAM technique — keep the
   position map outside the enclave too, recursively ORAM-protected.
3. **Stash kept in enclave memory** (the only part that *must* be in
   sealed memory to retain Path-ORAM's security argument).
4. **Constant-time evaluator:** the 8-rule engine is rewritten as a
   data-oblivious sequence — every rule reads the same blocks in the
   same order regardless of intent.

This is internal to the worker; nothing on-wire changes.

## 4. Wire Format / API Surface

Not on-wire — entirely internal to the worker. The new component is a
crate `tee-worker/src/oram/` exposing:

```rust
pub trait OramClient {
    fn read(&mut self, block_id: u64) -> [u8; ORAM_BLOCK_SIZE];
    fn write(&mut self, block_id: u64, data: [u8; ORAM_BLOCK_SIZE]);
}

pub struct PathOramClient<B: BlockStore> { /* … */ }
```

with a feature flag:

```toml
[features]
tee-worker-oram = ["dep:path-oram"]   # opt-in, off by default
```

`PolicyEngine::evaluate` gains a sibling
`PolicyEngine::evaluate_oblivious` selected by the feature flag.

## 5. Implementation Plan / Workstream

- **Owner:** TEE worker maintainer. Defer to **v3** — explicitly out of
  scope for v1 and v2.
- **Phases:**
  1. Bench the current 8-rule engine for end-to-end intent latency
     (target baseline: current `tee-worker/benches/` if present, else
     add one). Document the side-channel-leak surface as the motivation.
  2. Land a no-op `OramClient` trait + plaintext implementation. Switch
     `PolicyEngine::evaluate_oblivious` over with the feature flag.
  3. Integrate a vetted Path-ORAM crate (audit candidates: a fresh
     `path-oram` Rust port or wrap ZeroTrace via FFI — both will need
     security review).
  4. Rewrite policy evaluation as a data-oblivious sequence (each rule
     reads its block; no branch on rule-internal data; constant-time
     comparators throughout).
  5. Benchmark under realistic intents — published Path-ORAM overhead
     is **typically 10×-100× slowdown** depending on block size and
     tree depth. Re-evaluate whether the side-channel threat justifies
     the cost.
- **Out of scope:** ORAM over the on-chain `policy_commitment` — that
  commitment is public by design.

## 6. Risks & Trade-offs

- **Cost may exceed the threat.** Today's DSL is small (8 rules,
  documented in `docs/policy-dsl.md`); side-channel-recoverable bits
  per intent are bounded. Path-ORAM's 10×-100× slowdown likely
  prohibitive until the DSL grows.
- **Implementation complexity.** Path-ORAM is correct only when the
  *entire access pattern* is oblivious, including the position-map
  lookups and stash management. A single non-oblivious branch in the
  rewritten evaluator silently breaks the security argument. This
  demands formal review, ideally with a constant-time verifier such
  as `cargo-side-channel` or manual `cmov`-equivalent inspection.
- **SGX-specific hardening required.** Vanilla Path-ORAM does not
  defend against the full SGX side-channel zoo (page faults, branch
  predictor, etc.). ZeroTrace-style hardening is necessary for SGX
  deployments; Nitro and SEV have different (often weaker) attacker
  models and may need different mitigations.
- **Stash overflow.** Path-ORAM admits a small probability of stash
  overflow per access; the worker must handle that gracefully (refuse
  the intent or retry with re-shuffle) — a denial-of-service vector
  if the attacker can trigger overflows by carefully chosen access
  patterns.
- **Overkill for the current threat model.** GLYPH already treats the
  host OS / hypervisor as untrusted (`docs/architecture.md` §5
  Boundary B). For semi-honest adversaries — the thesis' own threat
  model — memory-encryption + attestation are already sufficient. ORAM
  is a defense against a stronger adversary that GLYPH does not
  currently model.
