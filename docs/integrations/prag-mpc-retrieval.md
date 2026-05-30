# Integration: PRAG — Private Retrieval-Augmented Generation

Out-of-scope integration design for GLYPH v1. Tracks paper alignment for
the upstream-retrieval layer that may feed agent intents.

## 1. Paper Reference

- Tobin South, *Private, Verifiable, and Auditable AI Systems*
  (arXiv:2509.00085), Chapter 3 §"Private retrieval augmented generation"
  (`PRAG.tex`):
  - §"Overview and Trust Model" (lines 46-54): *"we assume that all
    parties in the system are semi-honest… and that at most
    $t < n_{servers}/2$ of the servers are corrupt (the honest majority
    setting)."*
  - §"Exact MPC Tools" (lines 57-66): Shamir secret sharing over
    $\mathbb{F}_p$; Damgård-Nielsen multiplication; tree-reduction
    argmax for exact top-k.
  - Figure `fig:pragdiagram` (`PRAG.tex` line 38) — distributed
    secret-shared inverted file index.
  - Cross-reference: thesis Chapter 5 *"Holographic graph logs"* —
    PRAG's per-retrieval event is one of the named attestation links.

Companion paper cite from the thesis: South, Zyskind, Mahari, Pentland,
*Private Retrieval Augmented Generation* — implementation built on
CrypTen.

## 2. Current GLYPH State

GLYPH **does not perform retrieval**. It is the delegation, policy, and
on-chain-verification layer; the agent that emits a `TransactionIntent`
is responsible for its own RAG (if any). The repo has no vector DB, no
embedding pipeline, and no MPC primitives.

The only "data source" hash on the on-chain side is the
`policy_commitment` (`programs/glyph-verifier/src/state.rs`) — there is
no slot for binding a retrieval event to an intent.

This is intentional: PRAG is a multi-server MPC protocol whose trust
assumptions (honest majority, semi-honest) are orthogonal to GLYPH's
single-TEE + on-chain-verifier model.

## 3. Proposed Integration

Treat PRAG as an **external attested service**. GLYPH does not run the
MPC; it accepts a retrieval-attestation hash as evidence that retrieval
was performed by a known PRAG cluster.

1. The agent (off-chain) interacts with a PRAG cluster `(s_1, …, s_n)`
   under the honest-majority assumption.
2. The cluster returns top-k document tokens **and** a per-retrieval
   attestation — either a threshold signature over the
   `(query_hash, server_ids, t, n, top_k_hash)` tuple (using FROST per
   the thesis' threshold-governance recommendation in `communitytrans.tex`)
   or a small ZK proof of correct MPC execution.
3. The agent canonicalizes that attestation into a 32-byte hash and
   carries it on the `TransactionIntent`.
4. The TEE worker verifies the threshold signature off-chain against a
   registered PRAG-cluster public key; the on-chain side stores only
   the hash binding for audit (Chapter 5 "chains of cryptographic
   hashes linked each step").

This keeps the MPC entirely out of band — GLYPH only ratifies that *a*
PRAG retrieval occurred and binds it to the intent.

## 4. Wire Format / API Surface

Extend `TransactionIntent` (off-chain canonicalization):

```rust
pub struct TransactionIntent {
    // … existing fields …
    pub retrieval_attestation: Option<[u8; 32]>, // SHA-256 of canonical retrieval bundle
}
```

Canonical retrieval-attestation bundle (off-chain):

```text
"GLYPH:PRAG-RET:v1:"     (18 bytes ASCII)
‖ cluster_id              (32 — SHA-256 of sorted server pubkeys)
‖ query_hash              (32 — SHA-256 of query embedding canonical bytes)
‖ top_k_hash              (32 — SHA-256 of returned doc tokens, canonical order)
‖ t                       (1 byte — threshold)
‖ n                       (1 byte — total servers)
‖ threshold_signature     (variable — FROST/Ed25519 threshold signature)
```

The SHA-256 of these concatenated bytes IS `retrieval_attestation`.

A new sidecar service `glyph-prag-adapter/` exposes:

- `POST /retrieve { query_embedding } -> { top_k_docs, attestation_bundle }`
  — multiplexes onto a configured PRAG cluster.
- `POST /verify { attestation_bundle } -> { ok, cluster_pubkey, top_k_hash }`
  — verifies the threshold signature and returns the canonical hash.

The TEE worker registers `(cluster_id, cluster_aggregate_pubkey)` in a
local trust store; intent verification fails if `retrieval_attestation`
is present but the cluster is unknown.

## 5. Implementation Plan / Workstream

- **Owner:** `glyph-prag-adapter/` — separate service, fully out of scope
  for v1.
- **Phases:**
  1. Define the canonical bundle format and ship as a no-op
     `retrieval_attestation: None` field — purely a slot. Forward-compat.
  2. Build a mock PRAG cluster (3-of-5 servers) that returns canned
     responses and emits FROST threshold signatures.
  3. Integrate the upstream PRAG / CrypTen reference implementation
     (Python; bridge via gRPC). This is heavyweight and the cite is
     research-grade code — production hardening is a major project.
  4. Optionally produce a ZK proof of MPC correctness (a la
     Collaborative SNARKs / Ozdemir-Boneh 2022) instead of a threshold
     signature. Much harder; treated as v4.
- **Defer:** the data-owners-pre-share-data bootstrapping problem. The
  thesis explicitly punts on this: *"we do not focus on the data owners
  privately building the server"* (PRAG.tex line 53).

## 6. Risks & Trade-offs

- **Honest-majority assumption is strong.** PRAG security collapses if
  $\geq n/2$ servers collude or are compromised. GLYPH's on-chain
  attestation only proves the cluster *signed off*, not that the
  honesty assumption held. Operators must publish cluster-membership
  audits.
- **Semi-honest only.** The thesis is explicit: parties follow the
  protocol (PRAG.tex line 53). A malicious server can return wrong
  results while still producing a valid threshold signature. Upgrading
  to malicious security (e.g., SPDZ-style MACs) is an open research
  problem in this regime.
- **Performance.** PRAG's published numbers are sublinear *server-side*
  communication but still seconds-to-tens-of-seconds end-to-end for
  $10^6$-scale DBs. This is too slow for real-time agent execution and
  must be cached or moved off the critical path.
- **GLYPH's gap-bridging is shallow.** PRAG's threat model (multi-server
  honest majority) is fundamentally different from GLYPH's (single TEE
  + on-chain verifier). Binding a PRAG hash into an intent provides
  *audit* but does not *strengthen* GLYPH's security — it only ensures
  that if PRAG was used, the choice is recorded.
- **Cluster pubkey rotation.** FROST allows resharing without rotating
  the aggregate pubkey, but membership changes still require operator
  coordination. The on-chain `cluster_id` should be derivable from
  membership; spec a versioned cluster-id when membership changes.
- **Out of scope for v1.** GLYPH does not need PRAG to ship its core
  proposition (verifiable agent delegation on Solana). This integration
  exists to leave room for a v3 audit-trail story.
