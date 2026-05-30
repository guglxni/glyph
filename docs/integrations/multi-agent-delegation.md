# Integration: Multi-Agent Delegation Propagation

Out-of-scope integration design for GLYPH v1. Covers the
Alice→Bob inter-agent delegation pattern from the thesis.

## 1. Paper Reference

- Tobin South, *Private, Verifiable, and Auditable AI Systems*
  (arXiv:2509.00085), Chapter 4:
  - §4.3.4 paragraph *"Inter-agent scoping"*
    (`authenticated-delegation.tex` lines 409-416). Verbatim: *"Suppose
    that the user specifies the authorizations of an agent Alice. When
    Alice interacts with another agent, Bob, in natural language to
    perform a task, Bob can parse Alice's scoping instructions and
    interpret them in its own environment. By doing so, Bob can confirm
    that its assigned operations remain within the original scope, and
    provide an auditable receipt of the actions taken and the resources
    accessed."*
  - §4.1 *"Verification in multi-agent communication"* (lines 97-104)
    motivating mutual authentication between agents.
  - Chapter 5 (vignette in `chapter-5.tex`) on
    *"holographic graph logs… chains of cryptographic hashes linked each
    step"* — every delegation step adds an attestation to the audit
    chain.

The thesis sketches inter-agent delegation in **prose only**; concrete
scope-intersection semantics, revocation cascade rules, and audit-trail
format are unspecified. See `audit/PAPER_BRIEF.md` §6: *"Inter-agent /
multi-agent trust is sketched, not built."*

## 2. Current GLYPH State

`register_agent` (in `programs/glyph-verifier/src/lib.rs`, lines 772-841)
assumes a **flat, human→agent** model:

- `delegator_pubkey` is the human's Ed25519 key.
- `delegator_signature` covers the canonical payload (lib.rs
  `delegation_signing_payload`, lines 167-184).
- There is no notion of a *parent agent*; every agent is registered
  directly under a delegator.
- WS-6's `AuditAnchor` (lib.rs lines 72-86) anchors a per-agent Merkle
  root but knows nothing about cross-agent provenance.

## 3. Proposed Integration

Add **optional parent-agent fields** to `RegisterAgentArgs`, allowing an
already-registered agent (Alice) to act as the delegator for a child
agent (Bob). When set, the child's policy is **bounded by the
intersection** of its own declared policy and the parent's.

Semantics:

- **Identity.** If `parent_agent_pubkey` is `Some`, the registrar
  authority must be a key controlled by the parent agent's TEE worker
  (not a human). The `delegator_signature` is then over the same payload
  but signed by the parent agent's pubkey (which the on-chain registry
  already binds).
- **Scope intersection.** The child's `policy_commitment` is the SHA-256
  of `canonical_serialize(intersect(parent_policy, child_policy))`. The
  intersection is computed off-chain in the parent's TEE worker, where
  both policies are available in plaintext. The on-chain program does
  **not** re-derive the intersection; instead it hashes
  `(parent_policy_commitment, child_policy_commitment)` into a new
  combined commitment `derived_policy_commitment` and stores it on the
  child registry alongside the parent reference.
- **Revocation cascade.** Deregistering Alice
  (`deregister_agent`) marks `registry.is_active = false`. Any child
  whose `parent_agent_pubkey` references Alice is treated by
  `verify_and_execute` as inactive (require the parent registry's
  `is_active` to be true; one extra `AgentRegistry` account in
  `VerifyAndExecute` accounts).
- **Audit chain.** Each successful child registration emits an
  `AgentRegistered` event including `parent_agent_pubkey`. The parent's
  `AuditAnchor` Merkle root incorporates the child-registration entry as
  one of its leaves (see WS-6).

## 4. Wire Format / API Surface

```rust
pub struct RegisterAgentArgs {
    // ... existing v1 fields ...
    pub delegator_signature: [u8; 64],
    pub delegator_pubkey: [u8; 32],
    pub delegation_expiry: i64,

    // NEW (v3):
    pub parent_agent_pubkey:         Option<[u8; 32]>,
    pub parent_delegation_signature: Option<[u8; 64]>,
    pub parent_policy_commitment:    Option<[u8; 32]>,
}
```

Updated canonical payload prefix when parent is set:

```text
"GLYPH:DELEGATION:v3:CHILD:"   (26 bytes ASCII)
agent_pubkey                   (32)
parent_agent_pubkey            (32)
parent_policy_commitment       (32)
child_policy_commitment        (32)
derived_policy_commitment      (32 — sha256 of the two above, concatenated)
image_id                       (32 — 8 × u32 BE)
delegation_expiry              (8  LE i64)
scope_hash                     (32 — reserved)
```

The on-chain program:
1. Asserts `delegator_pubkey == parent_agent_pubkey` when the parent
   fields are set.
2. Asserts a separate `AgentRegistry` account (the parent's) is passed,
   `is_active`, and its `policy_commitment ==
   parent_policy_commitment`.
3. Computes `derived_policy_commitment = SHA-256(parent ||
   child)` and stores it in `registry.policy_commitment`.

New `AgentRegistry` fields (additive, behind a feature):

```rust
pub parent_agent_pubkey: Option<Pubkey>,   // 1 + 32 bytes
```

## 5. Implementation Plan / Workstream

- **Sits behind WS-9** in `IMPLEMENTATION_PLAN.md` and is a candidate v2
  workstream (`WS-9b — Multi-agent delegation`).
- **Phases:**
  1. Off-chain: extend `tee-worker` policy engine with
     `Policy::intersect(other) -> Policy` and matching canonical
     serialization. Property test: `serialize(intersect(a,b)) ==
     serialize(intersect(b,a))` (commutative).
  2. SDK: helper `signChildDelegation({ parent, child_policy, ... })`
     that calls into the parent TEE worker's signing endpoint.
  3. On-chain: feature-flagged `register_child_agent` instruction (or a
     branch in `register_agent`) that requires the parent registry
     account.
  4. Cascade revocation in `verify_and_execute`: require the
     parent-chain accounts up to the root human delegator, all
     `is_active`. Bounded depth (`MAX_DELEGATION_DEPTH = 3` proposed —
     see Rule 12 in `scope-structured-permissions.md`).
  5. Audit-trail format: extend WS-6 Merkle leaves with a `kind` tag
     (`leaf_kind: {Intent, ChildRegister, ChildRevoke}`).
- **Out of scope for v1** because the recursive-registry account
  pattern materially complicates `VerifyAndExecute` accounts and
  warrants its own audit pass.

## 6. Risks & Trade-offs

- **Account-count blowup in `verify_and_execute`.** Each delegation
  hop adds one read-only `AgentRegistry` account. Solana's 64-account
  limit is generous but caps practical depth; pair with Rule 12
  (`delegation_depth_max`).
- **Unspecified in thesis; GLYPH proposes** the strict-intersection
  rule. The thesis only says Bob *"can confirm that its assigned
  operations remain within the original scope"* but does not require
  *automatic* intersection. We make it mandatory because permissive
  delegation defeats GLYPH's deterministic-policy guarantee.
- **Revocation latency.** Cascade revocation is enforced at
  `verify_and_execute` time (the parent's `is_active` is re-read), not
  via a sweep. Stale child registries remain on-chain until garbage
  collected, but cannot execute. Document this loud.
- **Audit cost.** Each child registration is one extra Merkle leaf in
  the parent's audit chain, which is bounded but non-trivial for
  long-lived parents that spawn many short-lived children. Suggest a
  bounded ring buffer in the worker with periodic root rotation.
- **Policy intersection is undecidable in general** for some
  rule shapes (URL allowlists with regex, cron expressions). We
  restrict child policies to a *subset language* (currently: the 8
  base rules + URL allowlist + delegation depth) where intersection is
  computable in closed form.
- **Privacy.** Parent→child chains are publicly visible on-chain (the
  parent_agent_pubkey is in the registry). Same OP-surveillance
  concern as `oidc-vc-delegation.md`.
