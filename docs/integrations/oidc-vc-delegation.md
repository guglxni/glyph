# Integration: OIDC + W3C Verifiable Credential Delegation

Out-of-scope integration design for GLYPH v1. Tracks paper alignment for the
authenticated-delegation framework's identity-token bundle.

## 1. Paper Reference

- Tobin South, *Private, Verifiable, and Auditable AI Systems* (arXiv:2509.00085),
  Chapter 4 §"Authenticated delegation for AI agents":
  - §4.2 *"Extending OpenID Connect for identifying and authenticating AI
    agents"* (`authenticated-delegation.tex` lines 169-203).
  - §4.2.3 *"Token-based authentication framework"* (lines 270-286), defining
    the three-token bundle: **User's ID-token**, **Agent-ID token**,
    **Delegation Token**.
  - §4.2 *"Using verifiable credentials as an alternative"* (lines 292-300) on
    the hybrid VC/OIDC path: *"In practice, hybrid solutions often prove the
    most pragmatic. A user or AI agent could store and manage VCs encoding
    rich attributes or regulatory endorsements, while still leveraging OIDC
    tokens to bootstrap compatibility with existing authentication or
    authorization endpoints."*
  - Figure `OIDC-AI` (`authenticated-delegation.tex` line 225) — the
    canonical Client/OP/UMA/Agent diagram.
  - §4.4.1 *"Problems with an OpenID Connect approach"* (line 421) — privacy
    risks of OP-mediated correlation.

## 2. Current GLYPH State

GLYPH today implements a **single-signature** authenticated delegation,
captured in `programs/glyph-verifier/src/lib.rs`:

- `RegisterAgentArgs` carries `delegator_pubkey: [u8;32]` and
  `delegator_signature: [u8;64]`.
- `delegation_signing_payload` (lib.rs lines 167-184) defines a canonical
  Ed25519 payload `"GLYPH:DELEGATION:v1:" || agent_pubkey || policy_commitment
  || image_id (BE) || delegation_expiry || scope_hash`.
- `verify_ed25519_precompile` enforces the signature via the sibling
  `Ed25519Program` precompile (lib.rs lines 667-733).

This corresponds to a **stand-alone Delegation Token** signed by the human
delegator's Ed25519 key. There is **no User ID-token** (no OIDC binding) and
**no Agent-ID token** (the agent's `Pubkey` plus on-chain attestation hash is
the closest analogue, but it is not an OIDC client registration). The hybrid
VC/OIDC path is unrepresented.

## 3. Proposed Integration

Map the thesis three-token bundle onto GLYPH's existing on-chain primitive by
hashing the off-chain tokens into the signed payload and adding two optional
fields to `RegisterAgentArgs`:

1. **User ID-token** — JWT from the OP (Google, Auth0, an in-house IdP, etc.).
   Off-chain canonicalization: `id_token_hash = SHA-256(jwt_compact_serialization)`.
2. **Agent-ID token** — JWT or VC issued by the agent owner (per thesis,
   *"OAuth 2.0 Native Client (meaning the owner of the AI Agent controls all
   keying material)"*). For GLYPH the agent_pubkey IS the unique agent
   identifier; the Agent-ID token is the off-chain metadata wrapper
   (capabilities, system documentation per `chan2024ids`).
3. **Delegation Token** — already implemented as the on-chain
   `delegation_signing_payload`. Extended below to bind the User ID-token hash.

**Hybrid VC path.** When the delegator prefers a W3C VC, the
`delegator_vc_hash` carries `SHA-256(canonicalized_vc_jwt)`. An off-chain
**delegation gateway** is required to resolve the issuer-DID (`did:web`,
`did:key`, etc.) and verify the VC signature; the on-chain program only stores
the hash binding.

## 4. Wire Format / API Surface

Extend `RegisterAgentArgs` (Anchor serialization):

```rust
pub struct RegisterAgentArgs {
    // ... existing fields ...
    pub delegator_signature: [u8; 64],
    pub delegator_pubkey: [u8; 32],
    pub delegation_expiry: i64,

    // NEW (additive, both optional via Option<...> in v2):
    pub delegator_id_token_hash: Option<[u8; 32]>,  // SHA-256 of OIDC JWT
    pub delegator_vc_hash:       Option<[u8; 32]>,  // SHA-256 of canonical VC
}
```

Updated canonical signing payload (v2):

```text
"GLYPH:DELEGATION:v2:"   (20 bytes ASCII)
agent_pubkey             (32)
policy_commitment        (32)
image_id                 (32 — 8 × u32 BE)
delegation_expiry        (8  LE i64)
scope_hash               (32 — currently [0;32])
id_token_hash_present    (1 bool)
id_token_hash            (32 — zeros if absent)
vc_hash_present          (1 bool)
vc_hash                  (32 — zeros if absent)
```

The off-chain gateway exposes:
- `POST /resolve-id-token { jwt } -> { ok, sub, iss, exp, hash }` — verifies
  signature against the OP's JWKS, returns the canonical SHA-256.
- `POST /resolve-vc      { vc_jwt } -> { ok, issuer_did, subject_did, hash }` —
  resolves the issuer DID document and verifies the VC proof.

## 5. Implementation Plan / Workstream

- **Owner:** `glyph-delegation-gateway/` (new service, out-of-scope for v1
  on-chain repo). Builds on the existing `IMPLEMENTATION_PLAN.md` WS-9
  (human-delegator signature) which landed the Ed25519 plumbing.
- **Phases:**
  1. v2 payload constant added behind a feature flag in
     `programs/glyph-verifier/src/lib.rs`; existing v1 path preserved.
  2. Off-chain gateway library written in TypeScript (mirrors `sdk/typescript`),
     using `jose` for JWT and `@digitalbazaar/vc` for VC verification.
  3. SDK helper `signDelegationV2({ idToken, vc?, agentPubkey, ... })` that
     emits both the canonical payload and the user's signature.
  4. Integration test against a local OIDC mock (Keycloak/dex) and a static
     issuer DID.
- **Out of scope here:** any change to the on-chain `verify_and_execute`
  path; delegation token verification happens once at `register_agent`.

## 6. Risks & Trade-offs

- **OP as a surveillance choke point.** The thesis explicitly warns
  (§4.4.1, line 426): *"OIDC providers… gain the ability to track and
  correlate individual AI agent interactions across various services."*
  GLYPH's hash-only on-chain binding mitigates *on-chain* leakage but cannot
  prevent the OP itself from logging issuance.
- **JWT canonicalization.** JWT compact serialization is byte-stable but
  some signing libraries normalize whitespace inside the JSON payload before
  signing; the gateway MUST hash the exact bytes between the dots. Spec this
  in a fixture test that round-trips through `jose`.
- **VC issuer trust.** Thesis (§4.2, line 297): *"VCs, while powerful,
  require additional work to replicate [token refresh, revocation] at
  scale."* GLYPH does not solve VC revocation; the gateway must consult the
  issuer's status list (StatusList2021) before accepting.
- **Backwards compatibility.** Bumping the payload prefix from `v1:` to `v2:`
  is a hard fork for any pre-registered agent re-registering. v1 stays
  supported in parallel until a quorum window.
- **Selective disclosure.** The thesis highlights VC selective disclosure
  (line 295) as a privacy win; GLYPH's commitment-only design is compatible
  but does not itself implement BBS+ or other selective-disclosure proofs.
  Treated as future work.
