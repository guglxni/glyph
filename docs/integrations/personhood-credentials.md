# Integration: Personhood Credentials (PHC)

Out-of-scope integration design for GLYPH v1. Adds a hash binding for a
PHC-issued service-specific unlinkable pseudonym to the on-chain
delegation record.

## 1. Paper Reference

- Tobin South, *Private, Verifiable, and Auditable AI Systems*
  (arXiv:2509.00085), Chapter 4 §"Personhood Credentials" (`phc.tex`):
  - §"An executive summary of personhood credentials" (lines 12-97).
    Two foundational requirements (lines 42-46):
    1. **Credential limits** — *"The issuer of a PHC gives at most
       one credential to an eligible person."*
    2. **Unlinkable pseudonymity** — *"PHCs let a user interact with
       services anonymously through a service-specific pseudonym; the
       user's digital activity is untraceable by the issuer and
       unlinkable across service providers, even if service providers
       and issuers collude."*
  - §"Allow verified delegation to AI agents" (lines 100-109) — PHCs
    as the principal-identity anchor for authenticated delegation.
  - §"Connecting personhood credentials to AI agents" (lines 112-119):
    *"By integrating personhood credentials into [the authenticated
    delegation] framework, we can add an essential layer of trust: a
    verifiable, privacy-preserving guarantee that the human delegator
    is indeed a real person."*
  - Figure `fig:exec_summary` (`phc.tex` line 16) — overview of the
    PHC threat model and design.
  - Combined-architecture figure: `figs/PCandAuthDel.pdf` (referenced
    from `authenticated-delegation.tex` line 111) — PHC + auth-deleg
    integration sketch.

## 2. Current GLYPH State

GLYPH's `AgentRegistry` (`programs/glyph-verifier/src/lib.rs`, lines
41-62) and `RegisterAgentArgs` (lines 132-151) carry no PHC reference.
The human delegator is identified by an Ed25519 pubkey
(`delegator_pubkey`) — sufficient for the authenticated-delegation
chain but **does not prove humanity**. An attacker controlling a key
(or 1,000 keys) can register 1,000 agents that all look authenticated.

## 3. Proposed Integration

Add `delegator_phc_hash: Option<[u8;32]>` to `RegisterAgentArgs`. The
hash references a **service-specific unlinkable pseudonym** issued by
a trusted PHC issuer. On-chain stores the hash only; verification of
the PHC's signature, issuer trust, and freshness is performed by an
**off-chain PHC verifier service** *before* the registration
transaction is built. The signed-by-delegator payload binds the hash,
so the agent registration is cryptographically tied to a specific
PHC-anchored pseudonym.

**What the off-chain verifier checks** (per `phc.tex` design):
1. The pseudonym is issued by a recognized PHC issuer (allowlist
   maintained off-chain, governance is out-of-scope for v1).
2. The ZK proof of personhood (issuer-specific) verifies under the
   issuer's public parameters.
3. The pseudonym is **service-specific** — derived for the GLYPH
   namespace, not reusable on another service.
4. Freshness: the issuance epoch / nonce is within an issuer-defined
   window.

**What GLYPH stores:** `SHA-256(pseudonym_bytes ||
issuer_id || epoch)`. The pseudonym bytes themselves are NOT
on-chain (protects unlinkability across services per the PHC second
foundational requirement).

**Sybil-resistance amplification.** A future on-chain rule can
require that no two `AgentRegistry` entries share the same
`delegator_phc_hash` — enforced by deriving the
`AgentRegistry` PDA seed from the PHC hash as well as the
agent_pubkey, surfacing duplicate-registration as a PDA collision.

## 4. Wire Format / API Surface

```rust
pub struct RegisterAgentArgs {
    // ... existing v1 fields ...
    pub delegator_signature: [u8; 64],
    pub delegator_pubkey:    [u8; 32],
    pub delegation_expiry:   i64,

    // NEW (v4 — PHC integration):
    pub delegator_phc_hash: Option<[u8; 32]>,
    pub phc_issuer_id:      Option<[u8; 16]>, // short tag of issuer
}
```

Updated canonical payload (v4):

```text
"GLYPH:DELEGATION:v4:"   (20 bytes ASCII)
agent_pubkey             (32)
policy_commitment        (32)
image_id                 (32 — 8 × u32 BE)
delegation_expiry        (8  LE i64)
scope_hash               (32 — reserved)
phc_hash_present         (1 bool)
phc_hash                 (32 — zeros if absent)
phc_issuer_id            (16 — zeros if absent)
```

Off-chain PHC verifier API:

```
POST /verify-phc
  request:  { credential_blob: bytes, service_namespace: "glyph-mainnet" }
  response: { ok: bool, pseudonym_hash: [u8;32], issuer_id: [u8;16],
              epoch: u64, errors: [...] }
```

## 5. Implementation Plan / Workstream

- **Owner:** new service `glyph-phc-verifier/` (out-of-scope for v1
  on-chain repo). Builds on top of WS-9.
- **Phases:**
  1. Off-chain adapter trait `PhcIssuer` with implementations for the
     candidate issuers listed below. **Adapters are scaffolds today —
     they MUST be validated against the issuer's published spec
     before being trusted in production.**
  2. SDK helper `signDelegationWithPhc({ phcBlob, ... })`.
  3. Feature-flagged on-chain v4 payload + optional PHC fields.
  4. Optional: PDA-seed amendment to enforce one-agent-per-PHC.
- **Candidate issuers (publicly documented; technical claims below
  are limited to what is publicly stated by the projects themselves —
  we do not vouch for these claims and explicitly note this for
  auditors).**

  | Issuer | Public docs URL | What is publicly claimed |
  | --- | --- | --- |
  | Worldcoin / World ID | https://docs.world.org/ | ZK proof of unique-human via iris-imaging biometric, service-specific nullifier (`signal`). |
  | Polygon ID (Privado ID) | https://docs.privado.id/ | Iden3-based VC issuance with selective disclosure and nullifiers. |
  | BrightID | https://www.brightid.org/ | Social-graph based unique-human attestation; nullifier per context. |

  None of these are integrated today. Each requires its own adapter
  reading the issuer's verifier library and checking the
  service-specific pseudonym derivation. **Do not deploy any of them
  without the issuer's own SDK and a security review.**

- Mapped to `IMPLEMENTATION_PLAN.md` §8 (out-of-scope) — does not
  block any P0/P1/P2 workstream.

## 6. Risks & Trade-offs

- **Issuer trust is foundational.** PHC issuers become a critical
  trust anchor; a compromised issuer can mint pseudonyms at will.
  The thesis (`phc.tex` lines 71-77) flags this exact concern:
  *"Robustness to attack and error by different actors in the PHC
  ecosystem."* GLYPH proposes a multi-issuer allowlist and explicit
  governance for additions/removals (out of scope for v1).
- **Issuer-issued pseudonyms must be service-specific.** If GLYPH
  accepts a pseudonym derived from another service's namespace,
  unlinkability is broken across services. The off-chain verifier
  MUST check the `service_namespace` matches GLYPH's identifier.
- **Issuer revocation.** PHC revocation/rotation is issuer-specific
  and not standardized; the off-chain verifier consults the issuer's
  revocation list each time. The on-chain record cannot detect
  revocation after registration; high-trust deployments should
  combine this with a short `delegation_expiry`.
- **Privacy vs accountability tension.** The thesis (`phc.tex`
  lines 102-109) is explicit: *"PHCs alone do not directly identify
  the principal."* GLYPH inherits this. If a service later needs
  legal-identity attribution, a separate KYC flow is required.
- **Linkability through `delegator_pubkey`.** The Ed25519
  `delegator_pubkey` is itself a public identifier. If the same key
  registers multiple agents, those agents are linked even though
  their PHC pseudonyms are not. Recommendation: rotate
  `delegator_pubkey` per agent and treat it as ephemeral.
- **Unspecified in thesis; GLYPH proposes** the SHA-256(pseudonym ||
  issuer_id || epoch) canonical hash. The thesis says only *"every
  delegated action is cryptographically linked to a verified human
  identity"* without prescribing a binding format.
