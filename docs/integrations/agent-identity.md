# Agent Identity for GLYPH — Options, Research & Recommendation

Status: research note (2026-05-31). Informs the demo's "Agent Identity" feature and
the [`oidc-vc-delegation.md`](oidc-vc-delegation.md) / [`personhood-credentials.md`](personhood-credentials.md)
integration designs.

## The question

What is the best on-chain primitive to represent an **AI agent's identity** and bind it
to a **verified human principal**, for GLYPH (the verifiable guardrail layer)?

## What the thesis recommends (arXiv:2509.00085, Ch. 4)

Tobin South's dissertation — which GLYPH implements — is explicit, and it does **not**
recommend NFTs. Its model (`authenticated-delegation.tex`) is a three-token bundle
anchored to a verified human, built on battle-tested web auth (OAuth 2.0 / OpenID
Connect), optionally wrapped in W3C Verifiable Credentials + DIDs:

1. **User ID-token** — OIDC token proving a real human principal (the delegator).
2. **Agent-ID token** — the agent registered as an OAuth 2.0 *Native Client* (the owner
   controls all keying material); carries agent metadata/capabilities.
3. **Delegation Token** — the human signs to authorize the agent for a scoped, expiring
   set of actions on their behalf.

Reinforced by **Personhood Credentials** (`phc.tex`): a privacy-preserving, ZK-verifiable
proof that *a real person stands behind the agent*, revealing nothing else. Quote
(Ch. 4): *"By ensuring that every delegated action is cryptographically linked to a
verified human identity, this combined framework mitigates risks of impersonation,
unauthorized scalability of malicious operations, and ambiguity in responsibility."*

Key design principle: agent identity is a **non-transferable attestation bound to a
human** — not a tradeable asset.

## What GLYPH already implements

GLYPH's on-chain `register_agent` already realizes the **Delegation Token** directly:

- `RegisterAgentArgs { agent_pubkey, delegator_pubkey, delegator_signature, delegation_expiry, ... }`
- Canonical signed payload (`delegation_signing_payload`):
  `"GLYPH:DELEGATION:v1:" || agent_pubkey || policy_commitment || image_id (BE) || delegation_expiry || scope_hash`
- Verified on-chain via the **Ed25519 precompile** (`verify_ed25519_precompile`).

So today: **the agent's identity is its Ed25519 keypair / on-chain `agent_pubkey`**, and a
**human delegator's signature** binds that agent to a specific policy + circuit version,
with an expiry. That is the thesis's Delegation Token, on-chain.

## Solana FOSS primitives surveyed (real, maintained)

| Primitive | Repo | Fit for agent identity | Verdict |
|-----------|------|------------------------|---------|
| **Wallet keypair / PDA** | (native) | The agent's signer + on-chain `agent_pubkey`; GLYPH's current model | ✅ Base identity (in use) |
| **Ed25519 delegation signature** | GLYPH (native) | Human principal binds the agent (Delegation Token) | ✅ Implemented |
| **Solana Attestation Service (SAS)** | `solana-foundation/solana-attestation-service` | Foundation-built, FOSS, purpose-built for **on-chain verifiable credentials/attestations** → maps to W3C VC | ✅ Recommended credential layer |
| **sol-did (`did:sol`)** | `identity-com/sol-did` | W3C **DID** method/resolver for the human principal and/or agent | ✅ Recommended DID layer |
| **Gateway Protocol / Civic Pass** | `identity-com/on-chain-identity-gateway` | Proof-of-personhood / KYC gating tokens → the thesis's **personhood-credential** layer | ✅ Recommended personhood gate |
| **Metaplex Core (`mpl-core`)** | `metaplex-foundation/mpl-core` | NFT/asset (soulbound via freeze-delegate plugin possible) | ⚠️ Works, but off-thesis |
| **Token-2022 non-transferable (SBT)** | `solana-program/token-2022` | Native soulbound token extension | ⚠️ Works, but off-thesis |
| **Compressed NFTs (Bubblegum)** | `metaplex-foundation/mpl-bubblegum` | Cheap mass issuance of agent IDs | ⚠️ Asset, not credential |

### Why NOT NFTs (even soulbound)

An NFT/SBT is fundamentally an **asset standard**. Using it for agent identity:
- Conflates "identity" with "ownership of a tradeable thing" (the thesis's whole point is
  binding to a *non-transferable verified human*, not minting a token).
- Adds a metadata/marketplace surface and indexer dependencies that buy nothing for
  authorization — GLYPH already gets uniqueness + non-transferability from the keypair +
  delegation signature.
- Diverges from the OAuth2/OIDC/VC standards the paper (and existing web infra) builds on.

Soulbound tokens are a reasonable *display badge* ("this agent is GLYPH-registered") but
should not be the **authorization root**. The authorization root is the
delegator-signed, policy-bound on-chain registration.

## Recommendation (layered, thesis-faithful)

1. **Agent identity = wallet/PDA** (`agent_pubkey`) — already GLYPH's model. The demo's
   "Connect Wallet" sets the human principal; the agent gets its own keypair.
2. **Human binding = the existing Ed25519 delegation** — the connected wallet is the
   *delegator* authorizing the agent over the canonical payload (already on-chain).
3. **Verified-human extension (FOSS, thesis-aligned)** — layer **SAS** (attestation/VC) +
   **sol-did** (DID) + **Civic Pass / Gateway** (personhood) to upgrade the delegator from
   "some key" to "a *verified human*." This is the path in `oidc-vc-delegation.md` and
   `personhood-credentials.md`, now mapped to concrete Solana FOSS programs.

NFT/SBT identity is documented here as a **possible alternative** with its trade-offs, but
is **not recommended** because it contradicts the research GLYPH is built on.

## Sources

- Thesis Ch. 4 — `arXiv-2509.00085v1/chapter-4/authenticated-delegation.tex`, `phc.tex`.
- Solana Attestation Service — https://github.com/solana-foundation/solana-attestation-service
- sol-did — https://github.com/identity-com/sol-did
- On-chain Identity Gateway (Civic) — https://github.com/identity-com/on-chain-identity-gateway
- Metaplex Core — https://github.com/metaplex-foundation/mpl-core
- Token-2022 — https://github.com/solana-program/token-2022
