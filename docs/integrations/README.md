# GLYPH Integration Design Docs

This directory tracks **out-of-scope-for-v1** integration designs that align
GLYPH's identity, delegation, and policy surfaces with the architecture in
Tobin South's *Private, Verifiable, and Auditable AI Systems*
(arXiv:2509.00085), Chapter 4. Each doc states explicitly which thesis
section it implements, the current GLYPH state, a proposed integration, wire
format, an implementation plan, and risks/trade-offs.

Nothing in this directory ships in v1 on its own. These are the
specifications that v2/v3 work would consume — they are the design layer
above the workstreams tracked in `audit/IMPLEMENTATION_PLAN.md`.

## Documents

| Doc | One-line description | IMPLEMENTATION_PLAN workstream |
| --- | --- | --- |
| [`oidc-vc-delegation.md`](./oidc-vc-delegation.md) | OIDC + W3C VC three-token bundle (User ID-token / Agent-ID / Delegation Token) hashed into the on-chain delegator-signed payload. | Extends **WS-9** (paper-faithful authenticated delegation: human delegator signature). |
| [`nl-to-policy-compilation.md`](./nl-to-policy-compilation.md) | LLM-assisted natural-language → structured policy DSL pipeline with mandatory human review before commitment. | **§8 Out-of-scope** (not in P0-P3); future `glyph-policy-compiler/` service. |
| [`multi-agent-delegation.md`](./multi-agent-delegation.md) | Inter-agent delegation (Alice→Bob) with scope-intersection, cascade revocation, and Merkle-rooted audit trail. | Future **WS-9b** built on WS-9 + WS-6 (audit anchor). |
| [`personhood-credentials.md`](./personhood-credentials.md) | Optional PHC pseudonym hash bound into the delegation payload — Worldcoin / Polygon ID / BrightID as candidate issuers (publicly documented, not endorsed). | **§8 Out-of-scope**; future `glyph-phc-verifier/` service, depends on WS-9. |
| [`scope-structured-permissions.md`](./scope-structured-permissions.md) | Mapping XACML/ODRL/OBAC/ROWLBAC/KaOS/Multi-OrBAC/URL-allowlists onto GLYPH's DSL, plus three proposed new rules (10: `allowed_urls`, 11: `time_of_day_complex` cron, 12: `delegation_depth_max`). | Rules 10/11 extend **WS-10** (cleanup + observability); Rule 12 is required by the multi-agent doc. |
| [`verifiable-ml-evals.md`](./verifiable-ml-evals.md) | zkSNARK proofs of ML inference (`Prove(pk, W, x, y) -> π ⊃ {H(W), y}`, ezkl + Halo2 + KZG SRS); two modes — Mode A challenge-after registry, Mode B inline per-intent proof. | **§8 Out-of-scope**; new sub-project `glyph-evals/`, v3+ deliverable. |
| [`partial-zk-selective-proving.md`](./partial-zk-selective-proving.md) | Partial-ZK extension of Mode B: prove only the private slice ($BAx$ LoRA adapter or $HWx$ classifier head); cheaper but inherits the documented adapter-reconstruction side channel. | Extends `glyph-evals/` (same v3+ workstream as `verifiable-ml-evals.md`). |
| [`zktax-portable-data.md`](./zktax-portable-data.md) | TDS-anchored redact-and-prove provenance (`zkTax` three-service model) — intents carry `DataProvenance { tds_pubkey, original_hash, redaction_proof }` so policy claims about external state are cryptographically rooted. | **§8 Out-of-scope**; new sub-project `glyph-provenance/`, composes with `prag-mpc-retrieval.md`. |

## How to read these

1. Start with `oidc-vc-delegation.md` — it grounds the rest by mapping the
   thesis three-token model onto GLYPH's existing
   `register_agent` flow (`programs/glyph-verifier/src/lib.rs` lines
   132-184 and 772-841).
2. Then `scope-structured-permissions.md` — establishes the rule
   vocabulary the other docs reference (Rule 12 in particular).
3. Then `multi-agent-delegation.md` and `personhood-credentials.md`,
   which both build on the delegation-signing payload.
4. Finally `nl-to-policy-compilation.md` — purely an off-chain authoring
   convenience that consumes the rule schema.

## Conventions

- Every doc has the same 6-section structure: **Paper Reference,
  Current GLYPH state, Proposed Integration, Wire Format / API
  Surface, Implementation Plan / Workstream, Risks & Trade-offs.**
- Thesis citations use exact section names and `.tex` file line
  numbers from `arXiv-2509.00085v1/chapter-4/`.
- Where the thesis under-specifies a binding, the doc says **"Unspecified
  in thesis; GLYPH proposes:"** and supplies a concrete construction.
- Wire-format changes use **payload-prefix versioning** (`GLYPH:DELEGATION:v2:`
  …`v4:`) so v1 continues to verify in parallel during rollout.
