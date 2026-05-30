# Integration: Natural-Language to Policy DSL Compilation

Out-of-scope integration design for GLYPH v1. Documents the LLM-assisted policy
authoring pipeline that the thesis recommends as the *interface* layer above
GLYPH's structured policy.

## 1. Paper Reference

- Tobin South, *Private, Verifiable, and Auditable AI Systems*
  (arXiv:2509.00085), Chapter 4 §4.3 *"Defining scope and permissions for AI
  agents"* (`authenticated-delegation.tex` lines 303-407):
  - §4.3.1 *"Structured permission languages"* (lines 319-338) — XACML,
    ODRL, OBAC, etc. as the auditable foundation.
  - §4.3.3 *"Natural Language Mechanisms"* (lines 357-369) — *"natural
    language often lacks the precision needed for reliable policy
    enforcement… Relying solely on an LLM to interpret and enforce
    ambiguous natural language instructions can be risky in
    security-sensitive contexts."*
  - §4.3.4 *"Combining structured permissions, natural language, and user
    oversight"* (lines 372-407), specifically the three-step hybrid example
    (lines 397-401):
    1. user writes NL constraints;
    2. LLM translates to structured policy;
    3. user reviews, corrects, finalizes.
  - §4.4.2 *"Limitations of natural language scoping"* (lines 434-446) —
    evaluation reliability, prompt-injection threat, contextual drift,
    third-party enforcement reliance.

## 2. Current GLYPH State

GLYPH's policy DSL is structured TOML, specified in
`docs/policy-dsl.md`, with **9 rules** today enforced by
`tee-worker/src/policy.rs`:

1. `max_lamports_per_tx`
2. `allowed_programs`
3. `time_window` (UTC hour band)
4. `max_daily_volume_lamports`
5. `require_slippage_bps_lte`
6. `allowed_token_mints`
7. `max_accounts_per_tx`
8. `require_signer_present`
9. (Reserved — see `scope-structured-permissions.md` for proposed extensions.)

The policy is canonicalized (`canonical_serialize_policy` in
`common/`), SHA-256 hashed to `policy_commitment`, and bound on-chain via
`register_agent` / `update_policy`. **There is no NL ingestion path.**
Policies are authored by hand and reviewed by humans.

## 3. Proposed Integration

A separate service, `glyph-policy-compiler/`, performs the NL→DSL
translation. The on-chain program is **unchanged**; only the off-chain
authoring tooling moves.

Pipeline:

```
NL prompt -> LLM compiler -> candidate Policy TOML -> diff vs prior
          -> human reviewer (CLI/UI) -> approval signal
          -> canonical_serialize_policy -> policy_commitment
          -> register_agent / update_policy
```

**Hard constraints:**
- LLM output MUST be deterministically convertible (Borsh-compatible) to the
  canonical `Policy` struct. The compiler emits TOML, validates by
  round-tripping through the Rust parser, and rejects on any field the
  parser cannot bind.
- **Human approval is mandatory.** The compiler exposes no auto-commit
  path. The thesis (line 391): *"validating these structured access
  controls via the human delegator"* is enforced by requiring the
  delegator's Ed25519 signature over the resulting `policy_commitment`
  before the registry transaction is built.
- **Determinism for audit.** The LLM call is recorded with `(model_id,
  temperature, prompt_hash, output_hash)` and persisted alongside the
  policy file. A reviewer auditing a historical policy can replay the
  compilation.

## 4. Wire Format / API Surface

Compiler service (out-of-repo, sketched):

```
POST /compile
  request:  { nl_text: string, allowlist_examples?: [...], deny_examples?: [...] }
  response: { policy_toml: string, rationale: string, model_id: string,
              prompt_hash: [u8;32], output_hash: [u8;32] }

POST /validate
  request:  { policy_toml: string }
  response: { ok: bool, parsed_policy: Policy, canonical_hash: [u8;32], errors: [...] }
```

CLI workflow (`glyph policy compile`):

```
$ glyph policy compile \
    --nl "Allow swaps on Jupiter up to 50 SOL/day, only USDC/SOL pairs, 9-5 UTC" \
    --review
# emits candidate.toml, opens diff editor, requires `--approve` to print
# the final canonical hash. Final `register_agent` requires the delegator
# to sign that hash via the existing WS-9 path.
```

## 5. Implementation Plan / Workstream

- **Scope boundary:** Lives in `glyph-policy-compiler/` (new repo). **Out of
  scope for the on-chain v1 (`programs/glyph-verifier`) and the TEE worker.**
  The on-chain verifier does not need to know whether a policy was authored
  by hand or by an LLM — it only verifies the resulting commitment.
- **Phases:**
  1. Schema-prompted few-shot translator using the existing
     `docs/policy-dsl.md` as the system prompt. Output validated by the
     same Rust parser used in production (via WASM or a thin sidecar).
  2. Negative-example test bank (red-team prompts: injection attempts,
     conflicting clauses) measured for `parse_ok ∧ semantic_match` rate.
  3. Reviewer UI showing rule-by-rule rendering plus a "rejected actions"
     simulator: a few canned `TransactionIntent` samples evaluated against
     the candidate policy.
  4. Optional formal-verification hook: pass the resulting TOML through the
     existing `formal_verification/` pipeline to confirm rule
     well-formedness before signing.
- Maps to `IMPLEMENTATION_PLAN.md` **out-of-scope §8** (not a P0/P1/P2
  workstream).

## 6. Risks & Trade-offs

- **LLM compiler trust.** The compiler becomes a critical security
  component. Thesis (line 442): *"Prompt injection and jailbreak attacks
  can coerce a large language model into generating or accepting policies
  that exceed the original user's intent."* Mitigation: the compiler runs
  with no tools, no retrieval, fixed temperature; the policy is *always*
  reviewed by the human signer before signing.
- **Prompt injection in NL.** If the NL instruction is itself attacker
  controlled (e.g. an agent harvested it from a webpage), the policy can
  be subverted. Mitigation: the NL source must be authenticated to the
  human delegator (typed in the CLI or signed in the gateway).
- **Semantic drift between models.** Two LLM versions may translate the
  same NL differently. We pin `model_id` per policy and surface it in the
  audit trail; reviewers see the model used at compile time when the
  policy is later inspected.
- **Coverage gap vs structured-only authoring.** Some advanced rules
  (cron expressions, URL allowlists — see
  `scope-structured-permissions.md`) may be hard to express in NL. The
  compiler falls back to a hand-edited section the user can paste in.
- **Audit-trail bloat.** Persisting `(prompt, output, model_id)` per
  policy revision is large. We propose hashing it on-chain (a future
  optional field on `update_policy`) and storing the bytes in IPFS or
  worker-sealed audit log.
