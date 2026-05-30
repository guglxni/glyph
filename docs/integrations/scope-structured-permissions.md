# Integration: Structured Permissions Beyond the 8-Rule DSL

Out-of-scope integration design for GLYPH v1. Maps the structured-permission
languages the thesis surveys onto GLYPH's policy DSL and proposes three new
rules (10, 11, 12) for cases the current 8 rules do not cover.

## 1. Paper Reference

- Tobin South, *Private, Verifiable, and Auditable AI Systems*
  (arXiv:2509.00085), Chapter 4:
  - §4.3.1 *"Structured permission languages"*
    (`authenticated-delegation.tex` lines 319-338). Lists:
    - **XACML** (eXtensible Access Control Markup Language) —
      XML-encoded policies.
    - **ODRL** (Open Digital Rights Language) — usage permissions over
      digital content.
    - **OBAC** — Object-Based Access Control.
    - **ROWLBAC** — Role-and-OWL-Based Access Control.
    - **KaOS** — OWL-ontology-based policy framework.
    - **Multi-OrBAC** — multi-organization role-based extension.
    - URL allow/blocklists — *"In web-based contexts, this can often
      be as simple as whitelisting or blacklisting URLs and
      subdomains that an agent can access."*
  - §4.3.4 paragraph *"Resource scoping as a foundation"* (lines
    374-383). Verbatim: *"the most broadly applicable strategy is to
    enforce resource scoping with structured permissions."*
  - §4.3.2 *"Authentication flows"* (lines 340-355) on dynamic prompts
    for borderline cases — out of scope here (GLYPH is deterministic).

## 2. Current GLYPH State

`docs/policy-dsl.md` documents **8 enforced rules** (plus a reserved
slot 9). The TEE worker implementation lives in
`tee-worker/src/policy.rs`; canonical serialization for the
`policy_commitment` is in `common/`. Rules today:

1. `max_lamports_per_tx` — per-transaction lamport cap.
2. `allowed_programs` — Solana program ID allowlist.
3. `time_window` — UTC hour band (simple start/end).
4. `max_daily_volume_lamports` — rolling 24h cap.
5. `require_slippage_bps_lte` — DEX slippage ceiling.
6. `allowed_token_mints` — SPL mint allowlist.
7. `max_accounts_per_tx` — instruction account-count cap.
8. `require_signer_present` — payer/signer requirement.

Of the four required in-circuit rules
(`programs/glyph-verifier/src/lib.rs` `REQUIRED_RULES_MASK`, lines
1046-1053): `max_lamports`, `allowed_programs`, `max_accounts`,
`require_signer`. The other rules are checked off-circuit by the TEE
worker and bound through `policy_commitment`.

## 3. Proposed Integration — Mapping & New Rules

### 3.1 Mapping survey languages onto GLYPH

| Thesis language | Closest GLYPH rule(s) | Gap / new rule needed |
| --- | --- | --- |
| **XACML** *Subject/Resource/Action/Environment* | Rule 2 (programs ≈ resource), Rule 6 (mints ≈ resource), Rule 7 (accounts ≈ resource list) | XACML's *Environment* (time, location) covered by Rule 3 only crudely. **Rule 11** (cron) needed. |
| **ODRL** *permission/prohibition/duty + asset* | Rule 6 (asset = mint), Rule 1 (constraint = lamports) | No *duty* (post-action obligation) model in GLYPH. Out of scope for v1. |
| **OBAC** *object-typed permissions* | Rule 2 (program), Rule 6 (mint) — Solana's account model is naturally object-typed | OK as-is; OBAC adds nothing beyond what we have. |
| **ROWLBAC / KaOS / Multi-OrBAC** *ontology+OWL* | None | Solana on-chain semantics are not ontology-encoded; we treat these as **out-of-scope authoring conveniences** — the policy compiler (`nl-to-policy-compilation.md`) can ingest ontology fragments and lower them to the GLYPH rules. |
| **URL allow/blocklists** | None — GLYPH is on-chain only | **Rule 10** (`allowed_urls`) needed for agents that also act over HTTP. |

### 3.2 New Rule 10 — `allowed_urls`

Purpose: bind the agent's *off-chain* HTTP/HTTPS surface so any web
fetch performed by the TEE worker is policy-bounded too.

```toml
[rules]
allowed_urls = [
  "https://api.jup.ag/*",
  "https://price.jup.ag/*",
  "!https://api.jup.ag/admin/*",   # deny override
]
```

Semantics:
- Patterns: scheme-mandatory glob with `*` (path segment) and `**`
  (multi-segment). `!`-prefix denies. Most-specific match wins;
  ties → deny.
- Canonicalization: punycoded host, lowercased, default ports
  removed. The matcher operates on this canonical form.
- Enforced **off-circuit** in the TEE worker's HTTP client.

### 3.3 New Rule 11 — `time_of_day_complex` (cron)

Purpose: replace Rule 3's single UTC hour band with a full cron
expression for richer schedules (e.g., business hours, M-F only).

```toml
[rules]
time_of_day_complex = "0 9-17 * * 1-5"  # 9 AM-5 PM, Mon-Fri UTC
```

Semantics:
- Five-field cron (`minute hour day-of-month month day-of-week`),
  UTC only.
- Coexists with Rule 3 (`time_window`); when both present, both
  must permit. (Rule 3 stays for the in-circuit rule mask; Rule 11
  is off-circuit.)
- Requires a deterministic cron parser bundled in `common/` and
  fixture-tested between Rust and TS canonicalization (per
  `docs/canonicalization.md`).

### 3.4 New Rule 12 — `delegation_depth_max`

Purpose: bound recursion in the inter-agent delegation chain (see
`multi-agent-delegation.md`). With Rule 12 in place, an attacker
cannot chain N child agents to circumvent depth-sensitive monitoring.

```toml
[rules]
delegation_depth_max = 3   # human -> agent -> agent -> agent (max)
```

Semantics:
- Zero is a sentinel for "this agent may not delegate further".
- Enforced **on-chain** in `register_agent` when
  `parent_agent_pubkey.is_some()`: the program walks the parent's
  registry, asserts `parent.delegation_depth < max`, and stores
  `child.delegation_depth = parent.delegation_depth + 1`.

### 3.5 Updated rule count and circuit mask

Total rules: 12. In-circuit mask
(`programs/glyph-verifier/src/lib.rs` `REQUIRED_RULES_MASK`)
unchanged — the four stateless rules stay the in-circuit minimum.
Rules 10/11/12 are off-circuit, bound through `policy_commitment`.

## 4. Wire Format / API Surface

Schema additions in `docs/policy-dsl.md`:

```toml
[rules]
# ... existing rules 1-8 ...

# Rule 10
allowed_urls = [<glob-string>, ...]   # optional

# Rule 11
time_of_day_complex = "<cron-5-field>"  # optional, UTC

# Rule 12
delegation_depth_max = <u8>             # optional; defaults to 0
```

`Policy` Rust struct (in `common/`) gains three `Option` fields with
canonical serialization slots **appended** to preserve commitment
stability for v1 policies (a v1 policy serializes the new slots as
`None`/empty — the commitment is byte-identical to the v1 build).

Borsh tag bytes (additive, end of struct):
```
... existing 8 rule slots ...
[10] tag=0x0a, len: u16, body: Vec<String> (utf-8 glob patterns)
[11] tag=0x0b, len: u16, body: String      (cron expression)
[12] tag=0x0c, len: 1,   body: u8          (max depth, 0=disabled)
```

## 5. Implementation Plan / Workstream

- **Owner:** `tee-worker/src/policy.rs` + `common/` + on-chain
  `register_agent` for Rule 12 only.
- **Maps to IMPLEMENTATION_PLAN.md:**
  - Rule 10/11 → WS-10 (cleanup + observability) plus a new
    out-of-scope §8 entry.
  - Rule 12 → required dependency of `multi-agent-delegation.md`
    (which is itself out-of-scope for v1).
- **Phases:**
  1. Extend `Policy` Borsh schema with Rules 10/11/12 (append-only).
  2. Implement off-circuit Rule 10 matcher in worker; add fuzz
     corpus (URL canonicalization is a well-known foot-gun).
  3. Implement off-circuit Rule 11 cron parser; vendor a small
     deterministic crate (`cron` family) and pin its version in the
     reproducible build.
  4. Implement on-chain Rule 12 check in `register_agent`; add a
     `delegation_depth: u8` field to `AgentRegistry` (additive).
  5. Add cross-language fixtures in `tests/` so TS and Rust
     canonicalize identically.

## 6. Risks & Trade-offs

- **URL pattern semantics are notoriously tricky.** Subdomain
  injection, IDN homograph attacks, redirect-following — the
  worker MUST follow the deny-default model and refuse any URL it
  cannot canonicalize. **Recommendation:** mandatory `*.example.com`
  rather than `example.com` (no implicit subdomain match).
- **Cron parsing differences.** Different cron libraries
  disagree on `*/N` boundary semantics. Pin one Rust crate, write
  a Borsh-canonical normalized form (no synonyms like `@daily`),
  and test fixtures rigorously. **Unspecified in thesis; GLYPH
  proposes** the strict 5-field UTC cron form.
- **Rule 12 storage cost.** Adding `delegation_depth: u8` plus
  `parent_agent_pubkey: Option<Pubkey>` to `AgentRegistry` is +33
  bytes per agent. Acceptable; document in `MIGRATION.md`.
- **Off-circuit drift.** Rules 10/11 are bound through the policy
  commitment but **not** proven inside the ZK circuit. The TEE
  attestation chain remains the trust anchor for off-circuit
  rules; the same caveat applies as for existing rules 3/5/6.
- **ODRL "duty" and KaOS ontology features are not modeled.** This
  is a deliberate trade-off: GLYPH targets deterministic,
  on-chain-anchored rules. Higher-level policy languages are
  expected to **compile down** to the 12-rule DSL via the
  out-of-scope policy compiler (see
  `nl-to-policy-compilation.md`), not be encoded directly.
- **Authentication flows (§4.3.2 of thesis) are intentionally
  excluded.** GLYPH does not prompt the human at execution time
  (the on-chain path is asynchronous). Borderline-case prompting
  belongs in the off-chain authoring/compilation layer.
