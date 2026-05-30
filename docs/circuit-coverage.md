# GLYPH Circuit Coverage

This document is the canonical map of which policy rules are enforced **inside
the ZK circuit** (committed in `PublicOutputs.circuit_rule_bitmap`, gated
on-chain by `REQUIRED_RULES_MASK`) versus those that remain **off-circuit**
and tied in by the `policy_commitment` + TEE attestation envelope.

The on-chain verifier (`programs/glyph-verifier/src/lib.rs::verify_and_execute`)
rejects any proof whose `circuit_rule_bitmap` is missing a required bit, so
operators can read this table to know precisely what a successful verification
implies about a transaction.

## Status matrix

| # | Rule                       | Bit                           | Where enforced | Notes |
|---|----------------------------|-------------------------------|----------------|-------|
| 1 | `max_lamports_per_tx`      | `RULE_BIT_MAX_LAMPORTS`       | **In-circuit** | Stateless numeric bound. |
| 2 | `allowed_programs`         | `RULE_BIT_ALLOWED_PROGRAMS`   | **In-circuit** | Linear scan against policy-committed list. |
| 3 | `time_window`              | `RULE_BIT_TIME_WINDOW`        | **In-circuit** (WS-8) | Guest derives `hour` from `attested_timestamp`; verifier asserts `|attested_timestamp − Clock| ≤ 300s`. Closes AUDIT_TEE T9. |
| 4 | `max_daily_volume_lamports`| `RULE_BIT_DAILY_VOLUME`       | **Off-circuit** | Requires TEE-attested per-bucket state. Worker tracks volume in a sealed file; on-chain `DailyBucket` PDA is future work — substantial complexity for marginal gain at current scale. |
| 5 | `max_slippage_bps`         | `RULE_BIT_SLIPPAGE`           | **In-circuit** | Compared field-by-field with the intent. |
| 6 | `allowed_token_mints`      | `RULE_BIT_ALLOWED_TOKEN_MINTS`| **Off-circuit** | Would require Merkle-inclusion proofs per claimed mint inside the circuit. The data path is wired (`build_mint_merkle_root`, `verify_mint_merkle_path`), but the worker→guest plumbing for inclusion proofs is not — until the SDK surfaces mint paths, this rule stays TEE-attested via the policy commitment. |
| 7 | `max_accounts_per_tx`      | `RULE_BIT_MAX_ACCOUNTS`       | **In-circuit** | Count comparison. |
| 8 | `require_signer_present`   | `RULE_BIT_REQUIRE_SIGNER`     | **In-circuit** | Guest reads the boolean `has_signer` from `IntentExtras`; worker derives it from the intent. |
| 9 | `expires_at` / `expiry`    | `RULE_BIT_POLICY_EXPIRY`      | **In-circuit** | Plus on-chain `Clock` check on `expiry`. |

## `REQUIRED_RULES_MASK`

The verifier currently requires the **five rules the circuit fully proves
without auxiliary on-chain state**:

```rust
const REQUIRED_RULES_MASK: u32 = RULE_BIT_MAX_LAMPORTS
    | RULE_BIT_ALLOWED_PROGRAMS
    | RULE_BIT_TIME_WINDOW
    | RULE_BIT_MAX_ACCOUNTS
    | RULE_BIT_REQUIRE_SIGNER;
```

Adding `RULE_BIT_SLIPPAGE` and `RULE_BIT_POLICY_EXPIRY` to the mask is safe
once we audit guest's slippage/expiry edge cases against the verifier; they
are not in the mask today only because they have no on-chain coupling like
`time_window` does (whose semantics require a fresh `Clock` cross-check).

## Why the off-circuit rules stay off-circuit

- **`max_daily_volume_lamports`** — requires per-(agent, day) state. To make
  this trust-minimised inside the proof we would need either (a) a TEE-
  attested commitment to the bucket cursor that the on-chain verifier
  diffs against a `DailyBucket` PDA, or (b) a Merkle-accumulator of all
  spend events. Both are tractable; neither is free. Today the rule is
  enforced by the worker against a sealed file and rotated nightly.

- **`allowed_token_mints`** — Merkle inclusion is implemented
  (`merkle_*` helpers in `glyph-common`), and the guest already calls
  `verify_mint_merkle_path` when paths are supplied. The missing piece is
  the SDK→worker path that surfaces inclusion proofs per intent. Until
  that lands, the worker enforces the mint allowlist by string compare
  and the rule stays off the verifier's required mask.

## Attested-timestamp drift

The on-chain check is:

```rust
let drift = (clock_now - attested_timestamp).abs();
require!(drift <= ATTESTED_TIMESTAMP_MAX_DRIFT_SECS, …);
```

with `ATTESTED_TIMESTAMP_MAX_DRIFT_SECS = 300` (±5 minutes). The Lean
proof in `formal_verification/Proofs/Freshness.lean` (`fr2_attested_drift`)
states the same invariant.
