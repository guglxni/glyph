# GLYPH Policy DSL

A GLYPH policy is a per-agent TOML file that lists the rules an agent's transactions
must satisfy. The TEE worker evaluates the policy against each transaction intent, and the
RISC Zero guest re-evaluates it inside the zkVM so the result is provable. The engine lives
in `tee-worker/src/policy.rs`; the rule variants are the `PolicyRule` enum in
`tee-worker/src/types.rs` (mirrored in `common/src/types.rs`).

The policy is **program-agnostic**: a transaction intent carries `target_program`,
`accounts[]`, and `data` as opaque bytes. The only target allowlist is the per-agent
`AllowedPrograms` rule below — there is no hardcoded allowlist in the verifier or circuit.

---

## The 9 rules

| # | Rule | Parameters | Enforces |
|---|------|-----------|----------|
| 1 | `MaxLamportsPerTx` | `max_lamports: u64` | Per-transaction lamport ceiling. |
| 2 | `AllowedPrograms` | `programs: Vec<String>` | Target program must be on the per-agent allowlist. |
| 3 | `TimeWindow` | `start_hour: u8`, `end_hour: u8` | Action only within an allowed hour window. Enforced **in-circuit and on-chain against the `Clock` sysvar** (not host-side). |
| 4 | `MaxDailyVolumeLamports` | `max_lamports: u64` | Rolling daily volume cap. |
| 5 | `RequireSlippageBpsLte` | `max_bps: u16` | Slippage must be ≤ N basis points. |
| 6 | `AllowedTokenMints` | `mints: Vec<String>` | Only approved token mints may be touched. |
| 7 | `MaxAccountsPerTx` | `max_accounts: usize` | Bounds the number of accounts in the transaction. |
| 8 | `RequireSignerPresent` | `signer: String` | A required signer must be present. |
| 9 | `PolicyExpired` | `expires_at: i64` | Policy is rejected after its expiry timestamp (unix). |

---

## Example policy (TOML)

```toml
# Each rule is one entry. The agent's transactions must satisfy all of them.

[[rules]]
type = "MaxLamportsPerTx"
max_lamports = 1_000_000_000   # 1 SOL

[[rules]]
type = "AllowedPrograms"
programs = ["G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g"]

[[rules]]
type = "TimeWindow"
start_hour = 9
end_hour = 17

[[rules]]
type = "MaxDailyVolumeLamports"
max_lamports = 10_000_000_000

[[rules]]
type = "RequireSlippageBpsLte"
max_bps = 50

[[rules]]
type = "AllowedTokenMints"
mints = ["So11111111111111111111111111111111111111112"]

[[rules]]
type = "MaxAccountsPerTx"
max_accounts = 16

[[rules]]
type = "RequireSignerPresent"
signer = "<agent-owner-pubkey>"

[[rules]]
type = "PolicyExpired"
expires_at = 1769800000
```

---

## On-chain enforcement

Several guarantees are enforced by the on-chain verifier in addition to the policy:

- **Required-rules bitmask** — the verifier can require that specific mandatory rules were
  part of the evaluated policy.
- **Image-id pinning** — pins the exact circuit the agent must have run.
- **TimeWindow** — re-checked on-chain against the `Clock` sysvar.
- **Journal expiry, attested-timestamp drift, nonce replay protection, and tx-hash binding**
  to the next instruction.

See [Architecture](architecture.md) for how these compose.
