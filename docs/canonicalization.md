# GLYPH Canonical Encoding Specification

This document specifies the byte-level canonical encodings shared by the Rust
SDK, the TypeScript SDK, the TEE worker, the ZK circuit, and the on-chain
verifier program.

The single source of truth for all encodings is the
[`glyph_common`](../common/src/lib.rs) crate. Every other component MUST either
depend on `glyph_common` directly (Rust) or replicate these byte layouts
exactly (TS).

Cross-language test vectors live in
[`sdk/test-vectors/`](../sdk/test-vectors/) and pin the expected output for a
fixed set of inputs. Any change in canonical encoding MUST regenerate the
vectors and bump the wire-format `version` field.

---

## 1. Conventions

* **Endianness**: every multi-byte integer is **little-endian**.
* **Booleans**: encoded as a single byte, `0x00` or `0x01`.
* **Optionals**: encoded as a presence byte (`0x00` for `None`, `0x01` for
  `Some`) followed by the encoded value when present.
* **Variable-length collections**: encoded as `length:u32 LE` followed by the
  concatenated entries.
* **Sorted collections**: the canonical encoder sorts byte-for-byte
  ascending before serializing. This is documented per field below.
* **Pubkeys / hashes**: 32 raw bytes (NOT base58, NOT hex). The wire format
  used by the SDK strings (base58/hex) is decoded before canonicalization.

---

## 2. `canonical_target_instruction_bytes`

Used to compute `tx_hash` — the binding between a ZK proof and the next
Solana instruction in the transaction.

```text
+------------------+--------+--------------------------------------------------+
| Field            | Size   | Description                                      |
+------------------+--------+--------------------------------------------------+
| target_program   | 32     | Solana program ID                                |
| num_accounts     | 4 LE   | u32 — count of CanonicalAccountMeta entries      |
| accounts[i]      | 34 ea  | for each account:                                 |
|   pubkey         | 32     |   account public key                              |
|   is_signer      | 1      |   0x00 / 0x01                                     |
|   is_writable    | 1      |   0x00 / 0x01                                     |
| data_len         | 4 LE   | u32 — length of `data`                           |
| data             | data_len bytes | raw instruction data                       |
+------------------+--------+--------------------------------------------------+
```

The `num_accounts` and `data_len` length prefixes close
[AUDIT_TEE T28](../audit/AUDIT_TEE.md) — the previous unframed encoding was
length-extension ambiguous.

`tx_hash = SHA-256(canonical_target_instruction_bytes(...))`.

---

## 3. `canonical_signing_payload`

The bytes the agent's Ed25519 key signs to authorize a transaction intent.

```text
+----------------------------+----------+----------------------------------+
| Field                      | Size     | Description                      |
+----------------------------+----------+----------------------------------+
| agent_pubkey               | 32       |                                  |
| nonce                      | 32       | per-intent random nonce          |
| <target_ix encoding>       | variable | exact bytes of                   |
|                            |          | canonical_target_instruction_    |
|                            |          | bytes(target_program, accounts,  |
|                            |          | data)                            |
| max_lamports               | 8 LE     | u64                              |
| max_slippage_bps presence  | 1        | 0/1                              |
| max_slippage_bps           | 2 LE     | only if presence == 1            |
| allowed_tokens presence    | 1        | 0/1                              |
| allowed_tokens count       | 4 LE     | only if presence == 1            |
| allowed_tokens entries     | 32 each  | sorted ascending                 |
| expiry                     | 8 LE     | u64 unix seconds                 |
| timestamp                  | 8 LE     | u64 unix seconds                 |
| policy_commitment          | 32       | binds signature to a specific    |
|                            |          | policy version (closes T10)      |
| worker_pubkey presence     | 1        | 0/1                              |
| worker_pubkey              | 32       | only if presence == 1; binds     |
|                            |          | signature to a specific worker   |
| epoch                      | 8 LE     | u64 — bumps on each policy       |
|                            |          | rotation; old signatures invalid |
+----------------------------+----------+----------------------------------+
```

**Why these bind matters**

* `policy_commitment` prevents replay across policy edits.
* `worker_pubkey` (when set) prevents replay against a different worker.
* `epoch` forces signatures to be re-issued after every `update_policy`
  on-chain action.

Together these close [AUDIT_TEE T10](../audit/AUDIT_TEE.md).

---

## 4. `canonical_serialize_policy`

```text
+-----------------------------------+------+-----------------------------+
| Field                             | Size | Notes                       |
+-----------------------------------+------+-----------------------------+
| version                           | 4 LE | u32                         |
| max_lamports_per_tx               | 8 LE | u64                         |
| allowed_programs count            | 4 LE | u32                         |
| allowed_programs entries          | 32 ea| **sorted ascending**        |
| time_window presence              | 1    | 0/1                         |
| time_window.start_hour_utc        | 1    | only if presence == 1       |
| time_window.end_hour_utc          | 1    | only if presence == 1       |
| max_daily_volume_lamports         | 8 LE | u64                         |
| max_slippage_bps presence         | 1    | 0/1                         |
| max_slippage_bps                  | 2 LE | only if presence == 1       |
| allowed_token_mints presence      | 1    | 0/1                         |
| allowed_token_mints count         | 4 LE | only if presence == 1       |
| allowed_token_mints entries       | 32 ea| **sorted ascending**        |
| max_accounts_per_tx presence      | 1    | 0/1                         |
| max_accounts_per_tx               | 2 LE | only if presence == 1       |
| require_signer_present            | 1    | 0/1                         |
| expires_at                        | 8 LE | u64 unix seconds (0 = none) |
+-----------------------------------+------+-----------------------------+
```

`policy_commitment = SHA-256(canonical_serialize_policy(policy))`.

The on-chain `AgentRegistry.policy_commitment` stores this hash. The ZK
circuit recomputes it inside the guest and binds it into `PublicOutputs`.

---

## 5. JSON wire format (SDK ↔ worker)

Wire JSON uses [RFC 8785 JCS](https://www.rfc-editor.org/rfc/rfc8785) for any
canonical-bytes path that crosses the JSON boundary. In practice the
worker/SDK currently only exchange JSON for transport; the *signature* is
always over the binary `canonical_signing_payload` bytes (Section 3), not over
JSON. JCS is used only for any auxiliary commitments (e.g. metadata fields)
that need to round-trip without re-encoding ambiguity.

To avoid IEEE-754 corruption of `u64` values:

* `max_lamports`, `expiry`, `timestamp`, `epoch`, `expires_at`,
  `max_daily_volume_lamports`, and `max_lamports_per_tx` MUST be encoded as
  JSON **strings** of decimal digits when transferred over JSON. The Rust SDK
  decodes them back to `u64` before canonicalization.
* `max_slippage_bps`, `max_accounts_per_tx`, `version` fit safely in a JSON
  number and are encoded as such.

---

## 6. Worked example

Input intent (intents/1.input.json):

```json
{
  "agent_pubkey": "01...01",   (32 bytes of 0x01)
  "nonce":         "02...02",   (32 bytes of 0x02)
  "target_program":"03...03",   (32 bytes of 0x03)
  "accounts": [
    { "pubkey": "04...04", "is_signer": true, "is_writable": true }
  ],
  "data_hex": "deadbeef",
  "max_lamports": "1000",
  "max_slippage_bps": null,
  "allowed_tokens": null,
  "expiry": 1700000600,
  "timestamp": 1700000000,
  "policy_commitment": "05...05",
  "worker_pubkey": null,
  "epoch": 0
}
```

The canonical encoding (hex, with annotations) is:

```text
01 .. 01                                 // agent_pubkey   (32)
02 .. 02                                 // nonce          (32)
03 .. 03                                 // target_program (32)
01 00 00 00                              // num_accounts   = 1
04 .. 04 01 01                           // account[0]: pubkey + signer + writable
04 00 00 00                              // data_len       = 4
de ad be ef                              // data
e8 03 00 00 00 00 00 00                  // max_lamports   = 1000
00                                       // max_slippage_bps = None
00                                       // allowed_tokens   = None
58 79 4f 65 00 00 00 00                  // expiry         = 1700000600
00 c1 4e 65 00 00 00 00                  // timestamp      = 1700000000
05 .. 05                                 // policy_commitment (32)
00                                       // worker_pubkey  = None
00 00 00 00 00 00 00 00                  // epoch          = 0
```

Total length: `32+32 + (32+4+34+4+4) + (8+1) + 1 + (8+8+32) + 1 + 8 = 209 bytes`
(matches `sdk/test-vectors/intents/1.canonical.bytes`).

`tx_hash = SHA-256(target_ix_bytes)` is what is committed to inside the
circuit. `signature = Ed25519(canonical_signing_payload).Sign(agent_sk)`.

Run `bash scripts/gen-test-vectors.sh` to (re)materialize the
`*.canonical.bytes` and `*.signed.json` files for every input under
`sdk/test-vectors/`. CI MUST run this script and assert no diff.

---

## 7. Versioning

The `version: u32` prefix in `Policy` is the policy schema version. There is
currently no explicit version prefix in `canonical_signing_payload` — the
implicit version is "Glyph v1".

A future encoding change MUST:

1. Bump a new explicit version byte at the head of the payload.
2. Regenerate `sdk/test-vectors/`.
3. Update both Rust and TS SDKs in lockstep.
4. Bump the on-chain verifier program (existing nonces remain valid only if
   the migration script reproves them).
