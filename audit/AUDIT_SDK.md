# GLYPH SDK + Policy DSL Audit

**Date**: 2026-05-10
**Scope**: `sdk/rust/src/*`, `sdk/typescript/src/*`, `common/src/lib.rs`, `docs/policy-dsl.md`, `examples/*`
**Auditor goal**: Production-readiness review focused on cross-language canonicalization, mocks, error mapping, DSL completeness, type drift, replay protection, examples, and tests.

---

## Findings

### F-1 [CRITICAL] (A) Cross-language canonical signing payload mismatch — `max_lamports`

`sdk/rust/src/intent.rs:178-205` (Rust) and `sdk/typescript/src/intent.ts:54-56,189-200` (TS) both build a "canonical" payload by sort-keys + `JSON.stringify` / `serde_json::to_vec`. They will produce **different bytes** for identical logical inputs because:

- Rust serializes `IntentConstraints.max_lamports: u64` as a **JSON number** (e.g. `50000000`).
- TS coerces it to a **JSON string** (`sdk/typescript/src/intent.ts:190` — `this.constraints.maxLamports.toString()`), e.g. `"50000000"`.

The TEE worker re-builds the canonical payload using the same Rust struct (`tee-worker/src/main.rs:326-351`, with `IntentConstraints.max_lamports: u64` at `tee-worker/src/types.rs:46`). Therefore **every TS-built intent will fail Ed25519 signature verification at the worker**, and even before that will fail Serde deserialization (`u64` cannot accept a JSON string).

**Fix**: pick one wire format and enforce it on both sides. Recommended: keep `max_lamports` as JSON number with a guard that values fit in JS `Number.MAX_SAFE_INTEGER` for the TS path, OR change the wire format to a string and update Rust with `#[serde(with = "serde_with::DisplayFromStr")]` on `max_lamports`. Add a cross-language vector test (see F-9).

---

### F-2 [HIGH] (A) Optional-field encoding divergence

In Rust, `IntentConstraints` has `#[serde(skip_serializing_if = "Option::is_none")]` on `max_slippage_bps` and `allowed_tokens` (`sdk/rust/src/types.rs:44-51`). In TS, the builder spreads only when defined (`sdk/typescript/src/intent.ts:191-197`). These align in the *omitted* case, but:

- A consumer who passes `null` from JS will produce `"allowed_tokens": null` (preserved by the canonicalizer at line 23 — `value === null` → returned as `null`). Rust's `Option::is_none` skips, so `null` ≠ missing. Same canonical-key sort, different bytes.
- Empty arrays vs missing: TS `allowedTokens([])` will emit `"allowed_tokens": []`; Rust requires `Some(vec![])`. Equivalent semantically, distinct bytes.

**Fix**: have the TS canonicalizer drop `null` keys (treat `null` and `undefined` the same), and validate that empty `Vec`/array is rejected at the builder boundary (or canonicalized identically on both sides).

---

### F-3 [HIGH] (E) Type drift: `AccountMeta` field naming

- Rust SDK `types.rs:38-42`: `is_signer`, `is_writable` (snake_case).
- TS interface `types.ts:5-9`: `isSigner`, `isWritable` (camelCase).
- TS test `__tests__/sdk.test.ts:43-44`: uses `is_signer`, `is_writable` — does **not** match the declared interface; only compiles because TS allows extra/unknown keys via object literal widening through `accounts()` (the value gets stamped through unchanged into the wire payload at `intent.ts:186`).

Result: TS users following the typed interface will produce camelCase accounts on the wire; the worker's `AccountMeta` (snake_case, `tee-worker/src/types.rs:39-43`) will fail to deserialize. The test passes only because it bypasses the typed shape.

**Fix**: TS interface must use `is_signer` / `is_writable` (or add `serde(alias)` on the worker side and translate in `IntentBuilder.accounts`). Update `sdk.test.ts` to exercise the public typed surface.

---

### F-4 [HIGH] (E) Type drift: `Groth16Proof` byte arrays

- Rust SDK `types.rs:55-59`: `a: [u8; 64], b: [u8; 128], c: [u8; 64]`.
- TS SDK `types.ts:44-48`: `a: number[]; b: number[]; c: number[]` — no fixed length, no validation.
- TEE worker `tee-worker/src/types.rs:53-62`: `#[serde_as(as = "Bytes")]` — encodes as a byte array, but in `serde_json` this becomes `[u8]` numbers. The Rust SDK without `#[serde_as]` will serialize the `[u8; 64]` as a JSON array of 64 numbers (since `serde_json` defaults arrays of u8 to numeric arrays for `[u8; N]`).

The Rust SDK `GlyphProofBundle` is *received* from the worker. If the worker uses `serde_with::Bytes` (which for JSON encodes as an array of numbers — same shape as the SDK's plain `[u8; 64]`), this happens to align, but the contract is fragile and undocumented; a future switch to base64/hex on the worker side breaks the Rust SDK silently.

**Fix**: pin proof encoding (recommend hex or base64 strings) in `common/` and use `#[serde_as]` with the same encoder in both worker and SDK. TS should expose `Uint8Array`-aware constructors and validate lengths.

---

### F-5 [HIGH] (D) Policy DSL spec/implementation drift — `expires_at` field

`common/src/lib.rs::Policy` has a field **`expires_at: u64`** (line ~31) included in `canonical_serialize_policy` (last 8 bytes of canonical encoding). It is **absent from `docs/policy-dsl.md`** (the spec lists 9 serialized fields ending at `require_signer_present`). The worker config `tee-worker/src/policy.rs::PolicyConfig` does **not** parse it from TOML, so `config_to_canonical` always sets `expires_at = 0`. Three consequences:

1. The DSL spec is untruthful — operators cannot author policies with expiry.
2. The on-chain commitment commits to a field nobody can configure.
3. If a future worker sets `expires_at` from TOML, every existing policy commitment changes silently.

**Fix**: either (a) remove `expires_at` from `common::Policy` and `canonical_serialize_policy` (and from any circuit bindings), or (b) wire it through the TOML schema and document it as Rule 9. Pick one and ship a migration note.

---

### F-6 [MEDIUM] (D) Rule 8 `require_signer_present` field rename in canonical struct

DSL spec uses `require_signer_present`. `common::Policy` renames it to `require_signer` (line ~28). The worker correctly re-maps (`policy.rs:266`). Cosmetic but error-prone — a downstream tool that reads the canonical Policy via Borsh/Serde and re-emits TOML will produce a non-matching key.

**Fix**: rename the canonical field to `require_signer_present` to match the spec, or add an explicit serde rename + document.

---

### F-7 [MEDIUM] (B) Mock / unsafe defaults in TS `GlyphClient`

`sdk/typescript/src/client.ts:21-29` accepts any string `teeEndpoint` and only rejects empty. `sdk.test.ts:23-31` happily uses `tcp://127.0.0.1:8088` and `https://api.devnet.solana.com` — the localhost-default footgun pattern. There is no:

- TLS pin / attestation hash check on the TEE endpoint.
- Warning when the endpoint is `127.0.0.1` / `localhost` / `0.0.0.0`.
- Validation that `tcp://` is paired with a known-secure transport.

The Rust client (`client.rs:104-126`) is identical — strips `tcp://`, `http://`, `https://` and treats them all as raw `host:port` for an unauthenticated TCP socket (`client.rs:49-51`). HTTPS is therefore **silently downgraded to plaintext TCP**.

**Fix**: in both SDKs, only accept explicit transports; reject `http://`/`https://` unless an actual HTTP client is implemented (Rust currently doesn't); require an attestation pin or TLS cert pin on the TEE endpoint; emit a console warning when endpoint resolves to loopback in non-test mode.

---

### F-8 [MEDIUM] (C) Error mapping collapses real failure modes

TS `client.ts:35-56`: every transport, parse, and worker error becomes a generic `Error("...")` — callers cannot distinguish *connection refused* from *policy denial* from *malformed bundle*. There is no typed `GlyphError` enum.

Rust `errors.rs` has 8 variants, but `client.rs` collapses bincode + JSON failures into one `SerializationError` and TCP read/write/shutdown into a single `TeeConnectionError`. Notably missing: `IntentExpired`, `NonceReused`, `PolicyDenied(rule_id)`, `AttestationRejected`, `ProofVerifyFailed` — all of which the worker can return as distinct codes via `WorkerResponse::Error { code, message }`.

**Fix**: define `GlyphError` enum in TS mirroring the Rust set; surface the worker's `code` field as an enum discriminator (so callers can `if (e.code === 'POLICY_DENIED')`). Document the worker's full code set in `policy-dsl.md` or a new `error-codes.md`.

---

### F-9 [HIGH] (H) Tests do not verify cross-language canonical equivalence

`sdk.test.ts:114-134` checks only that *different inputs produce different signatures*. It never:

- Compares the canonical bytes against a Rust-produced fixture.
- Verifies the produced signature with `tweetnacl.sign.detached.verify` against the public key.
- Tests an intent built in TS being verified by an Ed25519 verifier with the Rust canonicalizer.

Given F-1, the suite would have caught the bug if it loaded a JSON fixture produced by the Rust SDK and asserted byte-equality of the canonical payload.

**Fix**: add a fixtures directory `sdk/test-vectors/` with intents canonicalized by the Rust SDK (script in `scripts/`) and assert TS produces identical bytes; add a verify-signature test that runs nacl verify against the Rust-produced signature.

---

### F-10 [MEDIUM] (G) Examples hide the bug

`examples/intent.json` has `"max_lamports": 1500000000` (number, no quotes) — matching the Rust wire format, contradicting the TS SDK output. Anyone using this fixture to test against a TS-built intent will see a divergence.

`examples/policy.toml` is missing `expires_at` (consistent with worker but inconsistent with `common::Policy`), masking F-5.

**Fix**: regenerate examples from canonical source (a small CLI in `scripts/` that uses `IntentBuilder` directly), and add both a Rust-built and TS-built example to highlight equivalence.

---

### F-11 [MEDIUM] (F) Replay protection is implicit and SDK-opaque

Nonce is generated inside `IntentBuilder.build` (random 32 bytes — Rust `intent.rs:144`, TS `intent.ts:175`). The SDK never:

- Surfaces the nonce to the caller pre-build for client-side dedup.
- Checks epoch / slot for staleness.
- Provides any deterministic-nonce mode for replay testing.

The worker tracks nonces in-memory (per F-10 in the TEE audit), so a worker restart re-opens the replay window. The SDK does not even document this.

**Fix**: add `IntentBuilder.with_nonce(...)` for caller-supplied nonces and a `current_epoch_window()` helper; document in the SDK docstring that replay protection requires a persistent worker store + on-chain epoch check.

---

### F-12 [LOW] (D) `IntentBuilder` does not expose Rule 7 / Rule 5 explicitly

Rules 5 (`require_slippage_bps_lte`) and 7 (`max_accounts_per_tx`) are *enforced* server-side, but the SDK builder in both languages does not mirror them as explicit setters with bounds-checking. A user can build an intent with 256 accounts and only learn at the worker. Same for slippage — the TS builder accepts any `number`, no `0..=10_000` bps validation.

**Fix**: add client-side bounds validation matching DSL caps (slippage ≤ 10000, accounts length cap configurable from a fetched policy).

---

### F-13 [LOW] (B) TS `tcp://` parsing accepts garbage

`client.ts:100-110` uses `new URL('tcp://...')` which is non-standard for `tcp:` and may behave inconsistently across Node versions; `Number(url.port)` returns `NaN` if the port is missing and the check `port <= 0` does not catch `NaN`.

**Fix**: parse `tcp://host:port` with a regex; reject explicitly if port missing.

---

## Severity Summary

| ID   | Sev      | Cat | One-liner |
|------|----------|-----|-----------|
| F-1  | CRITICAL | A   | `max_lamports` is u64 in Rust JSON, string in TS JSON — every TS intent fails worker verify |
| F-2  | HIGH     | A   | `null` vs missing optional fields differ between Rust and TS canonical bytes |
| F-3  | HIGH     | E   | `AccountMeta` is camelCase in TS interface, snake_case on the wire and in worker |
| F-4  | HIGH     | E   | `Groth16Proof` lengths unvalidated in TS; encoding contract not pinned |
| F-5  | HIGH     | D   | `Policy.expires_at` is committed but not in spec or TOML — silent commitment drift |
| F-6  | MEDIUM   | D   | Canonical struct field renamed from `require_signer_present` to `require_signer` |
| F-7  | MEDIUM   | B   | Both SDKs accept `https://`/loopback endpoints with no TLS or attestation pin |
| F-8  | MEDIUM   | C   | Errors collapsed to generic `Error`; `GlyphError` enum missing in TS, incomplete in Rust |
| F-9  | HIGH     | H   | No cross-language canonical-bytes test; signature test only diff-checks |
| F-10 | MEDIUM   | G   | `examples/intent.json` and `examples/policy.toml` mask F-1 and F-5 |
| F-11 | MEDIUM   | F   | Nonce/epoch handling implicit; SDK exposes nothing to callers |
| F-12 | LOW      | D   | Builder does not enforce Rule 5 / Rule 7 client-side |
| F-13 | LOW      | B   | TS `tcp://` URL parsing brittle; `Number(port)` NaN not caught |

## Top three to fix before any production traffic

1. **F-1**: pick one wire format for `max_lamports` and enforce it both sides; ship a fixture-driven cross-language test (F-9).
2. **F-5**: reconcile `Policy.expires_at` with the DSL spec or remove it — current state changes the on-chain commitment surface invisibly.
3. **F-3**: fix `AccountMeta` camelCase/snake_case drift; the test suite only passes because it bypasses the public type.
