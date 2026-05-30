# GLYPH ZK Pipeline — Production-Readiness Audit

**Auditor:** Claude (Opus 4.7, 1M context)
**Date:** 2026-05-10
**Scope:**
- Guest circuit: `circuits/glyph-circuit/guest/src/main.rs`
- Host prover: `circuits/glyph-circuit/host/{src/lib.rs, src/types.rs, build.rs, tests/integration.rs, Cargo.toml}`
- On-chain verifier: `programs/glyph-verifier/src/{lib.rs, errors.rs, client_utils.rs, groth16/{mod.rs, verifier.rs, vk.rs}}`
- TEE-worker prover invocation: `tee-worker/src/{prover.rs, types.rs, main.rs}`
- VK extractor: `scripts/extract-vk/src/main.rs`
- Common types: `common/src/lib.rs`

**Cross-references:**
- `aidlc-docs/zk-upgrade-design.md` (design doc, status "In Progress")
- `docs/SECURITY_AUDIT.md` (3 prior findings, all marked PATCHED)

---

## Summary of severity

| # | Severity | Finding | New / Known |
| --- | --- | --- | --- |
| 1 | **CRITICAL** | Hardcoded "DEV" Groth16 verification key in `vk.rs` accepts no real proofs (and arithmetic on it is undefined) | NEW |
| 2 | **CRITICAL** | Public input derivation omits `image_id` — even a real VK would not match RISC Zero's `claim_digest` | NEW |
| 3 | **CRITICAL** | `verify_vk_integrity()` is dead code — never called from `verify_groth16` | NEW |
| 4 | **CRITICAL** | No subgroup / on-curve check on `proof_a`, `proof_b`, `proof_c`, or `vk_x` | NEW (sBPF foot-gun) |
| 5 | **CRITICAL** | DevProver path remains in production binary; only opt-out is an env var checked at startup | NEW |
| 6 | **CRITICAL** | `verify_attestation_commitment` does substring search on raw attestation bytes — bypassable | Partial overlap with prior Finding #2 |
| 7 | **HIGH** | `GLYPH_CIRCUIT_ELF` is empty without `risc0` feature; default workspace build has no ELF | Acknowledged in design doc |
| 8 | **HIGH** | `image_id` (`GLYPH_CIRCUIT_ID`) is hardcoded to all zeros without `risc0` feature; no on-chain commitment to circuit version | NEW |
| 9 | **HIGH** | VK has no on-chain swap mechanism — VK upgrade requires full program upgrade with no governance/timelock | NEW |
| 10 | **HIGH** | `g1_negate` does naive subtraction without modular reduction — incorrect when `y > p` (and never validates `y < p`) | NEW |
| 11 | **HIGH** | `field_sub` in scalar reduction borrows incorrectly past the high byte — wraps silently | NEW |
| 12 | **HIGH** | `reduce_scalar` only subtracts `r` once; SHA-256 outputs may be `>= 2r` in pathological cases (mostly fine in practice but unsound) | NEW |
| 13 | **HIGH** | Compute budget (1.4M CU) is set client-side only; on-chain code does not enforce / detect insufficient budget | NEW |
| 14 | **HIGH** | The dev VK encodes `(0,1)` and `(0,2)` as G1 points — not on the BN254 curve; pairing syscall behavior is undefined / will silently abort | NEW |
| 15 | **HIGH** | RISC Zero seal extraction assumes RISC Zero v1.x layout; no version check against actual seal selector | NEW |
| 16 | **MEDIUM** | DevProver constructs a "fake but structurally valid" bundle and returns it through the same channel as real proofs (no type-level distinction) | NEW |
| 17 | **MEDIUM** | The `expires_at` rule allows `expires_at == 0` to mean "no expiry" — silently disables expiry check, easy footgun | NEW |
| 18 | **MEDIUM** | `intent.expiry` is committed in the journal but is **not** checked against on-chain `Clock` at `verify_and_execute` time | NEW |
| 19 | **MEDIUM** | `tx_signature` field in `GlyphProofBundle` is set to `hex(tx_hash[..8])` — not a real signature, misleading naming | NEW |
| 20 | **MEDIUM** | Nonce uniqueness derived only from `(epoch, nonce)`; the `agent_pubkey` is *not* part of the seed — two agents in the same epoch could clash | NEW |
| 21 | **MEDIUM** | `policy_epoch` is `u32` and increments by 1 per update with no monotonic clock binding; bumping past `u32::MAX` is checked but governance cadence not bounded | LOW |
| 22 | **MEDIUM** | Guest circuit does **not** assert `intent.expiry > 0`; an intent with expiry 0 + `policy.expires_at == 0` skips both expiry checks entirely | NEW |
| 23 | **MEDIUM** | Guest circuit only enforces 6 of 9 policy rules; `time_window`, `daily_volume`, `allowed_token_mints` are circuit-out (acknowledged) but not flagged in journal so verifier cannot tell which subset was proven | NEW (partial ack) |
| 24 | **MEDIUM** | `extract_vk` script's `#[cfg(feature = "risc0")]` path is itself a stub — calls `bail!` with instructions instead of extracting | NEW |
| 25 | **MEDIUM** | `extract_vk` non-risc0 path emits deterministic seeded "VK" that is structurally a VK but is not on-curve — copy/paste foot-gun | NEW |
| 26 | **MEDIUM** | Production-mode check uses `panic!` instead of `Err` → restart loops in supervisors instead of clean failure | LOW |
| 27 | **MEDIUM** | Replay: nonce PDA uses `init` (not `init_if_needed`); replay returns `NonceInitializationFailed` (Anchor-internal) instead of explicit `NonceAlreadyConsumed` — harder to detect operationally | NEW |
| 28 | **LOW** | `next_ix.is_signer` & `is_writable` are hashed by the verifier but the *guest circuit* hashes only `tx_bytes` (raw instruction data only, not full canonical instruction) — circuit `tx_hash` ≠ on-chain `tx_hash` if `tx_bytes` is just data | NEW (verify) |
| 29 | **LOW** | `tx_signature: String` in bundle is unbounded — DoS vector for clients that store bundles | NEW |
| 30 | **LOW** | `image_id` (`GLYPH_IMAGE_ID`) value `[0x48544f52, ...]` decodes as ASCII `"HTORN_DEV_V_KVA LUE_PLACEHOLDER_"` — stark visual signal that this is dev | INFO |
| 31 | **INFO** | Design doc `aidlc-docs/zk-upgrade-design.md` itself says "Status: In Progress" and calls Option A/B/C — current state is mid-construction | KNOWN |
| 32 | **INFO** | No fuzz / property tests for the verifier — only smoke tests of `field_sub` and `reduce_scalar` | NEW |
| 33 | **INFO** | Guest circuit uses `assert!`/`panic!` for all rule failures; no granular failure code reaches the journal | NEW |

---

## A. Mocks / stubs / fake values

### F-1 — Hardcoded "DEV" Groth16 VK (CRITICAL)

**File:** `programs/glyph-verifier/src/groth16/vk.rs:88-190`

The on-chain `GLYPH_VK` constant is a placeholder. `alpha_g1` is `(0, 2)`, `beta_g2`, `gamma_g2`, `delta_g2` are similar all-zero-with-trailing-1s, and `ic_0`, `ic_1` are `(1, 1)`. The file itself contains a 13-line "CRITICAL SECURITY WARNING" banner (line 75-87) explaining that this VK provides no cryptographic security. Any real RISC Zero proof submitted against this VK will fail — but the bigger issue is that the syscall behavior on these non-on-curve points is undefined (see F-14). The `GLYPH_VK_HASH` (line 197-202) is also a dummy value — not derived from the real VK and not equal to `SHA-256` of the dev VK either (so even `verify_vk_integrity()` would fail closed if it were called, see F-3).

**Recommended fix:**
1. Build the guest with `--features risc0` and the RISC Zero toolchain.
2. Implement `extract_vk_from_proving_key` in `scripts/extract-vk/src/main.rs:146` (currently a `bail!`) so the real VK can be derived from the embedded ELF.
3. Replace the constant; recompute `GLYPH_VK_HASH`; redeploy.
4. Add a CI check that fails the build if `GLYPH_VK.alpha_g1 == [0u8; 32, ..., 0u8; 32]` or any field is structurally a placeholder.

**Status vs prior audit:** NEW. `docs/SECURITY_AUDIT.md` does not mention the VK; only the data-only `tx_hash` issue and the attestation bypass on `update_policy` are tracked.

---

### F-5 — DevProver in production binary (CRITICAL)

**File:** `tee-worker/src/prover.rs:168-234`, `tee-worker/src/main.rs:43-58, 109-122`

`DevProver` is unconditionally compiled into the worker. The only barrier is a runtime `panic!` chain in `main.rs:34-58` when `GLYPH_MODE=production`:

- requires `--features risc0`
- requires `GLYPH_PROVER=risc0` env var
- requires `RISC0_DEV_MODE` to be unset

But:
- The `Prover` trait (line 14) is shared by both backends; the `AppState.prover: Arc<dyn Prover>` field can hold either. There is no type-level distinction.
- An operator who launches with `GLYPH_MODE=staging` (line 124-125: warn, do not enforce) keeps the dev path live.
- A misconfiguration that flips runtime_mode (default is `Dev` per `default_runtime_mode()` in `tee-worker/src/types.rs:144-146`) silently downgrades.
- `DevProver.generate_proof` produces a **structurally valid** bundle (`a`, `b`, `c` are 64/128/64 bytes derived deterministically from public inputs; journal_bytes are real). Off-chain consumers cannot distinguish the bundle from a real one without verifying the proof — exactly what the SDK is *not* required to do before submission.

**Recommended fix:**
- Gate `DevProver` behind `#[cfg(any(test, feature = "dev-prover"))]` so it does not exist in release artifacts.
- Add a sentinel byte / discriminator in the bundle that a real Groth16 receipt sets and `DevProver` cannot.
- Default `runtime_mode` to `Production` and require explicit opt-down to `Dev`.
- Have `Production` panic happen *before* opening the listener (it currently does, good), but also abort if `--features risc0` is enabled but `GLYPH_VK` is the placeholder (see F-1).

**Status vs prior audit:** NEW.

---

### F-7 — Empty `GLYPH_CIRCUIT_ELF` without `risc0` feature (HIGH)

**File:** `circuits/glyph-circuit/host/src/lib.rs:38-47`

```rust
#[cfg(not(feature = "risc0"))]
pub const GLYPH_CIRCUIT_ELF: &[u8] = &[];

#[cfg(not(feature = "risc0"))]
pub const GLYPH_CIRCUIT_ID: [u32; 8] = [0u32; 8];
```

Default `cargo build` of the workspace produces a host crate with no circuit. `generate_proof()` returns `Err`. The TEE worker's `RiscZeroProver` is `#[cfg(feature = "risc0")]` (prover.rs:73-155) so it doesn't even exist in the default build — the only available `Prover` impl is `DevProver`. In other words, **without an explicit feature flag and toolchain, the entire ZK pipeline is a stub**, and the binary still compiles, runs, and accepts traffic.

**Recommended fix:**
- Make `risc0` a default feature for release builds.
- Have `host/build.rs` `panic!` if the resulting ELF is `<MIN_BYTES`.
- Add `pub fn assert_real_circuit() { assert!(!GLYPH_CIRCUIT_ELF.is_empty()) }` and call it from worker startup.

**Status:** Acknowledged in `aidlc-docs/zk-upgrade-design.md` Layer 1, but the doc says "In Progress" — it is not done.

---

### F-8 — `GLYPH_CIRCUIT_ID = [0u32; 8]` without `risc0` feature (HIGH)

**File:** `circuits/glyph-circuit/host/src/lib.rs:47`

The image ID is what cryptographically binds the circuit code to the proof. Setting it to all zeros means there is no commitment to circuit version anywhere reachable in the default build. Combined with F-2, it means the on-chain verifier has no way to know whether a proof was generated for v1, v2, or a malicious v3 of the circuit even after the VK is fixed.

**Recommended fix:** See F-7. Additionally, store `image_id` in `AgentRegistry` at registration time and require it to match the proof's `image_id` (which must become a public input — see F-2).

---

### F-24 / F-25 — `extract-vk` script is itself a stub (MEDIUM)

**File:** `scripts/extract-vk/src/main.rs:146-157`

The `#[cfg(feature = "risc0")]` `extract_vk_from_proving_key()` returns `bail!("VK extraction from proving key requires running the prover. ...")`. So even after installing the RISC Zero toolchain, the documented workflow `cargo run --bin extract-vk --features risc0` does not actually extract a VK.

The non-risc0 fallback (line 159-221) generates deterministic "placeholder" VK bytes from a SHA-256 PRF and writes them to vk.rs in the same shape as a real VK. There is no visible warning at the byte level — only `eprintln!` warnings on stderr. An operator who runs the script and pipes its stdout into `vk.rs` (as the doc suggests) gets a fake VK with no marker that it is fake other than `image_id == 0x48544f52...` (which is "HTOR" ASCII — see F-30).

**Recommended fix:**
- Implement extraction by running a `RISC0_DEV_MODE=1` proof and pulling `receipt.inner.groth16()?.verifier_parameters` (RISC Zero v1.x exposes this).
- Remove the non-risc0 placeholder path, or have it write a clearly-broken VK (e.g., all 0xFF) so on-curve checks reject it.

---

### F-30 — `GLYPH_IMAGE_ID` is ASCII "HTOR_DEV..." (INFO)

**File:** `programs/glyph-verifier/src/groth16/vk.rs:47-50`

The 8 u32s decode to ASCII bytes spelling "RTOH"/"DE_N"/"V_V_"/"AVK_"/"_EUL"/"CALP"/"LOHE"/"_RED" (little-endian). It is a visual marker. Useful for grep, useless for security.

---

## B. Fallbacks / dual paths

### F-5 already covers DevProver fallback.

The host code has no fallback inside `generate_proof` — it either runs the real prover or returns `Err`, which is correct.

The verifier has no "if proof bytes look fake, accept anyway" fallback — every code path goes through `verify_groth16`. Good.

But:

### F-26 — Production check is `panic!` on hot path (LOW/MEDIUM)

**File:** `tee-worker/src/main.rs:34-58`

`panic!` in `main()` aborts with a stack trace that includes env vars in some configurations. In production this should be a clean `Err` returned from `load_config`/`main` so systemd/k8s see the failure, log it, and back off. As written, restart loops will hammer crash logs.

---

## C. VK lifecycle

### F-3 — `verify_vk_integrity()` is dead code (CRITICAL)

**File:** `programs/glyph-verifier/src/groth16/vk.rs:216-234`, never called from `verify_groth16`.

The function exists, computes `SHA-256(VK)`, compares to `GLYPH_VK_HASH`, and returns bool. But:
- It is `pub fn`, never invoked from `verify_and_execute`, `verify_groth16`, or anywhere in the codebase (`grep -rn verify_vk_integrity` yields one definition only).
- Even if called, `GLYPH_VK_HASH` is a dummy constant (line 197-202), so it would fail-closed in dev (returns `false`) but would never detect tampering in prod because the hash is never recomputed against the real VK.

**Recommended fix:** Either remove the function or call it from `verify_groth16` at the top:

```rust
require!(verify_vk_integrity(), GlyphError::InvalidVerifyingKey);
```

Even better: since the VK is `const`, compute the hash at compile time (`const fn` SHA-256) and emit a build error if mismatched.

---

### F-9 — No on-chain VK swap mechanism (HIGH)

**File:** `programs/glyph-verifier/src/groth16/vk.rs:88` (`pub const GLYPH_VK`)

The VK is a `pub const`. Updating it requires:
1. Recompiling the program.
2. `anchor upgrade` against the `glyph-verifier` program ID.
3. No timelock, no multisig, no on-chain commitment that operators can verify before signing the upgrade.

Neither `VerifierConfig` (lib.rs:79-90) nor any other PDA stores a VK hash. There is no event emitted when a VK changes (the program upgrade itself emits a generic upgrade event; operators have no app-level signal).

**Recommended fix:**
- Move VK into a `VerifierConfig` PDA (or a new `VkAccount` PDA). Read it at verify time (~64*4 + 128*3 = 640 bytes; cheap).
- Gate updates with a multisig + timelock.
- Emit `VkUpdated { old_hash, new_hash, image_id, timestamp }`.
- Have `AgentRegistry` pin a specific `image_id` so existing agents are not silently re-bound to a new circuit.

---

## D. Groth16 verifier correctness

### F-2 — Public input derivation omits `image_id` (CRITICAL) — and the deeper 5-vs-1 bug

**Files:** `programs/glyph-verifier/src/lib.rs:423`, `programs/glyph-verifier/src/groth16/verifier.rs:42-58`

```rust
// lib.rs:423
let public_inputs = Sha256::digest(&args.journal_bytes);
groth16::verifier::verify_groth16(&args.proof.a, &args.proof.b, &args.proof.c, &public_inputs.into())?;
```

But the verifier doc-comment in `verifier.rs:50-58` itself says:

> RISC Zero's Groth16 prover sets the public input as: PI = SHA-256(SHA-256(journal_bytes))
> Note: RISC Zero actually hashes the journal using its own Poseidon-based digest, but for the Groth16 wrapper it uses SHA-256 of the STARK receipt's image_id || journal.
> ... The prover computes: claim_digest = sha256(image_id || sha256(journal))

So the actual RISC Zero claim digest is `sha256(image_id || sha256(journal))`, not `sha256(journal)`. The current code computes the wrong public input. Even with a correct VK, no real RISC Zero Groth16 proof will pass verification. This is a *correctness* bug, not just a security gap — the verifier as written is mathematically incompatible with the RISC Zero prover that the host invokes.

**UPDATE (real-VK extraction):** while fixing F-2 we discovered the bug runs **a layer deeper** than originally written here. A RISC Zero v1.2.x Groth16 receipt has **5 Groth16 public inputs**, not 1. The receipt verifier in `risc0_zkvm-1.2.6/src/receipt/groth16.rs` (lines 85–105) feeds:

```text
public_inputs = [
    a0, a1,     // split_digest(control_root)
    c0, c1,     // split_digest(claim_digest)
    id_bn254_fr // bn254_control_id reversed, decoded as Fr
]
```

into the Groth16 verifier, against an IC vector of length **6**. Computing `claim_digest` correctly is necessary but not sufficient: the on-chain `vk_x` must be

```text
vk_x = IC[0] + s0·IC[1] + s1·IC[2] + s2·IC[3] + s3·IC[4] + s4·IC[5]
```

with the five scalars above. Earlier iterations of this audit's recommended fix would still have failed every real proof because both the VK shape and the public-input arity were wrong.

**Recommended fix (now landed):**
1. Make `image_id` a stored field on `AgentRegistry` (see F-9) or a global `VerifierConfig` field. ✅
2. Compute `claim_digest = sha256(image_id_bytes || sha256(journal_bytes))`. ✅
3. Extend the on-chain VK and `VerifierVk` PDA to carry **6** IC entries plus `control_root` and `bn254_control_id` digests (read from `risc0_zkvm::Groth16ReceiptVerifierParameters::default()`). ✅
4. Change `verify_groth16` to accept `&[[u8;32]; 5]`, compute `vk_x` as five `g1_scalar_mul` + four `g1_add` syscalls, then run the existing 4-pair pairing. ✅ — see `groth16::verifier::verify_groth16` and the §"RISC Zero 5-public-input layout" of `docs/zk-references.md`.
5. Update `scripts/extract-vk` to emit all 6 IC entries and the two digest fields; re-extract against the pinned prover (`risc0-zkvm 1.2.6`). ✅ — new VK fingerprint `109aba43410e587cf8f6865ece86bc4a1e30252d5331db6e32402f5f2f709707`.
6. Add a regression test: `(real_proof, real_journal) -> verify_groth16` returns `Ok(())`. (Outstanding — host-side LiteSVM harness against a freshly proved fixture.)

---

### F-4 — No subgroup / on-curve check (CRITICAL — known sBPF foot-gun)

**File:** `programs/glyph-verifier/src/groth16/verifier.rs:67-84`

Step 1 only validates that `proof_a`, `proof_c` are not the all-zero point. There is **no** check that:
- (x, y) satisfies `y^2 = x^3 + 3` mod p (on-curve check)
- The point is in the prime-order subgroup r·P = O (subgroup check; for BN254 G1 the cofactor is 1 so this is trivial there, but for **G2 the cofactor is non-trivial** and Solana's `alt_bn128_pairing` does NOT enforce subgroup membership)
- Coordinates are reduced mod p

For G2 (`proof_b`), an attacker can supply a point in a small-order subgroup or a point off-curve. Solana's `sol_alt_bn128_pairing` syscall (per the SIMD that introduced it) historically does *not* perform subgroup checks. This is the canonical "small-subgroup attack" on pairing-based SNARKs and is the reason high-quality verifiers (Groth16-Solana, Light Protocol's `groth16-solana`) do explicit subgroup checks via scalar multiplication by `r` and asserting `r·P == O`.

Without these checks, an attacker who knows the VK can craft `(A, B, C)` triples that satisfy the pairing equation but are not derived from any witness — full soundness break. RISC Zero's compressor produces well-formed proofs, but the verifier accepts arbitrary proofs from any caller, not just RISC Zero.

The error codes `Groth16InvalidG1Point = 6001` and `Groth16InvalidG2Point = 6002` are defined in `errors.rs:11-15` but never returned from anywhere.

**Recommended fix:**
- Use `solana_bn254::compression::prelude::*` and add explicit on-curve and subgroup checks before pairing.
- Or vendor a hardened verifier (e.g., adapt `groth16-solana` from Light Protocol which does these checks).
- Wire `Groth16InvalidG1Point` / `Groth16InvalidG2Point` so failures are diagnosable.

---

### F-10 — `g1_negate` does naive `p - y` without reducing (HIGH)

**File:** `programs/glyph-verifier/src/groth16/verifier.rs:160-184`

```rust
let neg_y = field_sub(&FIELD_PRIME, y);
```

Issues:
- No check that `y < p`. If a malicious caller passes `y >= p`, `field_sub(p, y)` underflows and the wrong value is returned (because `field_sub` assumes `a >= b` per its doc-comment, line 209: "assumes a >= b").
- The result is not reduced mod p again. If `y == 0` (valid, point at infinity case is handled, but `y == 0` for non-identity points is also possible at certain curve coords), `p - 0 == p` which is *not* a canonical representative.

**Recommended fix:**
- Validate `y < p` first (return `InvalidG1Point` otherwise).
- Reduce result mod p (single conditional subtraction is enough since both operands are < p).

---

### F-11 — `field_sub` borrow logic is incorrect at the high byte (HIGH)

**File:** `programs/glyph-verifier/src/groth16/verifier.rs:209-220`

```rust
fn field_sub(a: &[u8], b: &[u8]) -> [u8; 32] {
    ...
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let diff = (a[i] as u16).wrapping_sub(b[i] as u16).wrapping_sub(borrow);
        result[i] = diff as u8;
        borrow = if diff > 0xFF { 1 } else { 0 };
    }
    result
}
```

`diff` is `u16`. If `a[i] < b[i] + borrow`, `wrapping_sub` produces a large value (e.g. `0xFF__`). The condition `diff > 0xFF` is true *exactly* when borrow is needed, so the borrow logic is by accident correct... but only because `wrapping_sub` of `u16` from `0..0xFFFF` underflow ends up `> 0xFF`. For inputs where `a < b`, the function returns garbage (the high byte's borrow is silently dropped — there is no `assert!(borrow == 0)` at the end). This compounds with F-10's lack of `y < p` check: a caller can intentionally underflow.

**Recommended fix:**
- Use a clear `(a, borrow_out) = a.overflowing_sub(b)` style and `debug_assert_eq!(borrow_out, 0, "field_sub underflow")`.
- Better: use a vetted bigint crate (`num-bigint` is too heavy for sBPF, but `crypto-bigint` works) or `solana-bn254::compression` helpers.

---

### F-12 — `reduce_scalar` only subtracts r once (HIGH)

**File:** `programs/glyph-verifier/src/groth16/verifier.rs:199-206`

```rust
fn reduce_scalar(scalar: &[u8; 32]) -> [u8; 32] {
    if scalar >= &BN254_SCALAR_FIELD_ORDER {
        field_sub(scalar, &BN254_SCALAR_FIELD_ORDER)
    } else {
        *scalar
    }
}
```

For a 256-bit input `s`, the maximum value is `2^256 - 1`. BN254 r ≈ `2^254 + 2^33 + ...`. So `s` can be up to `~3.7r`. A single subtraction is not enough for inputs in `[2r, 2^256)`. SHA-256 outputs are uniformly random in `[0, 2^256)`, so ~25% of outputs are `>= 2r` and produce an unreduced result — which when fed to `g1_scalar_mul` gives undefined output (Solana's syscall internally reduces, *probably*, but it is an undocumented assumption to rely on).

**Recommended fix:** Loop the subtraction until `result < r`, or use `solana_bn254` reduction helpers.

---

### F-14 — Dev VK has off-curve G1/G2 points (HIGH)

**File:** `programs/glyph-verifier/src/groth16/vk.rs:88-190`

`alpha_g1 = (0, 2)` — must satisfy `4 = 0 + 3 = 3` mod p, which is `4 != 3`, so this point is not on `y^2 = x^3 + 3`. `gamma_g2 = (... ic_0 = (1, 1)`, etc. None of these are valid BN254 points. When `g1_scalar_mul`, `g1_add`, or `alt_bn128_pairing` is invoked with off-curve inputs, Solana's syscall *should* return `Err`, but the behavior across runtime versions is not strictly defined. This is fine for "fail-closed in dev" but means **the dev VK does not even exercise the verifier code paths that real proofs would**. End-to-end tests with this VK are ineffective.

---

### F-15 — Seal extraction assumes specific RISC Zero v1.x layout (HIGH)

**File:** `tee-worker/src/prover.rs:248-269`

```rust
let offset = if seal.len() == 260 { 4 } else { 0 };
```

The 4-byte selector at the front of the seal is RISC Zero's **proving system version tag**. Hardcoding `len == 260` is fragile:
- RISC Zero v2.x may add additional metadata.
- The tag value (selector) is never checked, so a proof from a different proving system (PLONK, FFLONK) with a 260-byte seal would silently parse as Groth16.

**Recommended fix:** Read and validate the 4-byte selector against an allowlist (`risc0_zkvm::sha::SELECTOR_GROTH16` or equivalent constant).

---

## E. Public input binding

### F-22 — Guest does not assert `intent.expiry > 0` (MEDIUM)

**File:** `circuits/glyph-circuit/guest/src/main.rs:81-87`

```rust
if policy.expires_at > 0 {
    assert!(intent.expiry <= policy.expires_at, "intent expiry exceeds policy expiry");
}
```

If `policy.expires_at == 0`, the rule is skipped entirely, and `intent.expiry` is also unconstrained (can be 0 or `u64::MAX`). The journal commits `intent_hash` (which includes `expiry`), but the on-chain verifier never compares `expiry` against `Clock::get()?.unix_timestamp` (lib.rs:388-448). So an old proof can be replayed *years later* as long as the nonce hasn't been consumed and the policy_epoch hasn't bumped.

Combined with F-18 (no on-chain expiry check) this is a real freshness bug.

**Recommended fix:**
- Add `intent.expiry > now` assertion in guest (uses `intent.expiry`, not real time, but at least bounds claim age relative to policy).
- Add on-chain check: `require!(public_outputs.expiry > Clock::get()?.unix_timestamp, GlyphError::ProofExpired)`. This requires adding `expiry` to `PublicOutputs` (currently only the 5 fields: policy_commitment, intent_hash, agent_pubkey, nonce, tx_hash).

---

### F-18 — On-chain verifier never checks freshness against Clock (MEDIUM)

**File:** `programs/glyph-verifier/src/lib.rs:388-448` (entire `verify_and_execute` body)

No `Clock::get()?` is consulted for expiry. `nonce_acct.consumed_at` is set but never compared. Proofs are valid until nonce or epoch invalidation, with no time bound.

---

### F-20 — Nonce PDA seed lacks `agent_pubkey` (MEDIUM)

**File:** `programs/glyph-verifier/src/lib.rs:222-228`

```rust
seeds = [
    NonceAccount::SEED_PREFIX,
    &registry.policy_epoch.to_le_bytes(),
    &args.nonce,
],
```

Two different agents in the same `policy_epoch` (which is per-agent — but the seed does not include `agent_pubkey`!) sharing a nonce will collide on the same PDA. Since `policy_epoch` is per-`AgentRegistry` and starts at 0, **all newly registered agents have epoch 0**. So if Agent A consumes nonce X with epoch 0, Agent B (also at epoch 0) cannot consume nonce X — and Agent B will fail with `NonceInitializationFailed`, which presents as a non-deterministic intermittent failure depending on which agent submits first.

Worse: this is a denial-of-service vector. An attacker who can predict another agent's nonces (e.g., an agent using deterministic counters) can front-run by burning the nonce on their own agent.

**Recommended fix:**
```rust
seeds = [
    NonceAccount::SEED_PREFIX,
    registry.agent_pubkey.as_ref(),
    &registry.policy_epoch.to_le_bytes(),
    &args.nonce,
],
```

---

### F-23 — Circuit only proves 6 of 9 policy rules; no per-rule flag in journal (MEDIUM)

**Files:** `circuits/glyph-circuit/guest/src/main.rs:47-92`, `aidlc-docs/zk-upgrade-design.md:87-89`

The guest comment (line 89-91) acknowledges that `time_window`, `daily_volume`, `allowed_token_mints` are enforced by the worker, not the circuit. But:
- Nothing in the journal tells the on-chain verifier *which subset* was proven.
- The on-chain verifier cannot reconstruct or enforce the missing rules — it accepts any policy_commitment that matches the registry.
- A compromised TEE worker could lie about evaluating the off-circuit rules; the on-chain verifier has no signal.

**Recommended fix:**
- Either move all rules into the circuit (requires committing real-time state via a TEE-attested oracle input), or
- Add to `PublicOutputs` a `circuit_rule_bitmap: u32` indicating which rules were enforced, and have the on-chain verifier require specific rules per policy class.

---

### F-28 — Guest `tx_hash` may not equal verifier's full-instruction hash (LOW — verify)

**File:** `circuits/glyph-circuit/guest/src/main.rs:32` vs `programs/glyph-verifier/src/lib.rs:410-417`

Guest:
```rust
let tx_hash = sha256(&tx_bytes);
```

Verifier:
```rust
tx_hasher.update(next_ix.program_id.as_ref());
for meta in &next_ix.accounts {
    tx_hasher.update(meta.pubkey.as_ref());
    tx_hasher.update(&[meta.is_signer as u8, meta.is_writable as u8]);
}
tx_hasher.update(&next_ix.data);
```

These match only if `tx_bytes` passed to the guest is the same canonicalization (program_id || accounts(pubkey, signer, writable) || data). The TEE worker's `canonical_target_instruction_bytes` (referenced in main.rs:267, declared in transaction_builder.rs) is supposed to produce this, but the **guest comment and the `tx_bytes` parameter name do not enforce this contract**. If a developer ever calls `generate_proof` with raw instruction `data` (which the type signature `Vec<u8>` permits), the proof will succeed locally but fail on-chain with `TxHashBindingFailed` — and the failure mode is opaque.

**Recommended fix:**
- Strongly type `tx_bytes` as `CanonicalInstructionBytes(Vec<u8>)` so it cannot be confused with raw data.
- Add an integration test that asserts `circuit_tx_hash == on_chain_canonical_hash` for the same inputs (the existing test `test_journal_field_offsets` does not cover this).

---

## F. Compute budget

### F-13 — Compute budget set client-side only; not enforced on-chain (HIGH)

**File:** `programs/glyph-verifier/src/client_utils.rs:8-33`

```rust
pub const MIN_COMPUTE_BUDGET: u32 = 1_400_000;
pub fn compute_budget_ix() -> Instruction { ... }
```

This is a helper for transaction *construction*. The on-chain `verify_and_execute` does not check `solana_program::log::sol_log_compute_units()` or otherwise verify the budget. If a caller submits with the default budget (200k CU), the pairing syscall will partially execute and silently abort, leaving the nonce account uninitialized — which, depending on Anchor's account-init semantics, may or may not consume the nonce. (In practice the tx fails atomically and nothing is committed, but error code is `ComputeBudgetExceeded` from the runtime, not the helpful `InsufficientComputeBudget = 6070` defined in errors.rs:135.)

The error code `InsufficientComputeBudget` exists but is dead code.

**Recommended fix:** It is impossible to *enforce* a minimum CU budget on-chain (the runtime kills the transaction before the program can return). But the program can:
1. At entry, log the remaining CUs and emit a structured `RemainingCu` event.
2. Hard-fail (early abort with `InsufficientComputeBudget`) if `sol_remaining_compute_units() < 1_300_000` *before* doing the pairing.

This converts the silent runtime kill into an explicit, debuggable error.

---

## G. Proof bundle format / replay protection

### F-19 — `tx_signature` is a fake (MEDIUM)

**File:** `tee-worker/src/main.rs:293`

```rust
bundle.tx_signature = hex::encode(&bundle.public_inputs.tx_hash[..8]);
```

The field is named `tx_signature: String` but stores the first 8 bytes of `tx_hash` hex-encoded — a 16-character string. There is no actual signature here. Any consumer that interprets this field as a Solana transaction signature (which the type strongly suggests) will be confused.

**Recommended fix:** Rename to `tx_hash_prefix` or remove. If a real signature is needed (e.g., for off-chain provenance), have the TEE sign over `(image_id, journal_bytes, proof)` with the worker's `signing_key`.

---

### F-27 — Replay rejection masked as `NonceInitializationFailed` (MEDIUM)

**File:** `programs/glyph-verifier/src/lib.rs:219-230` (`init` not `init_if_needed`)

When a nonce PDA already exists (replay), Anchor's `init` constraint fails with the generic Anchor error code (`AccountAlreadyInitialized`), not the protocol's `NonceAlreadyConsumed = 6030`. Operators reading logs see an Anchor framework error and may not realize this is an attack signal vs a benign race.

**Recommended fix:** Manually pre-check existence (using `try_from_slice` on the pre-init account data) and return `NonceAlreadyConsumed` explicitly. Or use a different pattern: a `Vec<[u8; 32]>` consumed-nonce list inside `AgentRegistry` (bounded to e.g. last 1024) with explicit insertion logic.

---

### F-29 — `tx_signature: String` unbounded (LOW)

`String` field in a public-facing serialization format is unbounded. Bound to e.g. 128 chars or remove (per F-19).

---

## H. Build / reproducibility

### F-15 already covers the seal version-tag fragility.

### F-16 — DevProver bundles look identical to real bundles (MEDIUM)

**File:** `tee-worker/src/prover.rs:212-216`

```rust
let proof = Groth16Proof {
    a: expand_bytes::<64>(&proof_seed, b"a"),
    b: expand_bytes::<128>(&proof_seed, b"b"),
    c: expand_bytes::<64>(&proof_seed, b"c"),
};
```

These bytes are *almost certainly* not on the BN254 curve (they are uniform-random SHA-256 outputs), so they will fail real verification. But:
- An off-chain consumer (SDK, gateway) cannot tell them apart from real proofs without doing pairing math.
- The bundle's `journal_bytes` are real and decode correctly.
- The `public_inputs` field is correctly populated.

If a downstream system caches/serves bundles based on shape rather than verification result, it cannot distinguish.

**Recommended fix:** Add `bundle.proof_kind: ProofKind` enum (`Groth16Real | DevPlaceholder`). Have the SDK and gateway refuse `DevPlaceholder` outside of Dev mode.

---

## I. "Coming soon" / Option A/B/C markers

### F-31 — Design doc marks the entire ZK upgrade "In Progress"

**File:** `aidlc-docs/zk-upgrade-design.md:3`

> Status: In Progress

> Decision: Implement Option B now (ark-bn254), design interfaces for Option A drop-in.

The current code uses Solana's native `alt_bn128` syscalls (verifier.rs:24) which is closer to Option A than Option B (ark-bn254). The doc has not been updated to reflect this. Several layers it lists (Layer 2: `prover.rs` with `RealProver`) do not exist as named — instead `RiscZeroProver` lives in `tee-worker/src/prover.rs`. The doc is stale and confusing for an auditor — should be brought up to date or marked superseded.

### Other "Option A/B" markers

- `tee-worker/src/vendors/sev.rs:66-70` — Option A (vTPM) / Option B (External KMS) for SEV attestation key sourcing. Not in ZK scope but relevant to the broader audit.

---

## Cross-reference matrix

| Finding | Already in `docs/SECURITY_AUDIT.md`? | Already in `aidlc-docs/zk-upgrade-design.md`? |
| --- | --- | --- |
| F-1 Dev VK | No | Implicit (says "hardcoded RISC Zero BN254 verification key" as a TODO) |
| F-2 Missing image_id in PI | No | No |
| F-3 Dead `verify_vk_integrity` | No | No |
| F-4 No subgroup check | No | No |
| F-5 DevProver in prod binary | No | No |
| F-6 Substring attestation check | Partial — Finding #2 patched call site, but did not fix the substring scan itself | No |
| F-7 Empty ELF | No | Yes (Layer 1 — "In Progress") |
| F-8 Zero image_id | No | No |
| F-9 No VK swap mechanism | No | No |
| F-10 g1_negate without reduction | No | No |
| F-11 field_sub borrow bug | No | No |
| F-12 reduce_scalar single subtraction | No | No |
| F-13 Compute budget not enforced on-chain | No | No |
| F-14 Off-curve dev VK | No | No |
| F-15 Seal version tag fragile | No | No |
| F-16 DevProver indistinguishable bundles | No | No |
| F-17 expires_at == 0 silent skip | No | No |
| F-18 No on-chain Clock check | No | No |
| F-19 Fake tx_signature | No | No |
| F-20 Nonce PDA missing agent seed | No | No |
| F-21 Epoch governance | No | No |
| F-22 Guest doesn't assert expiry > 0 | No | No |
| F-23 Circuit only 6 of 9 rules; no journal flag | No | Acknowledged only as future work (Layer 5 doesn't address) |
| F-24 extract_vk script bails | No | No |
| F-25 Non-risc0 fallback emits structurally valid VK | No | No |
| F-26 Production check is panic! | No | No |
| F-27 Replay error masked | No | No |
| F-28 Guest vs verifier tx_hash contract | No (Finding #1 fixed verifier side; the guest side was not addressed) | No |
| F-29 Unbounded tx_signature String | No | No |
| F-30 image_id ASCII = HTOR | No | No |
| F-31 Design doc stale | No | (it is the doc) |
| F-32 No fuzz tests | No | No |
| F-33 Guest uses panic! for failures | No | No |

**Verdict:** The prior `docs/SECURITY_AUDIT.md` covers TEE integration (intent hijacking, attestation bypass on update, DoS). It does **not** address ZK soundness, VK lifecycle, on-chain verifier correctness, or DevProver lifecycle. The `zk-upgrade-design.md` is a build plan — it identifies the work but the work is incomplete. Of the 33 findings here, 31 are **new** to this audit.

---

## Top-5 must-fix before any mainnet deployment

1. **F-1 / F-2 / F-3 (CRITICAL):** Replace dev VK with a real one extracted from the actual circuit ELF, fix the public-input derivation to include `image_id`, and call `verify_vk_integrity()` from `verify_groth16`. **Without this trio, the verifier mathematically cannot accept any real RISC Zero proof and the protocol is non-functional in addition to insecure.**
2. **F-4 (CRITICAL):** Add explicit on-curve and subgroup checks for all four pairing inputs. This is the standard sBPF Groth16 foot-gun.
3. **F-5 / F-16 (CRITICAL):** Remove `DevProver` from production binaries (`#[cfg(feature = "dev-prover")]`) or add a type-level discriminator that cannot be forged.
4. **F-9 (HIGH):** Move VK to a PDA with multisig+timelock-gated updates. Today's VK upgrade is "rebuild and `anchor upgrade`" with no governance signal.
5. **F-13 / F-18 / F-22 (HIGH/MEDIUM):** Wire on-chain freshness checks (Clock vs intent.expiry) and explicit compute-budget pre-flight checks. Today, expired proofs are accepted and CU exhaustion fails silently.

## Smaller patches recommended in the same release

- F-6: Replace substring scan in `verify_attestation_commitment` with structured COSE/CBOR parse anchored to vendor root CAs (this is WS-3 in the design doc — bring forward).
- F-10 / F-11 / F-12: Replace hand-rolled `field_sub` and scalar reduction with a vetted helper or vendored `groth16-solana` style implementation.
- F-19: Rename or remove `tx_signature: String`.
- F-20: Add `agent_pubkey` to nonce PDA seed.
- F-24 / F-25: Implement real VK extraction; remove placeholder fallback.
- F-27: Detect replay explicitly and return `NonceAlreadyConsumed`.
