# GLYPH ZK references

This file documents the cryptographic decisions behind the on-chain Groth16
verifier and the RISC Zero seal extraction in the TEE worker. It is the
authoritative companion to `programs/glyph-verifier/src/groth16/verifier.rs`
and `tee-worker/src/prover.rs`.

## RISC Zero version pin

- **`RISC0_PROVER_VERSION = "1.2.6"`** (declared in
  `programs/glyph-verifier/src/groth16/mod.rs`).
- Workspace-wide pin: `risc0-zkvm = "1.2"`, `risc0-build = "1.2"` in the root
  `Cargo.toml`.
- The on-chain claim-digest formula is locked to the format that this RISC
  Zero family emits. Any major version bump must re-validate:
  - `Receipt::inner.groth16().seal` length (currently exactly 256 bytes).
  - The `claim_digest = sha256(image_id || sha256(journal))` derivation.
  - The image_id wire-byte order (currently big-endian per `Digest`
    serialization in `risc0-zkp 1.2.6`).

## Claim digest layout

```
claim_digest = sha256(
    image_id_bytes              // 32 bytes: 8 × u32, big-endian per limb
 || sha256(journal_bytes)       // 32 bytes
)
```

The on-chain computation lives in `glyph_verifier::glyph_verifier::verify_and_execute`
(see Phase 4). The byte order is **explicit big-endian** because RISC Zero's
`Digest` type stores its 8 × u32 limbs in big-endian word order on the wire.
Mistakenly using `to_le_bytes()` here would silently fail every real proof
because the prover's claim digest would not match the verifier's recomputation.

`claim_digest` is **not** the single Groth16 public input — it is one of
*five* scalar inputs the on-chain verifier feeds into the pairing equation.
See the next section for the full layout.

A regression test (`programs/glyph-verifier/src/groth16/tests.rs ::
claim_digest_formula_is_image_id_be_then_journal_hash`) pins the formula.

## RISC Zero 5-public-input layout

### The bug we fixed

The first implementation passed a single 32-byte scalar
(`sha256(image_id || sha256(journal))`) into `verify_groth16` and computed
`vk_x = IC[0] + s · IC[1]`. This is what the doc-comments on
`verify_groth16` originally claimed.

That contract is **wrong**. A RISC Zero v1.2.x Groth16 receipt carries
**five** Groth16 public inputs, not one, and the on-chain VK therefore has
six IC entries (`IC[0]` constant + `IC[1..=5]` per-input). No real RISC Zero
proof verifies under the single-input formula regardless of how correct the
rest of the verifier is.

### The contract

Source: `risc0_zkvm-1.2.6/src/receipt/groth16.rs` lines 85–105 and
`risc0_groth16-1.2.6/src/lib.rs::split_digest` lines 91–100.

```text
let (a0, a1)      = split_digest(params.control_root);
let (c0, c1)      = split_digest(claim_digest);            // claim_digest as above
let mut id        = params.bn254_control_id;
id.as_mut_bytes().reverse();
let id_bn254_fr   = fr_from_hex_string(hex(id));

public_inputs = [a0, a1, c0, c1, id_bn254_fr];
```

where `params` is `risc0_zkvm::Groth16ReceiptVerifierParameters::default()`.

* `control_root` and `bn254_control_id` are *network-wide* RISC Zero
  constants for the pinned prover version (1.2.6). They are extracted into
  the on-chain `VerifierVk` PDA alongside the BN254 VK.
* `split_digest` reverses the 32-byte input (RISC Zero stores Digests in LE
  word order), splits at 16 bytes, and left-pads each half to a 32-byte
  Fr-compatible BE scalar (so each half holds ≤ 2¹²⁸ payload, comfortably
  inside r ≈ 2²⁵⁴).
* `bn254_control_id` is reversed in place (LE → BE) and decoded as a single
  Fr scalar.

### The on-chain helpers

* `groth16::verifier::split_digest_be(&[u8;32]) -> ([u8;32], [u8;32])` —
  mirror of `risc0_groth16::split_digest`.
* `groth16::verifier::bn254_control_id_to_fr(&[u8;32]) -> [u8;32]` — mirror
  of the `id_bn254_fr` derivation.

Both are `pub(crate)` and re-used by `verify_and_execute` (lib.rs, Phase 4)
to construct the 5-element `public_inputs` array.

### vk_x evaluation

```text
vk_x = IC[0] + s0·IC[1] + s1·IC[2] + s2·IC[3] + s3·IC[4] + s4·IC[5]
```

with `(s0, s1, s2, s3, s4) = (a0, a1, c0, c1, id_bn254_fr)`. Each scalar is
`reduce_scalar`'d (mod r) before the syscall; zero scalars short-circuit to
skip an unnecessary `g1_scalar_mul` (saving ~180k CU per skip).

### Compute budget

Five `alt_bn128_multiplication` syscalls and four `alt_bn128_addition`
syscalls take the budget from ~1.3M to ~1.27–1.37M CU including all
on-curve checks. The existing 1.4M CU limit set by `client_utils` covers
this comfortably. See the CU breakdown in `groth16/verifier.rs` header.

### Where the fix landed

1. `Groth16VerifyingKey` widened: `ic: [[u8;64]; 6]` plus `control_root` and
   `bn254_control_id`.
2. `VerifierVk` PDA and `VerifierVkInner` instruction args follow the same
   shape; `VerifierVk::SIZE` and `VkMultisig::SIZE` bumped accordingly.
3. `verify_groth16` signature now takes `&[[u8;32]; 5]`.
4. `lib.rs::verify_and_execute` derives the 5 scalars from the registry's
   `image_id`, the journal, and the VK's `control_root` / `bn254_control_id`
   fields, then calls `verify_groth16(.., &public_inputs, &vk)`.
5. `scripts/extract-vk` reads `Groth16ReceiptVerifierParameters::default()`
   and emits all 6 IC entries plus the two digest fields into `vk_real.rs`.

After re-extraction against `risc0-zkvm 1.2.6` the VK fingerprint is:

```
VK SHA-256:         109aba43410e587cf8f6865ece86bc4a1e30252d5331db6e32402f5f2f709707
control_root:       8cdad9242664be3112aba377c5425a4df735eb1c6966472b561d2855932c0469
bn254_control_id:   c07a65145c3cb48b6101962ea607a4dd93c753bb26975cb47feb00d3666e4404
prover_version:     risc0-zkvm 1.2.6
image_id:           257cf77928298715 56ee2220 f81c7bac edbff0e0 bf77ff46 712697b0 0e05f183
```

## Subgroup-check posture (F-4 / F-14)

### G1

Solana `alt_bn128` exposes `alt_bn128_addition` and `alt_bn128_multiplication`
for G1 (no G2 mul). BN254's G1 cofactor is **1**, so on-curve membership
implies subgroup membership. Our verifier still calls `r·P` via
`alt_bn128_multiplication` and asserts the identity result as defence in
depth and as a smoke test that the syscall is wired correctly.

### G2

Solana 1.18.x does **not** expose a G2 scalar-multiplication syscall, so the
classic `r·P == O` subgroup check cannot be performed on-chain. Our G2
validation therefore covers:

- Coordinate range (`< p`).
- On-curve over the twist: `y² ≡ x³ + 3/(9 + u) (mod p)` over Fp2.

We rely on the RISC Zero prover (which uses the bellman-style Groth16
implementation in `bellperson` / `risc0-groth16`) to emit subgroup-correct
G2 points. This matches the posture of:

- **Light Protocol's `groth16-solana`** —
  https://github.com/Lightprotocol/groth16-solana — which also performs only
  on-curve checks for G2 and notes the same Solana-syscall constraint.
- **Matter Labs' `awesome-zkp`** survey —
  https://github.com/matter-labs/awesome-zero-knowledge-proofs — which
  catalogues several BN254 verifiers that defer the G2 subgroup check to the
  prover when the host runtime lacks a G2 mul.

If a future Solana release adds a G2-mul syscall (e.g.
`sol_alt_bn128_g2_multiplication`) we should revisit and add the explicit
`r·P == O` check to `validate_g2`.

## Field arithmetic (F-10 / F-11 / F-12)

The verifier ships hand-rolled Fp / Fp2 arithmetic because pulling in
`crypto-bigint` or `ark-bn254` blows the BPF code-size budget. The relevant
helpers in `verifier.rs` are:

- `field_sub` — explicit borrow detection. Returns `Err(())` on underflow so
  callers cannot silently produce garbage from `field_sub(small, big)`.
- `reduce_scalar` — loops while `result >= r` (closes F-12). For BN254 r ≈
  2^254 and SHA-256 outputs in `[0, 2^256)` this loop runs at most 4 times.
- `g1_negate` — validates `y < p` first, then computes `p - y` and reduces.
  Closes F-10 (the previous version blindly trusted the caller).
- `fp_mul` / `reduce_512_mod_p` — schoolbook 256×256 → 512 multiply followed
  by shift-and-subtract reduction. Used only inside the on-curve checks.

## Solana syscall version compatibility

Verified against the workspace-pinned `solana-program = "=1.18.26"`. The
relevant entry points live in
`solana_program::alt_bn128::prelude::{alt_bn128_addition,
alt_bn128_multiplication, alt_bn128_pairing}` and
`solana_program::alt_bn128::compression::prelude::*`.

Compute budget: ~1.3M CU for the full pairing path (4-pair Miller loop +
on-curve checks + scalar reduction + G1 subgroup smoke test). The transaction
must include `ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)` —
see `programs/glyph-verifier/src/client_utils.rs`.

## Seal extraction (F-15)

The RISC Zero v1.2.x receipt exposes `inner.groth16().seal` as a flat 256-byte
vector laid out as `A_g1 (64) || B_g2 (128) || C_g1 (64)`. The Boundless /
Steel `encode_seal` helper prepends a 4-byte selector
(`verifier_parameters_digest[..4]`) producing a 260-byte form. Our
`tee-worker/src/prover.rs::extract_groth16_points` accepts either shape but:

- For the 256-byte form, parses directly.
- For the 260-byte form, **requires** the caller to pass the expected
  selector and verifies it byte-for-byte. Without an expected selector we
  refuse to skip the prefix — closes the silent-mis-parse path that an
  attacker could exploit by submitting a 260-byte non-Groth16 proof.

Selector references:
- `risc0-zkvm` 1.2.6 receipt module — `Receipt::inner.groth16().seal`.
- `risc0-groth16` 1.2.6 `Seal::SIZE = 256` (no selector at this layer).
- Boundless `encode_seal` / Steel `EncodedSeal` — adds the 4-byte
  `verifier_parameters` digest prefix.

## References

- Light Protocol `groth16-solana` — https://github.com/Lightprotocol/groth16-solana
- Matter Labs `awesome-zkp` — https://github.com/matter-labs/awesome-zero-knowledge-proofs
- RISC Zero `risc0-zkvm` 1.2.x — https://github.com/risc0/risc0
- Solana SIMD-0008 (`alt_bn128` syscalls) —
  https://github.com/solana-foundation/solana-improvement-documents
- BN254 curve / G2 twist constants — Aranha et al. (2013), "Faster
  explicit formulas for computing pairings over ordinary curves".
