# GLYPH Migration Notes — Wave 1 (WS-1 + WS-7)

This document captures the breaking changes introduced by the Wave 1
on-chain verifier mechanical fixes. Operators upgrading an existing
deployment must follow these steps in order.

## 1. Program ID rotation

The placeholder `G1yPHveri1111111111111111111111111111111111` has been
replaced with a freshly generated program ID:

```
G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g
```

The keypair lives at `target/deploy/glyph_verifier-keypair.json` (do **not**
check this into version control for production; it is the program upgrade
authority). Re-deploy is required:

```
anchor build
solana program deploy target/deploy/glyph_verifier.so \
  --program-id target/deploy/glyph_verifier-keypair.json
```

`Anchor.toml` and `tee-worker/src/main.rs` have been updated to the new ID.

## 2. NonceAccount PDA seed change (BREAKING)

`NonceAccount` PDAs are now derived as:

```
seeds = [
    NonceAccount::SEED_PREFIX,            // b"nonce"
    registry.agent_pubkey.as_ref(),       // NEW — prevents cross-agent collision
    &registry.policy_epoch.to_le_bytes(),
    &args.nonce,
]
```

The previously derived nonce PDAs are unreachable under the new derivation.
Because nonces are single-use anyway and we increment `policy_epoch` on every
policy change, this is forward-safe: the only consequence is that the rent
locked in pre-existing nonce PDAs is stranded until they are manually
reclaimed via `deregister_agent` and re-registration. SDK clients **must**
derive nonce PDAs using the new seed layout.

## 3. AgentRegistry layout change (BREAKING)

`AgentRegistry` now includes:

```rust
pub image_id: [u32; 8],   // 32 bytes — pinned RISC Zero circuit version
```

`AgentRegistry::SIZE` increased from 159 bytes (with discriminator) to 191.
Existing accounts are smaller than the new layout and will fail
deserialization. Deregister and re-register all agents after upgrade.

`register_agent` now requires an additional `image_id: [u32; 8]` argument
that pins which circuit version the agent's proofs must commit to. Use the
output of `cargo run --bin extract-vk --features risc0` for the `GLYPH_IMAGE_ID`
to populate this field for new agents.

## 4. PublicOutputs (circuit journal) layout change

`glyph_common::PublicOutputs` gains two fields:

```rust
pub expiry: u64,
pub image_id: [u32; 8],
```

Both are committed by the circuit (`circuits/glyph-circuit/guest/src/main.rs`)
and consumed by the on-chain verifier (`programs/glyph-verifier/src/lib.rs`).
Old proofs whose journal does not include these fields will fail
`InvalidJournalEncoding` (6010).

## 5. Bundle field rename — `tx_signature` → `tx_hash_prefix`

The misleading `tx_signature: String` field on `GlyphProofBundle` is now
`tx_hash_prefix: [u8; 16]`. SDK consumers that previously looked for
`tx_signature` must update to `tx_hash_prefix` and treat it as a debug
correlator only.

## 6. New error codes

| Code | Symbol             | When |
|------|--------------------|------|
| 6082 | `Paused`           | Verifier globally paused via `pause()` instruction. |
| 6083 | `ProofExpired`     | `public_outputs.expiry <= Clock::now`. |
| 6084 | `ImageIdMismatch`  | Proof committed to a different circuit version than `registry.image_id`. |
| 6085 | `VkIntegrityFailed`| `GLYPH_VK_HASH` does not match `SHA-256(GLYPH_VK)`. |

`DevModeNotAllowed` (6090) is now wired — proofs whose committed `tx_hash` is
all-zeros are rejected with this code.

## 7. Compute budget guidance

Production transactions invoking `verify_and_execute` should set:

```
ComputeBudgetInstruction::set_compute_unit_limit(1_400_000)
```

The verifier logs remaining compute units at entry via
`sol_log_compute_units` so operators can size budgets. The dead
`InsufficientComputeBudget` error (6070) remains reserved; runtime
enforcement of a pre-flight CU check requires
`solana_program::compute_units::sol_remaining_compute_units` which is not
yet stable in the Solana version pinned by this workspace. When that API
lands, add a `require!(remaining > 1_300_000, GlyphError::InsufficientComputeBudget)`
at the top of `verify_and_execute`.
