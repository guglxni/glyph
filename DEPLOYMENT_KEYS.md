# GLYPH Deployment Keys

## Program ID

The verifier program ID was rotated from the placeholder
`G1yPHveri1111111111111111111111111111111111` to:

```
G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g
```

## Keypair location

The on-disk keypair is:

```
target/deploy/glyph_verifier-keypair.json
```

This file is the **program upgrade authority** for any cluster where the
program is deployed under the same ID. Operator actions:

1. **Do not commit this file to public version control.** Add to `.gitignore`
   if you have not already.
2. Move the keypair into your secrets manager (1Password, Vault, KMS, etc.)
   and seal a copy into the TEE worker's sealed-policy directory if the
   worker performs upgrade operations.
3. Per-environment overrides: generate distinct keypairs for `localnet`,
   `devnet`, `testnet`, and `mainnet-beta`. Update `Anchor.toml` and the
   fallback in `tee-worker/src/main.rs` accordingly.
4. For mainnet, the upgrade authority **must** be transferred to a multisig
   (Squads V3 or equivalent) before the first audited deployment. Keeping
   the local keypair as upgrade authority is acceptable only for devnet/CI.

## Re-generation

If `target/deploy/glyph_verifier-keypair.json` is missing or you want a fresh
ID:

```
solana-keygen new \
  --no-bip39-passphrase --silent --force \
  --outfile target/deploy/glyph_verifier-keypair.json
solana-keygen pubkey target/deploy/glyph_verifier-keypair.json
```

Replace the resulting pubkey in:

- `programs/glyph-verifier/src/lib.rs` — `declare_id!(...)`
- `Anchor.toml` — `[programs.localnet]` and `[programs.devnet]`
- `tee-worker/src/main.rs` — fallback string in the `verifier_program_id`
  resolver
