# GLYPH Demo

This walks through the GLYPH demo: a multi-protocol policy-enforcement run that
shares a single policy commitment across several agent intents, plus the live
devnet deployment that the on-chain verifier runs against.

## Live on devnet

The verifier program is deployed, initialized, and seeded with the real
verification key on Solana **devnet**:

- **Program ID:** `G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g`
- **Explorer:** https://explorer.solana.com/address/G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g?cluster=devnet
- **Deploy tx:** https://explorer.solana.com/tx/2pidHYhjZxPmdw6tZnX4PW9j6yokU2HNvt3KAngu9GCt7GDe1j1vT2UVGCAY4RCoDLiGDrG6hHo4SF2KzPdE1tv?cluster=devnet
- **Config PDA:** `2371q4QnMm33R3G4nXxxBkieHa8E47BDTBsmZoiurZpT`
- **VK PDA:** `5V28XTKVnQYVEG16DzoHfeHKXsYUqG41PxQJhxFyhjyd`
- **Seeded `vk_hash`:** `109aba43410e587cf8f6865ece86bc4a1e30252d5331db6e32402f5f2f709707` (matches `vk_real.rs`; prover risc0-zkvm 1.2.6)

Live (deploy + initialize + VK-seed) is confirmed on devnet. The full agent
register→verify flow is not yet exercised end-to-end on devnet — that path needs
a real zk proof plus TEE attestation — so it is demonstrated locally via the
example below.

## Hosted web demo

- **Live demo:** `<WEB_DEMO_URL>`

## Multi-protocol demo

The example proves the same policy commitment is enforced across four different
agent intents and yields the expected allow/deny decisions:

```bash
cargo run --example multi_protocol_demo --manifest-path tee-worker/Cargo.toml
```

Expected result — one shared `policy_commitment`
(`d086deb34a864fb07618821aa5cf02283c4d73ac8f1267f3dbd7f9b0fe0053cb`) across all
four intents, with these decisions:

| Intent          | Decision |
| --------------- | -------- |
| System transfer | ALLOW    |
| SPL Token       | ALLOW    |
| Memo            | ALLOW    |
| Jupiter swap    | DENY     |
