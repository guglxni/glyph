# Capstone Gaps

Tracking the gaps identified for the GLYPH capstone and their current status.

## Done

- [x] **Program built, deployed, and initialized to devnet** — Program ID
  `G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g`, deploy tx
  `2pidHYhjZxPmdw6tZnX4PW9j6yokU2HNvt3KAngu9GCt7GDe1j1vT2UVGCAY4RCoDLiGDrG6hHo4SF2KzPdE1tv`,
  config PDA `2371q4QnMm33R3G4nXxxBkieHa8E47BDTBsmZoiurZpT`, VK PDA
  `5V28XTKVnQYVEG16DzoHfeHKXsYUqG41PxQJhxFyhjyd`. Real VK seeded — on-chain
  `vk_hash` = `109aba43410e587cf8f6865ece86bc4a1e30252d5331db6e32402f5f2f709707`
  (matches `vk_real.rs`).
- [x] **Anchor / toolchain build resolved** — built via `cargo-build-sbf` with the
  real-vk feature.
- [x] **Multi-protocol example added** — `multi_protocol_demo` proves a shared
  policy commitment
  (`d086deb34a864fb07618821aa5cf02283c4d73ac8f1267f3dbd7f9b0fe0053cb`) across 4
  intents (System ALLOW, SPL Token ALLOW, Memo ALLOW, Jupiter DENY).
- [x] **README 8→9 + VK wording fixed.**
- [x] **LICENSE added.**
- [x] **.gitignore hardened.**

## TODO

- [ ] **Git repository** — in progress; repo will be
  https://github.com/guglxni/glyph, push pending.
- [ ] **Web demo** — deploying to Vercel; hosted URL pending.
- [ ] **VK-rotation multisig** — not initialized (devnet-acceptable).
- [ ] **Full register→verify e2e on devnet** — needs a real proof + attestation;
  currently demonstrated locally only.
