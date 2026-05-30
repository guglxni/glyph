# GLYPH — Live Web Demo

A polished, live demo for **GLYPH**, a verifiable guardrail layer for autonomous
agents on Solana. Built with Next.js (App Router), TypeScript, and Tailwind.
Deployed on Vercel.

**Live:** https://web-aaryanguglanics21-3349s-projects.vercel.app
(alias: https://web-lovat-seven-23.vercel.app)

## What it shows

- **Hero** — the pitch + a live "● Live on devnet" badge linking to the program.
- **Interactive policy console** — pick one of four intents (System transfer,
  SPL Token, Memo, Jupiter violation) against a single multi-protocol policy.
  The `policy_commitment`, `intent_hash`, `tx_hash`, and the ALLOW/DENY decision
  are computed **in your browser** using the exact canonical SHA-256 encoding
  ported byte-for-byte from `sdk/rust/glyph-core` (and matching the TS SDK).
  The commitment is identical across all four programs — "one policy, any
  program."
- **Live on-chain proof** — reads the devnet RPC directly to show the Config and
  VK PDAs exist, are owned by the program, and displays the seeded `vk_hash`.
- **How it works** — the three-layer trust stack (TEE → RISC Zero → on-chain
  Groth16 verifier) and the `ix[0] verify_and_execute → ix[1] target` binding.

## Commitment parity

The whole point: the in-browser computation reproduces the verified artifact.

```
policy_commitment = d086deb34a864fb07618821aa5cf02283c4d73ac8f1267f3dbd7f9b0fe0053cb
```

Verify it with no toolchain:

```bash
npm run parity   # node scripts/parity-check.mjs  → "PARITY: PASS ✓"
```

The shipped logic lives in [`lib/glyph.ts`](lib/glyph.ts); the policy and intents
are in [`lib/data.ts`](lib/data.ts), ported from
`examples/multi-protocol/{policy.toml,intents.rs}`.

## Run locally

```bash
cd web
npm install
npm run dev      # http://localhost:3000
```

## Build

```bash
npm run build
npm start
```

## Deploy (Vercel)

```bash
vercel --prod --yes
```

The app is 100% static read-only (no secrets); it talks to
`https://api.devnet.solana.com` from the client.

## On-chain references (devnet)

| | |
|---|---|
| Program ID | `G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g` |
| Config PDA | `2371q4QnMm33R3G4nXxxBkieHa8E47BDTBsmZoiurZpT` |
| VK PDA | `5V28XTKVnQYVEG16DzoHfeHKXsYUqG41PxQJhxFyhjyd` |
| vk_hash | `109aba43410e587cf8f6865ece86bc4a1e30252d5331db6e32402f5f2f709707` |
| Prover | risc0-zkvm 1.2.6 |

The IDL is copied to [`public/glyph_verifier.json`](public/glyph_verifier.json)
(the program's `target/` is gitignored upstream).
