/**
 * The multi-protocol policy and the four demo intents.
 * Ported verbatim from:
 *   examples/multi-protocol/policy.toml
 *   examples/multi-protocol/intent-*.json
 *
 * The policy_commitment computed from THIS policy equals (verified):
 *   d086deb34a864fb07618821aa5cf02283c4d73ac8f1267f3dbd7f9b0fe0053cb
 */

import type { Intent, Policy } from "./glyph";

export const EXPECTED_POLICY_COMMITMENT =
  "d086deb34a864fb07618821aa5cf02283c4d73ac8f1267f3dbd7f9b0fe0053cb";

// glyph-verifier — devnet
export const PROGRAM_ID = "G5RnXgNZYiS4NJey6JzyxTLvPPPUMqUDL7wg6nqaMD3g";
export const CONFIG_PDA = "2371q4QnMm33R3G4nXxxBkieHa8E47BDTBsmZoiurZpT";
export const VK_PDA = "5V28XTKVnQYVEG16DzoHfeHKXsYUqG41PxQJhxFyhjyd";
export const VK_HASH =
  "109aba43410e587cf8f6865ece86bc4a1e30252d5331db6e32402f5f2f709707";
export const PROVER = "risc0-zkvm 1.2.6";
export const RPC_URL = "https://api.devnet.solana.com";

export const EXPLORER_PROGRAM = `https://explorer.solana.com/address/${PROGRAM_ID}?cluster=devnet`;
export const EXPLORER_DEPLOY_TX =
  "https://explorer.solana.com/tx/2pidHYhjZxPmdw6tZnX4PW9j6yokU2HNvt3KAngu9GCt7GDe1j1vT2UVGCAY4RCoDLiGDrG6hHo4SF2KzPdE1tv?cluster=devnet";
export const EXPLORER_CONFIG = `https://explorer.solana.com/address/${CONFIG_PDA}?cluster=devnet`;
export const EXPLORER_VK = `https://explorer.solana.com/address/${VK_PDA}?cluster=devnet`;

export const GITHUB_URL = "https://github.com/guglxni/glyph";

// ─── The policy (examples/multi-protocol/policy.toml) ──────────────────────────
// Policy schema version is 1 (the glyph-core default); daily=5 SOL;
// max_accounts=16; require_signer=true. Verified: this reproduces the
// on-chain policy_commitment d086deb3… exactly.

export const POLICY: Policy = {
  version: 1,
  max_lamports_per_tx: 1_000_000_000n, // 1 SOL
  allowed_programs: [
    "11111111111111111111111111111111", // System
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", // SPL Token
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", // Memo
  ],
  time_window: null,
  max_daily_volume_lamports: 5_000_000_000n, // 5 SOL
  max_slippage_bps: null,
  allowed_token_mints: null,
  max_accounts_per_tx: 16,
  require_signer_present: true,
  expires_at: 0n,
};

// ─── The four intents (examples/multi-protocol/intent-*.json) ──────────────────

export interface DemoIntent {
  id: string;
  label: string;
  protocol: string;
  blurb: string;
  intent: Intent;
}

export const INTENTS: DemoIntent[] = [
  {
    id: "system",
    label: "System transfer",
    protocol: "System Program",
    blurb: "Native SOL transfer of 0.5 SOL — under the 1 SOL cap, program allowlisted.",
    intent: {
      agent_pubkey: "Gokr9F4mEw4hHnVtBJjB55iL1WqdQQ5xrxujkjVrz3kt",
      nonce: "1111111111111111111111111111111111111111111111111111111111111111",
      target_program: "11111111111111111111111111111111",
      accounts: [
        { pubkey: "Gokr9F4mEw4hHnVtBJjB55iL1WqdQQ5xrxujkjVrz3kt", is_signer: true, is_writable: true },
        { pubkey: "3n1mC8x9aY9b7xQ9wZqg2t8rP4kF6vH1sJ5dN2eL7uVx", is_signer: false, is_writable: true },
      ],
      data: "AgAAAECcXAAAAAAA",
      max_lamports: 500_000_000n,
      max_slippage_bps: null,
      expiry: 1_764_003_600n,
    },
  },
  {
    id: "token",
    label: "SPL Token transfer",
    protocol: "SPL Token Program",
    blurb: "Token transfer — program allowlisted, generic caps satisfied.",
    intent: {
      agent_pubkey: "Gokr9F4mEw4hHnVtBJjB55iL1WqdQQ5xrxujkjVrz3kt",
      nonce: "2222222222222222222222222222222222222222222222222222222222222222",
      target_program: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
      accounts: [
        { pubkey: "5sourceTokenAccount1111111111111111111111111", is_signer: false, is_writable: true },
        { pubkey: "6destTokenAccount11111111111111111111111111111", is_signer: false, is_writable: true },
        { pubkey: "Gokr9F4mEw4hHnVtBJjB55iL1WqdQQ5xrxujkjVrz3kt", is_signer: true, is_writable: false },
      ],
      data: "AwoAAAAAAAAA",
      max_lamports: 250_000_000n,
      max_slippage_bps: null,
      expiry: 1_764_003_600n,
    },
  },
  {
    id: "memo",
    label: "Memo write",
    protocol: "SPL Memo Program",
    blurb: 'On-chain memo ("glyph: universal guardrail") — allowlisted, signer present.',
    intent: {
      agent_pubkey: "Gokr9F4mEw4hHnVtBJjB55iL1WqdQQ5xrxujkjVrz3kt",
      nonce: "3333333333333333333333333333333333333333333333333333333333333333",
      target_program: "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
      accounts: [
        { pubkey: "Gokr9F4mEw4hHnVtBJjB55iL1WqdQQ5xrxujkjVrz3kt", is_signer: true, is_writable: false },
      ],
      data: "Z2x5cGg6IHVuaXZlcnNhbCBndWFyZHJhaWw=",
      max_lamports: 0n,
      max_slippage_bps: null,
      expiry: 1_764_003_600n,
    },
  },
  {
    id: "jupiter",
    label: "Jupiter swap",
    protocol: "Jupiter Aggregator",
    blurb: "Swap via Jupiter — NOT in the allowlist. Denied by the allowed_programs rule.",
    intent: {
      agent_pubkey: "Gokr9F4mEw4hHnVtBJjB55iL1WqdQQ5xrxujkjVrz3kt",
      nonce: "4444444444444444444444444444444444444444444444444444444444444444",
      target_program: "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4",
      accounts: [
        { pubkey: "Gokr9F4mEw4hHnVtBJjB55iL1WqdQQ5xrxujkjVrz3kt", is_signer: true, is_writable: true },
      ],
      data: "AQIDBAUGBwg=",
      max_lamports: 500_000_000n,
      max_slippage_bps: null,
      expiry: 1_764_003_600n,
    },
  },
];
