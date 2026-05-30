// Standalone parity check — verifies the in-browser canonicalization
// reproduces the verified policy_commitment from the Rust multi-protocol demo.
// Run: node scripts/parity-check.mjs  (npm run parity)
//
// Inlines the SAME algorithm as lib/glyph.ts (which mirrors common/src/lib.rs)
// so it runs under plain Node with no TS toolchain.

import { createHash } from "node:crypto";

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function d58(s) {
  let n = 0n;
  for (const ch of s) n = n * 58n + BigInt(B58.indexOf(ch));
  const out = [];
  while (n > 0n) { out.unshift(Number(n & 0xffn)); n >>= 8n; }
  let pad = 0;
  for (const ch of s) { if (ch === "1") pad++; else break; }
  return Buffer.from([...new Array(pad).fill(0), ...out]);
}
const u2 = (v) => { const b = Buffer.alloc(2); b.writeUInt16LE(v); return b; };
const u4 = (v) => { const b = Buffer.alloc(4); b.writeUInt32LE(v); return b; };
const u8 = (v) => { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(v)); return b; };
const sha = (b) => createHash("sha256").update(b).digest("hex");
const cmp = Buffer.compare;

// canonical_serialize_policy(POLICY)
const progs = [
  "11111111111111111111111111111111",
  "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",
].map(d58).sort(cmp);

const parts = [
  u4(1),                 // version (glyph-core schema version)
  u8(1_000_000_000),     // max_lamports_per_tx
  u4(progs.length), ...progs,
  Buffer.from([0]),      // time_window None
  u8(5_000_000_000),     // max_daily_volume_lamports
  Buffer.from([0]),      // max_slippage_bps None
  Buffer.from([0]),      // allowed_token_mints None
  Buffer.from([1]), u2(16), // max_accounts_per_tx Some(16)
  Buffer.from([1]),      // require_signer_present true
  u8(0),                 // expires_at
];

const got = sha(Buffer.concat(parts));
const EXPECTED = "d086deb34a864fb07618821aa5cf02283c4d73ac8f1267f3dbd7f9b0fe0053cb";
console.log("policy_commitment:", got);
console.log("expected         :", EXPECTED);
const ok = got === EXPECTED;
console.log(ok ? "PARITY: PASS" : "PARITY: FAIL");
process.exit(ok ? 0 : 1);
