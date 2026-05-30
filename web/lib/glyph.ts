/**
 * In-browser port of Glyph canonical serialization + policy evaluation.
 *
 * Ported BYTE-FOR-BYTE from the single source of truth:
 *   common/src/lib.rs
 *     - canonical_serialize_policy()        -> policy_commitment
 *     - canonical_intent_preimage()         -> intent_hash
 *     - canonical_target_instruction_bytes()-> tx_hash
 *
 * Produces SHA-256 digests identical to the Rust SDK, the TEE worker, the
 * RISC Zero circuit, and the on-chain verifier. Verified against the
 * multi-protocol artifact: policy_commitment ==
 *   d086deb34a864fb07618821aa5cf02283c4d73ac8f1267f3dbd7f9b0fe0053cb
 *
 * All integers are little-endian. No domain tags — the Rust encoding does not
 * prefix one. Vectors are length-prefixed (u32 LE); program/mint vectors are
 * byte-sorted before encoding (matching Rust's `sort_unstable`).
 */

// ─── Types (mirror glyph_common::Policy / IntentPayload) ──────────────────────

export interface TimeWindow {
  start_hour_utc: number;
  end_hour_utc: number;
}

export interface Policy {
  version: number; // u32
  max_lamports_per_tx: bigint; // u64
  allowed_programs: string[]; // base58 pubkeys
  time_window: TimeWindow | null;
  max_daily_volume_lamports: bigint; // u64
  max_slippage_bps: number | null; // u16
  allowed_token_mints: string[] | null; // base58
  max_accounts_per_tx: number | null; // u16
  require_signer_present: boolean;
  expires_at: bigint; // u64
}

export interface AccountMetaData {
  pubkey: string; // base58
  is_signer: boolean;
  is_writable: boolean;
}

export interface Intent {
  agent_pubkey: string; // base58
  nonce: string; // 64 hex chars (32 bytes)
  target_program: string; // base58
  accounts: AccountMetaData[];
  data: string; // base64
  max_lamports: bigint; // u64
  max_slippage_bps: number | null;
  expiry: bigint; // u64
}

export type Decision =
  | { type: "allow" }
  | { type: "deny"; code: number; rule: string; reason: string };

// ─── base58 / hex / base64 helpers (no deps) ──────────────────────────────────

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

export function base58Decode(s: string): Uint8Array {
  let n = 0n;
  for (const ch of s) {
    const idx = B58.indexOf(ch);
    if (idx < 0) throw new Error(`invalid base58 char '${ch}'`);
    n = n * 58n + BigInt(idx);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  let pad = 0;
  for (const ch of s) {
    if (ch === "1") pad++;
    else break;
  }
  return Uint8Array.from([...new Array(pad).fill(0), ...bytes]);
}

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}

function base64ToBytes(b64: string): Uint8Array {
  if (typeof atob === "function") {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  // Node fallback
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  return new Uint8Array(Buffer.from(b64, "base64"));
}

export function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
}

// ─── Byte writer ──────────────────────────────────────────────────────────────

class W {
  private c: number[] = [];
  byte(v: number) { this.c.push(v & 0xff); }
  bytes(a: ArrayLike<number>) { for (let i = 0; i < a.length; i++) this.c.push(a[i] & 0xff); }
  u16(v: number) { this.c.push(v & 0xff, (v >>> 8) & 0xff); }
  u32(v: number) { this.c.push(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff); }
  u64(v: bigint) {
    let x = BigInt.asUintN(64, v);
    for (let i = 0; i < 8; i++) { this.c.push(Number(x & 0xffn)); x >>= 8n; }
  }
  out(): Uint8Array { return Uint8Array.from(this.c); }
}

// ─── SHA-256 (Web Crypto, async) ──────────────────────────────────────────────

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  const buf = await crypto.subtle.digest("SHA-256", bytes as unknown as ArrayBuffer);
  return new Uint8Array(buf);
}

// ─── canonical_serialize_policy ───────────────────────────────────────────────

export function serializePolicy(p: Policy): Uint8Array {
  const w = new W();
  w.u32(p.version);
  w.u64(p.max_lamports_per_tx);

  // allowed_programs (sorted, length-prefixed)
  const progs = p.allowed_programs.map(base58Decode).sort(compareBytes);
  w.u32(progs.length);
  for (const pr of progs) w.bytes(pr);

  // time_window (optional)
  if (p.time_window) {
    w.byte(1);
    w.byte(p.time_window.start_hour_utc);
    w.byte(p.time_window.end_hour_utc);
  } else {
    w.byte(0);
  }

  w.u64(p.max_daily_volume_lamports);

  // max_slippage_bps (optional)
  if (p.max_slippage_bps != null) {
    w.byte(1);
    w.u16(p.max_slippage_bps);
  } else {
    w.byte(0);
  }

  // allowed_token_mints (optional, sorted)
  if (p.allowed_token_mints != null) {
    w.byte(1);
    const mints = p.allowed_token_mints.map(base58Decode).sort(compareBytes);
    w.u32(mints.length);
    for (const m of mints) w.bytes(m);
  } else {
    w.byte(0);
  }

  // max_accounts_per_tx (optional)
  if (p.max_accounts_per_tx != null) {
    w.byte(1);
    w.u16(p.max_accounts_per_tx);
  } else {
    w.byte(0);
  }

  w.byte(p.require_signer_present ? 1 : 0);
  w.u64(p.expires_at);

  return w.out();
}

export async function hashPolicy(p: Policy): Promise<Uint8Array> {
  return sha256(serializePolicy(p));
}

// ─── canonical_intent_preimage (circuit intent_hash) ──────────────────────────

export function serializeIntent(it: Intent): Uint8Array {
  const w = new W();
  w.bytes(base58Decode(it.agent_pubkey));
  w.bytes(hexToBytes(it.nonce));
  w.bytes(base58Decode(it.target_program));
  w.u64(it.max_lamports);
  if (it.max_slippage_bps != null) {
    w.byte(1);
    w.u16(it.max_slippage_bps);
  } else {
    w.byte(0);
  }
  w.u16(it.accounts.length); // num_accounts (u16)
  w.u64(it.expiry);
  return w.out();
}

export async function hashIntent(it: Intent): Promise<Uint8Array> {
  return sha256(serializeIntent(it));
}

// ─── canonical_target_instruction_bytes (tx_hash) ─────────────────────────────

export function serializeTargetInstruction(it: Intent): Uint8Array {
  const w = new W();
  w.bytes(base58Decode(it.target_program));
  w.u32(it.accounts.length);
  for (const a of it.accounts) {
    w.bytes(base58Decode(a.pubkey));
    w.byte(a.is_signer ? 1 : 0);
    w.byte(a.is_writable ? 1 : 0);
  }
  const data = base64ToBytes(it.data);
  w.u32(data.length);
  w.bytes(data);
  return w.out();
}

export async function hashTxBinding(it: Intent): Promise<Uint8Array> {
  return sha256(serializeTargetInstruction(it));
}

// ─── Policy evaluation (mirrors tee-worker PolicyEngine, generic rules) ────────

export function evaluate(policy: Policy, it: Intent): Decision {
  // allowed_programs (the only program-aware rule)
  if (policy.allowed_programs.length > 0) {
    const ok = policy.allowed_programs.includes(it.target_program);
    if (!ok) {
      return {
        type: "deny",
        code: 2,
        rule: "allowed_programs",
        reason: `target program not in allowlist`,
      };
    }
  }
  // max_lamports_per_tx
  if (it.max_lamports > policy.max_lamports_per_tx) {
    return {
      type: "deny",
      code: 1,
      rule: "max_lamports_per_tx",
      reason: `max_lamports ${it.max_lamports} exceeds cap ${policy.max_lamports_per_tx}`,
    };
  }
  // max_accounts_per_tx
  if (policy.max_accounts_per_tx != null && it.accounts.length > policy.max_accounts_per_tx) {
    return {
      type: "deny",
      code: 7,
      rule: "max_accounts_per_tx",
      reason: `${it.accounts.length} accounts exceeds cap ${policy.max_accounts_per_tx}`,
    };
  }
  // require_signer_present
  if (policy.require_signer_present && !it.accounts.some((a) => a.is_signer)) {
    return {
      type: "deny",
      code: 8,
      rule: "require_signer_present",
      reason: `no signer present`,
    };
  }
  return { type: "allow" };
}
