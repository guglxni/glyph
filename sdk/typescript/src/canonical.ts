/**
 * GLYPH canonical binary encoding — TypeScript implementation.
 *
 * Byte-for-byte mirror of `glyph_common::canonical_signing_payload` in
 * `common/src/lib.rs`. Any deviation here breaks signature verification at
 * the TEE worker. The fixtures under `sdk/test-vectors/intents/*.canonical.bytes`
 * pin this contract.
 *
 * Layout (all integers little-endian):
 *
 *   agent_pubkey                 : 32
 *   nonce                        : 32
 *   target_program               : 32
 *   num_accounts                 : u32 LE
 *   for each account:
 *     pubkey                     : 32
 *     is_signer                  : u8
 *     is_writable                : u8
 *   data_len                     : u32 LE
 *   data                         : data_len bytes
 *   max_lamports                 : u64 LE
 *   max_slippage_bps presence    : u8
 *   max_slippage_bps             : u16 LE   (only if presence == 1)
 *   allowed_tokens presence      : u8
 *   allowed_tokens count         : u32 LE   (only if presence == 1; entries SORTED)
 *   allowed_tokens entries       : 32 bytes each
 *   expiry                       : u64 LE
 *   timestamp                    : u64 LE
 *   policy_commitment            : 32
 *   worker_pubkey presence       : u8
 *   worker_pubkey                : 32       (only if presence == 1)
 *   epoch                        : u64 LE
 */

import { sha256 as nobleSha256 } from '@noble/hashes/sha256';

import type { CanonicalAccountMeta, CanonicalIntent } from './types';

const PUBKEY_LEN = 32;

// ─── Buffer-growth helper ─────────────────────────────────────────────────────

class ByteBuf {
  private chunks: Uint8Array[] = [];

  private size = 0;

  push(bytes: Uint8Array): void {
    this.chunks.push(bytes);
    this.size += bytes.length;
  }

  pushU8(value: number): void {
    this.push(new Uint8Array([value & 0xff]));
  }

  pushU16LE(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xffff) {
      throw new Error(`u16 out of range: ${value}`);
    }
    const buf = new Uint8Array(2);
    buf[0] = value & 0xff;
    buf[1] = (value >>> 8) & 0xff;
    this.push(buf);
  }

  pushU32LE(value: number): void {
    if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
      throw new Error(`u32 out of range: ${value}`);
    }
    const buf = new Uint8Array(4);
    buf[0] = value & 0xff;
    buf[1] = (value >>> 8) & 0xff;
    buf[2] = (value >>> 16) & 0xff;
    buf[3] = (value >>> 24) & 0xff;
    this.push(buf);
  }

  pushU64LE(value: bigint): void {
    if (typeof value !== 'bigint') {
      throw new Error('pushU64LE requires bigint');
    }
    if (value < 0n || value > 0xffffffffffffffffn) {
      throw new Error(`u64 out of range: ${value.toString()}`);
    }
    const buf = new Uint8Array(8);
    let v = value;
    for (let i = 0; i < 8; i += 1) {
      buf[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    this.push(buf);
  }

  toUint8Array(): Uint8Array {
    const out = new Uint8Array(this.size);
    let offset = 0;
    for (const chunk of this.chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

function assertLen(name: string, bytes: Uint8Array, expected: number): void {
  if (bytes.length !== expected) {
    throw new Error(
      `canonical encoding: ${name} must be ${expected} bytes, got ${bytes.length}`,
    );
  }
}

function compareBytes(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i += 1) {
    if (a[i] !== b[i]) {
      return a[i] < b[i] ? -1 : 1;
    }
  }
  if (a.length === b.length) return 0;
  return a.length < b.length ? -1 : 1;
}

function writeAccount(buf: ByteBuf, account: CanonicalAccountMeta): void {
  assertLen('account.pubkey', account.pubkey, PUBKEY_LEN);
  buf.push(account.pubkey);
  buf.pushU8(account.is_signer ? 1 : 0);
  buf.pushU8(account.is_writable ? 1 : 0);
}

// ─── Public API ───────────────────────────────────────────────────────────────

/**
 * Canonical byte serialization of the target instruction
 * (used both as a substring of the signing payload and to compute tx_hash).
 *
 * Mirrors `glyph_common::canonical_target_instruction_bytes`.
 */
export function canonicalTargetInstructionBytes(
  target: Uint8Array,
  accounts: CanonicalAccountMeta[],
  data: Uint8Array,
): Uint8Array {
  assertLen('target_program', target, PUBKEY_LEN);
  if (accounts.length > 0xffffffff) {
    throw new Error('accounts.length exceeds u32');
  }
  if (data.length > 0xffffffff) {
    throw new Error('data.length exceeds u32');
  }

  const buf = new ByteBuf();
  buf.push(target);
  buf.pushU32LE(accounts.length);
  for (const account of accounts) {
    writeAccount(buf, account);
  }
  buf.pushU32LE(data.length);
  buf.push(data);
  return buf.toUint8Array();
}

/**
 * Canonical byte serialization of the signing payload (the bytes the agent's
 * Ed25519 key signs over). Mirrors `glyph_common::canonical_signing_payload`
 * exactly. Any drift here breaks worker-side signature verification.
 */
export function canonicalSigningPayload(intent: CanonicalIntent): Uint8Array {
  assertLen('agent_pubkey', intent.agent_pubkey, PUBKEY_LEN);
  assertLen('nonce', intent.nonce, PUBKEY_LEN);
  assertLen('target_program', intent.target_program, PUBKEY_LEN);
  assertLen('policy_commitment', intent.policy_commitment, PUBKEY_LEN);

  const buf = new ByteBuf();

  buf.push(intent.agent_pubkey);
  buf.push(intent.nonce);

  // Reuse target-instruction encoding (program/accounts/data)
  buf.push(
    canonicalTargetInstructionBytes(intent.target_program, intent.accounts, intent.data),
  );

  buf.pushU64LE(intent.max_lamports);

  if (intent.max_slippage_bps === undefined || intent.max_slippage_bps === null) {
    buf.pushU8(0);
  } else {
    buf.pushU8(1);
    buf.pushU16LE(intent.max_slippage_bps);
  }

  if (intent.allowed_tokens === undefined || intent.allowed_tokens === null) {
    buf.pushU8(0);
  } else {
    buf.pushU8(1);
    // Sort byte-wise to match Rust's `sort_unstable` on `[u8; 32]`.
    const sorted = [...intent.allowed_tokens]
      .map((t) => {
        assertLen('allowed_tokens entry', t, PUBKEY_LEN);
        return t;
      })
      .sort(compareBytes);
    buf.pushU32LE(sorted.length);
    for (const token of sorted) {
      buf.push(token);
    }
  }

  buf.pushU64LE(intent.expiry);
  buf.pushU64LE(intent.timestamp);
  buf.push(intent.policy_commitment);

  if (intent.worker_pubkey === undefined || intent.worker_pubkey === null) {
    buf.pushU8(0);
  } else {
    assertLen('worker_pubkey', intent.worker_pubkey, PUBKEY_LEN);
    buf.pushU8(1);
    buf.push(intent.worker_pubkey);
  }

  buf.pushU64LE(intent.epoch);

  return buf.toUint8Array();
}

/** SHA-256 of `canonicalSigningPayload(intent)` — the digest the agent signs. */
export function hashSigningPayload(intent: CanonicalIntent): Uint8Array {
  return nobleSha256(canonicalSigningPayload(intent));
}

/** SHA-256 of `canonicalTargetInstructionBytes(...)` — the tx_hash component. */
export function hashTargetInstruction(
  target: Uint8Array,
  accounts: CanonicalAccountMeta[],
  data: Uint8Array,
): Uint8Array {
  return nobleSha256(canonicalTargetInstructionBytes(target, accounts, data));
}

// ─── Hex helpers (used by tests and debug paths) ──────────────────────────────

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 1) {
    out += bytes[i].toString(16).padStart(2, '0');
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  if (clean.length % 2 !== 0) {
    throw new Error(`hex string has odd length: ${hex}`);
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    const byte = Number.parseInt(clean.substr(i * 2, 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error(`invalid hex at offset ${i * 2}: ${hex}`);
    }
    out[i] = byte;
  }
  return out;
}
