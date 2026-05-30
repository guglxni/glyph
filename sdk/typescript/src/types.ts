import { Connection, Keypair } from '@solana/web3.js';

import { hexToBytes, bytesToHex } from './canonical';

// ─── Action / wire types ──────────────────────────────────────────────────────

export type ActionType = 'swap' | 'transfer' | 'stake' | 'cpi_call';

/**
 * Canonical (wire-format) account metadata.
 *
 * Field names use snake_case to match the Rust `glyph_common::CanonicalAccountMeta`
 * struct on the TEE worker side. F-3 closes here: this is the *only* shape the
 * wire accepts.
 *
 * `pubkey` is a base58-encoded Solana pubkey string for ergonomic use; the
 * canonical encoder (`canonicalSigningPayload`) takes the binary `CanonicalIntent`
 * shape with `Uint8Array` pubkeys instead.
 */
export interface AccountMeta {
  pubkey: string; // base58-encoded
  is_signer: boolean;
  is_writable: boolean;
}

/**
 * Camel-case alias for ergonomic JS/TS code. Use `toAccountMeta()` to convert
 * to the canonical snake-case wire shape before signing or sending.
 */
export interface AccountMetaCamel {
  pubkey: string;
  isSigner: boolean;
  isWritable: boolean;
}

export function toAccountMeta(camel: AccountMetaCamel): AccountMeta {
  return {
    pubkey: camel.pubkey,
    is_signer: camel.isSigner,
    is_writable: camel.isWritable,
  };
}

export function fromAccountMeta(snake: AccountMeta): AccountMetaCamel {
  return {
    pubkey: snake.pubkey,
    isSigner: snake.is_signer,
    isWritable: snake.is_writable,
  };
}

export interface IntentAction {
  type: ActionType;
  targetProgram: string;
  accounts: AccountMeta[];
  data: string; // base64
}

export interface IntentConstraints {
  /** Lamports cap, kept as bigint to round-trip u64 without loss (closes F-1). */
  maxLamports: bigint;
  maxSlippageBps?: number;
  allowedTokens?: string[]; // base58 mint addresses
}

/**
 * Wire-format JSON intent shipped to the TEE worker.
 * `max_lamports` is encoded as a string so JS `Number` precision loss never
 * truncates a u64. The worker uses `serde_with::DisplayFromStr` to parse it.
 */
export interface TransactionIntent {
  version: 1;
  agent_pubkey: string;
  nonce: string; // hex (32 bytes ⇒ 64 chars)
  timestamp: number;
  expiry: number;
  action: {
    type: ActionType;
    target_program: string;
    accounts: AccountMeta[];
    data: string;
  };
  constraints: {
    max_lamports: string;
    max_slippage_bps?: number;
    allowed_tokens?: string[];
  };
  policy_commitment: string; // hex (32 bytes ⇒ 64 chars)
  worker_pubkey?: string; // hex (32 bytes ⇒ 64 chars), optional
  epoch: number;
  signature: string; // base64-encoded Ed25519 signature
}

// ─── CanonicalIntent (binary signing input) ───────────────────────────────────

/**
 * Mirror of `glyph_common::CanonicalIntent`.
 *
 * All pubkey-shaped fields are 32-byte `Uint8Array`. `max_lamports`, `expiry`,
 * `timestamp`, and `epoch` are `bigint` to round-trip u64 losslessly. This is
 * the shape consumed by `canonicalSigningPayload(...)`; the wire-format
 * `TransactionIntent` is the *output* of `IntentBuilder.build(...)`.
 */
export interface CanonicalAccountMeta {
  pubkey: Uint8Array; // 32 bytes
  is_signer: boolean;
  is_writable: boolean;
}

export interface CanonicalIntent {
  agent_pubkey: Uint8Array; // 32
  nonce: Uint8Array; // 32
  target_program: Uint8Array; // 32
  accounts: CanonicalAccountMeta[];
  data: Uint8Array;
  max_lamports: bigint;
  max_slippage_bps?: number; // 0..=65535
  allowed_tokens?: Uint8Array[]; // each 32 bytes
  expiry: bigint;
  timestamp: bigint;
  policy_commitment: Uint8Array; // 32
  worker_pubkey?: Uint8Array; // 32
  epoch: bigint;
}

// ─── Groth16 / proof types ────────────────────────────────────────────────────

const GROTH16_A_LEN = 64;
const GROTH16_B_LEN = 128;
const GROTH16_C_LEN = 64;

/**
 * Groth16 proof points serialized as fixed-length byte arrays. Lengths are
 * validated at construction time (closes F-4). Use `groth16ProofFromHex` /
 * `groth16ProofToHex` for human-friendly round-trip.
 */
export class Groth16Proof {
  readonly a: Uint8Array;

  readonly b: Uint8Array;

  readonly c: Uint8Array;

  constructor(parts: { a: Uint8Array; b: Uint8Array; c: Uint8Array }) {
    if (parts.a.length !== GROTH16_A_LEN) {
      throw new Error(`Groth16Proof.a must be ${GROTH16_A_LEN} bytes, got ${parts.a.length}`);
    }
    if (parts.b.length !== GROTH16_B_LEN) {
      throw new Error(`Groth16Proof.b must be ${GROTH16_B_LEN} bytes, got ${parts.b.length}`);
    }
    if (parts.c.length !== GROTH16_C_LEN) {
      throw new Error(`Groth16Proof.c must be ${GROTH16_C_LEN} bytes, got ${parts.c.length}`);
    }
    this.a = parts.a;
    this.b = parts.b;
    this.c = parts.c;
  }
}

export function groth16ProofFromHex(input: { a: string; b: string; c: string }): Groth16Proof {
  return new Groth16Proof({
    a: hexToBytes(input.a),
    b: hexToBytes(input.b),
    c: hexToBytes(input.c),
  });
}

export function groth16ProofToHex(proof: Groth16Proof): { a: string; b: string; c: string } {
  return {
    a: bytesToHex(proof.a),
    b: bytesToHex(proof.b),
    c: bytesToHex(proof.c),
  };
}

export interface PublicInputs {
  policy_commitment: Uint8Array; // 32
  intent_hash: Uint8Array; // 32
  agent_pubkey: Uint8Array; // 32
  nonce: Uint8Array; // 32
  tx_hash: Uint8Array; // 32
}

export interface GlyphProofBundle {
  proof: Groth16Proof;
  public_inputs: PublicInputs;
  signed_transaction: Uint8Array;
  /** Bounded debug correlator — first 16 bytes of public_inputs.tx_hash. NOT a Solana signature. Closes F-19, F-29. */
  tx_hash_prefix: Uint8Array;
}

// ─── Client config + worker response ──────────────────────────────────────────

export interface MtlsClientHandle {
  /**
   * Round-trip an intent payload over an mTLS-authenticated transport.
   * Implementations are pluggable; the SDK does not provide one yet.
   */
  send(payload: Uint8Array): Promise<Uint8Array>;
}

export interface GlyphClientConfig {
  connection: Connection;
  /** Accepted forms: `tcp://host:port` and `mtls://host:port`. */
  teeEndpoint: string;
  agentKeypair: Keypair;
  /** Optional injected mTLS transport for `mtls://` endpoints. */
  mtlsClient?: MtlsClientHandle;
  /** Override default 15s socket timeout. */
  timeoutMs?: number;
}

export interface WorkerResponseSuccess {
  status: 'success';
  bundle: GlyphProofBundle;
}

export interface WorkerResponseError {
  status: 'error';
  code?: string;
  message?: string;
}

export type WorkerResponse = WorkerResponseSuccess | WorkerResponseError;

// ─── GlyphError discriminated union ───────────────────────────────────────────

export type GlyphErrorKind =
  | 'ConnectionRefused'
  | 'PolicyDenied'
  | 'AttestationRejected'
  | 'IntentExpired'
  | 'NonceReused'
  | 'ProofVerifyFailed'
  | 'SerializationError'
  | 'TransportNotImplemented'
  | 'InvalidEndpoint'
  | 'WorkerProtocolError'
  | 'Unknown';

export class GlyphError extends Error {
  readonly kind: GlyphErrorKind;

  readonly code?: string;

  constructor(kind: GlyphErrorKind, message: string, code?: string) {
    super(message);
    this.name = 'GlyphError';
    this.kind = kind;
    this.code = code;
    // Restore prototype chain after super() (TS / extending built-ins quirk).
    Object.setPrototypeOf(this, GlyphError.prototype);
  }
}

const WORKER_CODE_TO_KIND: Record<string, GlyphErrorKind> = {
  POLICY_DENIED: 'PolicyDenied',
  POLICY_REJECTED: 'PolicyDenied',
  ATTESTATION_REJECTED: 'AttestationRejected',
  ATTESTATION_FAILED: 'AttestationRejected',
  INTENT_EXPIRED: 'IntentExpired',
  EXPIRED: 'IntentExpired',
  NONCE_REUSED: 'NonceReused',
  REPLAY: 'NonceReused',
  PROOF_VERIFY_FAILED: 'ProofVerifyFailed',
  PROOF_INVALID: 'ProofVerifyFailed',
  SERIALIZATION_ERROR: 'SerializationError',
  BAD_REQUEST: 'SerializationError',
};

export function workerCodeToKind(code: string | undefined): GlyphErrorKind {
  if (!code) return 'Unknown';
  return WORKER_CODE_TO_KIND[code.toUpperCase()] ?? 'Unknown';
}
