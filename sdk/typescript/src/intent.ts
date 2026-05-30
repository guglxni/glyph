import { Keypair, PublicKey } from '@solana/web3.js';
import bs58 from 'bs58';
import nacl from 'tweetnacl';
import { randomBytes } from 'crypto';

import {
  bytesToHex,
  canonicalSigningPayload,
  hashSigningPayload,
} from './canonical';
import {
  AccountMeta,
  ActionType,
  CanonicalAccountMeta,
  CanonicalIntent,
  GlyphError,
  IntentConstraints,
  TransactionIntent,
} from './types';

const MAX_SLIPPAGE_BPS = 10_000;
const MAX_ACCOUNTS = 256;
const MAX_U64 = 0xffffffffffffffffn;

function decodeBase58Pubkey(value: string): Uint8Array {
  const decoded = bs58.decode(value);
  const bytes = decoded instanceof Uint8Array ? decoded : Uint8Array.from(decoded);
  if (bytes.length !== 32) {
    throw new GlyphError(
      'SerializationError',
      `pubkey ${value} decoded to ${bytes.length} bytes, expected 32`,
    );
  }
  return bytes;
}

function decodeBase64(value: string): Uint8Array {
  // Buffer is faster and avoids node-vs-browser atob differences here; the SDK
  // is Node-only at the moment.
  return new Uint8Array(Buffer.from(value, 'base64'));
}

function toCanonicalAccount(account: AccountMeta): CanonicalAccountMeta {
  return {
    pubkey: decodeBase58Pubkey(account.pubkey),
    is_signer: account.is_signer,
    is_writable: account.is_writable,
  };
}

export interface BuildOptions {
  /** Override the timestamp embedded in the canonical payload. Defaults to wall clock. */
  timestamp?: bigint;
}

export class IntentBuilder {
  private constraints: Partial<IntentConstraints> = {};

  private expiryWindowSeconds = 300;

  private nonceOverride?: Uint8Array;

  private policyCommitment: Uint8Array = new Uint8Array(32);

  private workerPubkey?: Uint8Array;

  private epoch = 0n;

  // ─── Action setters ─────────────────────────────────────────────────────────
  //
  // Setters are independent — none silently fills in defaults for the other
  // fields. `build()` requires every field to be explicitly set.

  private actionTypeValue?: ActionType;

  private targetProgramValue?: string;

  private accountsValue: AccountMeta[] = [];

  private dataValue?: string;

  actionType(type: ActionType): IntentBuilder {
    this.actionTypeValue = type;
    return this;
  }

  targetProgram(program: string): IntentBuilder {
    this.targetProgramValue = program;
    return this;
  }

  accounts(accounts: AccountMeta[]): IntentBuilder {
    if (accounts.length > MAX_ACCOUNTS) {
      throw new GlyphError(
        'SerializationError',
        `accounts.length=${accounts.length} exceeds DSL Rule 7 cap of ${MAX_ACCOUNTS}`,
      );
    }
    this.accountsValue = accounts;
    return this;
  }

  data(base64Data: string): IntentBuilder {
    this.dataValue = base64Data;
    return this;
  }

  // ─── Constraint setters ────────────────────────────────────────────────────

  maxLamports(maxLamports: bigint): IntentBuilder {
    if (typeof maxLamports !== 'bigint') {
      throw new GlyphError(
        'SerializationError',
        'maxLamports must be a bigint (u64)',
      );
    }
    if (maxLamports < 0n || maxLamports > MAX_U64) {
      throw new GlyphError(
        'SerializationError',
        `maxLamports out of u64 range: ${maxLamports.toString()}`,
      );
    }
    this.constraints.maxLamports = maxLamports;
    return this;
  }

  maxSlippageBps(maxSlippageBps: number): IntentBuilder {
    if (
      !Number.isInteger(maxSlippageBps) ||
      maxSlippageBps < 0 ||
      maxSlippageBps > MAX_SLIPPAGE_BPS
    ) {
      throw new GlyphError(
        'SerializationError',
        `maxSlippageBps must be an integer in 0..=${MAX_SLIPPAGE_BPS}`,
      );
    }
    this.constraints.maxSlippageBps = maxSlippageBps;
    return this;
  }

  allowedTokens(allowedTokens: string[]): IntentBuilder {
    this.constraints.allowedTokens = allowedTokens;
    return this;
  }

  expirySeconds(seconds: number): IntentBuilder {
    if (!Number.isFinite(seconds) || seconds <= 0) {
      throw new GlyphError(
        'SerializationError',
        'expirySeconds must be a positive number',
      );
    }
    this.expiryWindowSeconds = seconds;
    return this;
  }

  /**
   * Use a caller-supplied 32-byte nonce instead of generating one. Closes F-11
   * — lets callers dedup on the client side and write deterministic replay tests.
   */
  withNonce(nonce: Uint8Array): IntentBuilder {
    if (nonce.length !== 32) {
      throw new GlyphError(
        'SerializationError',
        `nonce must be 32 bytes, got ${nonce.length}`,
      );
    }
    this.nonceOverride = nonce;
    return this;
  }

  policyCommitmentBytes(commitment: Uint8Array): IntentBuilder {
    if (commitment.length !== 32) {
      throw new GlyphError(
        'SerializationError',
        'policy_commitment must be 32 bytes',
      );
    }
    this.policyCommitment = commitment;
    return this;
  }

  workerPubkeyBytes(pubkey: Uint8Array | undefined): IntentBuilder {
    if (pubkey === undefined) {
      this.workerPubkey = undefined;
      return this;
    }
    if (pubkey.length !== 32) {
      throw new GlyphError(
        'SerializationError',
        'worker_pubkey must be 32 bytes',
      );
    }
    this.workerPubkey = pubkey;
    return this;
  }

  setEpoch(epoch: bigint | number): IntentBuilder {
    const value = typeof epoch === 'bigint' ? epoch : BigInt(epoch);
    if (value < 0n || value > MAX_U64) {
      throw new GlyphError(
        'SerializationError',
        `epoch out of u64 range: ${value.toString()}`,
      );
    }
    this.epoch = value;
    return this;
  }

  // ─── Build ─────────────────────────────────────────────────────────────────

  /**
   * Build the canonical intent struct (without signing). Useful when you want
   * to compute the signing-payload hash or pre-flight without producing a
   * wire-format payload.
   */
  buildCanonical(agent: PublicKey, options: BuildOptions = {}): CanonicalIntent {
    if (!this.actionTypeValue) {
      throw new GlyphError('SerializationError', 'Intent action type is required');
    }
    if (!this.targetProgramValue) {
      throw new GlyphError(
        'SerializationError',
        'Intent target program is required',
      );
    }
    if (!this.dataValue) {
      throw new GlyphError('SerializationError', 'Intent data (base64) is required');
    }
    if (this.constraints.maxLamports === undefined) {
      throw new GlyphError(
        'SerializationError',
        'Intent maxLamports constraint is required',
      );
    }

    const accounts = this.accountsValue.map(toCanonicalAccount);
    if (accounts.length > MAX_ACCOUNTS) {
      throw new GlyphError(
        'SerializationError',
        `accounts.length=${accounts.length} exceeds DSL Rule 7 cap`,
      );
    }

    const timestamp =
      options.timestamp ?? BigInt(Math.floor(Date.now() / 1000));
    const expiry = timestamp + BigInt(this.expiryWindowSeconds);
    const nonce = this.nonceOverride ?? new Uint8Array(randomBytes(32));

    const allowedTokens =
      this.constraints.allowedTokens === undefined
        ? undefined
        : this.constraints.allowedTokens.map(decodeBase58Pubkey);

    const canonical: CanonicalIntent = {
      agent_pubkey: agent.toBytes(),
      nonce,
      target_program: decodeBase58Pubkey(this.targetProgramValue),
      accounts,
      data: decodeBase64(this.dataValue),
      max_lamports: this.constraints.maxLamports,
      max_slippage_bps: this.constraints.maxSlippageBps,
      allowed_tokens: allowedTokens,
      expiry,
      timestamp,
      policy_commitment: this.policyCommitment,
      worker_pubkey: this.workerPubkey,
      epoch: this.epoch,
    };

    return canonical;
  }

  /**
   * Build, sign, and produce a wire-format `TransactionIntent`. The signature
   * covers `hashSigningPayload(canonicalIntent)` (SHA-256 of the canonical
   * binary bytes) — byte-for-byte identical to what the Rust SDK and TEE
   * worker compute (closes F-1, F-2).
   */
  build(keypair: Keypair, options: BuildOptions = {}): TransactionIntent {
    const canonical = this.buildCanonical(keypair.publicKey, options);
    const digest = hashSigningPayload(canonical);
    const signature = nacl.sign.detached(digest, keypair.secretKey);

    const wire: TransactionIntent = {
      version: 1,
      agent_pubkey: keypair.publicKey.toBase58(),
      nonce: bytesToHex(canonical.nonce),
      timestamp: Number(canonical.timestamp),
      expiry: Number(canonical.expiry),
      action: {
        type: this.actionTypeValue!,
        target_program: this.targetProgramValue!,
        accounts: this.accountsValue,
        data: this.dataValue!,
      },
      constraints: {
        max_lamports: this.constraints.maxLamports!.toString(),
        ...(this.constraints.maxSlippageBps !== undefined
          ? { max_slippage_bps: this.constraints.maxSlippageBps }
          : {}),
        ...(this.constraints.allowedTokens !== undefined
          ? { allowed_tokens: this.constraints.allowedTokens }
          : {}),
      },
      policy_commitment: bytesToHex(canonical.policy_commitment),
      ...(canonical.worker_pubkey !== undefined
        ? { worker_pubkey: bytesToHex(canonical.worker_pubkey) }
        : {}),
      epoch: Number(canonical.epoch),
      signature: Buffer.from(signature).toString('base64'),
    };

    return wire;
  }
}
