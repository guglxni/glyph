/**
 * GLYPH TypeScript SDK — Test Suite
 *
 * Coverage:
 *   - Cross-language canonicalization fixtures (sdk/test-vectors/intents/*).
 *   - IntentBuilder happy-path: builds a wire intent whose signature verifies
 *     under tweetnacl against the agent pubkey.
 *   - GlyphClient endpoint validation (F-7, F-13).
 */

import { Connection, Keypair, PublicKey } from '@solana/web3.js';
import bs58 from 'bs58';
import { readFileSync } from 'fs';
import { join } from 'path';
import nacl from 'tweetnacl';

import {
  canonicalSigningPayload,
  hashSigningPayload,
  hexToBytes,
  bytesToHex,
} from '../canonical';
import { GlyphClient } from '../client';
import { IntentBuilder } from '../intent';
import {
  CanonicalIntent,
  GlyphClientConfig,
  GlyphError,
  Groth16Proof,
  groth16ProofFromHex,
  groth16ProofToHex,
} from '../types';
import { sha256 } from '@noble/hashes/sha256';

// ─── Fixture loader ───────────────────────────────────────────────────────────

const TEST_VECTORS_DIR = join(__dirname, '..', '..', '..', 'test-vectors', 'intents');

interface VectorFile {
  name: string;
  description: string;
  intent: {
    agent_pubkey: string;
    nonce: string;
    target_program: string;
    accounts: { pubkey: string; is_signer: boolean; is_writable: boolean }[];
    data_hex: string;
    max_lamports: string;
    max_slippage_bps: number | null;
    allowed_tokens: string[] | null;
    expiry: string; // string after preserve-bigints pass
    timestamp: string;
    policy_commitment: string;
    worker_pubkey: string | null;
    epoch: string; // string after preserve-bigints pass
  };
}

/**
 * Pre-process JSON text: quote the values of u64-shaped fields so JSON.parse
 * doesn't lossily coerce u64::MAX through `Number`. We swap them back to
 * `bigint` when constructing the CanonicalIntent.
 */
function preserveBigInts(json: string): string {
  return json.replace(
    /("(?:expiry|timestamp|epoch)"\s*:\s*)(-?\d+)(\s*[,}])/g,
    (_m, prefix: string, num: string, suffix: string) => `${prefix}"${num}"${suffix}`,
  );
}

function loadVectorIntent(n: number): {
  input: VectorFile;
  canonicalBytes: Uint8Array;
  expectedSha256: string;
  expectedLen: number;
} {
  const raw = readFileSync(join(TEST_VECTORS_DIR, `${n}.input.json`), 'utf-8');
  const input = JSON.parse(preserveBigInts(raw)) as VectorFile;
  const hex = readFileSync(join(TEST_VECTORS_DIR, `${n}.canonical.bytes`), 'utf-8').trim();
  const canonicalBytes = hexToBytes(hex);
  const signed = JSON.parse(
    readFileSync(join(TEST_VECTORS_DIR, `${n}.signed.json`), 'utf-8'),
  ) as { len: number; sha256: string };
  return {
    input,
    canonicalBytes,
    expectedSha256: signed.sha256,
    expectedLen: signed.len,
  };
}

function vectorToCanonicalIntent(v: VectorFile): CanonicalIntent {
  return {
    agent_pubkey: hexToBytes(v.intent.agent_pubkey),
    nonce: hexToBytes(v.intent.nonce),
    target_program: hexToBytes(v.intent.target_program),
    accounts: v.intent.accounts.map((a) => ({
      pubkey: hexToBytes(a.pubkey),
      is_signer: a.is_signer,
      is_writable: a.is_writable,
    })),
    data: hexToBytes(v.intent.data_hex),
    max_lamports: BigInt(v.intent.max_lamports),
    max_slippage_bps:
      v.intent.max_slippage_bps === null ? undefined : v.intent.max_slippage_bps,
    allowed_tokens:
      v.intent.allowed_tokens === null
        ? undefined
        : v.intent.allowed_tokens.map(hexToBytes),
    expiry: BigInt(v.intent.expiry),
    timestamp: BigInt(v.intent.timestamp),
    policy_commitment: hexToBytes(v.intent.policy_commitment),
    worker_pubkey:
      v.intent.worker_pubkey === null ? undefined : hexToBytes(v.intent.worker_pubkey),
    epoch: BigInt(v.intent.epoch),
  };
}

// ─── Cross-language canonicalization tests ────────────────────────────────────

describe('canonicalSigningPayload — cross-language fixtures', () => {
  for (const n of [1, 2, 3, 4, 5]) {
    test(`vector ${n} matches Rust canonical bytes byte-for-byte`, () => {
      const { input, canonicalBytes, expectedSha256, expectedLen } = loadVectorIntent(n);
      const intent = vectorToCanonicalIntent(input);
      const produced = canonicalSigningPayload(intent);

      expect(produced.length).toBe(expectedLen);
      expect(bytesToHex(produced)).toBe(bytesToHex(canonicalBytes));

      const digest = sha256(produced);
      expect(bytesToHex(digest)).toBe(expectedSha256);

      expect(bytesToHex(hashSigningPayload(intent))).toBe(expectedSha256);
    });
  }
});

// ─── IntentBuilder ────────────────────────────────────────────────────────────

const TOKEN_PROGRAM = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
const SOL_MINT = 'So11111111111111111111111111111111111111112';
const DUMMY_DATA = Buffer.from('transfer_data').toString('base64');

describe('IntentBuilder', () => {
  const keypair = Keypair.generate();

  test('builds a signed transfer intent that nacl can verify', () => {
    const fixedNonce = new Uint8Array(32).fill(0xab);
    const intent = new IntentBuilder()
      .actionType('transfer')
      .targetProgram(TOKEN_PROGRAM)
      .accounts([
        { pubkey: keypair.publicKey.toBase58(), is_signer: true, is_writable: true },
        { pubkey: SOL_MINT, is_signer: false, is_writable: true },
      ])
      .data(DUMMY_DATA)
      .maxLamports(50_000_000n)
      .maxSlippageBps(100)
      .allowedTokens([USDC_MINT, SOL_MINT])
      .expirySeconds(300)
      .withNonce(fixedNonce)
      .build(keypair);

    expect(intent.version).toBe(1);
    expect(intent.agent_pubkey).toBe(keypair.publicKey.toBase58());
    expect(intent.nonce).toBe(bytesToHex(fixedNonce));
    expect(intent.constraints.max_lamports).toBe('50000000');
    expect(intent.signature).not.toBe('');

    // Reconstruct canonical bytes and verify the signature.
    const canonical: CanonicalIntent = {
      agent_pubkey: keypair.publicKey.toBytes(),
      nonce: fixedNonce,
      target_program: bs58.decode(TOKEN_PROGRAM),
      accounts: intent.action.accounts.map((a) => ({
        pubkey: bs58.decode(a.pubkey),
        is_signer: a.is_signer,
        is_writable: a.is_writable,
      })),
      data: new Uint8Array(Buffer.from(intent.action.data, 'base64')),
      max_lamports: 50_000_000n,
      max_slippage_bps: 100,
      allowed_tokens: [USDC_MINT, SOL_MINT].map((m) => bs58.decode(m)),
      expiry: BigInt(intent.expiry),
      timestamp: BigInt(intent.timestamp),
      policy_commitment: hexToBytes(intent.policy_commitment),
      worker_pubkey: undefined,
      epoch: BigInt(intent.epoch),
    };

    const digest = hashSigningPayload(canonical);
    const sigBytes = new Uint8Array(Buffer.from(intent.signature, 'base64'));
    const ok = nacl.sign.detached.verify(digest, sigBytes, keypair.publicKey.toBytes());
    expect(ok).toBe(true);
  });

  test('builds a swap intent', () => {
    const intent = new IntentBuilder()
      .actionType('swap')
      .targetProgram('JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5Nt6f9xWh')
      .accounts([
        { pubkey: keypair.publicKey.toBase58(), is_signer: true, is_writable: true },
      ])
      .data(DUMMY_DATA)
      .maxLamports(1_000_000_000n)
      .maxSlippageBps(50)
      .build(keypair);

    expect(intent.action.type).toBe('swap');
  });

  test('throws on missing action type', () => {
    expect(() =>
      new IntentBuilder()
        .targetProgram(TOKEN_PROGRAM)
        .data(DUMMY_DATA)
        .maxLamports(1_000n)
        .build(keypair),
    ).toThrow(/action type is required/);
  });

  test('throws on missing target program', () => {
    expect(() =>
      new IntentBuilder()
        .actionType('transfer')
        .data(DUMMY_DATA)
        .maxLamports(1_000n)
        .build(keypair),
    ).toThrow(/target program is required/);
  });

  test('throws on missing maxLamports', () => {
    expect(() =>
      new IntentBuilder()
        .actionType('transfer')
        .targetProgram(TOKEN_PROGRAM)
        .data(DUMMY_DATA)
        .build(keypair),
    ).toThrow(/maxLamports/);
  });

  test('rejects negative expirySeconds', () => {
    expect(() => new IntentBuilder().expirySeconds(-5)).toThrow(/positive/);
  });

  test('rejects out-of-range slippage (> 10000 bps)', () => {
    expect(() => new IntentBuilder().maxSlippageBps(20_000)).toThrow(/10000/);
  });

  test('rejects > 256 accounts (DSL Rule 7)', () => {
    const accounts = Array.from({ length: 257 }, () => ({
      pubkey: keypair.publicKey.toBase58(),
      is_signer: false,
      is_writable: false,
    }));
    expect(() => new IntentBuilder().accounts(accounts)).toThrow(/256/);
  });

  test('rejects nonce of wrong length', () => {
    expect(() => new IntentBuilder().withNonce(new Uint8Array(16))).toThrow(/32 bytes/);
  });

  test('two intents with the same fixed nonce produce identical canonical bytes', () => {
    const fixedNonce = new Uint8Array(32).fill(0x42);
    const fixedTimestamp = 1_700_000_000n;
    const a = new IntentBuilder()
      .actionType('transfer')
      .targetProgram(TOKEN_PROGRAM)
      .accounts([])
      .data(DUMMY_DATA)
      .maxLamports(123n)
      .withNonce(fixedNonce)
      .buildCanonical(keypair.publicKey, { timestamp: fixedTimestamp });
    const b = new IntentBuilder()
      .actionType('transfer')
      .targetProgram(TOKEN_PROGRAM)
      .accounts([])
      .data(DUMMY_DATA)
      .maxLamports(123n)
      .withNonce(fixedNonce)
      .buildCanonical(keypair.publicKey, { timestamp: fixedTimestamp });
    expect(bytesToHex(canonicalSigningPayload(a))).toBe(
      bytesToHex(canonicalSigningPayload(b)),
    );
  });
});

// ─── GlyphClient endpoint parsing ─────────────────────────────────────────────

function makeClient(opts: Partial<GlyphClientConfig> = {}): GlyphClient {
  const keypair = Keypair.generate();
  const connection = new Connection('https://api.devnet.solana.com');
  return new GlyphClient({
    connection,
    teeEndpoint: 'tcp://127.0.0.1:8088',
    agentKeypair: keypair,
    ...opts,
  });
}

describe('GlyphClient endpoint validation', () => {
  test('accepts tcp://host:port', () => {
    expect(() => makeClient()).not.toThrow();
  });

  test('accepts mtls://host:port', () => {
    expect(() => makeClient({ teeEndpoint: 'mtls://example.com:8443' })).not.toThrow();
  });

  test('rejects http(s):// endpoints with InvalidEndpoint', () => {
    expect(() => makeClient({ teeEndpoint: 'https://api.devnet.solana.com' })).toThrow(
      GlyphError,
    );
  });

  test('rejects tcp:// without port', () => {
    expect(() => makeClient({ teeEndpoint: 'tcp://localhost' })).toThrow(GlyphError);
  });

  test('rejects empty endpoint', () => {
    expect(() => makeClient({ teeEndpoint: '' })).toThrow(GlyphError);
  });

  test('mtls endpoint without mtlsClient throws TransportNotImplemented at execute', async () => {
    const client = makeClient({ teeEndpoint: 'mtls://example.com:8443' });
    const builder = client.buildIntent();
    const intent = builder
      .actionType('transfer')
      .targetProgram(TOKEN_PROGRAM)
      .accounts([])
      .data(DUMMY_DATA)
      .maxLamports(1n)
      .build(client['agentKeypair'] as Keypair);
    await expect(client.execute(intent)).rejects.toMatchObject({
      kind: 'TransportNotImplemented',
    });
  });

  test('buildIntent returns a chainable IntentBuilder', () => {
    const client = makeClient();
    const builder = client.buildIntent();
    expect(builder.actionType('transfer')).toBe(builder);
  });
});

// ─── Groth16Proof type ────────────────────────────────────────────────────────

describe('Groth16Proof', () => {
  test('rejects wrong-length a', () => {
    expect(
      () =>
        new Groth16Proof({
          a: new Uint8Array(63),
          b: new Uint8Array(128),
          c: new Uint8Array(64),
        }),
    ).toThrow(/64 bytes/);
  });

  test('hex round-trip', () => {
    const a = '00'.repeat(64);
    const b = '11'.repeat(128);
    const c = '22'.repeat(64);
    const proof = groth16ProofFromHex({ a, b, c });
    expect(groth16ProofToHex(proof)).toEqual({ a, b, c });
  });
});
